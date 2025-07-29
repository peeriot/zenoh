use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bluer::adv::{Advertisement, SecondaryChannel, Type};
use bluer::gatt::local::{
    characteristic_control, Application, Characteristic, CharacteristicControlEvent,
    CharacteristicNotify, CharacteristicNotifyMethod, CharacteristicWrite,
    CharacteristicWriteMethod, Service,
};
use bluer::gatt::{CharacteristicReader, CharacteristicWriter};
use bluer::{AdapterEvent, Address, AddressType, Device, DiscoveryFilter, DiscoveryTransport};
use futures::{pin_mut, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zenoh_core::{zasyncread, zasyncwrite};
use zenoh_link_commons::{
    ConstructibleLinkManagerUnicast, LinkAuthId, LinkManagerUnicastTrait, LinkUnicast,
    LinkUnicastTrait, NewLinkChannelSender,
};
use zenoh_protocol::core::{EndPoint, Locator};
use zenoh_result::{zerror, ZResult};

use crate::{BT_GATT_LOCATOR_PREFIX, BT_GATT_MAX_MTU};

#[derive(Debug)]
#[allow(dead_code)] // False positive
enum Error {
    Bluer(bluer::Error),
    Io(std::io::Error),
    UnrecognizedDevice,
    FailedToConnect,
}

impl From<bluer::Error> for Error {
    fn from(e: bluer::Error) -> Self {
        Error::Bluer(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Error::Io(value)
    }
}

struct LinkUnicastBtGatt {
    /// Handle to the Bluetooth device
    device_handle: Arc<Mutex<Option<Device>>>,
    /// Handler to the Characteristic Writer used for writing bytes
    char_writer: Arc<Mutex<Option<CharacteristicWriter>>>,
    /// Handler to the Characteristic Reader used for reading bytes
    char_reader: Arc<Mutex<Option<CharacteristicReader>>>,
    // The BT advertised name to use as locator
    src_locator: Locator,
    // The serial destination path (random UUIDv4)
    dst_locator: Locator,
    /// The interface used for this link
    interface: String,
}

unsafe impl Send for LinkUnicastBtGatt {}
unsafe impl Sync for LinkUnicastBtGatt {}

impl LinkUnicastBtGatt {
    fn new(
        device_handle: Option<Device>,
        char_reader: CharacteristicReader,
        char_writer: CharacteristicWriter,
        src_path: &str,
        dst_path: &str,
        interface: String,
    ) -> Self {
        Self {
            device_handle: Arc::new(Mutex::new(device_handle)),
            char_reader: Arc::new(Mutex::new(Some(char_reader))),
            char_writer: Arc::new(Mutex::new(Some(char_writer))),
            src_locator: Locator::new(BT_GATT_LOCATOR_PREFIX, src_path, "").unwrap(),
            dst_locator: Locator::new(BT_GATT_LOCATOR_PREFIX, dst_path, "").unwrap(),
            interface,
        }
    }
}

#[async_trait]
impl LinkUnicastTrait for LinkUnicastBtGatt {
    fn get_mtu(&self) -> u16 {
        let r_mtu = self
            .char_reader
            .try_lock()
            .ok()
            .and_then(|r| r.as_ref().map(|r| r.mtu()));
        let w_mtu = self
            .char_writer
            .try_lock()
            .ok()
            .and_then(|w| w.as_ref().map(|w| w.mtu()));

        // If we can't lock and find the true MTU, it's not a big deal
        r_mtu
            .zip(w_mtu)
            .map(|(r_mtu, w_mtu)| r_mtu.min(w_mtu) as u16)
            .unwrap_or(BT_GATT_MAX_MTU)
    }

    #[inline(always)]
    fn get_src(&self) -> &Locator {
        &self.src_locator
    }

    #[inline(always)]
    fn get_dst(&self) -> &Locator {
        &self.dst_locator
    }

    #[inline(always)]
    fn is_reliable(&self) -> bool {
        false
    }

    #[inline(always)]
    fn is_streamed(&self) -> bool {
        false
    }

    fn get_interface_names(&self) -> Vec<String> {
        vec![self.interface.clone()]
    }

    #[inline(always)]
    fn get_auth_id(&self) -> &LinkAuthId {
        // TODO: Can be expanded with BLE security
        &LinkAuthId::Ble
    }

    async fn write(&self, buffer: &[u8]) -> ZResult<usize> {
        match self.char_writer.lock().await.as_mut() {
            Some(writer) => writer.write(buffer).await.map_err(|e| {
                let e = zerror!("Unable to write on BT GATT link {}: {}", self, e);
                tracing::error!("{}", e);

                e.into()
            }),
            None => {
                let e = zerror!("Unable to write on BT GATT link {}: Port not open", self);
                tracing::error!("{}", e);

                Err(e.into())
            }
        }
    }

    async fn write_all(&self, buffer: &[u8]) -> ZResult<()> {
        match self.char_writer.lock().await.as_mut() {
            Some(writer) => writer.write_all(buffer).await.map_err(|e| {
                let e = zerror!("Unable to write on BT GATT link {}: {}", self, e);
                tracing::error!("{}", e);

                e.into()
            }),
            None => {
                let e = zerror!(
                    "Unable to write on BT GATT link {}: Peripheral not connected",
                    self
                );
                tracing::error!("{}", e);

                Err(e.into())
            }
        }
    }

    async fn read(&self, buffer: &mut [u8]) -> ZResult<usize> {
        match self.char_reader.lock().await.as_mut() {
            Some(reader) => {
                let res = reader.read(buffer).await.map_err(|e| {
                    let e = zerror!("Unable to read from BT GATT link {}: {}", self, e);
                    tracing::error!("{}", e);

                    tracing::trace!("Read END");
                    e.into()
                });

                match res {
                    Ok(0) if buffer.len() != 0 => {
                        return Err(zerror!("End Of Life for {}", self.src_locator).into());
                    }
                    _ => (),
                }

                res
            }
            None => {
                let e = zerror!(
                    "Unable to read from BT GATT link {}: Peripheral not connected",
                    self
                );
                tracing::error!("{}", e);

                Err(e.into())
            }
        }
    }

    async fn read_exact(&self, buffer: &mut [u8]) -> ZResult<()> {
        match self.char_reader.lock().await.as_mut() {
            Some(reader) => {
                let res = reader.read_exact(buffer).await.map(|_| ()).map_err(|e| {
                    let e = zerror!("Unable to read from BT GATT link {}: {}", self, e);
                    tracing::error!("{}", e);

                    e.into()
                });

                res
            }
            None => {
                let e = zerror!(
                    "Unable to read from BT GATT link {}: Peripheral not connected",
                    self
                );
                tracing::error!("{}", e);

                Err(e.into())
            }
        }
    }

    async fn close(&self) -> ZResult<()> {
        let mut bt_handle = self.device_handle.lock().await;
        if let Some(device) = bt_handle.take() {
            if device
                .is_connected()
                .await
                .expect("Can't check if the peripheral is connected")
            {
                device.disconnect().await.map_err(|e| {
                    let e = zerror!("Unable to close BT GATT link {}: {}", self, e);
                    tracing::error!("{}", e);
                    e
                })?;
            }
        }

        Ok(())
    }
}

impl fmt::Display for LinkUnicastBtGatt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} => {}", self.src_locator, self.dst_locator)?;
        Ok(())
    }
}

impl fmt::Debug for LinkUnicastBtGatt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BT GATT")
            .field("src", &self.src_locator)
            .field("dst", &self.dst_locator)
            .finish()
    }
}

/*************************************/
/*          LISTENER                 */
/*************************************/
struct ListenerUnicastBtGatt {
    endpoint: EndPoint,
    token: CancellationToken,
    handle: JoinHandle<ZResult<()>>,
}

impl ListenerUnicastBtGatt {
    fn new(endpoint: EndPoint, token: CancellationToken, handle: JoinHandle<ZResult<()>>) -> Self {
        Self {
            endpoint,
            token,
            handle,
        }
    }

    async fn stop(&self) {
        self.token.cancel();
    }
}

pub struct LinkManagerUnicastBtGatt {
    manager: NewLinkChannelSender,
    listeners: Arc<RwLock<HashMap<String, ListenerUnicastBtGatt>>>,
}

impl LinkManagerUnicastBtGatt {
    pub fn new(manager: NewLinkChannelSender) -> Self {
        Self {
            manager,
            listeners: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}
impl ConstructibleLinkManagerUnicast<()> for LinkManagerUnicastBtGatt {
    fn new(new_link_sender: NewLinkChannelSender, _: ()) -> ZResult<Self> {
        Ok(Self::new(new_link_sender))
    }
}

#[async_trait]
impl LinkManagerUnicastTrait for LinkManagerUnicastBtGatt {
    async fn new_link(&self, endpoint: EndPoint) -> ZResult<LinkUnicast> {
        let address = endpoint.address().to_string();
        let (adapter_choice, device_name) = if let Some((adapter, device)) = address.split_once("@")
        {
            (Some(adapter.to_owned()), device.to_owned())
        } else {
            (None, address)
        };

        // Attempt direct connection
        let link = Arc::new(find_device(device_name, adapter_choice).await?);

        Ok(LinkUnicast(link))
    }

    async fn new_listener(&self, endpoint: EndPoint) -> ZResult<Locator> {
        let device_name = endpoint.address().to_string();

        let session = bluer::Session::new().await?;

        // Grab adapter
        let (adapter, device_name) = if let Some((adapter, device)) = device_name.split_once("@") {
            (Some(adapter), device.to_owned())
        } else {
            (None, device_name)
        };
        let adapter = if let Some(adapter) = adapter {
            session.adapter(adapter)?
        } else {
            session.default_adapter().await?
        };

        if !adapter.is_powered().await? {
            adapter.set_powered(true).await?;
        }

        // Peeriot's BLE dongle lacks Public Addressing
        // NOTE: The listener code won't work unless the Linux kernel is patched, fixing the bug
        //       where static random addressed BLE controllers can't use extended advertising.
        //       See: io/zenoh-links/zenoh-link-bt-gatt/extended-advertising-static-random-address.patch
        if !matches!(adapter.address_type().await?, AddressType::LeRandom) {
            panic!("Not a LeRandom address");
        }

        // Close pre-existing active advertising instances for a clean slate
        if adapter.active_advertising_instances().await? > 0 {
            adapter.set_discoverable(false).await?;
        }

        tracing::info!("Adding new BLE listener: {}", &device_name);

        // Enable extended advertising. This will make sure we have less conflict with other BLE
        // devices that might be present, as it offloads the advertising to secondary channels which
        // are always less congested.
        let le_advertisement = Advertisement {
            advertisement_type: Type::Peripheral,
            service_uuids: vec![Uuid::from(bluer::id::Service::ComNordicsemiServiceUart)]
                .into_iter()
                .collect(),
            discoverable: Some(true),
            local_name: Some(device_name),
            // We don't care about speed of visibility, so set min-max intervals to be quite large
            // so that we have more radio time for actual existing connections.
            min_interval: Some(Duration::from_millis(1500)),
            max_interval: Some(Duration::from_millis(2000)),
            // Choose the fastest PHY for the secondary channel
            secondary_channel: Some(SecondaryChannel::TwoM),
            ..Default::default()
        };
        let _adv_handle = adapter.advertise(le_advertisement.clone()).await?;

        // Create GATT control application which will expose the Nordic Uart Service to communicate
        // with Peeriot.SwarmEmbedded devices
        let (mut char_write_control, char_write_handle) = characteristic_control();
        let (mut char_notify_control, char_notify_handle) = characteristic_control();
        let app = Application {
            services: vec![Service {
                uuid: Uuid::from(bluer::id::Service::ComNordicsemiServiceUart),
                primary: true,
                characteristics: vec![
                    Characteristic {
                        uuid: Uuid::from(
                            bluer::id::Characteristic::ComNordicsemiCharacteristicUartRx,
                        ),
                        write: Some(CharacteristicWrite {
                            write: true,
                            write_without_response: true,
                            method: CharacteristicWriteMethod::Io,
                            ..Default::default()
                        }),
                        control_handle: char_write_handle,
                        ..Default::default()
                    },
                    Characteristic {
                        uuid: Uuid::from(
                            bluer::id::Characteristic::ComNordicsemiCharacteristicUartTx,
                        ),
                        notify: Some(CharacteristicNotify {
                            notify: true,
                            method: CharacteristicNotifyMethod::Io,
                            ..Default::default()
                        }),
                        control_handle: char_notify_handle,
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
            ..Default::default()
        };
        let app_handle = adapter.serve_gatt_application(app).await?;
        let token = CancellationToken::new();

        let mut listeners = zasyncwrite!(self.listeners);
        let task = {
            let manager = self.manager.clone();
            let token = token.clone();

            let mut adapter_events = adapter.events().await?;
            let mut characteristics_rx_mapping: HashMap<Address, CharacteristicReader> =
                HashMap::new();
            let mut characteristics_tx_mapping: HashMap<Address, CharacteristicWriter> =
                HashMap::new();

            async move {
                // Make sure the handles we care about are kept alive
                let _keep_alive = (app_handle, session);
                let mut _adv_handle = Some(_adv_handle);

                loop {
                    tokio::select! {
                        evt = adapter_events.next() => {
                            // We can't rely on device added events because the device could've been
                            // added before we created the listener. However, what we can do is to
                            // remove keys if the device is removed (almost like a cleanup so that
                            // we don't check the hashmaps of devices that are not even connected)
                            if let Some(AdapterEvent::DeviceRemoved(address)) = evt {
                                characteristics_rx_mapping.remove(&address);
                                characteristics_tx_mapping.remove(&address);
                            }
                        }
                        evt = char_write_control.next() => {
                            match evt {
                                Some(CharacteristicControlEvent::Write(req)) => {
                                    tracing::debug!("Incoming write request from {}", req.device_address());
                                    characteristics_rx_mapping.insert(req.device_address(), req.accept().unwrap());
                                }
                                None => (),
                                // No other event is possible since we set up the characteristic to
                                // be just write/write_no_response
                                _ => unreachable!("Unexpected characteristic event"),
                            }
                        }
                        evt = char_notify_control.next() => {
                            match evt {
                                Some(CharacteristicControlEvent::Notify(notifier)) => {
                                    tracing::debug!("Incoming notify request from {}", notifier.device_address());
                                    characteristics_tx_mapping.insert(notifier.device_address(), notifier);
                                }
                                None => (),
                                // No other event is possible since we set up the characteristic to
                                // be just notify
                                _ => unreachable!("Unexpected characteristic event"),
                            }
                        }
                        _ = token.cancelled() => break,
                    }

                    // Check if we have all the information to consider the link established. This
                    // happens when we have: an active connection from a central + an active
                    // subscription to our NUS TX Characteristic + data being written to our NUS RX
                    // Characteristic
                    let rx_addresses = characteristics_rx_mapping
                        .keys()
                        .cloned()
                        .collect::<HashSet<Address>>();
                    let tx_addresses = characteristics_tx_mapping
                        .keys()
                        .cloned()
                        .collect::<HashSet<Address>>();
                    let mut need_readvertise = false;
                    for address in rx_addresses.intersection(&tx_addresses) {
                        need_readvertise = true;
                        let rx = characteristics_rx_mapping.remove(&address).unwrap();
                        let tx = characteristics_tx_mapping.remove(&address).unwrap();
                        let central = address.to_string();
                        tracing::info!("Accepted connection from central {}", &central);

                        // Signal the manager that we have got a new BLE link
                        manager
                            .send_async(LinkUnicast(Arc::new(LinkUnicastBtGatt::new(
                                None,
                                rx,
                                tx,
                                &central,
                                adapter.alias().await.unwrap().as_str(),
                                adapter.name().to_owned(),
                            ))))
                            .await
                            .unwrap();
                    }

                    // Resume explicitly advertising since BlueZ default behaviour is to stop
                    // after a successful connection. To do this, drop the advertisement handle
                    // that handled this connection, and advertise again using the same
                    // parameters.
                    if need_readvertise {
                        std::mem::drop(
                            _adv_handle.replace(adapter.advertise(le_advertisement.clone()).await?),
                        );
                    }
                }

                Ok(())
            }
        };

        let acceptor_handle = zenoh_runtime::ZRuntime::Acceptor.spawn(task);

        let locator = endpoint.to_locator();
        let listener = ListenerUnicastBtGatt::new(endpoint, token, acceptor_handle);
        listeners.insert(locator.to_string(), listener);

        Ok(locator)
    }

    async fn del_listener(&self, endpoint: &EndPoint) -> ZResult<()> {
        let device_name = endpoint.address().as_str();

        // Stop the listener
        let listener = zasyncwrite!(self.listeners)
            .remove(device_name)
            .ok_or_else(|| {
                let e = zerror!(
                    "Can not delete the GATT listener because it has not been found: {}",
                    device_name
                );
                tracing::trace!("{}", e);
                e
            })?;

        // Send the stop signal
        listener.stop().await;
        listener.handle.await?
    }

    async fn get_listeners(&self) -> Vec<EndPoint> {
        zasyncread!(self.listeners)
            .values()
            .map(|l| l.endpoint.clone())
            .collect()
    }

    async fn get_locators(&self) -> Vec<Locator> {
        zasyncread!(self.listeners)
            .values()
            .map(|x| x.endpoint.to_locator())
            .collect()
    }
}

/// Attempts to discover and connect to the requested BLE device (using the name)
async fn find_device(
    device_name: String,
    adapter_choice: Option<String>,
) -> ZResult<LinkUnicastBtGatt> {
    let session = bluer::Session::new().await?;
    let adapter = if let Some(adapter) = adapter_choice {
        session.adapter(&adapter)?
    } else {
        session.default_adapter().await?
    };
    let src = adapter.alias().await?;
    // Make sure adapter is powered
    adapter.set_powered(true).await?;
    // Quicker and more efficient discovery by just looking for BLE devices
    let mut discovery_filter = DiscoveryFilter::default();
    discovery_filter.transport = DiscoveryTransport::Le;
    discovery_filter.pattern = Some(device_name.clone());
    adapter.set_discovery_filter(discovery_filter).await?;

    let discover = adapter.discover_devices().await?;
    pin_mut!(discover);

    while let Some(evt) = discover.next().await {
        if let AdapterEvent::DeviceAdded(addr) = evt {
            let device = adapter.device(addr).map_err(|e| {
                let e = zerror!("Unable to get BT Device @addr {}:{}", addr, e);
                tracing::error!("{}", e);

                e
            })?;

            match try_connect(&device, device_name.clone()).await {
                Ok((write_io, notify_io)) => {
                    return Ok(LinkUnicastBtGatt::new(
                        Some(device),
                        notify_io,
                        write_io,
                        &src,
                        &device_name,
                        adapter.name().to_owned(),
                    ));
                }
                Err(e) => {
                    let e = zerror!("Not our device: {:?}", e);
                    tracing::error!("{}", e);
                }
            }
        }
    }

    let e = zerror!("Unable to search for device");
    tracing::error!("{}", e);

    Err(e.into())
}

/// Tries to connect to the specified device making sure it contains the proper name and services
///
/// # Returns
///
/// A [`CharacteristicWriter`] and [`CharacteristicReader`] which can be used to RX/TX data
async fn try_connect(
    device: &Device,
    device_name: String,
) -> Result<(CharacteristicWriter, CharacteristicReader), Error> {
    // Find the correct named device
    let name = device.alias().await?;
    if name != device_name {
        return Err(Error::UnrecognizedDevice);
    }

    // Make sure we are connected
    let services = {
        let mut retries = 10;
        loop {
            match device.is_connected().await {
                Ok(true) => {
                    if let Ok(services) = device.services().await {
                        break services;
                    } else {
                        tracing::warn!("Retry service resolution");

                        retries -= 1;
                        let _ = device.disconnect().await;
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
                Ok(false) if retries > 0 => {
                    if device.connect().await.is_err() {
                        tracing::warn!("Retry connection");
                        retries -= 1;
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
                _ => {
                    tracing::error!("Can't connect");
                    return Err(Error::FailedToConnect);
                }
            }
        }
    };

    // Extract the characteristics of interest
    let mut writer = None;
    let mut reader = None;

    for service in services {
        let uuid = service.uuid().await?;
        tracing::trace!("Found service {}", uuid);
        if uuid == Uuid::from(bluer::id::Service::ComNordicsemiServiceUart) {
            for char in service.characteristics().await? {
                tracing::trace!("Found char {}", uuid);
                let uuid = char.uuid().await?;
                if uuid == Uuid::from(bluer::id::Characteristic::ComNordicsemiCharacteristicUartRx)
                {
                    writer = Some(char.write_io().await?);
                } else if uuid
                    == Uuid::from(bluer::id::Characteristic::ComNordicsemiCharacteristicUartTx)
                {
                    reader = Some(char.notify_io().await?);
                }
            }
        }
    }

    match (writer, reader) {
        (Some(writer), Some(reader)) => Ok((writer, reader)),
        // Not our device
        _ => {
            tracing::warn!("Can't get to characteristics");
            Err(Error::UnrecognizedDevice)
        }
    }
}
