use std::collections::{HashMap, HashSet};
use std::fmt::{self, Display};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bluer::adv::{Advertisement, Type};
use bluer::gatt::local::{
    characteristic_control, Application, Characteristic, CharacteristicControlEvent,
    CharacteristicNotify, CharacteristicNotifyMethod, CharacteristicWrite,
    CharacteristicWriteMethod, Service,
};
use bluer::gatt::{CharacteristicReader, CharacteristicWriter, WriteOp};
use bluer::{AdapterEvent, Address, Device, DiscoveryFilter, DiscoveryTransport};
use futures::{pin_mut, StreamExt};
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::{uuid, Uuid};
use zenoh_core::{zasyncread, zasyncwrite};
use zenoh_link_commons::{
    ConstructibleLinkManagerUnicast, LinkAuthId, LinkManagerUnicastTrait, LinkUnicast,
    LinkUnicastTrait, NewLinkChannelSender,
};
use zenoh_protocol::core::{EndPoint, Locator};
use zenoh_result::{zerror, ZError, ZResult};

use crate::unicast::io::{
    GattCharRead, GattCharWrite, RemoteCharacteristicReader, RemoteCharacteristicWriter,
};
use crate::BT_GATT_LOCATOR_PREFIX;

mod io;

/// The Zenoh GATT Service UUID
const SERVICE_UUID: Uuid = uuid!("24A9597F-1060-41BB-AB31-B638662BDCCC");

/// The Zenoh GATT RX Characteristic UUID
const RX_CHAR_UUID: Uuid = uuid!("7E54E1BC-82BF-4B0E-9B3A-3C187934BD89");

/// The Zenoh GATT TX Characteristic UUID
const TX_CHAR_UUID: Uuid = uuid!("F47EA3E5-4D04-4EEE-9ACA-E397C4408952");

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

struct LinkUnicastBtGatt<R, W> {
    /// Handle to the Bluetooth device
    device_handle: Arc<Mutex<Option<Device>>>,
    /// Handler to the Characteristic Writer used for writing bytes
    char_writer: Arc<Mutex<Option<W>>>,
    /// Handler to the Characteristic Reader used for reading bytes
    char_reader: Arc<Mutex<Option<R>>>,
    // The BT advertised name to use as locator
    src_locator: Locator,
    // The serial destination path (random UUIDv4)
    dst_locator: Locator,
    /// The interface used for this link
    interface: String,
    /// The negotiated MTU
    mtu: usize,
}

impl<R, W> LinkUnicastBtGatt<R, W>
where
    R: GattCharRead,
    W: GattCharWrite,
{
    fn new(
        device_handle: Option<Device>,
        char_reader: R,
        char_writer: W,
        src_path: &str,
        dst_path: &str,
        interface: String,
    ) -> Self {
        let mtu = char_reader.mtu().min(char_writer.mtu());

        Self {
            device_handle: Arc::new(Mutex::new(device_handle)),
            char_reader: Arc::new(Mutex::new(Some(char_reader))),
            char_writer: Arc::new(Mutex::new(Some(char_writer))),
            src_locator: Locator::new(BT_GATT_LOCATOR_PREFIX, src_path, "").unwrap(),
            dst_locator: Locator::new(BT_GATT_LOCATOR_PREFIX, dst_path, "").unwrap(),
            interface,
            mtu,
        }
    }

    async fn read<T: GattCharRead>(mut read: T, buf: &mut [u8]) -> ZResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        read.read(buf).await.map_err(|e| {
            let e = zerror!("Unable to read from GATT characteristic: {}", e);
            tracing::error!("{}", e);

            e.into()
        })
    }

    async fn write<T: GattCharWrite>(mut write: T, data: &[u8], mtu: usize) -> ZResult<usize> {
        let data = &data[..data.len().min(mtu)];

        write.write(data).await.map(|_| data.len()).map_err(|e| {
            let e = zerror!("Unable to write to GATT characteristic: {}", e);
            tracing::error!("{}", e);

            e.into()
        })
    }

    fn read_err(link: impl Display) -> ZError {
        let e = zerror!(
            "Unable to read from BT GATT link {}: Peripheral not connected",
            link
        );
        tracing::error!("{}", e);

        e
    }

    fn write_err(link: impl Display) -> ZError {
        let e = zerror!(
            "Unable to read from BT GATT link {}: Peripheral not connected",
            link
        );
        tracing::error!("{}", e);

        e
    }
}

#[async_trait]
impl<R: GattCharRead, W: GattCharWrite> LinkUnicastTrait for LinkUnicastBtGatt<R, W> {
    fn get_mtu(&self) -> u16 {
        self.mtu as _
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
            Some(writer) => Self::write(writer, buffer, self.mtu).await,
            None => Err(Self::write_err(self).into()),
        }
    }

    async fn write_all(&self, buffer: &[u8]) -> ZResult<()> {
        match self.char_writer.lock().await.as_mut() {
            Some(writer) => {
                let mut written = 0;
                while written < buffer.len() {
                    written += Self::write(&mut *writer, &buffer[written..], self.mtu).await?;
                }

                Ok(())
            }
            None => Err(Self::write_err(self).into()),
        }
    }

    async fn read(&self, buffer: &mut [u8]) -> ZResult<usize> {
        match self.char_reader.lock().await.as_mut() {
            Some(reader) => {
                let len = Self::read(reader, buffer).await?;

                if len == 0 && !buffer.is_empty() {
                    Err(zerror!("End Of Life for {}", self.src_locator).into())
                } else {
                    Ok(len)
                }
            }
            None => Err(Self::read_err(self).into()),
        }
    }

    async fn read_exact(&self, buffer: &mut [u8]) -> ZResult<()> {
        match self.char_reader.lock().await.as_mut() {
            Some(reader) => {
                let mut read = 0;
                while read < buffer.len() {
                    let n = Self::read(&mut *reader, &mut buffer[read..]).await?;
                    read += n;
                }

                Ok(())
            }
            None => Err(Self::read_err(self).into()),
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

impl<R, W> fmt::Display for LinkUnicastBtGatt<R, W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} => {}", self.src_locator, self.dst_locator)?;
        Ok(())
    }
}

impl<R, W> fmt::Debug for LinkUnicastBtGatt<R, W> {
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

        // Close pre-existing active advertising instances for a clean slate
        if adapter.active_advertising_instances().await? > 0 {
            adapter.set_discoverable(false).await?;
        }

        tracing::info!("Adding new BLE listener: {}", &device_name);

        let le_advertisement = Advertisement {
            advertisement_type: Type::Peripheral,
            service_uuids: vec![SERVICE_UUID].into_iter().collect(),
            discoverable: Some(true),
            // Use something small or else it won't fit in the regular (non-extended) ad
            local_name: Some("ZN".to_string()),
            // We don't care about speed of visibility, so set min-max intervals to be quite large
            // so that we have more radio time for actual existing connections.
            min_interval: Some(Duration::from_millis(1500)),
            max_interval: Some(Duration::from_millis(2000)),
            // While it would be good to enable extended advertising (less conflicts with other BLE
            // devices that might be present), it is not ideal as some BLE stacks might not support it
            // and thus might not detect our presence.
            // secondary_channel: Some(SecondaryChannel::TwoM),
            ..Default::default()
        };
        let _adv_handle = adapter.advertise(le_advertisement.clone()).await?;

        // Create GATT control application which will expose the Zenoh BLE Service for communication
        let (mut char_write_control, char_write_handle) = characteristic_control();
        let (mut char_notify_control, char_notify_handle) = characteristic_control();
        let app = Application {
            services: vec![Service {
                uuid: SERVICE_UUID,
                primary: true,
                characteristics: vec![
                    Characteristic {
                        uuid: RX_CHAR_UUID,
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
                        uuid: TX_CHAR_UUID,
                        notify: Some(CharacteristicNotify {
                            notify: true,
                            indicate: true,
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
                        let rx = characteristics_rx_mapping.remove(address).unwrap();
                        let tx = characteristics_tx_mapping.remove(address).unwrap();
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
) -> ZResult<LinkUnicastBtGatt<impl GattCharRead, impl GattCharWrite>> {
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
    adapter
        .set_discovery_filter(DiscoveryFilter {
            transport: DiscoveryTransport::Le,
            pattern: Some(device_name.clone()),
            ..Default::default()
        })
        .await?;

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
                Ok((char_writer, char_reader)) => {
                    return Ok(LinkUnicastBtGatt::new(
                        Some(device),
                        char_reader,
                        char_writer,
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

/// Tries to connect to the specified device making sure it contains the proper services
///
/// # Returns
///
/// Types implementing [`GattCharWrite`] and [`GattCharRead`] which can be used to RX/TX data
async fn try_connect(
    device: &Device,
    _device_name: String,
) -> Result<(impl GattCharWrite, impl GattCharRead), Error> {
    // Matching by device name is deliberately not used,
    // because regular advertisements might not contain a name, or the name might be
    // short and not very meaningful.

    // Make sure we are connected
    let services = {
        let mut retries = 10;

        loop {
            match device.is_connected().await {
                Ok(true) => match device.services().await {
                    Ok(services) => break services,
                    Err(e) => {
                        tracing::warn!("Service resolution error: {}, retrying...", e);

                        retries -= 1;
                        let _ = device.disconnect().await;
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                },
                Ok(false) => {
                    if retries > 0 {
                        if let Err(e) = device.connect().await {
                            tracing::warn!("Connection error: {}, retrying...", e);
                            retries -= 1;
                            tokio::time::sleep(Duration::from_secs(1)).await;
                        }
                    } else {
                        tracing::error!("Connection retries expired");
                        return Err(Error::FailedToConnect);
                    }
                }
                Err(e) => {
                    tracing::error!("Connectivity state error: {}", e);
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
        if uuid == SERVICE_UUID {
            for char in service.characteristics().await? {
                let uuid = char.uuid().await?;
                tracing::trace!("Found char {}", uuid);
                if uuid == RX_CHAR_UUID {
                    // Cannot use `write_io` because we actually want _confirmed_ writes,
                    // so that we can apply backpressure on the other peer if we are receiving data too fast
                    // writer = Some(char.write_io().await?);
                    writer = Some(RemoteCharacteristicWriter::new(char, WriteOp::Request).await?);
                } else if uuid == TX_CHAR_UUID {
                    // Cannot use `notify_io` because we want _confirmed_ notifications (indications)
                    // so that the other peer can apply backpressure on us if we are sending
                    // data too fast
                    // reader = Some(char.notify_io().await?);
                    reader = Some(RemoteCharacteristicReader::new(char).await?);
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
