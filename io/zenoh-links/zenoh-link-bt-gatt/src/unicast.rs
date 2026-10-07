#[cfg(all(feature = "uring", target_os = "linux"))]
use std::os::fd::RawFd;
use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Display},
    future::Future,
    sync::{Arc, OnceLock},
    time::Duration,
};

use async_trait::async_trait;
use bluer::{
    adv::{Advertisement, Type},
    gatt::{
        local::{
            characteristic_control, Application, Characteristic, CharacteristicControlEvent,
            CharacteristicNotify, CharacteristicNotifyMethod, CharacteristicWrite,
            CharacteristicWriteMethod, Service,
        },
        CharacteristicReader, CharacteristicWriter, WriteOp,
    },
    AdapterEvent, Address, Device, DiscoveryFilter, DiscoveryTransport,
};
use futures::{pin_mut, StreamExt};
use tokio::{
    sync::{Mutex, RwLock},
    task::JoinHandle,
};
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
use uuid::{uuid, Uuid};
use zenoh_core::{zasyncread, zasyncwrite};
use zenoh_link_commons::{
    ConstructibleLinkManagerUnicast, LinkAuthId, LinkManagerUnicastTrait, LinkUnicast,
    LinkUnicastTrait, NewLinkChannelSender,
};
use zenoh_protocol::core::{EndPoint, Locator, Priority};
use zenoh_result::{bail, zerror, ZError, ZResult};

use crate::{
    addr::{BtGattAddress, Target, ANY, MAX_NAME_LEN},
    unicast::io::{
        GattCharRead, GattCharWrite, RemoteCharacteristicReader, RemoteCharacteristicWriter,
    },
    BT_GATT_LOCATOR_PREFIX,
};

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

    #[cfg(all(feature = "uring", target_os = "linux"))]
    fn get_fd(&self) -> ZResult<RawFd> {
        bail!("Not supported");
    }

    async fn write(&self, buffer: &[u8], _priority: Option<Priority>) -> ZResult<usize> {
        match self.char_writer.lock().await.as_mut() {
            Some(writer) => Self::write(writer, buffer, self.mtu).await,
            None => Err(Self::write_err(self).into()),
        }
    }

    async fn write_all(&self, buffer: &[u8], _priority: Option<Priority>) -> ZResult<()> {
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

    async fn read(&self, buffer: &mut [u8], _priority: Option<Priority>) -> ZResult<usize> {
        match self.char_reader.lock().await.as_mut() {
            Some(reader) => {
                let len = Self::read(reader, buffer).await?;

                if len == 0 && !buffer.is_empty() {
                    tracing::info!("BT GATT link {} closed", self);
                    Err(zerror!("End Of Life for {}", self.src_locator).into())
                } else {
                    Ok(len)
                }
            }
            None => Err(Self::read_err(self).into()),
        }
    }

    async fn read_exact(&self, buffer: &mut [u8], _priority: Option<Priority>) -> ZResult<()> {
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
/*          RUNTIME                  */
/*************************************/
/// The runtime on which all BlueZ interactions are driven.
///
/// `bluer` spawns the task driving its D-Bus connection (as well as the tasks serving our GATT
/// application) on the runtime which creates the session. Zenoh's runtimes may have their (few)
/// worker threads blocked synchronously, e.g. while pushing messages into a full transmission
/// pipeline, which in turn waits on a D-Bus reply to drain: a deadlock that only resolves when the
/// push times out and closes the transport. A dedicated runtime keeps the D-Bus traffic flowing.
fn bt_runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("bt-gatt")
            .enable_all()
            .build()
            .expect("Unable to create the BT GATT runtime")
    })
}

/// Runs `future` on the [`bt_runtime`], aborting it if the returned future is dropped
async fn on_bt_runtime<F, T>(future: F) -> ZResult<T>
where
    F: Future<Output = ZResult<T>> + Send + 'static,
    T: Send + 'static,
{
    AbortOnDropHandle::new(bt_runtime().spawn(future))
        .await
        .map_err(|e| zerror!("BT GATT task failed: {}", e))?
}

/*************************************/
/*          LISTENER                 */
/*************************************/
struct ListenerUnicastBtGatt {
    endpoint: EndPoint,
    /// The locator peers can use to reach this listener (`bt_gatt/<adapter MAC>`)
    locator: Locator,
    token: CancellationToken,
    handle: JoinHandle<ZResult<()>>,
}

impl ListenerUnicastBtGatt {
    fn new(
        endpoint: EndPoint,
        locator: Locator,
        token: CancellationToken,
        handle: JoinHandle<ZResult<()>>,
    ) -> Self {
        Self {
            endpoint,
            locator,
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
        let address: BtGattAddress = endpoint.address().as_str().parse()?;

        // Attempt direct connection
        let link = on_bt_runtime(find_device(address.target, address.adapter)).await?;

        Ok(LinkUnicast::from(
            Arc::new(link) as Arc<dyn LinkUnicastTrait>
        ))
    }

    async fn new_listener(&self, endpoint: EndPoint) -> ZResult<Locator> {
        on_bt_runtime(listen(
            self.manager.clone(),
            self.listeners.clone(),
            endpoint,
        ))
        .await
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
            .map(|x| x.locator.clone())
            .collect()
    }

    async fn get_locators_noloopback(&self) -> Vec<Locator> {
        self.get_locators().await
    }
}

/// Creates a listener: advertises the Zenoh GATT service and accepts connections from centrals
async fn listen(
    manager: NewLinkChannelSender,
    listeners: Arc<RwLock<HashMap<String, ListenerUnicastBtGatt>>>,
    endpoint: EndPoint,
) -> ZResult<Locator> {
    let address: BtGattAddress = endpoint.address().as_str().parse()?;
    let local_name = match address.target {
        Target::Any => None,
        Target::Name(name) if name.len() <= MAX_NAME_LEN => Some(name),
        Target::Name(name) => bail!(
            "Can not listen on {}: advertised name '{}' is longer than {} bytes",
            endpoint,
            name,
            MAX_NAME_LEN
        ),
        Target::Address(_) => bail!(
            "Can not listen on {}: a MAC address is not a valid listen address, use '{}' or a name",
            endpoint,
            ANY
        ),
    };

    let session = bluer::Session::new().await?;

    // Grab adapter
    let adapter = if let Some(adapter) = &address.adapter {
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

    let local_address = adapter.address().await?.to_string();
    let locator = Locator::new(BT_GATT_LOCATOR_PREFIX, &local_address, "")?;

    tracing::info!(
        "Adding new BLE listener on {} ({}), advertised name: {:?}",
        adapter.name(),
        local_address,
        local_name
    );

    let le_advertisement = Advertisement {
        advertisement_type: Type::Peripheral,
        service_uuids: vec![SERVICE_UUID].into_iter().collect(),
        discoverable: Some(true),
        // BlueZ places the name in the scan response, not in the advertisement itself
        local_name,
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
    // NOTE: The advertisement is registered once and kept for the lifetime of the listener.
    // The kernel keeps advertising it while centrals are connected and after they disconnect.
    let adv_handle = adapter.advertise(le_advertisement).await?;

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
                        // TODO:
                        // Try `CharacteristicWriteMethod::Fun` to see
                        // if this work-arounds the bug where BlueZ disconnects
                        // with ATT disconnect code 0x13 after ~ 8 seconds
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

    let mut listeners = zasyncwrite!(listeners);
    let task = {
        let manager = manager.clone();
        let token = token.clone();

        let mut adapter_events = adapter.events().await?;
        let mut characteristics_rx_mapping: HashMap<Address, CharacteristicReader> = HashMap::new();
        let mut characteristics_tx_mapping: HashMap<Address, CharacteristicWriter> = HashMap::new();

        async move {
            // Make sure the handles we care about are kept alive
            let _keep_alive = (app_handle, adv_handle, session);

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
                for address in rx_addresses.intersection(&tx_addresses) {
                    let rx = characteristics_rx_mapping.remove(address).unwrap();
                    let tx = characteristics_tx_mapping.remove(address).unwrap();
                    let central = address.to_string();
                    tracing::info!("Accepted connection from central {}", &central);

                    // Signal the manager that we have got a new BLE link
                    manager
                        .send_async(LinkUnicast::from(Arc::new(LinkUnicastBtGatt::new(
                            None,
                            rx,
                            tx,
                            &local_address,
                            &central,
                            adapter.name().to_owned(),
                        ))
                            as Arc<dyn LinkUnicastTrait>))
                        .await
                        .unwrap();
                }
            }

            Ok(())
        }
    };

    let acceptor_handle = tokio::spawn(task);

    let key = endpoint.address().to_string();
    let listener = ListenerUnicastBtGatt::new(endpoint, locator.clone(), token, acceptor_handle);
    listeners.insert(key, listener);

    Ok(locator)
}

/// Attempts to discover and connect to the requested BLE device
async fn find_device(
    target: Target,
    adapter_choice: Option<String>,
) -> ZResult<LinkUnicastBtGatt<impl GattCharRead, impl GattCharWrite>> {
    let session = bluer::Session::new().await?;
    let adapter = if let Some(adapter) = adapter_choice {
        session.adapter(&adapter)?
    } else {
        session.default_adapter().await?
    };
    // Make sure adapter is powered
    adapter.set_powered(true).await?;
    let src = adapter.address().await?.to_string();
    // Quicker and more efficient discovery by just looking for BLE devices advertising our service
    adapter
        .set_discovery_filter(DiscoveryFilter {
            transport: DiscoveryTransport::Le,
            uuids: HashSet::from([SERVICE_UUID]),
            ..Default::default()
        })
        .await?;

    // NOTE: The stream starts with all devices already known to BlueZ, regardless of the discovery
    // filter, and re-emits a device whenever its properties change (e.g. a fresh RSSI or name
    // from an advertisement). Hence the explicit filtering in `is_candidate`.
    let discover = adapter.discover_devices_with_changes().await?;
    pin_mut!(discover);

    let mut tried = HashSet::new();

    while let Some(evt) = discover.next().await {
        let AdapterEvent::DeviceAdded(addr) = evt else {
            continue;
        };

        if tried.contains(&addr) {
            continue;
        }

        let device = adapter.device(addr).map_err(|e| {
            let e = zerror!("Unable to get BT Device @addr {}:{}", addr, e);
            tracing::error!("{}", e);

            e
        })?;

        if !is_candidate(&device, &target).await {
            continue;
        }

        tried.insert(addr);
        tracing::debug!("Trying to connect to BLE device {}", addr);

        match try_connect(&device).await {
            Ok((char_writer, char_reader)) => {
                return Ok(LinkUnicastBtGatt::new(
                    Some(device),
                    char_reader,
                    char_writer,
                    &src,
                    &addr.to_string(),
                    adapter.name().to_owned(),
                ));
            }
            Err(e) => {
                tracing::warn!("Skipping BLE device {}: {:?}", addr, e);
                let _ = device.disconnect().await;
            }
        }
    }

    let e = zerror!("Unable to search for device");
    tracing::error!("{}", e);

    Err(e.into())
}

/// Checks whether a discovered device is worth connecting to: it must be in range,
/// advertise the Zenoh GATT service and match the requested target
async fn is_candidate(device: &Device, target: &Target) -> bool {
    if let Target::Address(address) = target {
        if device.address() != *address {
            return false;
        }
    }

    // Devices known to BlueZ but not currently advertising have no RSSI
    if !matches!(device.rssi().await, Ok(Some(_))) {
        return false;
    }

    let advertises_service = matches!(
        device.uuids().await,
        Ok(Some(uuids)) if uuids.contains(&SERVICE_UUID)
    );
    if !advertises_service {
        return false;
    }

    match target {
        Target::Any | Target::Address(_) => true,
        Target::Name(name) => matches!(device.name().await, Ok(Some(n)) if n == *name),
    }
}

/// Tries to connect to the specified device making sure it contains the proper services
///
/// # Returns
///
/// Types implementing [`GattCharWrite`] and [`GattCharRead`] which can be used to RX/TX data
async fn try_connect(device: &Device) -> Result<(impl GattCharWrite, impl GattCharRead), Error> {
    // Make sure we are connected
    let services = {
        // TODO:
        // Figure out why so many connection retries are necessary
        // i.e. why the connection attempt fails most often than not
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
