use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bluer::gatt::{CharacteristicReader, CharacteristicWriter};
use bluer::{AdapterEvent, Device, DiscoveryFilter, DiscoveryTransport};
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

struct GattPeripheral {
    device: Device,
    write_io: CharacteristicWriter,
    notify_io: CharacteristicReader,
}

struct LinkUnicastBtGatt {
    gatt_peripheral: Arc<Mutex<Option<GattPeripheral>>>,
    // The BT advertised name to use as locator
    src_locator: Locator,
    // The serial destination path (random UUIDv4)
    dst_locator: Locator,
}

unsafe impl Send for LinkUnicastBtGatt {}
unsafe impl Sync for LinkUnicastBtGatt {}

impl LinkUnicastBtGatt {
    fn new(gatt_peripheral: Option<GattPeripheral>, src_path: &str, dst_path: &str) -> Self {
        Self {
            gatt_peripheral: Arc::new(Mutex::new(gatt_peripheral)),
            src_locator: Locator::new(BT_GATT_LOCATOR_PREFIX, src_path, "").unwrap(),
            dst_locator: Locator::new(BT_GATT_LOCATOR_PREFIX, dst_path, "").unwrap(),
        }
    }
}

#[async_trait]
impl LinkUnicastTrait for LinkUnicastBtGatt {
    fn get_mtu(&self) -> u16 {
        match self.gatt_peripheral.try_lock() {
            Ok(ref mut peripheral) => peripheral
                .as_mut()
                .map(|port| port.write_io.mtu().min(port.notify_io.mtu()) as u16)
                .unwrap_or(BT_GATT_MAX_MTU),
            Err(_) => BT_GATT_MAX_MTU,
        }
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
        // Just use default BLE adapter
        vec!["hci0".to_owned()]
    }

    #[inline(always)]
    fn get_auth_id(&self) -> &LinkAuthId {
        // TODO: Can be expanded with BLE security
        &LinkAuthId::NONE
    }

    async fn write(&self, buffer: &[u8]) -> ZResult<usize> {
        let mut peripheral = self.gatt_peripheral.lock().await;

        match peripheral.as_mut() {
            Some(peripheral) => peripheral.write_io.write(buffer).await.map_err(|e| {
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
        let mut peripheral = self.gatt_peripheral.lock().await;

        match peripheral.as_mut() {
            Some(peripheral) => peripheral.write_io.write_all(buffer).await.map_err(|e| {
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
        let mut peripheral = self.gatt_peripheral.lock().await;

        match peripheral.as_mut() {
            Some(peripheral) => {
                let res = peripheral.notify_io.read(buffer).await.map_err(|e| {
                    let e = zerror!("Unable to read from BT GATT link {}: {}", self, e);
                    tracing::error!("{}", e);

                    tracing::trace!("Read END");
                    e.into()
                });

                match res {
                    Ok(0) if buffer.len() != 0 => {
                        return Err(zerror!("End Of Life").into());
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
        let mut peripheral = self.gatt_peripheral.lock().await;

        match peripheral.as_mut() {
            Some(peripheral) => {
                let res = peripheral
                    .notify_io
                    .read_exact(buffer)
                    .await
                    .map(|_| ())
                    .map_err(|e| {
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
        let peripheral = self.gatt_peripheral.lock().await;

        if let Some(peripheral) = peripheral.as_ref() {
            if peripheral
                .device
                .is_connected()
                .await
                .expect("Can't check if the peripheral is connected")
            {
                peripheral.device.disconnect().await.map_err(|e| {
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
    // TODO: Remove once listener is implemented
    #[allow(dead_code)]
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
    _manager: NewLinkChannelSender,
    listeners: Arc<RwLock<HashMap<String, ListenerUnicastBtGatt>>>,
}

impl LinkManagerUnicastBtGatt {
    pub fn new(_manager: NewLinkChannelSender) -> Self {
        Self {
            _manager,
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
        let device_name = endpoint.address().to_string();

        // Attempt direct connection
        let link = Arc::new(find_device(device_name).await?);

        Ok(LinkUnicast(link))
    }

    async fn new_listener(&self, endpoint: EndPoint) -> ZResult<Locator> {
        let _endpoint = endpoint;
        unimplemented!(
            "The BT GATT transport needs to implement listener locators as a BLE Peripheral"
        );
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
async fn find_device(device_name: String) -> ZResult<LinkUnicastBtGatt> {
    let session = bluer::Session::new().await?;
    let adapter = session.default_adapter().await?;
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
                    let peripheral = GattPeripheral {
                        device,
                        write_io,
                        notify_io,
                    };

                    return Ok(LinkUnicastBtGatt::new(Some(peripheral), &src, &device_name));
                }
                Err(e) => {
                    let e = zerror!("Not our device: {:?}", e);
                    tracing::trace!("{}", e);
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
