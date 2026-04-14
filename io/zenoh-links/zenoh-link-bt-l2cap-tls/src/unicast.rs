//! BLE L2CAP CoC + TLS unicast link.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    fs::File,
    io::BufReader,
    sync::{Arc, OnceLock},
    time::Duration,
};

use async_trait::async_trait;
use bluer::{
    l2cap::{SocketAddr, Stream},
    Adapter, AdapterEvent, DiscoveryFilter, DiscoveryTransport,
};
use futures::StreamExt;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    server::WebPkiClientVerifier,
    ClientConfig, RootCertStore, ServerConfig,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    sync::{Mutex, RwLock},
};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Parsed once on first use; panics then if the constant is malformed.
static SERVICE_UUID: OnceLock<Uuid> = OnceLock::new();
fn service_uuid() -> &'static Uuid {
    SERVICE_UUID.get_or_init(|| {
        ZENOH_BLE_SERVICE_UUID
            .parse()
            .expect("ZENOH_BLE_SERVICE_UUID constant is not a valid UUID")
    })
}
use zenoh_core::zasynclock;
use zenoh_link_commons::{
    tls::{
        config::{
            TLS_CONNECT_CERTIFICATE_FILE, TLS_CONNECT_PRIVATE_KEY_FILE, TLS_ENABLE_MTLS,
            TLS_HANDSHAKE_TIMEOUT_MS, TLS_HANDSHAKE_TIMEOUT_MS_DEFAULT,
            TLS_LISTEN_CERTIFICATE_FILE, TLS_LISTEN_PRIVATE_KEY_FILE, TLS_ROOT_CA_CERTIFICATE_FILE,
            TLS_VERIFY_NAME_ON_CONNECT,
        },
        WebPkiVerifierAnyServerName,
    },
    ConstructibleLinkManagerUnicast, LinkAuthId, LinkManagerUnicastTrait, LinkUnicast,
    LinkUnicastTrait, NewLinkChannelSender,
};
use zenoh_protocol::core::{EndPoint, Locator};
use zenoh_result::{zerror, ZResult};

use x509_parser::{certificate::X509Certificate, prelude::FromDer};

use crate::{
    BT_L2CAP_TLS_ENABLE_MTLS_DEFAULT, BT_L2CAP_TLS_LOCATOR_PREFIX,
    BT_L2CAP_TLS_VERIFY_NAME_ON_CONNECT_DEFAULT, SWARM_TLS_PSM, ZENOH_BLE_SERVICE_UUID,
};

/// MTU advertised to the Zenoh transport layer.
/// L2CAP CoC is streamed, so Zenoh uses length-prefixed framing and does not
/// rely on this value for message boundaries.
const L2CAP_MTU: u16 = 1500;

/// Maximum TLS record plaintext size for server-side connections.
/// Kept at 1 KiB so that TLS records fit comfortably within a single BLE
/// link-layer packet on constrained peers (e.g. zenoh-nano).
const TLS_MAX_FRAGMENT_SIZE: usize = 1024;

/// Per-attempt timeout for `bluer::Device::connect`.
const BLE_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);


pub struct LinkUnicastBtL2capTls {
    read_half: Mutex<ReadHalf<TlsStream<Stream>>>,
    write_half: Mutex<WriteHalf<TlsStream<Stream>>>,
    src_locator: Locator,
    dst_locator: Locator,
    interface: String,
    auth_id: LinkAuthId,
    // Dropped last; keeps the BlueZ D-Bus session alive for the lifetime of
    // this link (needed on the connector side where no outer scan_loop holds it).
    _session: Option<bluer::Session>,
}

impl LinkUnicastBtL2capTls {
    fn new(
        stream: TlsStream<Stream>,
        src: &str,
        dst: &str,
        interface: String,
        auth_id: LinkAuthId,
        session: Option<bluer::Session>,
    ) -> ZResult<Self> {
        let (read_half, write_half) = tokio::io::split(stream);
        Ok(Self {
            read_half: Mutex::new(read_half),
            write_half: Mutex::new(write_half),
            src_locator: Locator::new(BT_L2CAP_TLS_LOCATOR_PREFIX, src, "")
                .map_err(|e| zerror!("bt_l2cap_tls: invalid src locator {:?}: {}", src, e))?,
            dst_locator: Locator::new(BT_L2CAP_TLS_LOCATOR_PREFIX, dst, "")
                .map_err(|e| zerror!("bt_l2cap_tls: invalid dst locator {:?}: {}", dst, e))?,
            interface,
            auth_id,
            _session: session,
        })
    }
}

impl fmt::Display for LinkUnicastBtL2capTls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} => {}", self.src_locator, self.dst_locator)
    }
}

impl fmt::Debug for LinkUnicastBtL2capTls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BtL2capTls")
            .field("src", &self.src_locator)
            .field("dst", &self.dst_locator)
            .finish()
    }
}

#[async_trait]
impl LinkUnicastTrait for LinkUnicastBtL2capTls {
    fn get_mtu(&self) -> u16 {
        L2CAP_MTU
    }

    fn get_src(&self) -> &Locator {
        &self.src_locator
    }

    fn get_dst(&self) -> &Locator {
        &self.dst_locator
    }

    fn is_reliable(&self) -> bool {
        true
    }

    fn is_streamed(&self) -> bool {
        true
    }

    fn get_interface_names(&self) -> Vec<String> {
        vec![self.interface.clone()]
    }

    fn get_auth_id(&self) -> &LinkAuthId {
        &self.auth_id
    }

    async fn write(&self, buffer: &[u8]) -> ZResult<usize> {
        zasynclock!(self.write_half)
            .write(buffer)
            .await
            .map_err(|e| zerror!("bt_l2cap_tls write on {}: {}", self, e).into())
    }

    async fn write_all(&self, buffer: &[u8]) -> ZResult<()> {
        zasynclock!(self.write_half)
            .write_all(buffer)
            .await
            .map_err(|e| zerror!("bt_l2cap_tls write_all on {}: {}", self, e).into())
    }

    async fn read(&self, buffer: &mut [u8]) -> ZResult<usize> {
        let n = zasynclock!(self.read_half)
            .read(buffer)
            .await
            .map_err(|e| zerror!("bt_l2cap_tls read on {}: {}", self, e))?;
        if n == 0 && !buffer.is_empty() {
            return Err(zerror!("bt_l2cap_tls connection closed on {}", self).into());
        }
        Ok(n)
    }

    async fn read_exact(&self, buffer: &mut [u8]) -> ZResult<()> {
        zasynclock!(self.read_half)
            .read_exact(buffer)
            .await
            .map(|_| ())
            .map_err(|e| zerror!("bt_l2cap_tls read_exact on {}: {}", self, e).into())
    }

    async fn close(&self) -> ZResult<()> {
        zasynclock!(self.write_half)
            .shutdown()
            .await
            .map_err(|e| zerror!("bt_l2cap_tls close on {}: {}", self, e).into())
    }
}

struct ListenerBtL2capTls {
    endpoint: EndPoint,
    token: CancellationToken,
    handle: tokio::task::JoinHandle<ZResult<()>>,
}

impl ListenerBtL2capTls {
    fn new(
        endpoint: EndPoint,
        token: CancellationToken,
        handle: tokio::task::JoinHandle<ZResult<()>>,
    ) -> Self {
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

pub struct LinkManagerUnicastBtL2capTls {
    manager: NewLinkChannelSender,
    listeners: Arc<RwLock<HashMap<String, ListenerBtL2capTls>>>,
}

impl ConstructibleLinkManagerUnicast<()> for LinkManagerUnicastBtL2capTls {
    fn new(sender: NewLinkChannelSender, _: ()) -> ZResult<Self> {
        // install_default() fails if a provider is already installed (e.g. when
        // multiple transports initialise in the same process).  That is harmless.
        rustls::crypto::ring::default_provider().install_default().ok();
        Ok(Self {
            manager: sender,
            listeners: Arc::new(RwLock::new(HashMap::new())),
        })
    }
}

impl LinkManagerUnicastBtL2capTls {
    pub fn new(sender: NewLinkChannelSender) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        Self {
            manager: sender,
            listeners: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl LinkManagerUnicastTrait for LinkManagerUnicastBtL2capTls {
    async fn new_link(&self, endpoint: EndPoint) -> ZResult<LinkUnicast> {
        let epconf = endpoint.config();
        let address = endpoint.address().to_string();
        let (adapter_choice, device_name) = parse_address(&address)?;

        let handshake_timeout = Duration::from_millis(
            epconf
                .get(TLS_HANDSHAKE_TIMEOUT_MS)
                .and_then(|v| v.parse().ok())
                .unwrap_or(TLS_HANDSHAKE_TIMEOUT_MS_DEFAULT),
        );
        let connector = build_connector(&epconf)?;
        let (session, stream, local_alias, remote_name) =
            connect_l2cap(device_name, adapter_choice).await?;

        let server_name = rustls_pki_types::ServerName::try_from("zenoh-ble-peer")
            .map_err(|e| zerror!("bt_l2cap_tls: SNI: {}", e))?
            .to_owned();

        let tls = tokio::time::timeout(handshake_timeout, connector.connect(server_name, stream))
            .await
            .map_err(|_| -> zenoh_result::Error {
                zerror!("bt_l2cap_tls: TLS handshake with {} timed out", remote_name).into()
            })?
            .map_err(|e| zerror!("bt_l2cap_tls: TLS handshake with {}: {}", remote_name, e))?;

        let auth_id = peer_cert_cn(tls.get_ref().1.peer_certificates());
        tracing::info!("bt_l2cap_tls: connected to {}", remote_name);
        Ok(LinkUnicast(Arc::new(LinkUnicastBtL2capTls::new(
            TlsStream::Client(tls),
            &local_alias,
            &remote_name,
            "bluetooth".to_owned(),
            auth_id,
            Some(session),
        )?)))
    }

    async fn new_listener(&self, endpoint: EndPoint) -> ZResult<Locator> {
        let epconf = endpoint.config();
        let address = endpoint.address().to_string();
        let (adapter_choice, device_filter) = parse_address(&address)?;

        let acceptor = Arc::new(build_acceptor(&epconf)?);
        let handshake_timeout = Duration::from_millis(
            epconf
                .get(TLS_HANDSHAKE_TIMEOUT_MS)
                .and_then(|v| v.parse().ok())
                .unwrap_or(TLS_HANDSHAKE_TIMEOUT_MS_DEFAULT),
        );
        let (session, adapter) = open_adapter(adapter_choice).await?;

        tracing::info!(
            "bt_l2cap_tls: scanning for Zenoh BLE peripherals (filter='{}')",
            device_filter
        );

        let token = CancellationToken::new();
        let task = scan_loop(
            session,
            adapter,
            device_filter.to_string(),
            acceptor,
            self.manager.clone(),
            token.clone(),
            handshake_timeout,
        );
        let handle = zenoh_runtime::ZRuntime::Acceptor.spawn(task);

        let locator = endpoint.to_locator();
        zenoh_core::zasyncwrite!(self.listeners).insert(
            locator.to_string(),
            ListenerBtL2capTls::new(endpoint, token, handle),
        );
        Ok(locator)
    }

    async fn del_listener(&self, endpoint: &EndPoint) -> ZResult<()> {
        let key = endpoint.to_locator().to_string();
        let l = zenoh_core::zasyncwrite!(self.listeners)
            .remove(&key)
            .ok_or_else(|| zerror!("bt_l2cap_tls: listener not found: {}", key))?;
        l.stop().await;
        l.handle
            .await
            .map_err(|e| zerror!("bt_l2cap_tls: join: {}", e))?
    }

    async fn get_listeners(&self) -> Vec<EndPoint> {
        zenoh_core::zasyncread!(self.listeners)
            .values()
            .map(|l| l.endpoint.clone())
            .collect()
    }

    async fn get_locators(&self) -> Vec<Locator> {
        zenoh_core::zasyncread!(self.listeners)
            .values()
            .map(|l| l.endpoint.to_locator())
            .collect()
    }
}

/// Open a BlueZ session and return a powered adapter.
async fn open_adapter(adapter_choice: Option<&str>) -> ZResult<(bluer::Session, Adapter)> {
    let session = bluer::Session::new()
        .await
        .map_err(|e| zerror!("bt_l2cap_tls: BlueZ session: {}", e))?;
    let adapter = match &adapter_choice {
        Some(a) => session
            .adapter(a)
            .map_err(|e| zerror!("bt_l2cap_tls: adapter {}: {}", a, e))?,
        None => session
            .default_adapter()
            .await
            .map_err(|e| zerror!("bt_l2cap_tls: default adapter: {}", e))?,
    };
    if !adapter
        .is_powered()
        .await
        .map_err(|e| zerror!("bt_l2cap_tls: power check: {}", e))?
    {
        adapter
            .set_powered(true)
            .await
            .map_err(|e| zerror!("bt_l2cap_tls: power on: {}", e))?;
    }
    Ok((session, adapter))
}

/// Continuously scan for peripherals advertising the Zenoh service UUID and
/// spawn a connection task for each new one found.
async fn scan_loop(
    session: bluer::Session,
    adapter: Adapter,
    device_filter: String,
    acceptor: Arc<TlsAcceptor>,
    manager: NewLinkChannelSender,
    token: CancellationToken,
    handshake_timeout: Duration,
) -> ZResult<()> {
    let _session = session; // keep alive
    let local_alias = adapter.alias().await.unwrap_or_else(|_| "bt".to_string());

    let pattern = if device_filter.is_empty() {
        None
    } else {
        Some(device_filter)
    };
    if let Err(e) = adapter
        .set_discovery_filter(DiscoveryFilter {
            transport: DiscoveryTransport::Le,
            pattern,
            ..Default::default()
        })
        .await
    {
        tracing::warn!("bt_l2cap_tls: failed to set BLE discovery filter: {}", e);
    }

    // Lives outside the loop so tasks from a prior discover session still
    // remove their addresses from the same set after a restart.
    let in_progress: Arc<Mutex<HashSet<bluer::Address>>> = Arc::new(Mutex::new(HashSet::new()));

    loop {
        // TODO: discover_devices() or discover_devices_with_changes()?
        let discover = match adapter.discover_devices_with_changes().await {
            Ok(d) => d,
            Err(e) => {
                tracing::error!("bt_l2cap_tls: discover_devices_with_changes: {}", e);
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
        };
        futures::pin_mut!(discover);

        tokio::select! {
            _ = process_scan_events(
                &adapter,
                &mut *discover,
                service_uuid(),
                &local_alias,
                &acceptor,
                &manager,
                &in_progress,
                &token,
                handshake_timeout,
            ) => {}
            _ = token.cancelled() => break,
        }
    }
    Ok(())
}

/// Drain scan events from `discover`, spawning a per-peripheral connection task
/// for each new Zenoh peripheral seen.
async fn process_scan_events(
    adapter: &Adapter,
    discover: &mut (impl futures::Stream<Item = AdapterEvent> + Unpin),
    service_uuid: &Uuid,
    local_alias: &str,
    acceptor: &Arc<TlsAcceptor>,
    manager: &NewLinkChannelSender,
    in_progress: &Arc<Mutex<HashSet<bluer::Address>>>,
    token: &CancellationToken,
    handshake_timeout: Duration,
) {
    while let Some(evt) = discover.next().await {
        let AdapterEvent::DeviceAdded(addr) = evt else {
            continue;
        };
        let device = match adapter.device(addr) {
            Ok(d) => d,
            Err(_) => continue,
        };

        match device.uuids().await {
            Ok(Some(uuids)) if uuids.contains(service_uuid) => {}
            _ => continue,
        }

        let addr_type = match device.address_type().await {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!("bt_l2cap_tls: address type for {}: {}", addr, e);
                continue;
            }
        };

        // Insert returns false if already present; skip to avoid duplicate tasks.
        if !in_progress.lock().await.insert(addr) {
            continue;
        }
        tracing::info!("bt_l2cap_tls: found peripheral {} ({:?})", addr, addr_type);

        let acc = acceptor.clone();
        let mgr = manager.clone();
        let lname = local_alias.to_owned();
        let tok = token.clone();

        zenoh_runtime::ZRuntime::Acceptor.spawn(accept_peripheral(
            device,
            addr,
            addr_type,
            acc,
            mgr,
            lname,
            in_progress.clone(),
            tok,
            handshake_timeout,
        ));
    }
}

/// Connect to a peripheral, open the L2CAP channel, perform the TLS handshake,
/// and hand the resulting link to the Zenoh manager.
async fn accept_peripheral(
    device: bluer::Device,
    addr: bluer::Address,
    addr_type: bluer::AddressType,
    acceptor: Arc<TlsAcceptor>,
    manager: NewLinkChannelSender,
    local_alias: String,
    in_progress: Arc<Mutex<HashSet<bluer::Address>>>,
    token: CancellationToken,
    handshake_timeout: Duration,
) {
    if !ble_connect_with_retry(&device, addr).await {
        in_progress.lock().await.remove(&addr);
        return;
    }

    let sa = SocketAddr::new(addr, addr_type, SWARM_TLS_PSM);
    let l2cap_stream = match tokio::time::timeout(handshake_timeout, Stream::connect(sa)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            tracing::error!("bt_l2cap_tls: L2CAP connect to {}: {}", addr, e);
            disconnect_device(&device, addr).await;
            in_progress.lock().await.remove(&addr);
            return;
        }
        Err(_) => {
            tracing::warn!("bt_l2cap_tls: L2CAP connect to {} timed out", addr);
            disconnect_device(&device, addr).await;
            in_progress.lock().await.remove(&addr);
            return;
        }
    };
    tracing::info!("bt_l2cap_tls: L2CAP open to {}", addr);

    let peer_str = addr.to_string();
    match tokio::time::timeout(handshake_timeout, acceptor.accept(l2cap_stream)).await {
        Ok(Ok(tls)) => {
            // Server path: the BlueZ session stays alive in scan_loop for as
            // long as the listener runs, so we don't need to own it here.
            let auth_id = peer_cert_cn(tls.get_ref().1.peer_certificates());
            let link = match LinkUnicastBtL2capTls::new(
                TlsStream::Server(tls),
                &local_alias,
                &peer_str,
                "bluetooth".to_owned(),
                auth_id,
                None,
            ) {
                Ok(l) => Arc::new(l),
                Err(e) => {
                    tracing::error!("bt_l2cap_tls: bad locator for {}: {}", peer_str, e);
                    in_progress.lock().await.remove(&addr);
                    return;
                }
            };
            tracing::info!("bt_l2cap_tls: link established with {}", peer_str);
            // If the listener was removed while we were connecting, discard
            // the link rather than handing it to a shutting-down manager.
            // The TLS stream drop closes the underlying L2CAP socket.
            if token.is_cancelled() {
                tracing::debug!("bt_l2cap_tls: listener cancelled; discarding link with {}", peer_str);
            } else if let Err(e) = manager.send_async(LinkUnicast(link)).await {
                tracing::warn!(
                    "bt_l2cap_tls: dropping link with {}: transport manager channel closed: {}",
                    peer_str,
                    e
                );
            }
        }
        Ok(Err(e)) => {
            tracing::warn!("bt_l2cap_tls: TLS with {} failed: {}", peer_str, e);
            disconnect_device(&device, addr).await;
        }
        Err(_) => {
            tracing::warn!("bt_l2cap_tls: TLS handshake with {} timed out", peer_str);
            disconnect_device(&device, addr).await;
        }
    }

    in_progress.lock().await.remove(&addr);
}

fn build_connector(epconf: &zenoh_protocol::core::endpoint::Config) -> ZResult<TlsConnector> {
    let ca_path = epconf.get(TLS_ROOT_CA_CERTIFICATE_FILE).ok_or_else(|| {
        zerror!(
            "bt_l2cap_tls: {} required in endpoint config",
            TLS_ROOT_CA_CERTIFICATE_FILE
        )
    })?;

    let mut ca_store = RootCertStore::empty();
    for cert in load_certs(ca_path)? {
        ca_store
            .add(cert)
            .map_err(|e| zerror!("bt_l2cap_tls: CA cert: {}", e))?;
    }

    // Honour verify_name_on_connect (default: false for this transport — BLE
    // device identity comes from the hardware address, not a cert SAN).
    // When false, skip server-name validation while still verifying the server
    // cert against the CA.
    let verify_name = epconf
        .get(TLS_VERIFY_NAME_ON_CONNECT)
        .and_then(|v| v.parse::<bool>().ok())
        .unwrap_or(BT_L2CAP_TLS_VERIFY_NAME_ON_CONNECT_DEFAULT);

    let builder = if verify_name {
        ClientConfig::builder().with_root_certificates(ca_store)
    } else {
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(WebPkiVerifierAnyServerName::new(ca_store)))
    };

    let config = match (
        epconf.get(TLS_CONNECT_CERTIFICATE_FILE),
        epconf.get(TLS_CONNECT_PRIVATE_KEY_FILE),
    ) {
        (Some(cert), Some(key)) => builder
            .with_client_auth_cert(load_certs(cert)?, load_key(key)?)
            .map_err(|e| zerror!("bt_l2cap_tls: client cert/key: {}", e))?,
        (None, None) => builder.with_no_client_auth(),
        _ => {
            return Err(zerror!(
                "bt_l2cap_tls: {} and {} must both be set or both be absent",
                TLS_CONNECT_CERTIFICATE_FILE,
                TLS_CONNECT_PRIVATE_KEY_FILE
            )
            .into())
        }
    };
    Ok(TlsConnector::from(Arc::new(config)))
}

fn build_acceptor(epconf: &zenoh_protocol::core::endpoint::Config) -> ZResult<TlsAcceptor> {
    let cert_path = epconf
        .get(TLS_LISTEN_CERTIFICATE_FILE)
        .ok_or_else(|| zerror!("bt_l2cap_tls: {} required", TLS_LISTEN_CERTIFICATE_FILE))?;
    let key_path = epconf
        .get(TLS_LISTEN_PRIVATE_KEY_FILE)
        .ok_or_else(|| zerror!("bt_l2cap_tls: {} required", TLS_LISTEN_PRIVATE_KEY_FILE))?;

    let enable_mtls = epconf
        .get(TLS_ENABLE_MTLS)
        .and_then(|v| v.parse::<bool>().ok())
        .unwrap_or(BT_L2CAP_TLS_ENABLE_MTLS_DEFAULT);

    let cfg_builder = if enable_mtls {
        let ca_path = epconf
            .get(TLS_ROOT_CA_CERTIFICATE_FILE)
            .ok_or_else(|| zerror!("bt_l2cap_tls: {} required when enable_mtls=true", TLS_ROOT_CA_CERTIFICATE_FILE))?;
        let mut ca_store = RootCertStore::empty();
        for cert in load_certs(ca_path)? {
            ca_store
                .add(cert)
                .map_err(|e| zerror!("bt_l2cap_tls: CA cert: {}", e))?;
        }
        let verifier = WebPkiClientVerifier::builder(Arc::new(ca_store))
            .build()
            .map_err(|e| zerror!("bt_l2cap_tls: client verifier: {}", e))?;
        ServerConfig::builder().with_client_cert_verifier(verifier)
    } else {
        ServerConfig::builder().with_no_client_auth()
    };

    let mut cfg = cfg_builder
        .with_single_cert(load_certs(cert_path)?, load_key(key_path)?)
        .map_err(|e| zerror!("bt_l2cap_tls: server cert/key: {e}"))?;
    cfg.max_fragment_size = Some(TLS_MAX_FRAGMENT_SIZE);
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

fn load_certs(path: &str) -> ZResult<Vec<CertificateDer<'static>>> {
    let f = File::open(path).map_err(|e| zerror!("bt_l2cap_tls: open cert {path}: {e}"))?;
    rustls_pemfile::certs(&mut BufReader::new(f))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| zerror!("bt_l2cap_tls: read cert {}: {}", path, e).into())
}

fn load_key(path: &str) -> ZResult<PrivateKeyDer<'static>> {
    let f = File::open(path).map_err(|e| zerror!("bt_l2cap_tls: open key {}: {}", path, e))?;
    rustls_pemfile::private_key(&mut BufReader::new(f))
        .map_err(|e| zerror!("bt_l2cap_tls: read key {}: {}", path, e))?
        .ok_or_else(|| zerror!("bt_l2cap_tls: no key in {}", path).into())
}

fn parse_address(addr: &str) -> ZResult<(Option<&str>, &str)> {
    match addr.split_once('@') {
        Some((adapter, device)) => {
            if device.contains('@') {
                return Err(zerror!(
                    "bt_l2cap_tls: invalid address {:?}: at most one '@' allowed",
                    addr
                )
                .into());
            }
            if adapter.is_empty() {
                return Err(zerror!(
                    "bt_l2cap_tls: invalid address {:?}: adapter name before '@' must not be empty \
                     (omit '@' entirely to use the default adapter)",
                    addr
                )
                .into());
            }
            if device.is_empty() {
                return Err(zerror!(
                    "bt_l2cap_tls: invalid address {:?}: device name after '@' must not be empty",
                    addr
                )
                .into());
            }
            Ok((Some(adapter), device))
        }
        None => Ok((None, addr)),
    }
}

/// Extract the subject Common Name from the first certificate in a peer chain.
/// Returns `LinkAuthId::Tls(Some(cn))` when a CN is present, `LinkAuthId::Tls(None)` otherwise.
fn peer_cert_cn(certs: Option<&[rustls_pki_types::CertificateDer<'_>]>) -> LinkAuthId {
    let cn = certs.and_then(|chain| chain.first()).and_then(|der| {
        X509Certificate::from_der(der.as_ref())
            .ok()
            .and_then(|(_, cert)| {
                cert.subject
                    .iter_common_name()
                    .next()
                    .and_then(|cn| cn.as_str().ok())
                    .map(|s| s.to_owned())
            })
    });
    LinkAuthId::Tls(cn)
}

/// Best-effort BLE disconnect; logs a warning on failure but never propagates.
async fn disconnect_device(device: &bluer::Device, addr: bluer::Address) {
    if let Err(e) = device.disconnect().await {
        tracing::warn!("bt_l2cap_tls: disconnect {} after connection failure: {}", addr, e);
    }
}

async fn ble_connect_with_retry(device: &bluer::Device, addr: bluer::Address) -> bool {
    let mut retries = 5u8;
    loop {
        if device.is_connected().await.unwrap_or(false) {
            return true;
        }
        if retries == 0 {
            tracing::error!("bt_l2cap_tls: BLE connect to {} exhausted retries", addr);
            return false;
        }
        match tokio::time::timeout(BLE_CONNECT_TIMEOUT, device.connect()).await {
            Ok(Ok(())) => return true,
            Ok(Err(e)) => {
                tracing::warn!("bt_l2cap_tls: BLE connect to {}: {}; retrying", addr, e);
            }
            Err(_) => {
                tracing::warn!("bt_l2cap_tls: BLE connect to {} timed out; retrying", addr);
            }
        }
        retries -= 1;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

async fn connect_l2cap(
    device_name: &str,
    adapter_choice: Option<&str>,
) -> ZResult<(bluer::Session, Stream, String, String)> {
    tokio::time::timeout(
        Duration::from_secs(30),
        connect_l2cap_inner(device_name, adapter_choice),
    )
    .await
    .map_err(|_| -> zenoh_result::Error {
        zerror!("bt_l2cap_tls: discovery timed out for '{}'", device_name).into()
    })?
}

async fn connect_l2cap_inner(
    device_name: &str,
    adapter_choice: Option<&str>,
) -> ZResult<(bluer::Session, Stream, String, String)> {
    let (session, adapter) = open_adapter(adapter_choice).await?;

    adapter
        .set_discovery_filter(DiscoveryFilter {
            transport: DiscoveryTransport::Le,
            pattern: Some(device_name.to_string()),
            ..Default::default()
        })
        .await
        .map_err(|e| zerror!("bt_l2cap_tls: discovery filter: {}", e))?;

    let local_alias = adapter
        .alias()
        .await
        .map_err(|e| zerror!("bt_l2cap_tls: adapter alias: {}", e))?;
    let discover = adapter
        .discover_devices_with_changes()
        .await
        .map_err(|e| zerror!("bt_l2cap_tls: discover: {}", e))?;
    futures::pin_mut!(discover);

    while let Some(evt) = discover.next().await {
        let AdapterEvent::DeviceAdded(addr) = evt else {
            continue;
        };

        let Ok(device) = adapter.device(addr) else {
            continue;
        };

        match device.uuids().await {
            Ok(Some(uuids)) if uuids.contains(service_uuid()) => {}
            _ => continue,
        }

        let addr_type = match device.address_type().await {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!("bt_l2cap_tls: address type for {}: {}", addr, e);
                continue;
            }
        };

        if !ble_connect_with_retry(&device, addr).await {
            return Err(zerror!("bt_l2cap_tls: cannot connect to {}", addr).into());
        }
        tracing::info!("bt_l2cap_tls: BLE connected to {} ({:?})", addr, addr_type);

        let sa = SocketAddr::new(addr, addr_type, SWARM_TLS_PSM);
        let stream: Stream = tokio::time::timeout(BLE_CONNECT_TIMEOUT, Stream::connect(sa))
            .await
            .map_err(|_| -> zenoh_result::Error {
                zerror!("bt_l2cap_tls: L2CAP connect to {} timed out", addr).into()
            })?
            .map_err(|e| zerror!("bt_l2cap_tls: L2CAP PSM 0x{:04X}: {}", SWARM_TLS_PSM, e))?;

        return Ok((session, stream, local_alias, addr.to_string()));
    }
    Err(zerror!("bt_l2cap_tls: device '{}' not found", device_name).into())
}
