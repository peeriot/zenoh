// bluer is Linux-only (BlueZ / D-Bus). Gate the entire crate accordingly.
#![cfg(target_os = "linux")]

//! Zenoh BLE L2CAP CoC + TLS transport.
//!
//! # Locator format
//!
//! `bt_l2cap_tls/<device-name>` or `bt_l2cap_tls/<adapter>@<device-name>`
//!
//! # TLS configuration
//!
//! Reads from the standard `transport.link.tls.*` config section:
//!
//! ```json5
//! { transport: { link: { tls: {
//!     root_ca_certificate: "/path/ca.crt",
//!     listen_certificate:  "/path/server.crt",
//!     listen_private_key:  "/path/server.key",
//!     connect_certificate: "/path/client.crt",
//!     connect_private_key: "/path/client.key",
//! }}}}
//! ```

mod unicast;

pub use unicast::*;

use async_trait::async_trait;
use zenoh_config::Config as ZenohConfig;
use zenoh_link_commons::{
    tls::config::{
        TLS_CONNECT_CERTIFICATE_FILE, TLS_CONNECT_PRIVATE_KEY_FILE, TLS_ENABLE_MTLS,
        TLS_LISTEN_CERTIFICATE_FILE, TLS_LISTEN_PRIVATE_KEY_FILE,
        TLS_ROOT_CA_CERTIFICATE_FILE, TLS_VERIFY_NAME_ON_CONNECT,
    },
    ConfigurationInspector, LocatorInspector,
};
use zenoh_protocol::core::{parameters, Locator};
use zenoh_result::ZResult;

pub const BT_L2CAP_TLS_LOCATOR_PREFIX: &str = "bt_l2cap_tls";

/// PSM used for the Swarm mTLS L2CAP CoC channel.
/// Must match `SWARM_TLS_PSM` in `zenoh-nano/src/link/l2cap.rs`.
pub const SWARM_TLS_PSM: u16 = 0x00F0;

/// Zenoh BLE service UUID — shared with the GATT transport and zenoh-nano.
pub const ZENOH_BLE_SERVICE_UUID: &str = "24A9597F-1060-41BB-AB31-B638662BDCCC";

/// BLE device identity comes from the hardware address, not a cert SAN, so
/// server-name verification defaults to off for this transport.
/// Users can opt in via `verify_name_on_connect = true` in their zenoh config,
/// provided their server certificates carry `"zenoh-ble-peer"` as a DNS SAN.
pub const BT_L2CAP_TLS_VERIFY_NAME_ON_CONNECT_DEFAULT: bool = false;

/// Mutual TLS is the intended security model for this transport: both peers
/// authenticate with certificates.  Default is `true` (unlike the shared
/// `TLS_ENABLE_MTLS_DEFAULT = false` used by the TCP-TLS transport).
pub const BT_L2CAP_TLS_ENABLE_MTLS_DEFAULT: bool = true;

/// Reads `transport.link.tls.*` from the global config and encodes cert paths
/// as URL parameters so that `new_link` / `new_listener` can read them without
/// direct config access.
#[derive(Default, Clone, Copy)]
pub struct BtL2capTlsConfigurator;

impl ConfigurationInspector<ZenohConfig> for BtL2capTlsConfigurator {
    fn inspect_config(&self, config: &ZenohConfig) -> ZResult<String> {
        let tls = config.transport().link().tls();
        let mut ps: Vec<(&str, &str)> = Vec::new();

        if let Some(v) = tls.root_ca_certificate() {
            ps.push((TLS_ROOT_CA_CERTIFICATE_FILE, v));
        }
        if let Some(v) = tls.listen_certificate() {
            ps.push((TLS_LISTEN_CERTIFICATE_FILE, v));
        }
        if let Some(v) = tls.listen_private_key() {
            ps.push((TLS_LISTEN_PRIVATE_KEY_FILE, v));
        }
        if let Some(v) = tls.connect_certificate() {
            ps.push((TLS_CONNECT_CERTIFICATE_FILE, v));
        }
        if let Some(v) = tls.connect_private_key() {
            ps.push((TLS_CONNECT_PRIVATE_KEY_FILE, v));
        }

        let enable_mtls = tls.enable_mtls().unwrap_or(BT_L2CAP_TLS_ENABLE_MTLS_DEFAULT);
        ps.push((TLS_ENABLE_MTLS, if enable_mtls { "true" } else { "false" }));

        let verify_name = tls
            .verify_name_on_connect()
            .unwrap_or(BT_L2CAP_TLS_VERIFY_NAME_ON_CONNECT_DEFAULT);
        ps.push((
            TLS_VERIFY_NAME_ON_CONNECT,
            if verify_name { "true" } else { "false" },
        ));

        Ok(parameters::from_iter(ps.drain(..)))
    }
}

#[derive(Default, Clone, Copy)]
pub struct BtL2capTlsLocatorInspector;

#[async_trait]
impl LocatorInspector for BtL2capTlsLocatorInspector {
    fn protocol(&self) -> &str {
        BT_L2CAP_TLS_LOCATOR_PREFIX
    }

    async fn is_multicast(&self, _locator: &Locator) -> ZResult<bool> {
        Ok(false)
    }

    fn is_reliable(&self, _locator: &Locator) -> ZResult<bool> {
        Ok(true)
    }
}
