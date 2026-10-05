//
// Copyright (c) 2026 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//

//! ⚠️ WARNING ⚠️
//!
//! This crate is intended for Zenoh's internal use.
//!
//! A zenoh link over the iroh network: `iroh/<endpoint-id>`.
use async_trait::async_trait;
pub use iroh;
pub use iroh_lighthouse_client;
use zenoh_link_commons::LocatorInspector;
use zenoh_protocol::{core::Locator, transport::BatchSize};
use zenoh_result::ZResult;

mod endpoint;
mod unicast;

pub use endpoint::{IrohEndpoint, IrohEndpointConfig};
pub use unicast::*;

pub const IROH_LOCATOR_PREFIX: &str = "iroh";
/// ALPN spoken on every zenoh iroh connection.
pub const ALPN: &[u8] = b"myrmic/1";
/// Same constraint as the QUIC link: zenoh frames streamed batches with a 16-bit length.
const IROH_MAX_MTU: BatchSize = BatchSize::MAX;
const KEY_CONTEXT: &str = "zenoh-link-iroh/v1/secret-key";

#[derive(Default, Clone, Copy, Debug)]
pub struct IrohLocatorInspector;

#[async_trait]
impl LocatorInspector for IrohLocatorInspector {
    fn protocol(&self) -> &str {
        IROH_LOCATOR_PREFIX
    }

    async fn is_multicast(&self, _locator: &Locator) -> ZResult<bool> {
        Ok(false)
    }

    fn is_reliable(&self, _locator: &Locator) -> ZResult<bool> {
        Ok(true)
    }
}

/// The iroh key of a node that has no explicit `zone.secret_key`.
///
/// Only as secret as the zenoh id, which is public. See the zone design spec.
pub fn derive_secret_key(zid_le_bytes: &[u8; 16]) -> iroh::SecretKey {
    iroh::SecretKey::from_bytes(&blake3::derive_key(KEY_CONTEXT, zid_le_bytes))
}

/// The locator of an iroh endpoint: `iroh/<id>`.
pub fn locator_of(id: &iroh::EndpointId) -> Locator {
    Locator::new(IROH_LOCATOR_PREFIX, id.to_string(), "")
        .expect("endpoint ids are valid locator addresses")
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use zenoh_link_commons::LocatorInspector;
    use zenoh_protocol::core::Locator;

    use super::*;

    #[test]
    fn derived_key_is_deterministic_and_zid_specific() {
        let a = [1u8; 16];
        let mut b = [1u8; 16];
        b[15] = 2;
        assert_eq!(
            derive_secret_key(&a).public(),
            derive_secret_key(&a).public()
        );
        assert_ne!(
            derive_secret_key(&a).public(),
            derive_secret_key(&b).public()
        );
    }

    #[test]
    fn iroh_locators_are_reliable_unicast() {
        let l = Locator::from_str("iroh/abc").unwrap();
        assert!(IrohLocatorInspector.is_reliable(&l).unwrap());
        assert!(!futures_lite_block_on(IrohLocatorInspector.is_multicast(&l)).unwrap());
    }

    #[test]
    fn locator_of_formats_the_endpoint_id() {
        let id = derive_secret_key(&[7u8; 16]).public();
        assert_eq!(locator_of(&id).to_string(), format!("iroh/{id}"));
    }

    fn futures_lite_block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[tokio::test]
    async fn bound_endpoint_uses_the_configured_key() {
        let key = derive_secret_key(&[9u8; 16]);
        let expected = key.public();
        let ep = IrohEndpoint::bind(IrohEndpointConfig {
            secret_key: key,
            relays: false,
        })
        .await
        .unwrap();
        assert_eq!(ep.id(), expected);
        ep.close().await;
    }
}
