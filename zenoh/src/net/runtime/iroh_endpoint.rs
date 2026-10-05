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
#![cfg(feature = "transport_iroh")]
use std::str::FromStr;

use secrecy::ExposeSecret;
use zenoh_config::{zone::Zone, ExpandedConfig, ModeDependent};
use zenoh_link::{
    iroh::{
        derive_secret_key, iroh::SecretKey, iroh_lighthouse_client, IrohEndpoint,
        IrohEndpointConfig, IROH_LOCATOR_PREFIX,
    },
    EndPoint,
};
use zenoh_protocol::core::{EndPoints, ZenohIdProto};
use zenoh_result::{zerror, ZResult};

pub(crate) fn resolve_secret_key(zone: Option<&Zone>, zid: ZenohIdProto) -> ZResult<SecretKey> {
    match zone.and_then(|z| z.secret_key.as_ref()) {
        Some(key) => SecretKey::from_str(key.expose_secret())
            .map_err(|e| zerror!("invalid zone.secret_key: {e}").into()),
        None => Ok(derive_secret_key(&zid.to_le_bytes())),
    }
}

pub(crate) fn with_zone_listener(mut listeners: Vec<EndPoint>, has_zone: bool) -> Vec<EndPoint> {
    if has_zone
        && !listeners
            .iter()
            .any(|e| e.protocol().as_str() == IROH_LOCATOR_PREFIX)
    {
        listeners.push(EndPoint::from_str("iroh/auto").expect("valid endpoint"));
    }
    listeners
}

/// Binds this runtime's iroh endpoint when the config needs one.
pub(crate) async fn bind_for(config: &ExpandedConfig) -> ZResult<Option<IrohEndpoint>> {
    let mode = config.mode();
    let zone = config.zone().as_ref().map(|z| z.resolve());
    let is_iroh = |e: &EndPoint| e.protocol().as_str() == IROH_LOCATOR_PREFIX;
    // `listen.endpoints` is `Vec<EndPoint>`; `connect.endpoints` is `Vec<EndPoints>` (single or a locator group).
    let listens = config
        .listen()
        .endpoints()
        .get(mode)
        .is_some_and(|eps| eps.iter().any(is_iroh));
    let connects = config
        .connect()
        .endpoints()
        .get(mode)
        .is_some_and(|eps| eps.iter().flat_map(EndPoints::as_vec).any(|e| is_iroh(&e)));
    if zone.is_none() && !listens && !connects {
        return Ok(None);
    }
    if let Some(z) = &zone {
        iroh_lighthouse_client::parse_url(&z.lighthouse)
            .map_err(|e| zerror!("invalid zone.lighthouse {}: {e}", z.lighthouse))?;
    }
    let endpoint = IrohEndpoint::bind(IrohEndpointConfig {
        secret_key: resolve_secret_key(zone.as_ref(), config.id().into())?,
        relays: zone.as_ref().map_or(true, |z| z.relays),
    })
    .await?;
    Ok(Some(endpoint))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use zenoh_config::Config;
    use zenoh_link::EndPoint;
    use zenoh_protocol::core::ZenohIdProto;

    use super::*;

    fn zone(json5: &str) -> zenoh_config::zone::Zone {
        let mut c = Config::default();
        c.insert_json5("zone", json5).unwrap();
        c.zone().as_ref().unwrap().resolve()
    }

    #[test]
    fn derived_key_follows_the_zid() {
        let zid = ZenohIdProto::from_str("a1b2").unwrap();
        let k1 = resolve_secret_key(None, zid).unwrap();
        let k2 = resolve_secret_key(Some(&zone(r#""z""#)), zid).unwrap();
        assert_eq!(k1.public(), k2.public());
        assert_eq!(
            k1.public(),
            zenoh_link::iroh::derive_secret_key(&zid.to_le_bytes()).public()
        );
    }

    #[test]
    fn explicit_key_wins_and_bad_keys_are_rejected() {
        let zid = ZenohIdProto::from_str("a1b2").unwrap();
        let explicit = zenoh_link::iroh::iroh::SecretKey::generate();
        let hex: String = explicit
            .to_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let z = zone(&format!(r#"{{ id: "z", secret_key: "{hex}" }}"#));
        assert_eq!(
            resolve_secret_key(Some(&z), zid).unwrap().public(),
            explicit.public()
        );

        let bad = zone(r#"{ id: "z", secret_key: "nope" }"#);
        let err = resolve_secret_key(Some(&bad), zid).unwrap_err().to_string();
        assert!(err.contains("zone.secret_key"), "{err}");
    }

    #[test]
    fn zone_listener_is_added_once() {
        let tcp = EndPoint::from_str("tcp/[::]:0").unwrap();
        let iroh = EndPoint::from_str("iroh/auto").unwrap();
        assert_eq!(
            with_zone_listener(vec![tcp.clone()], false),
            vec![tcp.clone()]
        );
        assert_eq!(
            with_zone_listener(vec![tcp.clone()], true),
            vec![tcp.clone(), iroh.clone()]
        );
        assert_eq!(with_zone_listener(vec![iroh.clone()], true), vec![iroh]);
    }
}
