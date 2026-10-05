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

//! The `zone` section: lighthouse-based discovery of peers in the same zone.
use serde::{Deserialize, Serialize};

use crate::SecretValue;

/// Lighthouse topic name used when `zone.topic` is not set.
pub const DEFAULT_TOPIC: &str = "myrmic/zone";
/// Lighthouse used when `zone.lighthouse` is not set.
pub const DEFAULT_LIGHTHOUSE: &str = "iroh.ichor.io";

/// A non-empty zone id. It is the lighthouse topic secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ZoneId(String);

impl TryFrom<String> for ZoneId {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty() {
            Err("zone id must not be empty")
        } else {
            Ok(Self(value))
        }
    }
}

impl From<ZoneId> for String {
    fn from(value: ZoneId) -> Self {
        value.0
    }
}

/// `zone: "id"` or `zone: { id, topic?, lighthouse?, secret_key?, relays? }`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ZoneConf {
    Id(ZoneId),
    Full(ZoneFullConf),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZoneFullConf {
    pub id: ZoneId,
    pub topic: Option<String>,
    pub lighthouse: Option<String>,
    pub secret_key: Option<SecretValue>,
    pub relays: Option<bool>,
}

/// A [`ZoneConf`] with every default applied.
#[derive(Debug, Clone)]
pub struct Zone {
    pub id: String,
    pub topic: String,
    pub lighthouse: String,
    pub secret_key: Option<SecretValue>,
    pub relays: bool,
}

impl ZoneConf {
    pub fn resolve(&self) -> Zone {
        match self {
            ZoneConf::Id(id) => Zone {
                id: id.0.clone(),
                topic: DEFAULT_TOPIC.to_owned(),
                lighthouse: DEFAULT_LIGHTHOUSE.to_owned(),
                secret_key: None,
                relays: true,
            },
            ZoneConf::Full(full) => Zone {
                id: full.id.0.clone(),
                topic: full
                    .topic
                    .clone()
                    .unwrap_or_else(|| DEFAULT_TOPIC.to_owned()),
                lighthouse: full
                    .lighthouse
                    .clone()
                    .unwrap_or_else(|| DEFAULT_LIGHTHOUSE.to_owned()),
                secret_key: full.secret_key.clone(),
                relays: full.relays.unwrap_or(true),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use crate::Config;

    fn zone_of(json5: &str) -> super::Zone {
        let mut c = Config::default();
        c.insert_json5("zone", json5).unwrap();
        c.zone().as_ref().unwrap().resolve()
    }

    #[test]
    fn shorthand_and_full_form_resolve_to_the_same_zone() {
        let a = zone_of(r#""blah""#);
        let b = zone_of(r#"{ id: "blah" }"#);
        assert_eq!(a.id, "blah");
        assert_eq!(a.topic, super::DEFAULT_TOPIC);
        assert_eq!(a.lighthouse, super::DEFAULT_LIGHTHOUSE);
        assert!(a.secret_key.is_none());
        assert!(a.relays);
        assert_eq!(
            (a.id, a.topic, a.lighthouse, a.relays),
            (b.id, b.topic, b.lighthouse, b.relays)
        );
    }

    #[test]
    fn full_form_overrides_every_default() {
        let z = zone_of(
            r#"{ id: "z", topic: "t/x", lighthouse: "http://127.0.0.1:9", secret_key: "abc", relays: false }"#,
        );
        assert_eq!(z.topic, "t/x");
        assert_eq!(z.lighthouse, "http://127.0.0.1:9");
        assert_eq!(z.secret_key.unwrap().expose_secret().as_str(), "abc");
        assert!(!z.relays);
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let mut c = Config::default();
        assert!(c.insert_json5("zone", r#"{ id: "z", nope: 1 }"#).is_err());
    }

    #[test]
    fn empty_id_is_rejected_in_both_forms() {
        let mut c = Config::default();
        assert!(c.insert_json5("zone", r#""""#).is_err());
        assert!(c.insert_json5("zone", r#"{ id: "" }"#).is_err());
    }

    #[test]
    fn zone_is_unset_by_default() {
        assert!(Config::default().zone().is_none());
    }

    /// Only `Debug` is redacted. Serde output (config JSON, admin space) still holds the key.
    #[test]
    fn secret_key_is_not_printed() {
        let mut c = Config::default();
        c.insert_json5("zone", r#"{ id: "z", secret_key: "topsecret" }"#)
            .unwrap();
        assert!(!format!("{c:?}").contains("topsecret"));
    }
}
