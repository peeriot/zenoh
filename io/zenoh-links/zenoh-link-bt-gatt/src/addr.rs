//! Parsing of the address part of `bt_gatt` endpoints: `[<adapter>@]<target>`
//!
//! - `<adapter>` is the BlueZ adapter name (e.g. `hci1`); when omitted, the default adapter is used.
//! - `<target>` is one of:
//!   - `[::]`: any device (connect) / advertise without a name (listen)
//!   - a MAC address `AA:BB:CC:DD:EE:FF`: the device with that address (connect only)
//!   - anything else: an advertised name (exact match on connect, advertised as-is on listen)

use std::str::FromStr;

use bluer::Address;
use zenoh_result::{bail, ZResult};

/// The `<target>` meaning "any device"
pub const ANY: &str = "[::]";

/// What an endpoint points at
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// Any device advertising the Zenoh GATT service
    Any,
    /// The device with this address
    Address(Address),
    /// The device advertising this name
    Name(String),
}

/// A parsed `bt_gatt` endpoint address
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtGattAddress {
    /// The BlueZ adapter to use, or `None` for the default one
    pub adapter: Option<String>,
    /// What the endpoint points at
    pub target: Target,
}

impl FromStr for BtGattAddress {
    type Err = zenoh_result::Error;

    fn from_str(s: &str) -> ZResult<Self> {
        let (adapter, target) = match s.split_once('@') {
            Some((adapter, target)) => {
                if adapter.is_empty() {
                    bail!("Invalid BT GATT address '{}': empty adapter name", s);
                }
                (Some(adapter.to_owned()), target)
            }
            None => (None, s),
        };

        let target = if target.is_empty() {
            bail!("Invalid BT GATT address '{}': empty target", s);
        } else if target == ANY {
            Target::Any
        } else if let Some(address) = parse_mac(target) {
            Target::Address(address)
        } else {
            Target::Name(target.to_owned())
        };

        Ok(Self { adapter, target })
    }
}

/// Parse a MAC address strictly in the `AA:BB:CC:DD:EE:FF` form (hex digits in any case)
fn parse_mac(s: &str) -> Option<Address> {
    let well_formed = s.len() == 17
        && s.split(':').count() == 6
        && s.split(':')
            .all(|part| part.len() == 2 && part.chars().all(|c| c.is_ascii_hexdigit()));

    if well_formed {
        Address::from_str(s).ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> BtGattAddress {
        s.parse().unwrap()
    }

    const MAC: Address = Address([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

    #[test]
    fn any() {
        assert_eq!(
            parse("[::]"),
            BtGattAddress {
                adapter: None,
                target: Target::Any
            }
        );
    }

    #[test]
    fn mac() {
        assert_eq!(
            parse("AA:BB:CC:DD:EE:FF"),
            BtGattAddress {
                adapter: None,
                target: Target::Address(MAC)
            }
        );
        assert_eq!(parse("aa:bb:cc:dd:ee:ff").target, Target::Address(MAC));
    }

    #[test]
    fn name() {
        assert_eq!(
            parse("Myrmic"),
            BtGattAddress {
                adapter: None,
                target: Target::Name("Myrmic".into())
            }
        );
    }

    #[test]
    fn with_adapter() {
        assert_eq!(
            parse("hci1@Myrmic"),
            BtGattAddress {
                adapter: Some("hci1".into()),
                target: Target::Name("Myrmic".into())
            }
        );
        assert_eq!(
            parse("hci1@AA:BB:CC:DD:EE:FF"),
            BtGattAddress {
                adapter: Some("hci1".into()),
                target: Target::Address(MAC)
            }
        );
        assert_eq!(
            parse("hci1@[::]"),
            BtGattAddress {
                adapter: Some("hci1".into()),
                target: Target::Any
            }
        );
    }

    #[test]
    fn mac_lookalikes_are_names() {
        for s in [
            "A:B:C:D:E:F",
            "AA:BB:CC:DD:EE",
            "AA:BB:CC:DD:EE:FF:00",
            "GG:BB:CC:DD:EE:FF",
        ] {
            assert_eq!(parse(s).target, Target::Name(s.into()), "{s}");
        }
    }

    #[test]
    fn only_first_at_separates_the_adapter() {
        assert_eq!(
            parse("hci0@my@device"),
            BtGattAddress {
                adapter: Some("hci0".into()),
                target: Target::Name("my@device".into())
            }
        );
    }

    #[test]
    fn invalid() {
        for s in ["", "@Myrmic", "hci0@", "@"] {
            assert!(s.parse::<BtGattAddress>().is_err(), "{s}");
        }
    }
}
