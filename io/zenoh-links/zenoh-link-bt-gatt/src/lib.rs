//! ⚠️ WARNING ⚠️
//!
//! This crate is intended for Zenoh's internal use.
//!
//! [Click here for Zenoh's documentation](../zenoh/index.html)
mod unicast;

use std::str::FromStr;

use async_trait::async_trait;
use zenoh_link_commons::LocatorInspector;
use zenoh_protocol::core::{EndPoint, Locator, Metadata, Reliability};
use zenoh_result::ZResult;

pub use unicast::*;

const DEFAULT_EXCLUSIVE: bool = true;

pub const BT_GATT_LOCATOR_PREFIX: &str = "bt_gatt";

#[derive(Default, Clone, Copy)]
pub struct BtGattLocatorInspector;
#[async_trait]
impl LocatorInspector for BtGattLocatorInspector {
    fn protocol(&self) -> &str {
        BT_GATT_LOCATOR_PREFIX
    }

    async fn is_multicast(&self, _locator: &Locator) -> ZResult<bool> {
        Ok(false)
    }

    fn is_reliable(&self, locator: &Locator) -> ZResult<bool> {
        if let Some(reliability) = locator
            .metadata()
            .get(Metadata::RELIABILITY)
            .map(Reliability::from_str)
            .transpose()?
        {
            Ok(reliability == Reliability::Reliable)
        } else {
            Ok(false)
        }
    }
}

pub fn get_exclusive(endpoint: &EndPoint) -> bool {
    if let Some(exclusive) = endpoint.config().get(config::PORT_EXCLUSIVE_RAW) {
        bool::from_str(exclusive).unwrap_or(DEFAULT_EXCLUSIVE)
    } else {
        DEFAULT_EXCLUSIVE
    }
}

pub mod config {
    pub const PORT_EXCLUSIVE_RAW: &str = "exclusive";
}
