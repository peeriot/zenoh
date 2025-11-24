//! `Arc` and `Weak` types for Zenoh buffers and downstream crates:
//! - If the target does have atomic ptr, then the `alloc::sync::Arc` and `alloc::sync::Weak` types
//!   are re-exported, as they are available for that target;
//! - Otherwise, a portable implementation based on `portable-atomic-util` is provided.
//!
//! While it would've been better to unconditionally just always export our own implementation
//! (or the `portable-atomic-util` one), that would've required too many changes in the downstream crates
//! in that all of those should've switched to our own `Arc` type instead of the standard one.
//!
//! Therefore, a middle ground is taken:
//! - Zenoh crates that are `no_std` **should** depend on this crate and use the exported `Arc` and `Weak` types;
//! - Zenoh crates that are `std`-only **may** depend on this crate and use the exported `Arc` and `Weak` types, but
//!   they can also directly use the standard library ones if they want to.

#[cfg(target_has_atomic = "ptr")]
pub use alloc::sync::{Arc, Weak};

#[cfg(not(target_has_atomic = "ptr"))]
pub use portable_atomic_util::{Arc, Weak};
