# Zone discovery over iroh-lighthouse Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A `zone` config key makes a zenoh node join an iroh-lighthouse topic, discover the other members of its zone, and connect to them over a new iroh transport link (`iroh/<endpoint-id>`).

**Architecture:** A new link crate `zenoh-link-iroh` wraps an iroh `Endpoint` as a zenoh unicast link (one QUIC connection plus one bidirectional stream per link, ALPN `myrmic/1`). The runtime owns one `IrohEndpoint` per runtime, hands it to the transport manager (and from there to the iroh link manager), and uses the same endpoint for a lighthouse `Session` in a new `runtime/zone.rs` task. That task dials every discovered peer at `iroh/<id>`, using a lower-id-dials tie-break. Discovery is the zone topic alone: nothing is published to n0 DNS or to the lighthouse's zone-less directory.

**Tech Stack:** Rust 1.97.1 (pinned), tokio, `iroh` 1.3, `iroh-lighthouse-client` 0.1, `iroh-lighthouse` 0.1 (dev only), `blake3`, zenoh's `validated_struct` config.

**Spec:** `docs/superpowers/specs/2026-10-02-zone-iroh-lighthouse-design.md`

## Global Constraints

- Version control is **jj** (`jj describe -m ...` then `jj new`), never `git commit`. No AI attribution in descriptions.
- ALPN is exactly `b"myrmic/1"`.
- Locator protocol prefix is exactly `iroh`; the locator address is the endpoint id (`EndpointId` `Display`, lowercase hex).
- Default topic `"myrmic/zone"`; default lighthouse `"iroh.ichor.io"`; zone `id` is the topic secret (`Topic::with_secret(topic, id.as_bytes())`).
- Derived key: `SecretKey::from_bytes(&blake3::derive_key("zenoh-link-iroh/v1/secret-key", &zid.to_le_bytes()))`, where `zid: ZenohIdProto`.
- `ZONE_TTL = 120s`. Client lookup poll and reconcile interval: `ZONE_POLL_INTERVAL = 10s` and `ZONE_RECONCILE_INTERVAL = 5s`.
- Feature `transport_iroh`. It is **not** in any default feature set. Every new line of code that touches iroh sits behind it.
- iroh and the lighthouse crates need Rust ≥ 1.91, so the new crate sets `rust-version = "1.91"` instead of `workspace = true`. The pinned toolchain is 1.97.1. The workspace version is `1.10.1`.
- Link trait surface (upstream `main` as of 2026-09-30): `read`/`write`/`write_all`/`read_exact` take a trailing `priority: Option<Priority>`; `LinkManagerUnicastTrait` has `get_locators_noloopback`; `LinkUnicast` wraps `NewLink`, so it is built with `LinkUnicast::from(arc as Arc<dyn LinkUnicastTrait>)`, never `LinkUnicast(arc)`; under `all(feature = "uring", target_os = "linux")` every link implements `get_fd`.
- The iroh endpoint is per runtime. No `static`, `OnceLock` or `lazy_static` holding an endpoint.
- Zenoh start must never fail because the lighthouse is unreachable, and close must never hang on it: every lighthouse call is cancellable or time-bounded.
- No address publishing: no `PkarrPublisher`, no `LighthouseLookup`. Peer addresses come only from the zone topic and are put into the endpoint's `MemoryLookup` before dialling. With `relays: true`, n0's relays and n0 DNS *resolvers* are used; only the publisher is left out.
- iroh uses `tls-ring`, like the rest of zenoh. The lighthouse crates and reqwest also compile aws-lc-rs, which needs a C toolchain; this is accepted.
- The session-level zone tests need the `iroh-lighthouse` server. It is an *optional normal* dependency of `zenoh`, enabled only by the test-only feature `transport_iroh_test = ["transport_iroh", "dep:iroh-lighthouse"]`, so default `cargo test -p zenoh` and workspace clippy never compile it.
- Every new file starts with the repo's EPL-2.0/Apache-2.0 copyright header (copy from any existing file, year 2026).

## Review Focus

1. **Silent or unreachable lighthouse:** `zenoh::open` returns promptly with a dead lighthouse (`http://127.0.0.1:1`), and `Session::close` returns promptly with one that accepts TCP but never answers. Tests: Task 5 `open_succeeds_with_unreachable_lighthouse`, Task 6 `close_is_prompt_with_a_silent_lighthouse`.
2. **Zone client with default config:** multicast scouting stays on and there are no connect endpoints. `open` must not fail on the 3s scouting timeout, and the client connects through the zone. Test: Task 6 `zone_client_with_default_scouting_opens_and_connects`.
3. **Two peers discovering each other simultaneously:** only one side dials. Checked by counting dial attempts, because `max_links = 1` and per-zid dedup would hide a double dial from a link count. Test: Task 6 `two_peers_in_a_zone_connect_once`.
4. **Peer restart with a stable zid:** the other side reconnects, with the restarted node in both roles. Test: Task 6 `peer_restart_is_redialled`.
5. **Malformed `zone.secret_key`:** `zenoh::open` returns an error naming `zone.secret_key` and does not panic. Test: Task 5 `invalid_secret_key_is_rejected`.

Also tested but not in this list: an explicit `iroh/` listener alongside a zone (Task 5 `explicit_iroh_listener_with_zone_is_not_duplicated`).

## Spec deltas (decided while planning; already applied to the spec)

- `zone.relays: bool` (default `true`). `false` uses `presets::Minimal` plus `RelayMode::Disabled` (no n0 relays and no n0 DNS publishing). This is needed for offline tests and is useful for LAN-only deployments.
- Dial retry is a fixed reconcile tick (`ZONE_RECONCILE_INTERVAL`, 5s) that re-evaluates the latest peer list. It replaces the `connect.retry` backoff. The tick also redials dropped peers without waiting for a list change.
- The explicit-connect (`iroh/<id>`) test lives at link-crate level (Task 3), where the test can seed addresses directly. Session-level tests go through the zone.
- No publishing: drop `LighthouseLookup` and n0's `PkarrPublisher`. Discovery is the zone topic only. A bare `connect: iroh/<id>` to a node outside the zone works only if n0 DNS resolves it (because that node publishes) or a relay path is otherwise known.
- `secret_key` is redacted in `Debug` only. Like the existing TLS `*_base64` secrets, it is visible through serde (config JSON, admin space).
- Clients keep one connection: they dial members one at a time until one succeeds.
- Lighthouse calls are cancellable (`join`, `lookup`) or time-bounded (`leave`, 2s).
- A zone client does not fail on the multicast scouting timeout. The zone races multicast.
- `ZoneConf::Id` holds a `ZoneId` newtype that rejects empty strings.
- New enum variants: `LinkAuthId::Iroh(String)` (the remote endpoint id; ACL `cert_common_names` does not match it, which is a follow-up) and `InterceptorLink::Iroh` (`"iroh"` in `link_protocols`).
- `iroh/<id>` locators are advertised in hellos/gossip. Nodes without the feature skip them at trace level; nodes with the feature but no endpoint fail that dial at debug level. `open.return_conditions.connect_scouted` does not wait for zone peers, so early publications may be lost.
- The test server dependency is an optional normal dependency behind `transport_iroh_test`, not a dev-dependency.

## File Structure

| File | Status | Responsibility |
|---|---|---|
| `commons/zenoh-config/src/zone.rs` | create | `ZoneConf`, `ZoneId`, `ZoneFullConf`, `Zone` (resolved), defaults, unit tests |
| `commons/zenoh-config/src/lib.rs` | modify | `pub mod zone;`, `zone: Option<zone::ZoneConf>` field, `InterceptorLink::Iroh` |
| `DEFAULT_CONFIG.json5` | modify | documented, commented-out `zone` example |
| `io/zenoh-link-commons/src/unicast.rs` | modify | `LinkAuthId::Iroh(String)` |
| `io/zenoh-links/zenoh-link-iroh/Cargo.toml` | create | crate manifest |
| `io/zenoh-links/zenoh-link-iroh/src/lib.rs` | create | constants, `IrohLocatorInspector`, `derive_secret_key`, re-exports |
| `io/zenoh-links/zenoh-link-iroh/src/endpoint.rs` | create | `IrohEndpoint`, `IrohEndpointConfig` (bind/close/seed addresses) |
| `io/zenoh-links/zenoh-link-iroh/src/unicast.rs` | create | `LinkUnicastIroh`, `LinkManagerUnicastIroh` |
| `io/zenoh-links/zenoh-link-iroh/tests/link.rs` | create | link round-trip tests over two local endpoints |
| `Cargo.toml` (workspace) | modify | member, workspace deps |
| `io/zenoh-link/{Cargo.toml,src/lib.rs}` | modify | `LinkKind::Iroh`, inspector, `make(..., iroh)` |
| `io/zenoh-transport/{Cargo.toml,src/manager.rs,src/unicast/manager.rs}` | modify | `iroh_endpoint` config/builder, pass to `make` |
| `zenoh/Cargo.toml` | modify | `transport_iroh` feature, `iroh-lighthouse` dev-dep |
| `zenoh/src/api/info.rs`, `zenoh/src/net/routing/interceptor/mod.rs` | modify | exhaustive matches on new `LinkAuthId::Iroh` |
| `zenoh/src/net/runtime/iroh_endpoint.rs` | create | decide whether to bind, resolve the key, bind for a runtime |
| `zenoh/src/net/runtime/zone.rs` | create | lighthouse join/lookup, reconcile, tie-break, leave |
| `zenoh/src/net/runtime/mod.rs` | modify | own `Option<IrohEndpoint>`, pass to transport manager, close |
| `zenoh/src/net/runtime/orchestrator.rs` | modify | implicit `iroh/` listener, start zone in each mode |
| `zenoh/tests/zone.rs` | create | session-level zone tests against in-process lighthouse |

---

### Task 1: `zone` configuration

**Files:**
- Create: `commons/zenoh-config/src/zone.rs`
- Modify: `commons/zenoh-config/src/lib.rs` (module list at line 25; `Config` struct at line 562, after `pub gateway: gateway::GatewayConf,`)
- Modify: `DEFAULT_CONFIG.json5` (after the `gateway` block, which starts at line 272)

**Interfaces:**
- Produces:
  - `zenoh_config::zone::{ZoneConf, ZoneId, ZoneFullConf, Zone, DEFAULT_TOPIC, DEFAULT_LIGHTHOUSE}`
  - `ZoneConf::resolve(&self) -> Zone`
  - `Zone { id: String, topic: String, lighthouse: String, secret_key: Option<SecretValue>, relays: bool }`
  - Getter `Config::zone(&self) -> &Option<ZoneConf>` (generated by `validated_struct`)
  - `InterceptorLink::Iroh`

- [ ] **Step 1: Write the failing tests** in `commons/zenoh-config/src/zone.rs` (the file holds only the test module for now, plus `pub mod zone;` in `lib.rs`):

```rust
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
        assert_eq!((a.id, a.topic, a.lighthouse, a.relays), (b.id, b.topic, b.lighthouse, b.relays));
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
        c.insert_json5("zone", r#"{ id: "z", secret_key: "topsecret" }"#).unwrap();
        assert!(!format!("{c:?}").contains("topsecret"));
    }
}
```

- [ ] **Step 2: Run them and confirm they fail**

Run: `cargo test -p zenoh-config zone::`
Expected: compile errors (`Zone`, `zone()` not found).

- [ ] **Step 3: Implement** above the test module in `zone.rs`:

```rust
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
                topic: full.topic.clone().unwrap_or_else(|| DEFAULT_TOPIC.to_owned()),
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
```

In `lib.rs`, add `pub mod zone;` next to `pub mod gateway;`. In the `Config { ... }` validator, add the field after `pub gateway: gateway::GatewayConf,`:

```rust
        /// Lighthouse-based discovery of the other members of a zone, connected over iroh.
        /// Either a zone id string or `{ id, topic, lighthouse, secret_key, relays }`.
        zone: Option<zone::ZoneConf>,
```

Add `Iroh,` as the last variant of `InterceptorLink` (line ~330, after `Ble,`).

`SecretValue` (`lib.rs:99`) serializes through `secrecy`'s `serde` feature, which the workspace enables. If the derive still complains, copy the attributes used on `root_ca_certificate_base64: Option<SecretValue>` in the same file.

- [ ] **Step 4: Run the tests**

Run: `cargo test -p zenoh-config`
Expected: all pass, including existing config tests (proves the default config still parses).

- [ ] **Step 5: Document in `DEFAULT_CONFIG.json5`** after the `gateway` block:

```json5
  // /// Zone discovery over iroh (requires the `transport_iroh` feature).
  // ///
  // /// Nodes with the same zone id find each other through an iroh-lighthouse server and
  // /// connect over the iroh network (`iroh/<endpoint-id>` links). Peers and routers listen on
  // /// `iroh/` automatically and announce themselves; clients only look the zone up.
  // ///
  // /// Shorthand: `zone: "my-zone"`. Full form:
  // zone: {
  //   /// Zone id, used as the lighthouse topic secret. Required, non-empty.
  //   id: "my-zone",
  //   /// Lighthouse topic name.
  //   topic: "myrmic/zone",
  //   /// Lighthouse address. A bare host means https; localhost and IP addresses mean http.
  //   lighthouse: "iroh.ichor.io",
  //   /// iroh ed25519 secret key (hex or base32). When unset it is derived from the zenoh id,
  //   /// which is public: anyone who knows the zid can derive the key. Set it for real authentication.
  //   secret_key: null,
  //   /// Use the n0 relay and DNS infrastructure. Disable for LAN-only or isolated deployments.
  //   relays: true,
  // },
```

Add `"iroh"` to the four commented `link_protocols` example lists in `DEFAULT_CONFIG.json5` (lines 313, 377, 482 and 517).

- [ ] **Step 6: Lint and commit**

Run: `cargo clippy -p zenoh-config --all-targets -- -D warnings && cargo fmt --all -- --check`

```bash
jj describe -m "Add the zone config section"
jj new
```

---

### Task 2: `zenoh-link-iroh` crate core (endpoint, key, inspector)

**Files:**
- Create: `io/zenoh-links/zenoh-link-iroh/Cargo.toml`, `src/lib.rs`, `src/endpoint.rs`
- Modify: workspace `Cargo.toml` (members list at line 46; `[workspace.dependencies]` near line 257)
- Modify: `io/zenoh-link-commons/src/unicast.rs:165-190` (add `LinkAuthId::Iroh(String)`)
- Modify: `zenoh/src/api/info.rs:337-348`, `zenoh/src/net/routing/interceptor/mod.rs:80-94` (exhaustive matches)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces (all in `zenoh_link_iroh`):
  - `pub const IROH_LOCATOR_PREFIX: &str = "iroh";`
  - `pub const ALPN: &[u8] = b"myrmic/1";`
  - `pub struct IrohLocatorInspector;` (implements `zenoh_link_commons::LocatorInspector`)
  - `pub fn derive_secret_key(zid_le_bytes: &[u8; 16]) -> iroh::SecretKey`
  - `pub fn locator_of(id: &iroh::EndpointId) -> Locator` (`iroh/<id>`)
  - `pub struct IrohEndpointConfig { pub secret_key: SecretKey, pub relays: bool }`
  - `#[derive(Clone, Debug)] pub struct IrohEndpoint` with:
    - `pub async fn bind(cfg: IrohEndpointConfig) -> ZResult<Self>`
    - `pub fn endpoint(&self) -> &iroh::Endpoint`
    - `pub fn id(&self) -> iroh::EndpointId`
    - `pub fn set_addr(&self, addr: iroh::EndpointAddr)` (replaces what is known for `addr.id`)
    - `pub async fn close(&self)`
  - Re-exports: `pub use iroh; pub use iroh_lighthouse_client;`
  - `LinkAuthId::Iroh(String)` (remote endpoint id)

- [ ] **Step 1: Scaffold the crate.** Workspace `Cargo.toml`: add the member `"io/zenoh-links/zenoh-link-iroh/",` next to the bt-gatt member, and add these workspace deps:

```toml
blake3 = "1"
iroh = { version = "1.3", default-features = false, features = ["metrics", "tls-ring"] }
iroh-lighthouse = "0.1"
iroh-lighthouse-client = "0.1"
zenoh-link-iroh = { version = "1.10.1", path = "io/zenoh-links/zenoh-link-iroh" }
```

`io/zenoh-links/zenoh-link-iroh/Cargo.toml`: copy the header and `[package]` from `zenoh-link-quic/Cargo.toml`, but set `name = "zenoh-link-iroh"` and `rust-version = "1.91"`, and use these features and deps:

```toml
[features]
uring = ["zenoh-link-commons/uring"]

[dependencies]
async-trait = { workspace = true }
blake3 = { workspace = true }
iroh = { workspace = true }
iroh-lighthouse-client = { workspace = true }
tokio = { workspace = true, features = ["sync", "time", "macros"] }
tokio-util = { workspace = true, features = ["rt"] }
tracing = { workspace = true }
zenoh-core = { workspace = true }
zenoh-link-commons = { workspace = true }
zenoh-protocol = { workspace = true }
zenoh-result = { workspace = true }
zenoh-runtime = { workspace = true }

[dev-dependencies]
tokio = { workspace = true, features = ["rt-multi-thread", "macros", "time"] }
```

Add `Iroh(String)` to `LinkAuthId`, with `LinkAuthId::Iroh(_) => None` in `get_cert_common_name`. In `zenoh/src/api/info.rs`, map `LinkAuthId::Iroh(id) => Some(id.clone())` (an authenticated identity, like a cert CN). In the interceptor, map `LinkAuthId::Iroh(_) => Self(InterceptorLink::Iroh)`.

- [ ] **Step 2: Write the failing unit tests** at the bottom of `src/lib.rs`:

```rust
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
        assert_eq!(derive_secret_key(&a).public(), derive_secret_key(&a).public());
        assert_ne!(derive_secret_key(&a).public(), derive_secret_key(&b).public());
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
        tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(f)
    }

    #[tokio::test]
    async fn bound_endpoint_uses_the_configured_key() {
        let key = derive_secret_key(&[9u8; 16]);
        let expected = key.public();
        let ep = IrohEndpoint::bind(IrohEndpointConfig { secret_key: key, relays: false })
            .await
            .unwrap();
        assert_eq!(ep.id(), expected);
        ep.close().await;
    }
}
```

Add `tokio = { workspace = true, features = ["rt", "macros"] }` to `[dev-dependencies]` if `rt` is missing.

- [ ] **Step 3: Run them and confirm they fail**

Run: `cargo test -p zenoh-link-iroh --lib`
Expected: compile errors (items not defined).

- [ ] **Step 4: Implement `src/lib.rs`:**

```rust
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
#[allow(dead_code)] // used from Task 3 on; remove the allow there
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
    Locator::new(IROH_LOCATOR_PREFIX, id.to_string(), "").expect("endpoint ids are valid locator addresses")
}
```

The `LocatorInspector` trait is `protocol`, `is_multicast` (async) and `is_reliable`, matching the impl above. For now, create `src/unicast.rs` holding only the copyright header (Task 3 fills it).

`src/endpoint.rs`:

```rust
use iroh::{
    address_lookup::{DnsAddressLookup, MemoryLookup, PkarrResolver},
    endpoint::{default_relay_mode, presets},
    Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey,
};
use zenoh_result::{zerror, ZResult};

use crate::ALPN;

pub struct IrohEndpointConfig {
    pub secret_key: SecretKey,
    /// n0 relays and n0 DNS resolution when true; direct addresses only when false.
    /// Never publishes this endpoint's addresses anywhere.
    pub relays: bool,
}

/// The iroh endpoint of one zenoh runtime, shared by the iroh link manager and zone discovery.
#[derive(Clone, Debug)]
pub struct IrohEndpoint {
    endpoint: Endpoint,
    memory: MemoryLookup,
}

impl IrohEndpoint {
    pub async fn bind(cfg: IrohEndpointConfig) -> ZResult<Self> {
        let memory = MemoryLookup::new();
        // `presets::N0` minus `PkarrPublisher`: discovery happens on the zone topic, so
        // nothing is published to n0 DNS.
        let mut builder = Endpoint::builder(presets::Minimal);
        builder = if cfg.relays {
            builder
                .relay_mode(default_relay_mode())
                .address_lookup(PkarrResolver::n0_dns())
                .address_lookup(DnsAddressLookup::n0_dns())
        } else {
            builder.relay_mode(RelayMode::Disabled)
        };
        let endpoint = builder
            .secret_key(cfg.secret_key)
            .alpns(vec![ALPN.to_vec()])
            .address_lookup(memory.clone())
            .bind()
            .await
            .map_err(|e| zerror!("Cannot bind iroh endpoint: {e}"))?;
        tracing::info!("iroh endpoint {} bound", endpoint.id());
        Ok(Self { endpoint, memory })
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub fn id(&self) -> EndpointId {
        self.endpoint.id()
    }

    /// Replace what is known about `addr.id`, so a dial by id alone uses these addresses.
    pub fn set_addr(&self, addr: EndpointAddr) {
        self.memory.set_endpoint_info(addr);
    }

    pub async fn close(&self) {
        self.endpoint.close().await;
    }
}
```

`set_endpoint_info` replaces the entry; `add_endpoint_info` would merge and accumulate stale ports across peer restarts. The paths `iroh::endpoint::default_relay_mode` (`endpoint.rs:2049`), `address_lookup::{PkarrResolver, DnsAddressLookup}::n0_dns()` (`pkarr.rs:525`, `dns.rs:92`) and `presets::Minimal` (which selects ring when both TLS features are on) are confirmed in iroh 1.3.0. `DnsAddressLookup` is not built for wasm; zenoh does not target wasm with this feature.

`iroh::{Endpoint, RelayMode, EndpointAddr, EndpointId, SecretKey}` are root re-exports in iroh 1.3.0.

- [ ] **Step 5: Run the tests**

Run: `cargo test -p zenoh-link-iroh --lib && cargo check -p zenoh`
Expected: 4 tests pass; zenoh still compiles with the new `LinkAuthId` variant.

- [ ] **Step 6: Lint and commit**

Run: `cargo clippy -p zenoh-link-iroh -p zenoh-link-commons -p zenoh --all-targets -- -D warnings`

```bash
jj describe -m "Add the zenoh-link-iroh crate with the per-runtime iroh endpoint"
jj new
```

---

### Task 3: iroh unicast link and link manager

**Files:**
- Modify: `io/zenoh-links/zenoh-link-iroh/src/unicast.rs`
- Create: `io/zenoh-links/zenoh-link-iroh/tests/link.rs`

**Interfaces:**
- Consumes: `IrohEndpoint`, `ALPN`, `IROH_LOCATOR_PREFIX`, `IROH_MAX_MTU`, `locator_of` (Task 2).
- Produces: `pub struct LinkManagerUnicastIroh` with `pub fn new(manager: NewLinkChannelSender, endpoint: IrohEndpoint) -> Self`, implementing `LinkManagerUnicastTrait` (including `get_locators_noloopback`, which equals `get_locators`); and `pub struct LinkUnicastIroh` implementing `LinkUnicastTrait` (single stream; the `priority` arguments are ignored; `get_fd` bails under `uring`).

Behaviour:
- `new_listener(ep)`: the address must be empty or equal to the own id, otherwise error `"iroh listener address must be empty or this endpoint's id"`. A second listener is an error `"already listening on iroh"`. It spawns one accept task and returns `locator_of(&own_id)` with the endpoint's metadata.
- `del_listener` cancels the accept task. `get_listeners` and `get_locators` report the single listener, if any.
- `new_link(ep)`: parse the address as an `EndpointId` (error `"invalid iroh endpoint id"`), then `connect(EndpointAddr::new(id), ALPN)`, then `open_bi`.
- The accept task loops over `endpoint.accept()` until it is cancelled or returns `None`. For each one: `incoming.accept()?.await`, then `accept_bi`, then `send_async(LinkUnicast(link))`. Per-connection errors are logged at `debug` and the loop continues. Each connection is handled in its own spawned task, so one slow handshake does not block others.

- [ ] **Step 1: Write the failing integration tests** `tests/link.rs`:

```rust
use std::{str::FromStr, time::Duration};

use iroh::Watcher;
use zenoh_link_commons::{LinkManagerUnicastTrait, NewLinkChannelSender};
use zenoh_link_iroh::{derive_secret_key, IrohEndpoint, IrohEndpointConfig, LinkManagerUnicastIroh};
use zenoh_protocol::core::EndPoint;

async fn endpoint(seed: u8) -> IrohEndpoint {
    IrohEndpoint::bind(IrohEndpointConfig {
        secret_key: derive_secret_key(&[seed; 16]),
        relays: false,
    })
    .await
    .unwrap()
}

/// Wait until `ep` has a direct address, then return its full address.
async fn dialable(ep: &IrohEndpoint) -> iroh::EndpointAddr {
    let mut w = ep.endpoint().watch_addr();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let a = w.get();
            if a.ip_addrs().next().is_some() {
                return a;
            }
            w.updated().await.unwrap();
        }
    })
    .await
    .unwrap()
}

fn manager(ep: IrohEndpoint) -> (LinkManagerUnicastIroh, flume::Receiver<zenoh_link_commons::LinkUnicast>) {
    let (tx, rx): (NewLinkChannelSender, _) = flume::unbounded();
    (LinkManagerUnicastIroh::new(tx, ep), rx)
}

#[tokio::test(flavor = "multi_thread")]
async fn dial_by_id_and_exchange_bytes() {
    let (a, b) = (endpoint(1).await, endpoint(2).await);
    let (ma, accepted) = manager(a.clone());
    let (mb, _) = manager(b.clone());

    let locator = ma.new_listener(EndPoint::from_str("iroh/").unwrap()).await.unwrap();
    assert_eq!(locator.to_string(), format!("iroh/{}", a.id()));

    b.set_addr(dialable(&a).await);
    let dialled = mb.new_link(EndPoint::from_str(&format!("iroh/{}", a.id())).unwrap()).await.unwrap();
    dialled.write_all(b"hello", None).await.unwrap();

    let inbound = tokio::time::timeout(Duration::from_secs(10), accepted.recv_async()).await.unwrap().unwrap();
    let mut buf = [0u8; 5];
    inbound.read_exact(&mut buf, None).await.unwrap();
    assert_eq!(&buf, b"hello");

    assert_eq!(dialled.get_dst().to_string(), format!("iroh/{}", a.id()));
    assert_eq!(inbound.get_dst().to_string(), format!("iroh/{}", b.id()));
    assert!(dialled.is_streamed() && dialled.is_reliable());
    assert_eq!(*inbound.get_auth_id(), zenoh_link_commons::LinkAuthId::Iroh(b.id().to_string()));

    inbound.write_all(b"back!", None).await.unwrap();
    dialled.read_exact(&mut buf, None).await.unwrap();
    assert_eq!(&buf, b"back!");

    dialled.close().await.unwrap();
    a.close().await;
    b.close().await;
}

#[tokio::test]
async fn listener_rejects_a_foreign_id_and_a_second_listener() {
    let a = endpoint(3).await;
    let other = derive_secret_key(&[4; 16]).public();
    let (ma, _) = manager(a.clone());
    assert!(ma.new_listener(EndPoint::from_str(&format!("iroh/{other}")).unwrap()).await.is_err());
    ma.new_listener(EndPoint::from_str(&format!("iroh/{}", a.id())).unwrap()).await.unwrap();
    assert!(ma.new_listener(EndPoint::from_str("iroh/").unwrap()).await.is_err());
    a.close().await;
}

#[tokio::test]
async fn dialling_garbage_is_an_error() {
    let a = endpoint(5).await;
    let (ma, _) = manager(a.clone());
    assert!(ma.new_link(EndPoint::from_str("iroh/not-an-id").unwrap()).await.is_err());
    a.close().await;
}
```

`NewLinkChannelSender` is `flume::Sender<LinkUnicast>`, so add `flume = { workspace = true }` to `[dev-dependencies]`. Run the suite once more with `--features uring` on Linux, so the `get_fd` stub compiles.

- [ ] **Step 2: Run them and confirm they fail**

Run: `cargo test -p zenoh-link-iroh --test link`
Expected: compile error (`LinkManagerUnicastIroh` not found).

- [ ] **Step 3: Implement `src/unicast.rs`:**

```rust
use std::{fmt, str::FromStr, sync::Arc};

use async_trait::async_trait;
use iroh::{
    endpoint::{Connection, RecvStream, SendStream, VarInt},
    EndpointAddr, EndpointId,
};
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::CancellationToken;
use zenoh_core::zasynclock;
#[cfg(all(feature = "uring", target_os = "linux"))]
use std::os::fd::RawFd;

use zenoh_link_commons::{
    LinkAuthId, LinkManagerUnicastTrait, LinkUnicast, LinkUnicastTrait, NewLinkChannelSender,
};
use zenoh_protocol::{
    core::{EndPoint, Locator, Priority},
    transport::BatchSize,
};
use zenoh_result::{bail, zerror, ZResult};

use crate::{locator_of, IrohEndpoint, ALPN, IROH_MAX_MTU};

pub struct LinkUnicastIroh {
    connection: Connection,
    src_locator: Locator,
    dst_locator: Locator,
    send: AsyncMutex<SendStream>,
    recv: AsyncMutex<RecvStream>,
    auth_id: LinkAuthId,
}

impl LinkUnicastIroh {
    fn new(local: EndpointId, connection: Connection, send: SendStream, recv: RecvStream) -> Self {
        let remote = connection.remote_id();
        Self {
            src_locator: locator_of(&local),
            dst_locator: locator_of(&remote),
            auth_id: LinkAuthId::Iroh(remote.to_string()),
            connection,
            send: AsyncMutex::new(send),
            recv: AsyncMutex::new(recv),
        }
    }
}

#[async_trait]
impl LinkUnicastTrait for LinkUnicastIroh {
    async fn close(&self) -> ZResult<()> {
        tracing::trace!("Closing iroh link: {}", self);
        if let Err(e) = zasynclock!(self.send).finish() {
            tracing::trace!("Error finishing iroh stream {}: {}", self, e);
        }
        self.connection.close(VarInt::from_u32(0), b"");
        Ok(())
    }

    // One stream per link: priorities are not separated (`supports_priorities` keeps its default, false).
    async fn write(&self, buffer: &[u8], _priority: Option<Priority>) -> ZResult<usize> {
        zasynclock!(self.send)
            .write(buffer)
            .await
            .map_err(|e| zerror!("Write error on iroh link {}: {}", self, e).into())
    }

    async fn write_all(&self, buffer: &[u8], _priority: Option<Priority>) -> ZResult<()> {
        zasynclock!(self.send)
            .write_all(buffer)
            .await
            .map_err(|e| zerror!("Write error on iroh link {}: {}", self, e).into())
    }

    async fn read(&self, buffer: &mut [u8], _priority: Option<Priority>) -> ZResult<usize> {
        zasynclock!(self.recv)
            .read(buffer)
            .await
            .map_err(|e| zerror!("Read error on iroh link {}: {}", self, e))?
            .ok_or_else(|| zerror!("Read error on iroh link {}: stream closed", self).into())
    }

    async fn read_exact(&self, buffer: &mut [u8], _priority: Option<Priority>) -> ZResult<()> {
        zasynclock!(self.recv)
            .read_exact(buffer)
            .await
            .map_err(|e| zerror!("Read error on iroh link {}: {}", self, e).into())
    }

    fn get_src(&self) -> &Locator {
        &self.src_locator
    }

    fn get_dst(&self) -> &Locator {
        &self.dst_locator
    }

    fn get_mtu(&self) -> BatchSize {
        IROH_MAX_MTU
    }

    fn get_interface_names(&self) -> Vec<String> {
        vec![]
    }

    fn is_reliable(&self) -> bool {
        true
    }

    fn is_streamed(&self) -> bool {
        true
    }

    fn get_auth_id(&self) -> &LinkAuthId {
        &self.auth_id
    }

    #[cfg(all(feature = "uring", target_os = "linux"))]
    fn get_fd(&self) -> ZResult<RawFd> {
        bail!("Not supported");
    }
}

impl Drop for LinkUnicastIroh {
    fn drop(&mut self) {
        self.connection.close(VarInt::from_u32(0), b"");
    }
}

impl fmt::Display for LinkUnicastIroh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} => {}", self.src_locator, self.dst_locator)
    }
}

impl fmt::Debug for LinkUnicastIroh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Iroh")
            .field("src", &self.src_locator)
            .field("dst", &self.dst_locator)
            .finish()
    }
}

struct Listener {
    endpoint: EndPoint,
    locator: Locator,
    token: CancellationToken,
}

pub struct LinkManagerUnicastIroh {
    manager: NewLinkChannelSender,
    iroh: IrohEndpoint,
    listener: std::sync::Mutex<Option<Listener>>,
}

impl LinkManagerUnicastIroh {
    pub fn new(manager: NewLinkChannelSender, iroh: IrohEndpoint) -> Self {
        Self { manager, iroh, listener: std::sync::Mutex::new(None) }
    }
}

#[async_trait]
impl LinkManagerUnicastTrait for LinkManagerUnicastIroh {
    async fn new_link(&self, endpoint: EndPoint) -> ZResult<LinkUnicast> {
        let addr = endpoint.address();
        let id = EndpointId::from_str(addr.as_str())
            .map_err(|e| zerror!("invalid iroh endpoint id {}: {}", addr, e))?;
        let connection = self
            .iroh
            .endpoint()
            .connect(EndpointAddr::new(id), ALPN)
            .await
            .map_err(|e| zerror!("Cannot connect to iroh endpoint {}: {}", id, e))?;
        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(|e| zerror!("Cannot open iroh stream to {}: {}", id, e))?;
        let link: Arc<dyn LinkUnicastTrait> =
            Arc::new(LinkUnicastIroh::new(self.iroh.id(), connection, send, recv));
        Ok(LinkUnicast::from(link))
    }

    async fn new_listener(&self, endpoint: EndPoint) -> ZResult<Locator> {
        let own = self.iroh.id();
        let addr = endpoint.address();
        if !addr.as_str().is_empty() && addr.as_str() != own.to_string() {
            bail!("iroh listener address must be empty or this endpoint's id ({own}), got {addr}");
        }
        let mut guard = self.listener.lock().unwrap();
        if guard.is_some() {
            bail!("already listening on iroh as {own}");
        }
        let locator = Locator::new(crate::IROH_LOCATOR_PREFIX, own.to_string(), endpoint.metadata())?;
        let token = CancellationToken::new();
        zenoh_runtime::ZRuntime::Acceptor.spawn(accept_task(self.iroh.clone(), self.manager.clone(), token.clone()));
        *guard = Some(Listener { endpoint, locator: locator.clone(), token });
        Ok(locator)
    }

    async fn del_listener(&self, _endpoint: &EndPoint) -> ZResult<()> {
        match self.listener.lock().unwrap().take() {
            Some(l) => {
                l.token.cancel();
                Ok(())
            }
            None => bail!("not listening on iroh"),
        }
    }

    async fn get_listeners(&self) -> Vec<EndPoint> {
        self.listener.lock().unwrap().iter().map(|l| l.endpoint.clone()).collect()
    }

    async fn get_locators(&self) -> Vec<Locator> {
        self.listener.lock().unwrap().iter().map(|l| l.locator.clone()).collect()
    }

    /// iroh locators carry no IP address, so there is no loopback to filter out.
    async fn get_locators_noloopback(&self) -> Vec<Locator> {
        self.get_locators().await
    }
}

async fn accept_task(iroh: IrohEndpoint, manager: NewLinkChannelSender, token: CancellationToken) {
    tracing::trace!("Ready to accept iroh connections as {}", iroh.id());
    loop {
        let incoming = tokio::select! {
            _ = token.cancelled() => break,
            incoming = iroh.endpoint().accept() => match incoming {
                Some(incoming) => incoming,
                None => break, // endpoint closed
            },
        };
        let (iroh, manager) = (iroh.clone(), manager.clone());
        zenoh_runtime::ZRuntime::Acceptor.spawn(async move {
            let result: ZResult<()> = async {
                let connection = incoming.accept().map_err(|e| zerror!("{e}"))?.await.map_err(|e| zerror!("{e}"))?;
                let (send, recv) = connection.accept_bi().await.map_err(|e| zerror!("{e}"))?;
                let link = LinkUnicastIroh::new(iroh.id(), connection, send, recv);
                tracing::debug!("Accepted iroh connection: {}", link);
                let link: Arc<dyn LinkUnicastTrait> = Arc::new(link);
                manager
                    .send_async(LinkUnicast::from(link))
                    .await
                    .map_err(|e| zerror!("{e}").into())
            }
            .await;
            if let Err(e) = result {
                tracing::debug!("Failed to accept iroh connection: {}", e);
            }
        });
    }
}
```

The accept loop and the per-connection handshakes run on `ZRuntime::Acceptor`, like `ListenersUnicastIP` (`io/zenoh-link-commons/src/listener.rs:112`). Remove the `#[allow(dead_code)]` on `IROH_MAX_MTU` added in Task 2.

- [ ] **Step 4: Run the tests**

Run: `cargo test -p zenoh-link-iroh && cargo check -p zenoh-link-iroh --features uring`
Expected: all pass (unit tests from Task 2 plus the 3 link tests), and the `uring` build compiles.

- [ ] **Step 5: Lint and commit**

Run: `cargo clippy -p zenoh-link-iroh --all-targets -- -D warnings`

```bash
jj describe -m "Implement the iroh unicast link and link manager"
jj new
```

---

### Task 4: Wire the iroh link into zenoh-link and zenoh-transport

**Files:**
- Modify: `io/zenoh-link/Cargo.toml` (features near line 28; deps)
- Modify: `io/zenoh-link/src/lib.rs` (imports at the top, `LinkKind`, `new_supported_links`, `TryFrom<&Locator>`, `ALL_SUPPORTED_LINKS`, `LocatorInspector`, `LinkManagerBuilderUnicast::make`)
- Modify: `io/zenoh-transport/Cargo.toml` (feature), `io/zenoh-transport/src/manager.rs` (config struct ends at line 146, `region_name` builder at 401, `from_config` at 414, `build` at 470), `io/zenoh-transport/src/unicast/manager.rs:397-398`
- Modify: `zenoh/Cargo.toml` (feature)

**Interfaces:**
- Consumes: `zenoh_link_iroh::{LinkManagerUnicastIroh, IrohLocatorInspector, IrohEndpoint, IROH_LOCATOR_PREFIX}`.
- Produces:
  - `zenoh_link::iroh` (= `zenoh_link_iroh` re-export) and `LinkKind::Iroh`
  - `LinkManagerBuilderUnicast::make(manager, endpoint, #[cfg(feature = "transport_iroh")] iroh: Option<&IrohEndpoint>)`
  - `TransportManagerBuilder::iroh_endpoint(self, Option<IrohEndpoint>) -> Self` and `TransportManagerConfig::iroh_endpoint: Option<IrohEndpoint>`, both `#[cfg(feature = "transport_iroh")]`
  - The `transport_iroh` feature on `zenoh-link`, `zenoh-transport` and `zenoh`

- [ ] **Step 1: Features.**
  - `zenoh-link`: `transport_iroh = ["zenoh-link-iroh"]` and `zenoh-link-iroh = { workspace = true, optional = true }`. Also add `"zenoh-link-iroh?/uring",` to its `uring` feature list (next to `"zenoh-link-bt-gatt?/uring"`).
  - `zenoh-transport`: `transport_iroh = ["zenoh-link/transport_iroh"]`.
  - `zenoh`: `transport_iroh = ["zenoh-link/transport_iroh", "zenoh-transport/transport_iroh"]` (not in `default`). zenoh uses `zenoh_link::iroh` directly, so it must enable the link feature itself rather than rely on unification.
  - `zenoh`: also add `"sync"` to its `tokio` features (`zenoh/Cargo.toml:109`). Task 6 uses `tokio::sync::watch`.

- [ ] **Step 2: `zenoh-link/src/lib.rs`.** Follow the existing pattern for every match/list, under `#[cfg(feature = "transport_iroh")]`:

```rust
#[cfg(feature = "transport_iroh")]
pub use zenoh_link_iroh as iroh;
#[cfg(feature = "transport_iroh")]
use zenoh_link_iroh::{IrohEndpoint, IrohLocatorInspector, LinkManagerUnicastIroh, IROH_LOCATOR_PREFIX};
```

  - Add the `Iroh` variant to `LinkKind`.
  - In `new_supported_links`: `IROH_LOCATOR_PREFIX => supported_links.push(LinkKind::Iroh),`.
  - In `TryFrom<&Locator>`: `IROH_LOCATOR_PREFIX => Ok(LinkKind::Iroh),`.
  - Add `LinkKind::Iroh` to `ALL_SUPPORTED_LINKS`.
  - Add the field `iroh_inspector: IrohLocatorInspector` to `LocatorInspector`, plus arms in `is_reliable` and `is_multicast`.
  - Change `make`:

```rust
    pub fn make(
        _manager: NewLinkChannelSender,
        endpoint: &EndPoint,
        #[cfg(feature = "transport_iroh")] iroh: Option<&IrohEndpoint>,
    ) -> ZResult<LinkManagerUnicast> {
        ...
            #[cfg(feature = "transport_iroh")]
            LinkKind::Iroh => {
                let iroh = iroh.ok_or_else(|| zenoh_result::zerror!("iroh endpoint not configured"))?;
                Ok(std::sync::Arc::new(LinkManagerUnicastIroh::new(_manager, iroh.clone())))
            }
```

- [ ] **Step 3: `zenoh-transport`.**
  - In `manager.rs`, add `#[cfg(feature = "transport_iroh")] pub iroh_endpoint: Option<zenoh_link::iroh::IrohEndpoint>,` to `TransportManagerConfig`, and `#[cfg(feature = "transport_iroh")] iroh_endpoint: Option<zenoh_link::iroh::IrohEndpoint>,` to `TransportManagerBuilder`.
  - Default it to `None` in `Default` and copy it in `build()`.
  - Add the builder method:

```rust
    #[cfg(feature = "transport_iroh")]
    pub fn iroh_endpoint(mut self, iroh_endpoint: Option<zenoh_link::iroh::IrohEndpoint>) -> Self {
        self.iroh_endpoint = iroh_endpoint;
        self
    }
```

  - In `unicast/manager.rs:397`:

```rust
            let lm = LinkManagerBuilderUnicast::make(
                self.new_unicast_link_sender.clone(),
                endpoint,
                #[cfg(feature = "transport_iroh")]
                self.config.iroh_endpoint.as_ref(),
            )?;
```

- [ ] **Step 4: Verify both feature states build, and existing tests pass**

Run:
```bash
cargo check -p zenoh --all-targets
cargo check -p zenoh --all-targets --features transport_iroh
cargo test -p zenoh-link -p zenoh-transport --features zenoh-transport/transport_iroh --lib
```
Expected: all succeed. A transport manager without an endpoint that is asked to listen on `iroh/` returns `iroh endpoint not configured` (Task 5 makes the runtime supply the endpoint).

- [ ] **Step 5: Lint and commit**

Run: `cargo clippy -p zenoh --all-targets --features transport_iroh -- -D warnings`

```bash
jj describe -m "Register the iroh link behind the transport_iroh feature"
jj new
```

---

### Task 5: Runtime-owned iroh endpoint and implicit iroh listener

**Files:**
- Create: `zenoh/src/net/runtime/iroh_endpoint.rs`
- Modify: `zenoh/src/net/runtime/mod.rs` (`mod` list at lines 20-23; `RuntimeState` fields at line 180; `RuntimeBuilder::build` at line 745, with the transport manager builder at 798-810, and the `RuntimeState { .. }` literal after it; `close_inner` at line 1349)
- Modify: `zenoh/src/net/runtime/orchestrator.rs` (`start_client`, `start_peer`, `start_router`)
- Modify: `zenoh/Cargo.toml` (optional dep `iroh-lighthouse` and the `transport_iroh_test` feature)
- Create: `zenoh/tests/zone.rs` (startup tests only here; discovery tests come in Task 6)

**Interfaces:**
- Consumes: `zenoh_config::zone::Zone` and `Config::zone()` (Task 1); `zenoh_link::iroh::{IrohEndpoint, IrohEndpointConfig, derive_secret_key, IROH_LOCATOR_PREFIX}` (Tasks 2 and 4); `TransportManagerBuilder::iroh_endpoint` (Task 4).
- Produces:
  - `pub(crate) async fn bind_for(config: &ExpandedConfig) -> ZResult<Option<IrohEndpoint>>` in `iroh_endpoint.rs`
  - `pub(crate) fn resolve_secret_key(zone: Option<&Zone>, zid: ZenohIdProto) -> ZResult<SecretKey>`
  - `pub(crate) fn with_zone_listener(listeners: Vec<EndPoint>, has_zone: bool) -> Vec<EndPoint>`
  - `Runtime::iroh(&self) -> Option<&IrohEndpoint>` (cfg feature)

Rules:
- Bind only if `zone` is set, or any `listen`/`connect` endpoint for the current mode has protocol `iroh`. Otherwise return `None`.
- Key: `zone.secret_key` parsed with `SecretKey::from_str(expose_secret())`. On failure, return the error `"invalid zone.secret_key: {e}"`. Without one, derive from `zid.to_le_bytes()`.
- `relays`: `zone.relays` if a zone is set, otherwise `true`.
- `lighthouse`: validated with `iroh_lighthouse_client::parse_url(&zone.lighthouse)` when a zone is set, and on failure returns `"invalid zone.lighthouse {url}: {e}"`. It is not passed to the endpoint, because nothing publishes to or resolves through the lighthouse directory.
- `with_zone_listener` appends `iroh/` when `has_zone` is true and no listener already has protocol `iroh`. It is called for peer and router only.
- With a zone set but the crate built without `transport_iroh`, the runtime logs `tracing::warn!("zone is configured but zenoh was built without the transport_iroh feature; ignoring it")` once at start and otherwise behaves as if no zone were set.
- On close: `self.manager.close().await;` then `if let Some(iroh) = &self.iroh { iroh.close().await }`.

- [ ] **Step 1: Write the failing unit tests** at the bottom of `iroh_endpoint.rs`:

```rust
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
        assert_eq!(k1.public(), zenoh_link::iroh::derive_secret_key(&zid.to_le_bytes()).public());
    }

    #[test]
    fn explicit_key_wins_and_bad_keys_are_rejected() {
        let zid = ZenohIdProto::from_str("a1b2").unwrap();
        let explicit = zenoh_link::iroh::iroh::SecretKey::generate();
        let hex: String = explicit.to_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let z = zone(&format!(r#"{{ id: "z", secret_key: "{hex}" }}"#));
        assert_eq!(resolve_secret_key(Some(&z), zid).unwrap().public(), explicit.public());

        let bad = zone(r#"{ id: "z", secret_key: "nope" }"#);
        let err = resolve_secret_key(Some(&bad), zid).unwrap_err().to_string();
        assert!(err.contains("zone.secret_key"), "{err}");
    }

    #[test]
    fn zone_listener_is_added_once() {
        let tcp = EndPoint::from_str("tcp/[::]:0").unwrap();
        let iroh = EndPoint::from_str("iroh/").unwrap();
        assert_eq!(with_zone_listener(vec![tcp.clone()], false), vec![tcp.clone()]);
        assert_eq!(with_zone_listener(vec![tcp.clone()], true), vec![tcp.clone(), iroh.clone()]);
        assert_eq!(with_zone_listener(vec![iroh.clone()], true), vec![iroh]);
    }
}
```

`SecretKey::from_str` accepts hex. If it turns out to accept base32 only, encode the test key the way `SecretKey`'s `Display` or `to_string()` emits it, or check `iroh-base-1.3.0/src/key.rs` (`decode_base32_hex`).

- [ ] **Step 2: Write the failing session-level tests** `zenoh/tests/zone.rs` (these also cover Review Focus 1, 4 and 5):

```rust
#![cfg(all(feature = "transport_iroh_test", feature = "unstable"))]
use std::time::{Duration, Instant};

use zenoh::{config::WhatAmI, Config};

/// A config that only talks iroh: no multicast/gossip, no TCP listener, no relays.
pub fn zone_config(zone: &str, lighthouse: &str, mode: WhatAmI, id: Option<&str>) -> Config {
    let mut c = Config::default();
    c.set_mode(Some(mode)).unwrap();
    if let Some(id) = id {
        c.insert_json5("id", &format!(r#""{id}""#)).unwrap();
    }
    c.insert_json5("scouting/multicast/enabled", "false").unwrap();
    c.insert_json5("scouting/gossip/enabled", "false").unwrap();
    c.insert_json5("listen/endpoints", "[]").unwrap();
    c.insert_json5(
        "zone",
        &format!(r#"{{ id: "{zone}", lighthouse: "{lighthouse}", relays: false }}"#),
    )
    .unwrap();
    c
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn open_succeeds_with_unreachable_lighthouse() {
    let start = Instant::now();
    let s = zenoh::open(zone_config("z", "http://127.0.0.1:1", WhatAmI::Peer, None)).await.unwrap();
    assert!(start.elapsed() < Duration::from_secs(10), "open blocked on the lighthouse");
    let locators = s.info().locators().await;
    assert!(locators.iter().any(|l| l.protocol().as_str() == "iroh"), "{locators:?}");
    s.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn explicit_iroh_listener_with_zone_is_not_duplicated() {
    let mut c = zone_config("z", "http://127.0.0.1:1", WhatAmI::Peer, None);
    c.insert_json5("listen/endpoints", r#"["iroh/"]"#).unwrap();
    let s = zenoh::open(c).await.unwrap();
    s.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_secret_key_is_rejected() {
    let mut c = zone_config("z", "http://127.0.0.1:1", WhatAmI::Peer, None);
    c.insert_json5("zone", r#"{ id: "z", lighthouse: "http://127.0.0.1:1", relays: false, secret_key: "nope" }"#)
        .unwrap();
    let err = zenoh::open(c).await.err().expect("open must fail").to_string();
    assert!(err.contains("zone.secret_key"), "{err}");
}
```

`SessionInfo::locators()` and `links()` are `unstable`, which is why the file is gated on both features.

In `zenoh/Cargo.toml`, add the test server as an optional *normal* dependency, plus the feature that enables it. A dev-dependency cannot be optional, and would put iroh, aws-lc-rs and axum into every `cargo test -p zenoh`:

```toml
[features]
transport_iroh_test = ["transport_iroh", "dep:iroh-lighthouse"]

[dependencies]
iroh-lighthouse = { workspace = true, optional = true }
```

zenoh's lib code never uses `iroh_lighthouse`. If CI's `cargo machete` flags it, add a `[package.metadata.cargo-machete] ignored = ["iroh-lighthouse"]` table, as `ci/zenoh-1-75/Cargo.toml` does.

- [ ] **Step 3: Run them and confirm they fail**

Run: `cargo test -p zenoh --features transport_iroh,unstable --lib iroh_endpoint && cargo test -p zenoh --features transport_iroh_test,unstable --test zone`
Expected: compile errors, then failures (no iroh listener yet).

- [ ] **Step 4: Implement `iroh_endpoint.rs`** (the whole module is `#![cfg(feature = "transport_iroh")]`; declare it in `mod.rs` as `#[cfg(feature = "transport_iroh")] mod iroh_endpoint;`):

```rust
use std::str::FromStr;

use secrecy::ExposeSecret;
use zenoh_config::{zone::Zone, ExpandedConfig, ModeDependent};
use zenoh_link::{
    iroh::{derive_secret_key, iroh::SecretKey, iroh_lighthouse_client, IrohEndpoint, IrohEndpointConfig, IROH_LOCATOR_PREFIX},
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
    if has_zone && !listeners.iter().any(|e| e.protocol().as_str() == IROH_LOCATOR_PREFIX) {
        listeners.push(EndPoint::from_str("iroh/").expect("valid endpoint"));
    }
    listeners
}

/// Binds this runtime's iroh endpoint when the config needs one.
pub(crate) async fn bind_for(config: &ExpandedConfig) -> ZResult<Option<IrohEndpoint>> {
    let mode = config.mode();
    let zone = config.zone().as_ref().map(|z| z.resolve());
    let is_iroh = |e: &EndPoint| e.protocol().as_str() == IROH_LOCATOR_PREFIX;
    // `listen.endpoints` is `Vec<EndPoint>`; `connect.endpoints` is `Vec<EndPoints>` (single or a locator group).
    let listens = config.listen().endpoints().get(mode).is_some_and(|eps| eps.iter().any(is_iroh));
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
        relays: zone.as_ref().is_none_or(|z| z.relays),
    })
    .await?;
    Ok(Some(endpoint))
}
```

`ModeDependent::get(WhatAmI)` returns `Option<&T>`. If `EndPoints` is not re-exported from `zenoh_protocol::core`, import it from wherever `commons/zenoh-protocol/src/core/endpoint.rs:749` is exported. If `secrecy` is not a direct dep of `zenoh`, add `secrecy = { workspace = true }`.

`mod.rs`:
- Add `#[cfg(feature = "transport_iroh")] iroh: Option<zenoh_link::iroh::IrohEndpoint>,` to `RuntimeState`.
- In `build()`, before `TransportManager::builder()`:

```rust
        #[cfg(feature = "transport_iroh")]
        let iroh = iroh_endpoint::bind_for(&config).await?;
```

- Chain `.iroh_endpoint(iroh.clone())` onto `transport_manager_builder` under `#[cfg(feature = "transport_iroh")]`. Use a `let` rebinding like the `shm_reader` lines.
- Set the `iroh,` field (cfg-gated) in the `RuntimeState` literal.
- Add the accessor:

```rust
    #[cfg(feature = "transport_iroh")]
    pub(crate) fn iroh(&self) -> Option<&zenoh_link::iroh::IrohEndpoint> {
        self.state.iroh.as_ref()
    }
```

- In `close_inner`, after `self.manager.close().await;`:

```rust
        #[cfg(feature = "transport_iroh")]
        if let Some(iroh) = &self.iroh {
            iroh.close().await;
        }
```

`orchestrator.rs`:
- In `start_peer` and `start_router`, right after the config tuple is read and before `self.bind_listeners(&listeners)`:

```rust
        #[cfg(feature = "transport_iroh")]
        let listeners = super::iroh_endpoint::with_zone_listener(listeners, self.config().lock().zone().is_some());
```

- At the top of `start()`, before the `match`:

```rust
        #[cfg(not(feature = "transport_iroh"))]
        if self.config().lock().zone().is_some() {
            tracing::warn!("zone is configured but zenoh was built without the transport_iroh feature; ignoring it");
        }
```

- [ ] **Step 5: Run the tests**

Run: `cargo test -p zenoh --features transport_iroh,unstable --lib iroh_endpoint && cargo test -p zenoh --features transport_iroh_test,unstable --test zone`
Expected: all 6 pass. `open_succeeds_with_unreachable_lighthouse` passes because nothing contacts the lighthouse yet; it keeps guarding Review Focus 1 once Task 6 adds the join.

- [ ] **Step 6: Lint and commit**

Run: `cargo clippy -p zenoh --all-targets --features transport_iroh_test,unstable -- -D warnings && cargo clippy -p zenoh --all-targets -- -D warnings`

```bash
jj describe -m "Give each runtime an iroh endpoint and listen on iroh when a zone is set"
jj new
```

---

### Task 6: Zone discovery

**Files:**
- Create: `zenoh/src/net/runtime/zone.rs`
- Modify: `zenoh/src/net/runtime/mod.rs` (`#[cfg(feature = "transport_iroh")] mod zone;`)
- Modify: `zenoh/src/net/runtime/orchestrator.rs` (`start_client` at line 194, `start_peer` at 265, `start_router` at 333)
- Modify: `zenoh/tests/zone.rs` (discovery tests)

**Interfaces:**
- Consumes: `Runtime::{iroh, manager, spawn, spawn_abortable, get_cancellation_token, zid, whatami, config}`, `Zone`, `zenoh_link::iroh::{iroh, iroh_lighthouse_client, locator_of, IrohEndpoint}`.
- Produces:
  - `pub(crate) fn should_dial(own: &EndpointId, remote: &EndpointId) -> bool`. This is the member tie-break; clients do not use it.
  - `pub(crate) fn start(runtime: &Runtime)`: spawns the zone task if a zone and an endpoint are both present; otherwise does nothing.
  - `Runtime::wait_for_unicast_transport(&self)` (orchestrator, cfg feature): resolves once at least one unicast transport exists.
  - Debug log line `"zone dial from {own_zid} to {endpoint_id}"`, emitted once per dial attempt. The tie-break test counts these lines.

Behaviour:
- **Topic:** `Topic::with_secret(zone.topic, zone.id.as_bytes())`. **Lighthouse:** `Lighthouse::http(parse_url(&zone.lighthouse)?)`. The URL was already validated by `bind_for` (Task 5), so a parse failure here only logs a warning and returns.
- **Every lighthouse call is cancellable.** `join`, `lookup` and the initial address wait each run inside `select!` with `token.cancelled()`. `leave` runs under `tokio::time::timeout(LEAVE_TIMEOUT = 2s)`. Runtime close awaits this task with no timeout of its own (`TaskController::terminate_all_async`), so this is what keeps close from hanging on a silent lighthouse.
- **Peer/router ("member"):**
  1. Wait up to 5s for a direct address.
  2. Loop `join(endpoint, topic, ZONE_TTL)` with backoff 1s→60s (doubling). On error, log `warn!("Cannot join zone {} on {}: {e}", zone.topic, zone.lighthouse)`.
  3. Once joined, reconcile once, then `select!` on: `token.cancelled()` (then leave and return); `peers.changed()` (reconcile with the latest list); a `ZONE_RECONCILE_INTERVAL` tick created with `interval_at(now + interval, interval)`, so it does not fire immediately and double the first reconcile (reconcile with `session.peers()`).
- **Member reconcile(peers):** for each `p`:
  1. Skip `!should_dial(own, &p.addr.id)`.
  2. Skip if any unicast transport has a link whose `dst == locator_of(&p.addr.id)`.
  3. Skip if the id is in the pending set.
  4. Otherwise insert it into the pending set and `iroh.set_addr(p.addr.clone())`; the lighthouse list is authoritative, so stale ports are replaced, not accumulated.
  5. Log the dial line, then `runtime.spawn_abortable` the dial `manager.open_transport_unicast(locator_of(&id).into())`. Log failures at debug. Always remove the id from the pending set when the dial ends.
- **Client:** a zenoh client holds one connection. Each round (every `ZONE_POLL_INTERVAL`, the whole round inside `select!` with the token):
  1. If any unicast transport exists, do nothing.
  2. Otherwise run `lookup(&topic)`, and for each peer in order call `set_addr`, log the dial line, and await `open_transport_unicast`. Stop at the first success.
  3. On lookup error, warn.
- **`start_peer` / `start_router`:** call `zone::start(self)` right after `bind_listeners`.
- **`start_client`:**
  - Compute `zone_set` once (`false` without the feature).
  - Call `zone::start(self)` right after `bind_listeners`, before any scouting, so the zone races multicast instead of waiting behind it.
  - **Multicast on, no connect endpoints:** when `zone_set`, replace `self.connect_first(..).await?` with a `select!` between `connect_first(..)` and `self.wait_for_unicast_transport()`. Whichever finishes first wins, and a scouting timeout is not an error. Without a zone the line is unchanged.
  - **Multicast off, no connect endpoints:** the existing `bail!("No peer specified and multicast scouting deactivated!")` fires only when `!zone_set`. When `zone_set`, await `tokio::time::timeout(timeout, self.wait_for_unicast_transport())` and on timeout `warn!("No zone peer connected within the scouting timeout")`; open still succeeds.
  - With no zone configured, `start_client` behaves exactly as before.

- [ ] **Step 1: Write the failing unit test** in `zone.rs`:

```rust
#[cfg(test)]
mod tests {
    use zenoh_link::iroh::iroh::SecretKey;

    use super::should_dial;

    #[test]
    fn exactly_one_side_of_a_member_pair_dials() {
        let (a, b) = (SecretKey::generate().public(), SecretKey::generate().public());
        assert_ne!(should_dial(&a, &b), should_dial(&b, &a));
        assert!(!should_dial(&a, &a));
    }
}
```

- [ ] **Step 2: Add the failing discovery tests** to `zenoh/tests/zone.rs`. They cover Review Focus 1 (close half), 2, 3 and 4.

Add the capture setup at the top of the file (the pattern of `zenoh/tests/regions/scenario4.rs`, with `std::sync::LazyLock` in place of `lazy_static`). Every test in this file calls `init_tracing()` first:

```rust
use std::sync::LazyLock;

static STORAGE: LazyLock<tracing_capture::SharedStorage> = LazyLock::new(Default::default);

fn init_tracing() {
    use tracing_subscriber::layer::SubscriberExt;
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("warn,zenoh::net::runtime::zone=debug")
        .finish()
        .with(tracing_capture::CaptureLayer::new(&STORAGE));
    tracing::subscriber::set_global_default(subscriber).ok();
}

/// Zone dial attempts made by `from`. Tests run in parallel, so filter by zid.
fn dials_from(from: &zenoh::session::ZenohId) -> usize {
    let needle = format!("zone dial from {from} ");
    STORAGE
        .lock()
        .all_events()
        .filter(|e| e.message().is_some_and(|m| m.contains(&needle)))
        .count()
}
```

Then the tests:

```rust
use std::net::SocketAddr;

use iroh_lighthouse::{handler::Limits, registry::SizeLimits, Config as LhConfig, Server};
use zenoh::Session;

async fn lighthouse() -> (Server, String) {
    let server = Server::spawn(LhConfig {
        http_listen: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
        iroh: None,
        snapshot: None,
        sweep_interval: Duration::from_secs(30),
        limits: Limits {
            min_ttl_secs: 1,
            max_ttl_secs: 3600,
            max_skew_secs: 300,
            size: SizeLimits { max_peers_per_topic: 16, max_topics: 100 },
        },
    })
    .await
    .unwrap();
    let url = format!("http://{}", server.http_addr().unwrap());
    (server, url)
}

async fn wait_until(what: &str, mut cond: impl AsyncFnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(30), async {
        while !cond().await {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting until {what}"));
}

async fn connected(s: &Session, other: &Session) -> bool {
    let other = other.zid();
    s.info().peers_zid().await.any(|z| z == other)
}

async fn assert_pubsub(publisher: &Session, subscriber: &Session) {
    let sub = subscriber.declare_subscriber("zone/test").await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await; // declaration propagation
    publisher.put("zone/test", "hi").await.unwrap();
    let sample = tokio::time::timeout(Duration::from_secs(10), sub.recv_async()).await.unwrap().unwrap();
    assert_eq!(sample.payload().try_to_string().unwrap(), "hi");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_peers_in_a_zone_connect_once() {
    init_tracing();
    let (server, url) = lighthouse().await;
    let a = zenoh::open(zone_config("z1", &url, WhatAmI::Peer, None)).await.unwrap();
    let b = zenoh::open(zone_config("z1", &url, WhatAmI::Peer, None)).await.unwrap();
    wait_until("a and b are connected", async || connected(&a, &b).await && connected(&b, &a).await).await;
    tokio::time::sleep(Duration::from_secs(6)).await; // past one reconcile tick
    // max_links = 1 and per-zid dedup would hide a double dial, so check the dial attempts.
    let (da, db) = (dials_from(&a.zid()), dials_from(&b.zid()));
    assert!((da == 0) != (db == 0), "exactly one side must dial: a={da} b={db}");
    let iroh_links = a
        .info()
        .links()
        .await
        .filter(|l| *l.zid() == b.zid() && l.dst().protocol().as_str() == "iroh")
        .count();
    assert_eq!(iroh_links, 1);
    assert_pubsub(&a, &b).await;
    a.close().await.unwrap();
    b.close().await.unwrap();
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn other_zones_are_never_connected() {
    init_tracing();
    let (server, url) = lighthouse().await;
    let a = zenoh::open(zone_config("z1", &url, WhatAmI::Peer, None)).await.unwrap();
    let b = zenoh::open(zone_config("z1", &url, WhatAmI::Peer, None)).await.unwrap();
    let c = zenoh::open(zone_config("z2", &url, WhatAmI::Peer, None)).await.unwrap();
    wait_until("a sees b", async || connected(&a, &b).await).await;
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert!(!connected(&a, &c).await);
    assert!(c.info().peers_zid().await.next().is_none());
    for s in [a, b, c] {
        s.close().await.unwrap();
    }
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn client_in_a_zone_connects_to_a_peer() {
    init_tracing();
    let (server, url) = lighthouse().await;
    let p = zenoh::open(zone_config("z1", &url, WhatAmI::Peer, None)).await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await; // let the peer announce
    let mut cc = zone_config("z1", &url, WhatAmI::Client, None);
    cc.insert_json5("scouting/timeout", "15000").unwrap();
    let c = zenoh::open(cc).await.unwrap();
    wait_until("p sees c", async || connected(&p, &c).await).await;
    assert_pubsub(&c, &p).await;
    c.close().await.unwrap();
    p.close().await.unwrap();
    server.shutdown().await.unwrap();
}

/// Review Focus 2: multicast scouting left at its default (on). Needs a multicast-capable
/// interface, like the other zenoh scouting tests.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn zone_client_with_default_scouting_opens_and_connects() {
    init_tracing();
    let (server, url) = lighthouse().await;
    let p = zenoh::open(zone_config("zs", &url, WhatAmI::Peer, None)).await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    let mut cc = zone_config("zs", &url, WhatAmI::Client, None);
    cc.insert_json5("scouting/multicast/enabled", "true").unwrap();
    let c = zenoh::open(cc).await.expect("a zone client must not fail on the multicast scouting timeout");
    wait_until("p sees c", async || connected(&p, &c).await).await;
    c.close().await.unwrap();
    p.close().await.unwrap();
    server.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peer_restart_is_redialled() {
    init_tracing();
    let (server, url) = lighthouse().await;
    // Restart each side once, so the restarted node is the acceptor in one round and the dialler in
    // the other. Which side dials depends on the endpoint ids, not on the zids, hence two rounds.
    for restart_a in [false, true] {
        let a = zenoh::open(zone_config("zr", &url, WhatAmI::Peer, Some("a1"))).await.unwrap();
        let b = zenoh::open(zone_config("zr", &url, WhatAmI::Peer, Some("b1"))).await.unwrap();
        wait_until("a and b are connected", async || connected(&a, &b).await).await;
        let (stay, gone) = if restart_a { (b, a) } else { (a, b) };
        let gone_zid = gone.zid();
        gone.close().await.unwrap();
        // Without this wait, the check below could pass on the dying transport.
        wait_until("the closed node is gone", async || !stay.info().peers_zid().await.any(|z| z == gone_zid)).await;
        let id = if restart_a { "a1" } else { "b1" };
        let back = zenoh::open(zone_config("zr", &url, WhatAmI::Peer, Some(id))).await.unwrap();
        wait_until("the restarted node is reconnected", async || connected(&stay, &back).await).await;
        assert_pubsub(&stay, &back).await;
        stay.close().await.unwrap();
        back.close().await.unwrap();
    }
    server.shutdown().await.unwrap();
}

/// Review Focus 1 (close half): a lighthouse that accepts TCP but never answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn close_is_prompt_with_a_silent_lighthouse() {
    init_tracing();
    let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", silent.local_addr().unwrap());
    let _hold = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((sock, _)) = silent.accept().await {
            held.push(sock); // accept and never reply
        }
    });
    let start = Instant::now();
    let s = zenoh::open(zone_config("z", &url, WhatAmI::Peer, None)).await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await; // the join is now in flight
    tokio::time::timeout(Duration::from_secs(10), s.close()).await.expect("close hung").unwrap();
    assert!(start.elapsed() < Duration::from_secs(15));
}
```

The `wait_until` closures use async closures (`async ||`), which are stable since Rust 1.85; the pinned toolchain is 1.97.1. If `ZenohId` is not at `zenoh::session::ZenohId`, use the path that `Session::zid()` returns. If the `Limits` and `SizeLimits` paths differ, copy them from `iroh-lighthouse-0.1.0/tests/common/mod.rs`, which constructs exactly this config. Check the subscriber/payload API names against `zenoh/tests/session.rs`.

- [ ] **Step 3: Run them and confirm they fail**

Run: `cargo test -p zenoh --features transport_iroh_test,unstable --lib zone::tests && cargo test -p zenoh --features transport_iroh_test,unstable --test zone`
Expected: the unit test fails to compile (no `should_dial`); the discovery tests time out waiting for connections.

- [ ] **Step 4: Implement `zone.rs`:**

```rust
//! Zone discovery: find the other members of this node's zone through an
//! iroh-lighthouse topic and connect to them over iroh.
use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio_util::sync::CancellationToken;
use zenoh_config::zone::Zone;
use zenoh_link::iroh::{
    iroh::{EndpointId, Watcher},
    iroh_lighthouse_client::{parse_url, protocol::Peer, Lighthouse, Topic},
    locator_of, IrohEndpoint,
};
use zenoh_protocol::core::WhatAmI;

use super::Runtime;

const ZONE_TTL: Duration = Duration::from_secs(120);
const ZONE_POLL_INTERVAL: Duration = Duration::from_secs(10);
const ZONE_RECONCILE_INTERVAL: Duration = Duration::from_secs(5);
const ADDR_WAIT: Duration = Duration::from_secs(5);
const LEAVE_TIMEOUT: Duration = Duration::from_secs(2);
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// Between two announcing members only the lower endpoint id dials.
pub(crate) fn should_dial(own: &EndpointId, remote: &EndpointId) -> bool {
    own.as_bytes() < remote.as_bytes()
}

pub(crate) fn start(runtime: &Runtime) {
    let Some(zone) = runtime.config().lock().zone().as_ref().map(|z| z.resolve()) else {
        return;
    };
    let Some(iroh) = runtime.iroh().cloned() else {
        return;
    };
    let url = match parse_url(&zone.lighthouse) {
        Ok(url) => url,
        Err(e) => {
            tracing::warn!("Invalid zone.lighthouse {}: {e}", zone.lighthouse);
            return;
        }
    };
    let discovery = Discovery {
        runtime: runtime.clone(),
        iroh,
        lighthouse: Lighthouse::http(url),
        topic: Topic::with_secret(zone.topic.clone(), zone.id.as_bytes()),
        zone,
        pending: Arc::new(Mutex::new(HashSet::new())),
    };
    let token = runtime.get_cancellation_token();
    runtime.spawn(async move {
        if discovery.runtime.whatami() == WhatAmI::Client {
            discovery.run_client(token).await
        } else {
            discovery.run_member(token).await
        }
    });
}

#[derive(Clone)]
struct Discovery {
    runtime: Runtime,
    iroh: IrohEndpoint,
    lighthouse: Lighthouse,
    topic: Topic,
    zone: Zone,
    pending: Arc<Mutex<HashSet<EndpointId>>>,
}

impl Discovery {
    async fn run_member(&self, token: CancellationToken) {
        tokio::select! {
            _ = token.cancelled() => return,
            _ = self.wait_for_direct_addr() => {}
        }
        let mut backoff = INITIAL_BACKOFF;
        let session = loop {
            let attempt = tokio::select! {
                _ = token.cancelled() => return,
                r = self.lighthouse.join(self.iroh.endpoint(), self.topic.clone(), ZONE_TTL) => r,
            };
            match attempt {
                Ok(session) => break session,
                Err(e) => tracing::warn!("Cannot join zone {} on {}: {e}", self.zone.topic, self.zone.lighthouse),
            }
            tokio::select! {
                _ = token.cancelled() => return,
                _ = tokio::time::sleep(backoff) => {}
            }
            backoff = (backoff * 2).min(MAX_BACKOFF);
        };
        tracing::info!("Joined zone {} ({}) on {}", self.zone.topic, self.topic.id(), self.zone.lighthouse);
        let mut peers = session.watch_peers();
        let mut tick = tokio::time::interval_at(
            tokio::time::Instant::now() + ZONE_RECONCILE_INTERVAL,
            ZONE_RECONCILE_INTERVAL,
        );
        self.reconcile(&session.peers()).await;
        loop {
            tokio::select! {
                _ = token.cancelled() => {
                    match tokio::time::timeout(LEAVE_TIMEOUT, session.leave()).await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => tracing::debug!("Leaving zone {} failed: {e}", self.zone.topic),
                        Err(_) => tracing::debug!("Leaving zone {} timed out", self.zone.topic),
                    }
                    return;
                }
                changed = peers.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    let latest = peers.borrow_and_update().clone();
                    self.reconcile(&latest).await;
                }
                _ = tick.tick() => self.reconcile(&session.peers()).await,
            }
        }
    }

    async fn run_client(&self, token: CancellationToken) {
        loop {
            tokio::select! {
                _ = token.cancelled() => return,
                _ = self.client_round() => {}
            }
            tokio::select! {
                _ = token.cancelled() => return,
                _ = tokio::time::sleep(ZONE_POLL_INTERVAL) => {}
            }
        }
    }

    /// A client keeps one connection: dial members one at a time until one answers.
    async fn client_round(&self) {
        let manager = self.runtime.manager();
        if !manager.get_transports_unicast().await.is_empty() {
            return;
        }
        let peers = match self.lighthouse.lookup(&self.topic).await {
            Ok(peers) => peers,
            Err(e) => {
                tracing::warn!("Cannot look up zone {} on {}: {e}", self.zone.topic, self.zone.lighthouse);
                return;
            }
        };
        for peer in peers {
            let id = peer.addr.id;
            self.iroh.set_addr(peer.addr);
            tracing::debug!("zone dial from {} to {id}", self.runtime.zid());
            match manager.open_transport_unicast(locator_of(&id).into()).await {
                Ok(_) => {
                    tracing::debug!("Connected to zone peer {id}");
                    return;
                }
                Err(e) => tracing::debug!("Cannot connect to zone peer {id}: {e}"),
            }
        }
    }

    async fn wait_for_direct_addr(&self) {
        let mut watcher = self.iroh.endpoint().watch_addr();
        let _ = tokio::time::timeout(ADDR_WAIT, async {
            while watcher.get().ip_addrs().next().is_none() {
                if watcher.updated().await.is_err() {
                    return;
                }
            }
        })
        .await;
    }

    async fn reconcile(&self, peers: &[Peer]) {
        let own = self.iroh.id();
        let manager = self.runtime.manager();
        let mut connected = HashSet::new();
        for t in manager.get_transports_unicast().await {
            if let Ok(links) = t.get_links() {
                connected.extend(links.into_iter().map(|l| l.dst));
            }
        }
        for peer in peers {
            let id = peer.addr.id;
            if !should_dial(&own, &id) || connected.contains(&locator_of(&id)) {
                continue;
            }
            if !self.pending.lock().unwrap().insert(id) {
                continue;
            }
            self.iroh.set_addr(peer.addr.clone());
            tracing::debug!("zone dial from {} to {id}", self.runtime.zid());
            let this = self.clone();
            // Abortable: a dial in flight must not hold up runtime close.
            self.runtime.spawn_abortable(async move {
                match this.runtime.manager().open_transport_unicast(locator_of(&id).into()).await {
                    Ok(_) => tracing::debug!("Connected to zone peer {id}"),
                    Err(e) => tracing::debug!("Cannot connect to zone peer {id}: {e}"),
                }
                this.pending.lock().unwrap().remove(&id);
            });
        }
    }
}
```

If a dial is aborted on close, its id stays in `pending`. That is harmless, because the whole `Discovery` goes away with the runtime.

`orchestrator.rs`:
- Add the helper:

```rust
    /// Resolves once this runtime has at least one unicast transport.
    #[cfg(feature = "transport_iroh")]
    async fn wait_for_unicast_transport(&self) {
        while self.manager().get_transports_unicast().await.is_empty() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
```

- In `start_peer` and `start_router`, after `self.bind_listeners(&listeners).await?;`:

```rust
        #[cfg(feature = "transport_iroh")]
        super::zone::start(self);
```

- In `start_client`, after `self.bind_listeners(&listeners).await?;`:

```rust
        #[cfg(feature = "transport_iroh")]
        let zone_set = self.config().lock().zone().is_some();
        #[cfg(not(feature = "transport_iroh"))]
        let zone_set = false;
        #[cfg(feature = "transport_iroh")]
        if zone_set {
            super::zone::start(self);
        }
```

- Inside the scouting branch, replace `if peers.is_empty() { self.connect_first(&sockets, autoconnect, &addr, timeout).await? }` with:

```rust
                        if peers.is_empty() {
                            let scouted = self.connect_first(&sockets, autoconnect, &addr, timeout);
                            #[cfg(feature = "transport_iroh")]
                            if zone_set {
                                // Either multicast or the zone may find someone first. A scouting
                                // timeout is not fatal while the zone keeps looking.
                                tokio::select! {
                                    _ = scouted => {}
                                    _ = self.wait_for_unicast_transport() => {}
                                }
                            } else {
                                scouted.await?
                            }
                            #[cfg(not(feature = "transport_iroh"))]
                            scouted.await?
                        }
```

- Replace the trailing `} else if peers.is_empty() { bail!("No peer specified and multicast scouting deactivated!") } else { ... }` with:

```rust
        } else if peers.is_empty() && !zone_set {
            bail!("No peer specified and multicast scouting deactivated!")
        } else if peers.is_empty() {
            #[cfg(feature = "transport_iroh")]
            if tokio::time::timeout(timeout, self.wait_for_unicast_transport()).await.is_err() {
                tracing::warn!("No zone peer connected within the scouting timeout");
            }
            Ok(())
        } else {
            self.connect_peers(&peers, true).await
        }
```

The `if`/`else` under `#[cfg]` and the `scouted` binding need to type-check in both feature states. If the cfg-on-statement form gets awkward, factor the scouting call into `async fn scout_first(&self, zone_set: bool, ...) -> ZResult<()>` with the cfg inside. With no zone, `start_client` must behave exactly as before.

- [ ] **Step 5: Run the tests**

Run: `cargo test -p zenoh --features transport_iroh_test,unstable --lib zone::tests && cargo test -p zenoh --features transport_iroh_test,unstable --test zone`
Expected: all pass, including the Task 5 tests.

- [ ] **Step 6: Lint and commit**

Run: `cargo clippy -p zenoh --all-targets --features transport_iroh_test,unstable -- -D warnings && cargo clippy -p zenoh --all-targets -- -D warnings`

```bash
jj describe -m "Discover zone peers through iroh-lighthouse and dial them over iroh"
jj new
```

---

### Task 7: Whole-workspace verification

**Files:**
- Modify: `deny.toml` only if `cargo deny` reports new licenses or bans.

- [ ] **Step 1: Format and lint everything in both feature states**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p zenoh --all-targets --features transport_iroh_test,unstable -- -D warnings
```
Expected: clean.

- [ ] **Step 2: Run the affected test suites**

```bash
cargo test -p zenoh-config -p zenoh-link-iroh -p zenoh-link -p zenoh-transport
cargo test -p zenoh --features transport_iroh_test,unstable --test zone
cargo test -p zenoh --lib
cargo check --manifest-path ci/zenoh-1-75/Cargo.toml   # MSRV job still resolves with the new lockfile entries
```
Expected: all pass. The default-feature zenoh lib tests prove nothing regressed without the feature.

- [ ] **Step 3: Dependency policy**

Run: `cargo deny check` (if `cargo-deny` is installed; CI runs it).
Expected: pass without edits (the iroh tree's licences are already allowed), possibly with multiple-version warnings. For a new license, add it to `deny.toml`'s `allow` list only if it is permissive (MIT/Apache/BSD/ISC/Zlib/Unicode/CC0/MPL-2.0). For anything else, stop and ask the user. Also confirm `cargo tree -p zenoh -e normal` without features shows no `iroh`.

- [ ] **Step 4: Commit (only if Steps 1–3 required edits)**

```bash
jj describe -m "Allow the iroh dependency tree in cargo-deny"
jj new
```
