# Zone discovery over iroh and iroh-lighthouse

## Goal

Let zenoh nodes that share a *zone* find each other through an
[iroh-lighthouse](https://github.com/peeriot/iroh-lighthouse) topic and talk
over the iroh network (QUIC with hole-punching and relay fallback), without
knowing each other's IP addresses.

A node opts in by setting `zone` in its config. Nodes in the same zone
discover and dial each other. Discovery is the zone topic alone: reading it
requires the topic key, which is derived from the zone id. Nothing is published
to n0's DNS or to the lighthouse's zone-less directory, so nodes in other zones
cannot discover a node's addresses through this feature.

A zone is a **discovery** boundary, not an access-control boundary. A node that
learns another node's endpoint id and a route to it (for example from a
gossiped `iroh/<id>` locator) can still connect, as with any zenoh listener.

## Non-goals

- Mode-aware autoconnect for lighthouse-discovered peers. The lighthouse does
  not carry a node's `whatami`, so `scouting.*.autoconnect` matchers do not
  apply here.
- Multicast transports over iroh.
- Any change to the existing `region_name` / `gateway` region machinery.
  `region_name` is a routing label exchanged in the INIT handshake
  (`ext_region_name`) and matched by `gateway.south[].filters[].region_names`;
  it is unrelated to discovery, which is why this feature is called *zone*.
- Making `open` wait for zone peers. `open.return_conditions.connect_scouted`
  and `scouting.delay` do not account for them, so publications made right
  after `open` on a peer may be lost.
- ACL `cert_common_names` matching on iroh endpoint ids (follow-up).

## 1. Configuration

New top-level `zone` key in `zenoh-config`, accepted in two forms:

```json5
zone: "blah",          // shorthand for { id: "blah" }
```

```json5
zone: {
  id: "blah",                    // required; the lighthouse topic secret
  topic: "myrmic/zone",          // optional; lighthouse topic name
  lighthouse: "iroh.ichor.io",   // optional; lighthouse address
  secret_key: null,              // optional; iroh ed25519 secret key
  relays: true,                  // optional; n0 relays + n0 DNS resolution
},
```

- Type: `Option<ZoneConf>` where

  ```rust
  #[derive(Debug, Clone, Serialize, Deserialize)]
  #[serde(untagged)]
  pub enum ZoneConf {
      Id(ZoneId),
      Full(ZoneFullConf),
  }

  /// Non-empty; deserialization rejects "".
  #[serde(try_from = "String", into = "String")]
  pub struct ZoneId(String);

  #[derive(Debug, Clone, Serialize, Deserialize)]
  #[serde(deny_unknown_fields)]
  pub struct ZoneFullConf {
      pub id: ZoneId,
      pub topic: Option<String>,
      pub lighthouse: Option<String>,
      pub secret_key: Option<SecretValue>,
      pub relays: Option<bool>,
  }
  ```

  This mirrors `gateway.south` (`GatewaySouthConf`). Consequence, same as for
  `gateway`: runtime path inserts such as `zone/id` are not supported; only
  the whole `zone` value can be replaced.
- `ZoneConf::resolve(&self) -> Zone` normalises both forms into
  `Zone { id, topic, lighthouse, secret_key, relays }`, applying the defaults
  `topic = "myrmic/zone"`, `lighthouse = "iroh.ichor.io"` and `relays = true`.
- `lighthouse` is parsed with `iroh_lighthouse_client::parse_url` (bare host →
  `https://`, localhost/IP → `http://`). An unparsable value is an error at
  runtime start.
- `secret_key` is the iroh secret key in its string encoding (hex or base32),
  held as a `SecretValue`. That redacts it in `Debug` output only. Like the
  existing TLS `*_base64` secrets, it is visible through serde (config JSON,
  admin space).
- `relays: false` disables n0's relays and DNS entirely (direct addresses
  only), for LAN-only or isolated deployments and for tests.
- `DEFAULT_CONFIG.json5` gets a commented-out, documented `zone` example, and
  `"iroh"` is added to its `link_protocols` example lists.

## 2. iroh link: `zenoh-link-iroh`

New crate `io/zenoh-links/zenoh-link-iroh`, enabled by a new
`transport_iroh` feature on `zenoh-link`, `zenoh-transport` and `zenoh`.
**Not** in the default feature set (it pulls in iroh and reqwest).

### Locator and link semantics

- Protocol prefix `iroh`; locator address is the endpoint id:
  `iroh/<endpoint-id>`. A listen endpoint is `iroh/auto` (zenoh endpoints
  cannot have an empty address) or `iroh/<own-endpoint-id>`; any other
  address on a listen endpoint is an error. Either way the listener's
  locator is `iroh/<own-endpoint-id>`.
- ALPN: `myrmic/1`.
- One zenoh link = one iroh `Connection` with one bidirectional stream: the
  dialler calls `open_bi`, the acceptor `accept_bi`.
- Streamed, reliable, unicast only. MTU equals the QUIC link's (`BatchSize::MAX`).
- One stream carries every priority: `supports_priorities()` stays `false` and the
  `priority` argument of the read/write calls is ignored. A stream per priority, as
  the QUIC link now does, is a possible follow-up, not part of this work.
- `get_locators_noloopback` returns the same as `get_locators`, because an iroh
  locator holds no IP address. Under the `uring` feature `get_fd` returns
  "Not supported", like the other non-socket links.
- `get_src`/`get_dst` are `iroh/<local-id>` and `iroh/<remote-id>`.
- `get_auth_id` is the new `LinkAuthId::Iroh(remote endpoint id)`, which the
  connection authenticates. It is exposed as the link's `auth_identifier`.
  `InterceptorLink::Iroh` (`"iroh"`) lets interceptors filter on the protocol.
- `get_interface_names` returns an empty list.
- Structure follows `zenoh-link-quic`: `lib.rs` (inspector, constants),
  `endpoint.rs` (the per-runtime endpoint), `unicast.rs` (link, listener,
  manager). The accept loop runs on `ZRuntime::Acceptor`.
- `iroh/<id>` locators are advertised in hellos and gossip like any other
  listener. Nodes built without the feature skip them at trace level. Nodes
  with the feature but no endpoint fail that dial at debug level.

### Endpoint ownership

The iroh `Endpoint` is owned by the **runtime**, one per runtime, never a
process-wide global, so several sessions in one process (as the test suite
uses) stay isolated.

- The runtime builds the endpoint at start when the feature is enabled and
  either `zone` is set or any `listen`/`connect` endpoint has protocol
  `iroh`.
- Builder: `presets::Minimal`, the resolved secret key, ALPN `myrmic/1`, and
  an `iroh::address_lookup::MemoryLookup` kept with the endpoint.
  - `relays: true` adds n0's default relay map and n0 DNS **resolvers**
    (`PkarrResolver`, `DnsAddressLookup`). It is `presets::N0` without the
    `PkarrPublisher`.
  - `relays: false` sets `RelayMode::Disabled` and adds no DNS lookup.
  - No publisher and no `LighthouseLookup`: this endpoint's addresses are only
    ever announced on the zone topic.
- Plumbing: a feature-gated `iroh_endpoint: Option<IrohEndpoint>` on
  `TransportManagerConfig` / `TransportManagerBuilder`, passed into
  `LinkManagerBuilderUnicast::make`, which hands it to
  `LinkManagerUnicastIroh::new`. Creating the iroh link manager without an
  endpoint is an error ("iroh endpoint not configured").
- The link manager runs one accept loop over the endpoint while an `iroh`
  listener exists, and pushes accepted links into the new-link channel like
  the other link managers.
- On runtime close, the endpoint is closed after the transport manager has
  shut down.

### Secret key

1. If `zone.secret_key` is set, parse and use it. Invalid → error at start
   naming `zone.secret_key`.
2. Otherwise derive it from the zenoh id:
   `SecretKey::from_bytes(&blake3::derive_key("zenoh-link-iroh/v1/secret-key", &zid.to_le_bytes()))`,
   using the zero-padded 16-byte form. A stable zid gives a stable endpoint id.

**Security note:** the derived key is only as secret as the zenoh id, and zids
are sent in clear in hellos and handshakes. Anyone who learns a node's zid can
derive its iroh key and impersonate it on iroh and on the lighthouse topic, if
they also know the zone id. The default protects against accidental
collisions, not against an attacker. Deployments that need real
authentication set `zone.secret_key`.

## 3. Zone discovery

New module `zenoh/src/net/runtime/zone.rs`, started from the orchestrator
right after the listeners are bound (before scouting, for clients). Runs as a
task on the runtime's task controller, so it is cancelled on close.

### Topic

`Topic::with_secret(zone.topic, zone.id.as_bytes())` against
`Lighthouse::http(zone.lighthouse)`.

### Per mode

- **Peer and router ("members"):** implicitly listen on `iroh/auto` (added to the
  listener set when no `iroh` listener is configured, not to the user's
  config). Join the topic with `Lighthouse::join(&endpoint, topic, ZONE_TTL)`,
  `ZONE_TTL = 120s` (internal). The session re-announces itself, at half the
  granted TTL and on address changes, and publishes peer changes through
  `watch_peers()`.
- **Client:** no iroh listener and no announce, since clients do not accept
  connections. A zenoh client holds one connection. Every 10s, if it has no
  unicast transport, it looks the topic up and dials the members one at a
  time until one succeeds.
  - **Client startup:** the zone races multicast scouting. With multicast on
    and no connect endpoints, `open` returns when either finds someone, and
    the multicast scouting timeout is not an error. With multicast off and no
    connect endpoints, `open` waits up to `scouting.timeout` for a zone
    connection, then succeeds with a warning instead of bailing.

### Dialling (members)

On every peer-list change, and on a 5s reconcile tick, for each listed peer `p`:

1. **Tie-break:** dial only if `own_id < p.addr.id` (byte order). The other
   side dials us.
2. **Already connected?** Skip if any unicast transport has a link whose
   `dst` is `iroh/<p.addr.id>`.
3. **Already dialling?** Skip if a dial to this id is in flight
   (a `HashSet<EndpointId>` of pending dials).
4. Otherwise **set** the peer's full `EndpointAddr` from the topic in the
   `MemoryLookup` (`set_endpoint_info`; the topic is authoritative, so stale
   ports are replaced rather than accumulated), then spawn an abortable dial:
   `manager.open_transport_unicast("iroh/<id>")`.

A failed or dropped connection is retried by the next tick, while the peer is
still listed.

### Failure handling

- Lighthouse unreachable or refusing: log at `warn`. The client crate's
  session backs off and retries internally. For the initial `join`, the zone
  task retries with exponential backoff (1s → 60s) instead of failing.
  **Zenoh start never fails** because of the lighthouse.
- **Close never hangs on the lighthouse.** Runtime close awaits its tasks with
  no timeout, and the lighthouse client's HTTP requests have none either. So
  `join` and `lookup` always run inside `select!` with the cancellation token,
  in-flight dials are abortable, and `session.leave()` on close is bounded by
  a 2s timeout (best effort, errors logged at `debug`).

## 4. Dependencies

- `iroh = "1.3"` (`default-features = false`, `metrics` + `tls-ring`),
  `iroh-lighthouse-client = "0.1"`, `blake3`. All optional, behind
  `transport_iroh`.
- TLS: iroh uses ring (`presets::Minimal` prefers ring when both providers are
  on), like the rest of zenoh. The lighthouse crates hard-enable iroh's
  `tls-aws-lc-rs`, and reqwest's `rustls` feature pulls aws-lc-rs too, so
  aws-lc-rs is compiled when the feature is on. This needs a C toolchain, and
  cmake/nasm on some cross targets. Accepted; nothing installs a conflicting
  process-wide provider.
- `iroh-lighthouse = "0.1"` (in-process server) is an **optional normal**
  dependency of `zenoh`, enabled only by the test-only feature
  `transport_iroh_test = ["transport_iroh", "dep:iroh-lighthouse"]`. A
  dev-dependency cannot be optional and would put iroh, aws-lc-rs and axum
  into every `cargo test -p zenoh`.
- The lighthouse crates need Rust ≥ 1.91; the pinned toolchain is 1.97.1.
  `zenoh-link-iroh` declares `rust-version = "1.91"`. The workspace
  `rust-version` (1.75) and the `ci/zenoh-1-75` job are unaffected because the
  feature is off by default.
- `deny.toml`: the iroh tree's licences are already allowed. Only
  multiple-version warnings are expected.

## 5. Testing

Unit (no network):

- `zone: "x"` and `zone: { id: "x" }` parse to the same `Zone` with defaults.
- Full form with every field set; unknown fields are rejected; an empty `id`
  is rejected in both forms; `secret_key` is redacted in `Debug`.
- Key derivation: the same zid gives the same key, different zids give
  different keys, an explicit `secret_key` overrides derivation, and a
  malformed one is an error naming `zone.secret_key`.
- Tie-break predicate; implicit `iroh/auto` listener added once.
- `iroh` locator inspector: reliable, not multicast.

Link level (`zenoh-link-iroh/tests`, offline):

- Two endpoints with `relays: false`: listen on `iroh/auto`, dial `iroh/<id>` with
  addresses seeded into the `MemoryLookup`, exchange bytes both ways; check
  locators and `LinkAuthId::Iroh`. Listen-address validation; garbage ids are
  rejected.

Session level (`zenoh/tests/zone.rs`, `transport_iroh_test` + `unstable`,
`relays: false`, in-process http-only lighthouse):

- `open` is prompt with a dead lighthouse; `close` is prompt with a lighthouse
  that accepts TCP but never answers.
- Explicit `iroh/auto` listener plus zone starts once; malformed `secret_key`
  fails `open`.
- Two peers in a zone connect, and exactly one side dials, counted from the
  dial log lines (a link count alone cannot show this because `max_links = 1`
  dedups); put/sub works.
- A node in another zone on the same lighthouse is never connected.
- A client in the zone connects to a peer, with multicast both off and at its
  default (on).
- A restarted peer with the same zid is reconnected, with the restarted node
  as dialler in one round and acceptor in the other.
