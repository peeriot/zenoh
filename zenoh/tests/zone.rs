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
#![cfg(all(feature = "transport_iroh_test", feature = "unstable"))]
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use iroh_lighthouse::{handler::Limits, registry::SizeLimits, Config as LhConfig, Server};
use zenoh::{config::WhatAmI, Config, Session};
use zenoh_core::lazy_static;

// `lazy_static` rather than `std::sync::LazyLock`: clippy checks against MSRV 1.75.
lazy_static! {
    static ref STORAGE: tracing_capture::SharedStorage = tracing_capture::SharedStorage::default();
}

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

/// Whether some member has joined the zone topic `topic`.
fn joined(topic: &str) -> bool {
    let needle = format!("Joined zone {topic} ");
    STORAGE
        .lock()
        .all_events()
        .any(|e| e.message().is_some_and(|m| m.contains(&needle)))
}

/// A config that only talks iroh: no multicast/gossip, no TCP listener, no relays.
pub fn zone_config(zone: &str, lighthouse: &str, mode: WhatAmI, id: Option<&str>) -> Config {
    let mut c = Config::default();
    c.set_mode(Some(mode)).unwrap();
    if let Some(id) = id {
        c.insert_json5("id", &format!(r#""{id}""#)).unwrap();
    }
    c.insert_json5("scouting/multicast/enabled", "false")
        .unwrap();
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
    init_tracing();
    let start = Instant::now();
    let s = zenoh::open(zone_config("z", "http://127.0.0.1:1", WhatAmI::Peer, None))
        .await
        .unwrap();
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "open blocked on the lighthouse"
    );
    let locators = s.info().locators().await;
    assert!(
        locators.iter().any(|l| l.protocol().as_str() == "iroh"),
        "{locators:?}"
    );
    s.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn explicit_iroh_listener_with_zone_is_not_duplicated() {
    init_tracing();
    let mut c = zone_config("z", "http://127.0.0.1:1", WhatAmI::Peer, None);
    c.insert_json5("listen/endpoints", r#"["iroh/auto"]"#)
        .unwrap();
    let s = zenoh::open(c).await.unwrap();
    s.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_secret_key_is_rejected() {
    init_tracing();
    let mut c = zone_config("z", "http://127.0.0.1:1", WhatAmI::Peer, None);
    c.insert_json5(
        "zone",
        r#"{ id: "z", lighthouse: "http://127.0.0.1:1", relays: false, secret_key: "nope" }"#,
    )
    .unwrap();
    let err = zenoh::open(c)
        .await
        .expect_err("open must fail")
        .to_string();
    assert!(err.contains("zone.secret_key"), "{err}");
}

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
            size: SizeLimits {
                max_peers_per_topic: 16,
                max_topics: 100,
            },
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

/// Whether `s` has a unicast transport to `other`. `peers_zid` would miss clients.
async fn connected(s: &Session, other: &Session) -> bool {
    let other = other.zid();
    s.info().transports().await.any(|t| *t.zid() == other)
}

async fn assert_pubsub(publisher: &Session, subscriber: &Session) {
    let sub = subscriber.declare_subscriber("zone/test").await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await; // declaration propagation
    publisher.put("zone/test", "hi").await.unwrap();
    let sample = tokio::time::timeout(Duration::from_secs(10), sub.recv_async())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sample.payload().try_to_string().unwrap(), "hi");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_peers_in_a_zone_connect_once() {
    init_tracing();
    let (server, url) = lighthouse().await;
    let a = zenoh::open(zone_config("z1", &url, WhatAmI::Peer, None))
        .await
        .unwrap();
    let b = zenoh::open(zone_config("z1", &url, WhatAmI::Peer, None))
        .await
        .unwrap();
    wait_until("a and b are connected", async || {
        connected(&a, &b).await && connected(&b, &a).await
    })
    .await;
    tokio::time::sleep(Duration::from_secs(6)).await; // past one reconcile tick
                                                      // max_links = 1 and per-zid dedup would hide a double dial, so check the dial attempts.
    let (da, db) = (dials_from(&a.zid()), dials_from(&b.zid()));
    assert!(
        (da == 0) != (db == 0),
        "exactly one side must dial: a={da} b={db}"
    );
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
    let a = zenoh::open(zone_config("z1", &url, WhatAmI::Peer, None))
        .await
        .unwrap();
    let b = zenoh::open(zone_config("z1", &url, WhatAmI::Peer, None))
        .await
        .unwrap();
    let c = zenoh::open(zone_config("z2", &url, WhatAmI::Peer, None))
        .await
        .unwrap();
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
    let p = zenoh::open(zone_config("z1", &url, WhatAmI::Peer, None))
        .await
        .unwrap();
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

/// A zone client that also has an explicit connect endpoint keeps a single transport: the zone
/// starts after the explicit connect, and its round idles because a transport exists.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn zone_client_with_explicit_connect_keeps_one_transport() {
    init_tracing();
    let (server, url) = lighthouse().await;
    // A topic of its own, so the "Joined zone" event below is this member's.
    let zone = format!(
        r#"{{ id: "zx", topic: "zone/explicit-connect", lighthouse: "{url}", relays: false }}"#
    );
    let mut mc = zone_config("zx", &url, WhatAmI::Peer, None);
    mc.insert_json5("zone", &zone).unwrap();
    let member = zenoh::open(mc).await.unwrap();
    let mut tc = Config::default();
    tc.set_mode(Some(WhatAmI::Peer)).unwrap();
    tc.insert_json5("scouting/multicast/enabled", "false")
        .unwrap();
    tc.insert_json5("scouting/gossip/enabled", "false").unwrap();
    tc.insert_json5("listen/endpoints", r#"["tcp/127.0.0.1:0"]"#)
        .unwrap();
    let tcp_peer = zenoh::open(tc).await.unwrap();
    let tcp_locator = tcp_peer
        .info()
        .locators()
        .await
        .into_iter()
        .find(|l| l.protocol().as_str() == "tcp")
        .unwrap();
    wait_until("the member has joined", async || {
        joined("zone/explicit-connect")
    })
    .await;
    let mut cc = zone_config("zx", &url, WhatAmI::Client, None);
    cc.insert_json5("zone", &zone).unwrap();
    cc.insert_json5("connect/endpoints", &format!(r#"["{tcp_locator}"]"#))
        .unwrap();
    let c = zenoh::open(cc).await.unwrap();
    assert!(connected(&c, &tcp_peer).await);
    // The zone's first round runs right after open; give it time to look up and dial.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let zids: Vec<_> = c.info().transports().await.map(|t| *t.zid()).collect();
    assert_eq!(zids, vec![tcp_peer.zid()], "a client keeps one transport");
    // The runtime also rejects a second north-bound client transport, which would hide a racing
    // zone dial above; so check the zone did not dial at all.
    assert_eq!(dials_from(&c.zid()), 0, "the zone round must idle");
    c.close().await.unwrap();
    tcp_peer.close().await.unwrap();
    member.close().await.unwrap();
    server.shutdown().await.unwrap();
}

/// Review Focus 2: multicast scouting left at its default (on). Needs a multicast-capable
/// interface, like the other zenoh scouting tests.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn zone_client_with_default_scouting_opens_and_connects() {
    init_tracing();
    let (server, url) = lighthouse().await;
    let p = zenoh::open(zone_config("zs", &url, WhatAmI::Peer, None))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    let mut cc = zone_config("zs", &url, WhatAmI::Client, None);
    cc.insert_json5("scouting/multicast/enabled", "true")
        .unwrap();
    let c = zenoh::open(cc)
        .await
        .expect("a zone client must not fail on the multicast scouting timeout");
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
        let a = zenoh::open(zone_config("zr", &url, WhatAmI::Peer, Some("a1")))
            .await
            .unwrap();
        let b = zenoh::open(zone_config("zr", &url, WhatAmI::Peer, Some("b1")))
            .await
            .unwrap();
        wait_until("a and b are connected", async || connected(&a, &b).await).await;
        let (stay, gone) = if restart_a { (b, a) } else { (a, b) };
        let gone_zid = gone.zid();
        gone.close().await.unwrap();
        // Without this wait, the check below could pass on the dying transport.
        wait_until("the closed node is gone", async || {
            !stay.info().peers_zid().await.any(|z| z == gone_zid)
        })
        .await;
        let id = if restart_a { "a1" } else { "b1" };
        let back = zenoh::open(zone_config("zr", &url, WhatAmI::Peer, Some(id)))
            .await
            .unwrap();
        wait_until("the restarted node is reconnected", async || {
            connected(&stay, &back).await
        })
        .await;
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
    let s = zenoh::open(zone_config("z", &url, WhatAmI::Peer, None))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await; // the join is now in flight
    tokio::time::timeout(Duration::from_secs(10), s.close())
        .await
        .expect("close hung")
        .unwrap();
    assert!(start.elapsed() < Duration::from_secs(15));
}
