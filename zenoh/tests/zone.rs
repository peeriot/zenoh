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
use std::time::{Duration, Instant};

use zenoh::{config::WhatAmI, Config};

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
    let mut c = zone_config("z", "http://127.0.0.1:1", WhatAmI::Peer, None);
    c.insert_json5("listen/endpoints", r#"["iroh/auto"]"#)
        .unwrap();
    let s = zenoh::open(c).await.unwrap();
    s.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_secret_key_is_rejected() {
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
