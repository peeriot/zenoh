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

//! Multicast scouting with tags: peers with the same tag link, peers with
//! another tag or none do not, peers without a tag link as before, and
//! `zenoh::scout` with a tag reports only peers carrying it.

use std::{collections::HashSet, time::Duration};

use zenoh::{config::WhatAmI, session::ZenohId, Config, Session};

/// A multicast group of its own, apart from the groups other tests use.
const GROUP: &str = "224.1.1.1:9400";
/// Loopback on a port the OS picks: the Hellos' locators resolve on this host
/// only.
const LISTEN: &str = "tcp/127.0.0.1:0";
const TAG_A: &str = "0123456789abcdef0123456789abcdef";
const TAG_B: &str = "01234567-89ab-cdef-fedc-ba9876543210";
/// How long peers get to find each other by multicast.
const LINK_WAIT: Duration = Duration::from_secs(10);
/// How often the test looks for a link.
const LINK_POLL: Duration = Duration::from_millis(100);
/// Longer than the scout interval once all peers are open: Scouts back off
/// 1 s, 2 s, 4 s. Within it every peer scouts again after all have opened, and
/// a link the tag should prevent would form.
const QUIET_WINDOW: Duration = Duration::from_secs(5);

/// A peer that finds others by multicast only: gossip is off.
fn peer(tag: Option<&str>) -> Config {
    let mut config = Config::default();
    for (key, value) in [
        ("mode", "\"peer\"".to_owned()),
        ("listen/endpoints", format!("[\"{LISTEN}\"]")),
        ("scouting/multicast/enabled", "true".to_owned()),
        ("scouting/multicast/address", format!("\"{GROUP}\"")),
        ("scouting/gossip/enabled", "false".to_owned()),
    ] {
        config.insert_json5(key, &value).unwrap();
    }
    if let Some(tag) = tag {
        config
            .insert_json5("scouting/multicast/tag", &format!("\"{tag}\""))
            .unwrap();
    }
    config
}

async fn peers(session: &Session) -> Vec<ZenohId> {
    session.info().peers_zid().await.collect()
}

/// Whether `session` links to `other` within `LINK_WAIT`.
async fn links(session: &Session, other: &Session) -> bool {
    let other = other.info().zid().await;
    let deadline = tokio::time::Instant::now() + LINK_WAIT;
    while tokio::time::Instant::now() < deadline {
        if peers(session).await.contains(&other) {
            return true;
        }
        tokio::time::sleep(LINK_POLL).await;
    }
    false
}

/// Whether every peer of `session` is `allowed`.
async fn links_only(session: &Session, allowed: &[ZenohId]) -> bool {
    peers(session).await.iter().all(|zid| allowed.contains(zid))
}

// Five sessions' scouting and responder tasks run side by side: more than one
// worker keeps them from waiting on each other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_peers_with_the_same_tag_link_by_multicast() {
    let a1 = zenoh::open(peer(Some(TAG_A))).await.unwrap();
    let a2 = zenoh::open(peer(Some(TAG_A))).await.unwrap();
    let b = zenoh::open(peer(Some(TAG_B))).await.unwrap();
    let untagged1 = zenoh::open(peer(None)).await.unwrap();
    let untagged2 = zenoh::open(peer(None)).await.unwrap();
    let [a1_zid, a2_zid, untagged1_zid, untagged2_zid] = [
        a1.info().zid().await,
        a2.info().zid().await,
        untagged1.info().zid().await,
        untagged2.info().zid().await,
    ];

    assert!(links(&a1, &a2).await, "two peers with tag A did not link");
    assert!(
        links(&untagged1, &untagged2).await,
        "two peers without a tag did not link"
    );

    // Over the quiet window: zenoh::scout with tag A collects the Hellos it
    // gets, and every peer scouts again.
    let scout = zenoh::scout(WhatAmI::Peer, peer(Some(TAG_A)))
        .await
        .unwrap();
    let deadline = tokio::time::Instant::now() + QUIET_WINDOW;
    let mut scouted = HashSet::new();
    while let Ok(Ok(hello)) = tokio::time::timeout_at(deadline, scout.recv_async()).await {
        scouted.insert(hello.zid());
    }
    tokio::time::sleep_until(deadline).await;

    assert!(
        links_only(&a1, &[a2_zid]).await && links_only(&a2, &[a1_zid]).await,
        "a peer with tag A linked outside tag A"
    );
    assert!(
        peers(&b).await.is_empty(),
        "the only peer with tag B linked"
    );
    assert!(
        links_only(&untagged1, &[untagged2_zid]).await
            && links_only(&untagged2, &[untagged1_zid]).await,
        "a peer without a tag linked to a tagged one"
    );
    assert!(
        !scouted.is_empty() && scouted.iter().all(|zid| [a1_zid, a2_zid].contains(zid)),
        "zenoh::scout with tag A reported {scouted:?}, expected only {a1_zid} and {a2_zid}"
    );

    for session in [a1, a2, b, untagged1, untagged2] {
        session.close().await.unwrap();
    }
}
