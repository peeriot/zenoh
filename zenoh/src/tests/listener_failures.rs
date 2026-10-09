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
#![cfg(all(feature = "internal", feature = "transport_tcp"))]

use crate::{open, Config};

/// TEST-NET-1 (RFC 5737): no host owns it, so a listener on it fails anywhere.
const UNBINDABLE: &str = "tcp/192.0.2.1:0";
const LOOPBACK: &str = "tcp/127.0.0.1:0";

/// A peer kept off the network, listening on `endpoints`.
fn config(endpoints: &[&str], exit_on_failure: bool) -> Config {
    let mut config = Config::default();
    config
        .insert_json5(
            "listen/endpoints",
            &serde_json::to_string(endpoints).unwrap(),
        )
        .unwrap();
    config
        .insert_json5("listen/exit_on_failure", &exit_on_failure.to_string())
        .unwrap();
    config
        .insert_json5("scouting/multicast/enabled", "false")
        .unwrap();
    config
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_skipped_listener_is_reported_with_its_reason() {
    let session = open(config(&[UNBINDABLE, LOOPBACK], false)).await.unwrap();
    let runtime = session.static_runtime().unwrap();

    let failures = runtime.listener_failures();
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert_eq!(failures[0].0.to_string(), UNBINDABLE);
    assert!(!failures[0].1.is_empty());

    let listeners = runtime.get_listeners().await;
    assert_eq!(listeners.len(), 1, "{listeners:?}");
    assert!(listeners[0].to_string().starts_with("tcp/127.0.0.1:"));

    session.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_runtime_whose_every_listener_failed_lists_none() {
    let session = open(config(&[UNBINDABLE], false)).await.unwrap();
    let runtime = session.static_runtime().unwrap();

    assert_eq!(runtime.listener_failures().len(), 1);
    assert!(runtime.get_listeners().await.is_empty());

    session.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_listener_that_exits_on_failure_still_fails_the_start() {
    assert!(open(config(&[UNBINDABLE, LOOPBACK], true)).await.is_err());
}
