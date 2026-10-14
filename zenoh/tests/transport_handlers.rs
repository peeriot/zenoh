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

//! A runtime's transport event handlers: a handler's refusal of a multicast
//! transport refuses the transport.
#![cfg(feature = "internal")]

use std::sync::Arc;

use zenoh::{
    internal::runtime::{DynamicRuntime, RuntimeBuilder},
    Config,
};
use zenoh_result::{bail, ZResult};
use zenoh_transport::{
    multicast::TransportMulticast, unicast::TransportUnicast, DummyTransportPeerEventHandler,
    TransportEventHandler, TransportMulticastEventHandler, TransportPeer,
    TransportPeerEventHandler,
};

const REFUSAL: &str = "this handler takes no multicast transport";
/// A multicast group of its own, apart from the groups other tests use.
const MULTICAST_LISTENER: &str = "udp/224.1.1.2:9410";

/// Takes every unicast transport and refuses every multicast one.
struct RefuseMulticast;

impl TransportEventHandler for RefuseMulticast {
    fn new_unicast(
        &self,
        _peer: TransportPeer,
        _transport: TransportUnicast,
    ) -> ZResult<Arc<dyn TransportPeerEventHandler>> {
        Ok(Arc::new(DummyTransportPeerEventHandler))
    }

    fn new_multicast(
        &self,
        _transport: TransportMulticast,
    ) -> ZResult<Arc<dyn TransportMulticastEventHandler>> {
        bail!("{REFUSAL}")
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_handlers_refusal_refuses_a_multicast_transport() {
    zenoh_util::init_log_from_env_or("error");
    let mut config = Config::default();
    for (key, value) in [
        ("mode", "\"peer\"".to_owned()),
        ("listen/endpoints", format!("[\"{MULTICAST_LISTENER}\"]")),
        ("scouting/multicast/enabled", "false".to_owned()),
        ("scouting/gossip/enabled", "false".to_owned()),
    ] {
        config.insert_json5(key, &value).unwrap();
    }
    let mut runtime = RuntimeBuilder::new(config).build().await.unwrap();
    // Added before start opens the listeners.
    DynamicRuntime::from(runtime.clone()).new_handler(Arc::new(RefuseMulticast));

    // A listener's failure fails the start: listen/exit_on_failure is on by
    // default.
    let err = runtime
        .start()
        .await
        .expect_err("a refused multicast listener started");
    assert!(err.to_string().contains(REFUSAL), "{err}");
    runtime.close().await.unwrap();
}
