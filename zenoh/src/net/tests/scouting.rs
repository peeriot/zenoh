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
#[cfg(feature = "test")]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use zenoh_buffers::writer::HasWriter;
    use zenoh_codec::{WCodec, Zenoh080};
    use zenoh_protocol::{
        core::whatami::WhatAmIMatcher,
        scouting::{Scout, ScoutingMessage},
    };

    use crate::{
        api::config::Config,
        net::{
            common::AutoConnect,
            runtime::{orchestrator::ScoutStart, Runtime, RuntimeBuilder},
        },
    };

    /// A documentation address, so no host on any network answers for it.
    const UNUSABLE: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    const MULTICAST_TTL: u32 = 1;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn spawning_without_unicast_sockets_starts_no_responder() {
        let runtime = create_runtime().await;
        let addr = scout_address();
        let (mcast_socket, ucast_sockets) = Runtime::bind_scout_sockets(&addr, &[], MULTICAST_TTL)
            .await
            .unwrap();
        assert!(ucast_sockets.is_empty());

        let outcome = runtime.spawn_scout_tasks(
            mcast_socket,
            ucast_sockets,
            true,
            AutoConnect::disabled(),
            addr,
        );

        assert_eq!(outcome, ScoutStart::NoUsableSockets);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_datagram_is_dropped_when_no_unicast_socket_is_available() {
        let runtime = create_runtime().await;
        let peer = SocketAddr::new(UNUSABLE, 7446);

        assert!(runtime
            .scout_reply(peer, &scout_datagram(), &[], &[])
            .is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn binding_unusable_addresses_yields_no_unicast_sockets() {
        let (_mcast_socket, ucast_sockets) =
            Runtime::bind_scout_sockets(&scout_address(), &[UNUSABLE], MULTICAST_TTL)
                .await
                .unwrap();

        assert!(ucast_sockets.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_scouting_runtime_stores_what_its_scout_tasks_run_on() {
        let scouting = start_runtime(true, "auto").await;
        assert!(scouting.scout_token().is_some());
        assert!(!scouting.scout_socket_addrs().is_empty());

        let silent = start_runtime(false, "auto").await;
        assert!(silent.scout_token().is_none());
        assert!(silent.scout_socket_addrs().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn cancelling_the_scout_token_leaves_the_runtime_running() {
        let runtime = start_runtime(true, "auto").await;
        let token = runtime.scout_token().unwrap();

        token.cancel();

        assert!(token.is_cancelled());
        assert!(!runtime.get_cancellation_token().is_cancelled());
        assert!(!runtime.is_closed());
        assert!(!runtime.get_locators().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_rebuild_that_cannot_bind_keeps_the_running_scout_tasks() {
        let runtime = start_runtime(true, "auto").await;
        let token = runtime.scout_token().unwrap();
        let addrs = runtime.scout_socket_addrs();

        let outcome = runtime
            .rebuild_scout_tasks(
                true,
                AutoConnect::disabled(),
                scout_address(),
                &UNUSABLE.to_string(),
                MULTICAST_TTL,
            )
            .await;

        assert_eq!(outcome, ScoutStart::NoUsableSockets);
        assert_eq!(runtime.scout_socket_addrs(), addrs);
        assert!(!token.is_cancelled());
        assert!(!runtime.scout_token().unwrap().is_cancelled());

        // Cancelling what was stored before the rebuild cancels what is stored
        // after it, which only holds while the two are the same token.
        token.cancel();
        assert!(runtime.scout_token().unwrap().is_cancelled());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_rebuild_moves_the_responder_onto_the_new_sockets() {
        let runtime = start_runtime(true, "127.0.0.1").await;
        let before = runtime.scout_socket_addrs();

        let outcome = runtime
            .rebuild_scout_tasks(
                true,
                AutoConnect::disabled(),
                scout_address(),
                &rebuilt_interfaces(),
                MULTICAST_TTL,
            )
            .await;

        assert_eq!(outcome, ScoutStart::Started);
        let after = runtime.scout_socket_addrs();
        assert_ne!(after, before);

        // An answer to this address would be the node talking to itself, and a
        // filter left over from the previous sockets would not recognise it.
        let own = after[0];
        assert!(!before.contains(&own));

        let (_mcast_socket, ucast_sockets) = Runtime::bind_scout_sockets(
            &scout_address(),
            &[IpAddr::V4(Ipv4Addr::LOCALHOST)],
            MULTICAST_TTL,
        )
        .await
        .unwrap();

        assert!(runtime
            .scout_reply(own, &scout_datagram(), &after, &ucast_sockets)
            .is_none());
        assert!(runtime
            .scout_reply(
                SocketAddr::new(UNUSABLE, 7446),
                &scout_datagram(),
                &after,
                &ucast_sockets,
            )
            .is_some());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_rebuild_without_a_usable_interface_changes_nothing() {
        let runtime = start_runtime(true, "auto").await;
        let token = runtime.scout_token().unwrap();
        let addrs = runtime.scout_socket_addrs();

        let outcome = runtime
            .rebuild_scout_tasks(
                true,
                AutoConnect::disabled(),
                scout_address(),
                "no-such-interface-42",
                MULTICAST_TTL,
            )
            .await;

        assert_eq!(outcome, ScoutStart::NoUsableInterfaces);
        assert_eq!(runtime.scout_socket_addrs(), addrs);
        assert!(!token.is_cancelled());
    }

    async fn create_runtime() -> Runtime {
        RuntimeBuilder::new(Config::default())
            .build()
            .await
            .unwrap()
    }

    /// A started peer, listening on loopback.
    async fn start_runtime(multicast: bool, ifaces: &str) -> Runtime {
        let mut config = Config::default();
        config
            .insert_json5("scouting/multicast/interface", &format!("\"{ifaces}\""))
            .unwrap();
        config
            .insert_json5("listen/endpoints", r#"["tcp/127.0.0.1:0"]"#)
            .unwrap();
        config.insert_json5("scouting/delay", "0").unwrap();
        config
            .insert_json5("scouting/multicast/enabled", &multicast.to_string())
            .unwrap();
        config
            .insert_json5(
                "scouting/multicast/address",
                &format!("\"{}\"", scout_address()),
            )
            .unwrap();
        let mut runtime = RuntimeBuilder::new(config).build().await.unwrap();
        runtime.start().await.unwrap();

        runtime
    }

    /// A scouting address of this module's own, so a node running on the host does
    /// not join the exchange.
    fn scout_address() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 224)), 17447)
    }

    /// A wider interface list than the node started on, so rebuilding against it
    /// really binds a different set of sockets rather than the same one again.
    fn rebuilt_interfaces() -> String {
        let mut names = vec![Ipv4Addr::LOCALHOST.to_string()];
        names.extend(
            zenoh_util::net::get_ipv4_ipaddrs(None)
                .iter()
                .map(ToString::to_string),
        );

        names.join(",")
    }

    /// A scout every mode answers, so a dropped reply is never the matcher's doing.
    fn scout_datagram() -> Vec<u8> {
        let scout = Scout {
            version: zenoh_protocol::VERSION,
            what: WhatAmIMatcher::empty().router().peer().client(),
            zid: None,
        };
        let message: ScoutingMessage = scout.into();
        let mut buffer = vec![];
        Zenoh080::new()
            .write(&mut buffer.writer(), &message)
            .unwrap();

        buffer
    }
}
