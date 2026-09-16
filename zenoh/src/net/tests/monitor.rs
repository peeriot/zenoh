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
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };

    use async_trait::async_trait;
    use zenoh_config::PollIntervalMillis;
    use zenoh_protocol::core::Locator;
    use zenoh_result::ZResult;

    use crate::{
        api::config::Config,
        net::{
            common::AutoConnect,
            runtime::{
                interface_monitor::{
                    InterfaceMonitor, InterfaceProbe, InterfaceSnapshot, MonitorConfig,
                },
                Runtime, RuntimeBuilder,
            },
        },
    };

    const SLOW_INTERVAL: Duration = Duration::from_secs(10);

    /// The interval the monitor started with has to survive a configuration write, or
    /// anything able to write the running configuration can retime the poll, and an
    /// operator who turned it off cannot keep it off.
    #[tokio::test(start_paused = true)]
    async fn a_configuration_write_does_not_retime_a_running_monitor() {
        let runtime = build_runtime().await;
        let probe = Arc::new(ScriptedProbe::new(vec![snapshot(&[], &[loopback()])]));
        let monitor = InterfaceMonitor::new(
            Runtime::downgrade(&runtime),
            timing_monitor_config(SLOW_INTERVAL),
            probe.clone(),
        );
        let counters = monitor.counters();
        tokio::spawn(monitor.run());

        runtime
            .config()
            .lock()
            .insert_json5("scouting/interface_poll_interval", "1")
            .unwrap();
        assert_eq!(
            runtime.config().lock().scouting().interface_poll_interval(),
            &Some(PollIntervalMillis::from(1))
        );
        tokio::time::sleep(10 * SLOW_INTERVAL).await;

        let ticks = counters.ticks.load(Ordering::Relaxed);
        assert!(ticks >= 1, "the monitor never ticked");
        assert!(
            ticks <= 11,
            "the monitor ticked {ticks} times in ten intervals, so it followed the written value"
        );
    }

    /// A refresh that outlasts its interval must drop the timer firings it covered
    /// rather than have them fire back to back once it is done.
    #[tokio::test(start_paused = true)]
    async fn a_slow_probe_suppresses_ticks_instead_of_queueing_them() {
        let interval = Duration::from_millis(100);
        let runtime = build_runtime().await;
        let probe = Arc::new(
            ScriptedProbe::new(vec![snapshot(&[], &[loopback()])])
                .with_delays(vec![5 * interval, Duration::ZERO]),
        );
        let monitor = InterfaceMonitor::new(
            Runtime::downgrade(&runtime),
            timing_monitor_config(interval),
            probe.clone(),
        );
        let counters = monitor.counters();
        tokio::spawn(monitor.run());

        // Half an interval past the slow refresh: the five firings it covered are
        // gone, so at most the one due right after it has happened.
        tokio::time::sleep(Duration::from_millis(550)).await;
        let ticks = counters.ticks.load(Ordering::Relaxed);
        assert!(
            ticks <= 2,
            "{ticks} refreshes right after a slow one, so the missed firings were replayed"
        );
        assert_eq!(counters.suppressed_ticks.load(Ordering::Relaxed), 5);

        tokio::time::sleep(30 * interval).await;
        assert!(!probe.overlapped(), "two refreshes ran at the same time");
        assert!(
            counters.ticks.load(Ordering::Relaxed) > ticks,
            "the monitor stopped after the slow refresh"
        );
    }

    /// The poll is the operator's to turn off, and the off state has to be told apart
    /// from a monitor that is merely broken - hence both halves in one test.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_poll_interval_switches_the_monitor_on_and_off() {
        let disabled = start_peer(0).await;
        assert!(disabled.interface_monitor().is_none());

        for value in ["50", "-1", "1.5"] {
            let _ = disabled
                .config()
                .lock()
                .insert_json5("scouting/interface_poll_interval", value);
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(disabled.interface_monitor().is_none());

        let enabled = start_peer(50).await;
        let counters = enabled
            .interface_monitor()
            .expect("a non-zero interval starts a monitor");
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            counters.ticks.load(Ordering::Relaxed) >= 2,
            "the monitor did not tick"
        );
    }

    /// Nothing on the host moved, so the node must leave its addresses, its sockets
    /// and its peers alone.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_unchanged_host_moves_nothing() {
        let runtime = start_scouting_peer("127.0.0.1").await;
        let probe = Arc::new(ScriptedProbe::new(vec![steady_snapshot(&runtime)]));
        let mut monitor = InterfaceMonitor::new(
            Runtime::downgrade(&runtime),
            monitor_config(Duration::from_millis(50), "127.0.0.1"),
            probe,
        );
        let counters = monitor.counters();

        for _ in 0..3 {
            monitor.tick().await;
        }

        assert_eq!(counters.ticks.load(Ordering::Relaxed), 3);
        assert_eq!(counters.adoptions.load(Ordering::Relaxed), 0);
        assert_eq!(counters.announces.load(Ordering::Relaxed), 0);
        assert_eq!(counters.rebuilds.load(Ordering::Relaxed), 0);
    }

    /// The node reached a new address, so it stores it and tells its peers once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_new_locator_set_is_adopted_and_announced_once() {
        let runtime = start_scouting_peer("127.0.0.1").await;
        let moved = InterfaceSnapshot {
            locators: vec!["tcp/127.0.0.1:65530".parse().unwrap()],
            locators_noloopback: vec!["tcp/127.0.0.1:65530".parse().unwrap()],
            multicast: vec![loopback()],
        };
        let probe = Arc::new(ScriptedProbe::new(vec![
            steady_snapshot(&runtime),
            moved.clone(),
        ]));
        let mut monitor = InterfaceMonitor::new(
            Runtime::downgrade(&runtime),
            monitor_config(Duration::from_millis(50), "127.0.0.1"),
            probe,
        );
        let counters = monitor.counters();

        monitor.tick().await;
        monitor.tick().await;
        monitor.tick().await;

        assert_eq!(runtime.get_locators(), moved.locators);
        assert_eq!(runtime.get_locators_noloopback(), moved.locators_noloopback);
        assert_eq!(counters.adoptions.load(Ordering::Relaxed), 1);
        assert_eq!(counters.announces.load(Ordering::Relaxed), 1);
        assert_eq!(counters.rebuilds.load(Ordering::Relaxed), 0);
    }

    /// Only the scouting interfaces moved, so the sockets follow and nothing else does.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_moved_multicast_set_rebuilds_the_scout_sockets_once() {
        let runtime = start_scouting_peer("127.0.0.1").await;
        let before = runtime.scout_socket_addrs();
        assert!(!before.is_empty());
        let steady = steady_snapshot(&runtime);
        let moved = InterfaceSnapshot {
            locators: steady.locators.clone(),
            locators_noloopback: steady.locators_noloopback.clone(),
            multicast: vec![loopback(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))],
        };
        let probe = Arc::new(ScriptedProbe::new(vec![steady, moved]));
        let mut monitor = InterfaceMonitor::new(
            Runtime::downgrade(&runtime),
            monitor_config(Duration::from_millis(50), "127.0.0.1"),
            probe,
        );
        let counters = monitor.counters();

        monitor.tick().await;
        monitor.tick().await;
        monitor.tick().await;

        assert_ne!(runtime.scout_socket_addrs(), before);
        assert_eq!(counters.rebuilds.load(Ordering::Relaxed), 1);
        assert_eq!(counters.adoptions.load(Ordering::Relaxed), 0);
        assert_eq!(counters.announces.load(Ordering::Relaxed), 0);
    }

    /// The host has no multicast interface left. Scouting on the old addresses beats
    /// scouting on none, so the poll waits for the host to come back.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_empty_multicast_set_leaves_the_sockets_alone() {
        let runtime = start_scouting_peer("127.0.0.1").await;
        let before = runtime.scout_socket_addrs();
        assert!(!before.is_empty());
        let probe = Arc::new(ScriptedProbe::new(vec![InterfaceSnapshot {
            locators: vec![],
            locators_noloopback: vec![],
            multicast: vec![],
        }]));
        let mut monitor = InterfaceMonitor::new(
            Runtime::downgrade(&runtime),
            monitor_config(Duration::from_millis(50), "127.0.0.1"),
            probe,
        );
        let counters = monitor.counters();

        monitor.tick().await;
        monitor.tick().await;

        assert_eq!(runtime.scout_socket_addrs(), before);
        assert_eq!(counters.empty_set_ticks.load(Ordering::Relaxed), 2);
        assert_eq!(counters.adoptions.load(Ordering::Relaxed), 0);
        assert_eq!(counters.announces.load(Ordering::Relaxed), 0);
        assert_eq!(counters.rebuilds.load(Ordering::Relaxed), 0);
    }

    /// The interface had no address yet when the process started - a DHCP lease not
    /// granted, a container attached to its network just after exec - so the node
    /// joined no multicast group. The poll that sees the interface arrive is the only
    /// thing that can still bring scouting up, and it only can if an empty set counts
    /// as an observation rather than as nothing seen.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_interface_arriving_after_the_start_brings_scouting_up() {
        let runtime = start_scouting_peer("127.0.0.1").await;
        let before = runtime.scout_socket_addrs();
        assert!(!before.is_empty());
        let arrived = steady_snapshot(&runtime);
        let probe = Arc::new(ScriptedProbe::new(vec![
            InterfaceSnapshot {
                locators: arrived.locators.clone(),
                locators_noloopback: arrived.locators_noloopback.clone(),
                multicast: vec![],
            },
            arrived,
        ]));
        let mut monitor = InterfaceMonitor::new(
            Runtime::downgrade(&runtime),
            monitor_config(Duration::from_millis(50), "127.0.0.1"),
            probe,
        );
        let counters = monitor.counters();

        monitor.tick().await;
        monitor.tick().await;

        assert_ne!(runtime.scout_socket_addrs(), before);
        assert_eq!(counters.empty_set_ticks.load(Ordering::Relaxed), 1);
        assert_eq!(counters.rebuilds.load(Ordering::Relaxed), 1);
    }

    /// The configured interface name did not resolve at start, so no scout socket was
    /// ever bound. A poll that only moves the sockets it already has leaves that node
    /// answering no scout for the life of the process. The monitor the test drives is
    /// pointed at a name that does resolve, which is what the interface gaining an
    /// address looks like from the poll's side.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_poll_starts_scouting_that_never_came_up() {
        let runtime = start_scouting_peer("zenohtest-absent").await;
        assert!(runtime.scout_socket_addrs().is_empty());
        let probe = Arc::new(ScriptedProbe::new(vec![steady_snapshot(&runtime)]));
        let mut monitor = InterfaceMonitor::new(
            Runtime::downgrade(&runtime),
            monitor_config(Duration::from_millis(50), "127.0.0.1"),
            probe,
        );
        let counters = monitor.counters();

        monitor.tick().await;

        assert!(!runtime.scout_socket_addrs().is_empty());
        assert_eq!(counters.rebuilds.load(Ordering::Relaxed), 1);
    }

    /// A host whose only device carries no multicast - a `tun` or a wireguard link -
    /// still moves its address, and a node there is reached over its locators rather
    /// than by scouting. Tying the locator half to the multicast half would leave
    /// exactly that deployment advertising an address it no longer holds.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_host_without_a_multicast_interface_still_adopts_and_announces() {
        let runtime = start_scouting_peer("127.0.0.1").await;
        let moved = InterfaceSnapshot {
            locators: vec!["tcp/127.0.0.1:65530".parse().unwrap()],
            locators_noloopback: vec!["tcp/127.0.0.1:65530".parse().unwrap()],
            multicast: vec![],
        };
        let probe = Arc::new(ScriptedProbe::new(vec![moved.clone()]));
        let mut monitor = InterfaceMonitor::new(
            Runtime::downgrade(&runtime),
            monitor_config(Duration::from_millis(50), "127.0.0.1"),
            probe,
        );
        let counters = monitor.counters();

        monitor.tick().await;
        monitor.tick().await;

        assert_eq!(runtime.get_locators(), moved.locators);
        assert_eq!(runtime.get_locators_noloopback(), moved.locators_noloopback);
        assert_eq!(counters.adoptions.load(Ordering::Relaxed), 1);
        assert_eq!(counters.announces.load(Ordering::Relaxed), 1);
        assert_eq!(counters.empty_set_ticks.load(Ordering::Relaxed), 2);
        assert_eq!(counters.rebuilds.load(Ordering::Relaxed), 0);
    }

    /// Between losing an address and getting the next one there is nothing truthful
    /// to advertise, so the node keeps saying what it said before.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_empty_locator_set_is_refused() {
        let runtime = start_scouting_peer("127.0.0.1").await;
        let before = runtime.get_locators();
        let before_noloopback = runtime.get_locators_noloopback();
        assert!(!before.is_empty());
        let probe = Arc::new(ScriptedProbe::new(vec![InterfaceSnapshot {
            locators: vec![],
            locators_noloopback: vec![],
            multicast: vec![loopback()],
        }]));
        let mut monitor = InterfaceMonitor::new(
            Runtime::downgrade(&runtime),
            monitor_config(Duration::from_millis(50), "127.0.0.1"),
            probe,
        );
        let counters = monitor.counters();

        monitor.tick().await;

        assert_eq!(runtime.get_locators(), before);
        assert_eq!(runtime.get_locators_noloopback(), before_noloopback);
        assert_eq!(counters.refused_adoptions.load(Ordering::Relaxed), 1);
        assert_eq!(counters.adoptions.load(Ordering::Relaxed), 0);
        assert_eq!(counters.announces.load(Ordering::Relaxed), 0);
    }

    /// A wildcard listener resolves to loopback as well, so a host that lost its last
    /// external address still lists loopback locators. No other host can reach the
    /// node there, so that is refused like an empty set.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_loopback_only_locator_set_is_refused() {
        let runtime = start_scouting_peer("127.0.0.1").await;
        let before = runtime.get_locators();
        let before_noloopback = runtime.get_locators_noloopback();
        let probe = Arc::new(ScriptedProbe::new(vec![InterfaceSnapshot {
            locators: vec!["tcp/127.0.0.1:65530".parse().unwrap()],
            locators_noloopback: vec![],
            multicast: vec![loopback()],
        }]));
        let mut monitor = InterfaceMonitor::new(
            Runtime::downgrade(&runtime),
            monitor_config(Duration::from_millis(50), "127.0.0.1"),
            probe,
        );
        let counters = monitor.counters();

        monitor.tick().await;

        assert_eq!(runtime.get_locators(), before);
        assert_eq!(runtime.get_locators_noloopback(), before_noloopback);
        assert_eq!(counters.refused_adoptions.load(Ordering::Relaxed), 1);
        assert_eq!(counters.adoptions.load(Ordering::Relaxed), 0);
        assert_eq!(counters.announces.load(Ordering::Relaxed), 0);
    }

    /// A runtime that binds nothing, so the loop tests touch no socket and stay safe
    /// on the current-thread runtime the paused clock needs.
    async fn build_runtime() -> Runtime {
        RuntimeBuilder::new(Config::default())
            .build()
            .await
            .unwrap()
    }

    /// A started peer whose only endpoint is loopback.
    async fn start_peer(poll_interval: u64) -> Runtime {
        let mut config = Config::default();
        config
            .insert_json5("listen/endpoints", r#"["tcp/127.0.0.1:0"]"#)
            .unwrap();
        config
            .insert_json5("scouting/multicast/enabled", "false")
            .unwrap();
        config.insert_json5("scouting/delay", "0").unwrap();
        config
            .insert_json5(
                "scouting/interface_poll_interval",
                &poll_interval.to_string(),
            )
            .unwrap();
        let mut runtime = RuntimeBuilder::new(config).build().await.unwrap();
        runtime.start().await.unwrap();

        runtime
    }

    /// A started peer answering scouts on the given interfaces, with the poll off so
    /// that the only monitor in the test is the one the test drives itself.
    async fn start_scouting_peer(ifaces: &str) -> Runtime {
        let mut config = Config::default();
        config
            .insert_json5("listen/endpoints", r#"["tcp/127.0.0.1:0"]"#)
            .unwrap();
        config.insert_json5("scouting/delay", "0").unwrap();
        config
            .insert_json5("scouting/interface_poll_interval", "0")
            .unwrap();
        config
            .insert_json5("scouting/multicast/enabled", "true")
            .unwrap();
        config
            .insert_json5("scouting/multicast/interface", &format!("\"{ifaces}\""))
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

    fn monitor_config(poll_interval: Duration, interfaces: &str) -> MonitorConfig {
        MonitorConfig {
            poll_interval,
            scouting: true,
            interfaces: interfaces.to_string(),
            multicast_address: scout_address(),
            multicast_ttl: 1,
            listen: true,
            autoconnect: AutoConnect::disabled(),
        }
    }

    /// The tests that only look at the loop's timing drive a runtime that binds
    /// nothing. A monitor that scouts would try to bring the missing scout sockets up
    /// there, and the socket paths refuse the current-thread scheduler the paused
    /// clock needs.
    fn timing_monitor_config(poll_interval: Duration) -> MonitorConfig {
        MonitorConfig {
            scouting: false,
            ..monitor_config(poll_interval, "auto")
        }
    }

    /// A scouting address of this module's own, so a node running on the host does
    /// not join the exchange.
    fn scout_address() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 224)), 17450)
    }

    /// What a probe would report if nothing on the host had moved.
    fn steady_snapshot(runtime: &Runtime) -> InterfaceSnapshot {
        InterfaceSnapshot {
            locators: runtime.get_locators(),
            locators_noloopback: runtime.get_locators_noloopback(),
            multicast: vec![loopback()],
        }
    }

    /// Explicit addresses are advertised with or without loopback, so both sets match.
    fn snapshot(locators: &[&str], multicast: &[IpAddr]) -> InterfaceSnapshot {
        let locators: Vec<Locator> = locators
            .iter()
            .map(|l| l.parse::<Locator>().unwrap())
            .collect();
        InterfaceSnapshot {
            locators_noloopback: locators.clone(),
            locators,
            multicast: multicast.to_vec(),
        }
    }

    fn loopback() -> IpAddr {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }

    /// A probe that answers from a script instead of from the host, and that records
    /// whether it was ever entered twice at once.
    struct ScriptedProbe {
        snapshots: Vec<InterfaceSnapshot>,
        delays: Vec<Duration>,
        calls: AtomicUsize,
        in_flight: AtomicBool,
        overlapped: AtomicBool,
    }

    impl ScriptedProbe {
        fn new(snapshots: Vec<InterfaceSnapshot>) -> Self {
            Self {
                snapshots,
                delays: vec![Duration::ZERO],
                calls: AtomicUsize::new(0),
                in_flight: AtomicBool::new(false),
                overlapped: AtomicBool::new(false),
            }
        }

        /// How long each call takes; the last one holds for every call after it.
        fn with_delays(mut self, delays: Vec<Duration>) -> Self {
            self.delays = delays;

            self
        }

        fn overlapped(&self) -> bool {
            self.overlapped.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl InterfaceProbe for ScriptedProbe {
        async fn probe(&self, _iface_names: &str) -> ZResult<InterfaceSnapshot> {
            if self.in_flight.swap(true, Ordering::SeqCst) {
                self.overlapped.store(true, Ordering::SeqCst);
            }
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            let delay = self.delays[call.min(self.delays.len() - 1)];
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let snapshot = self.snapshots[call.min(self.snapshots.len() - 1)].clone();
            self.in_flight.store(false, Ordering::SeqCst);

            Ok(snapshot)
        }
    }
}
