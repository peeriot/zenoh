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
use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use async_trait::async_trait;
use tokio::time::{Instant, MissedTickBehavior};
use zenoh_protocol::core::Locator;
use zenoh_result::{bail, ZResult};

use super::{orchestrator::ScoutStart, Runtime, WeakRuntime};
use crate::net::common::AutoConnect;

/// What the host currently offers, reduced to the two sets a poll decides on.
#[derive(Clone, Debug)]
pub(crate) struct InterfaceSnapshot {
    /// The addresses the node's listeners can be reached at.
    pub(crate) locators: Vec<Locator>,
    /// The addresses multicast scouting can be carried on.
    pub(crate) multicast: Vec<IpAddr>,
}

/// Makes the host's interface view current and derives what the node can use.
#[async_trait]
pub(crate) trait InterfaceProbe: Send + Sync + 'static {
    async fn probe(&self, iface_names: &str) -> ZResult<InterfaceSnapshot>;
}

/// The configuration a poll works from, read once when the monitor is built.
///
/// Reading it again on every poll would put the node's own timing, and with it an
/// operator's decision to turn the poll off, in reach of whoever can write the
/// running configuration.
pub(crate) struct MonitorConfig {
    /// How long to wait between two polls.
    pub(crate) poll_interval: Duration,
    /// Whether the node answers multicast scouts at all.
    pub(crate) scouting: bool,
    /// The interfaces multicast scouting was configured with.
    pub(crate) interfaces: String,
    /// The group multicast scouting runs on.
    pub(crate) multicast_address: SocketAddr,
    /// The time to live of the scouting datagrams.
    pub(crate) multicast_ttl: u32,
    /// Whether the node answers scouts it receives.
    pub(crate) listen: bool,
    /// Which discovered nodes the node dials by itself.
    pub(crate) autoconnect: AutoConnect,
}

/// What the polls did, so that "nothing happened" is an assertion rather than an
/// absence of evidence.
#[derive(Debug, Default)]
pub(crate) struct MonitorCounters {
    /// Polls that ran to their end, whatever they found.
    pub(crate) ticks: AtomicU64,
    /// Polls whose look at the host failed, which counts as nothing observed.
    pub(crate) probe_errors: AtomicU64,
    /// Polls that found no usable multicast interface.
    pub(crate) empty_set_ticks: AtomicU64,
    /// Timer firings dropped because the poll they belonged to was still running.
    pub(crate) suppressed_ticks: AtomicU64,
    /// Locator sets taken over from the host.
    pub(crate) adoptions: AtomicU64,
    /// Locator sets left alone because the recomputed one was empty.
    pub(crate) refused_adoptions: AtomicU64,
    /// Scout socket sets moved onto the current interfaces.
    pub(crate) rebuilds: AtomicU64,
    /// Scout socket moves that did not work out, leaving the previous ones running.
    pub(crate) failed_rebuilds: AtomicU64,
    /// Locator sets pushed to the established links.
    pub(crate) announces: AtomicU64,
}

/// Watches the host's address set and reports what moved.
pub(crate) struct InterfaceMonitor {
    runtime: WeakRuntime,
    config: MonitorConfig,
    probe: Arc<dyn InterfaceProbe>,
    /// The multicast address set of the previous poll, absent until the first one
    /// has something to compare against.
    previous_multicast: Option<Vec<IpAddr>>,
    counters: Arc<MonitorCounters>,
}

impl InterfaceMonitor {
    pub(crate) fn new(
        runtime: WeakRuntime,
        config: MonitorConfig,
        probe: Arc<dyn InterfaceProbe>,
    ) -> Self {
        Self {
            runtime,
            config,
            probe,
            previous_multicast: None,
            counters: Arc::new(MonitorCounters::default()),
        }
    }

    pub(crate) fn counters(&self) -> Arc<MonitorCounters> {
        self.counters.clone()
    }

    /// Polls the host until the runtime goes away.
    pub(crate) async fn run(mut self) {
        let mut interval = tokio::time::interval(self.config.poll_interval);
        // Without this the ticks that fall during a slow poll fire back to back
        // afterwards, which is the opposite of the bound the interval is there for.
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            self.tick().await;
        }
    }

    /// Looks at the host once.
    pub(crate) async fn tick(&mut self) {
        let started = Instant::now();
        self.observe().await;

        let elapsed = started.elapsed();
        let interval = self.config.poll_interval.as_nanos();
        let suppressed = u64::try_from(elapsed.as_nanos() / interval).unwrap_or(u64::MAX);
        if suppressed > 0 {
            self.counters
                .suppressed_ticks
                .fetch_add(suppressed, Ordering::Relaxed);
        }
        self.counters.ticks.fetch_add(1, Ordering::Relaxed);
    }

    async fn observe(&mut self) {
        let Some(runtime) = self.runtime.upgrade() else {
            return;
        };
        let snapshot = match self.probe.probe(&self.config.interfaces).await {
            Ok(snapshot) => snapshot,
            Err(err) => {
                tracing::warn!("Unable to read the host interfaces: {}", err);
                self.counters.probe_errors.fetch_add(1, Ordering::Relaxed);

                return;
            }
        };

        self.observe_locators(&runtime, sorted_locators(snapshot.locators));
        self.observe_multicast(&runtime, sorted(snapshot.multicast))
            .await;
    }

    /// Takes over the locator set the host offers now, if it moved.
    ///
    /// A node is reached over its locators whether or not the host carries a device
    /// multicast can run on, so this half waits for nothing the other one finds.
    fn observe_locators(&self, runtime: &Runtime, locators: Vec<Locator>) {
        if locators == sorted_locators(runtime.get_locators()) {
            return;
        }
        tracing::debug!("The node is now reachable at {:?}", locators);

        self.adopt(runtime, locators);
    }

    /// Puts the scout sockets on the multicast set the host offers now, when that set
    /// moved or when the node has no scout socket to answer on.
    async fn observe_multicast(&mut self, runtime: &Runtime, multicast: Vec<IpAddr>) {
        if multicast.is_empty() {
            tracing::warn!("No multicast interface on the host, looking again on the next poll");
            self.counters
                .empty_set_ticks
                .fetch_add(1, Ordering::Relaxed);
            // An empty set is something seen, not nothing seen. Leaving it out of the
            // comparison hides the interface coming back, which is the one transition
            // a node that started without an address depends on.
            self.previous_multicast = Some(multicast);

            return;
        }

        let moved = self
            .previous_multicast
            .as_ref()
            .is_some_and(|previous| previous != &multicast);
        // Scouting the configuration asks for but that never came up has to be
        // started, not only moved: nothing else in the process will start it, and a
        // node whose interface had no address at exec time answers no scout until
        // something does.
        let down = self.config.scouting && runtime.scout_socket_addrs().is_empty();
        if !moved && !down {
            self.previous_multicast = Some(multicast);

            return;
        }
        tracing::debug!("Multicast scouting moves onto {:?}", multicast);

        // A move that did not work out keeps the previous set, so that the next poll
        // sees the same difference again and tries once more.
        if self.rebuild(runtime).await {
            self.previous_multicast = Some(multicast);
        }
    }

    /// Takes over a locator set and pushes it to the established links.
    ///
    /// The store is released before the announcement, which takes the routing locks
    /// and reads the stored set underneath them.
    fn adopt(&self, runtime: &Runtime, locators: Vec<Locator>) {
        if locators.is_empty() {
            tracing::warn!(
                "The host holds no address the node can be reached at, keeping the previous ones"
            );
            self.counters
                .refused_adoptions
                .fetch_add(1, Ordering::Relaxed);

            return;
        }

        runtime.store_locators(locators);
        self.counters.adoptions.fetch_add(1, Ordering::Relaxed);
        runtime.announce_locators();
        self.counters.announces.fetch_add(1, Ordering::Relaxed);
    }

    /// Moves the scout sockets onto the interfaces the host has now, and reports
    /// whether the move happened.
    async fn rebuild(&self, runtime: &Runtime) -> bool {
        if !self.config.scouting {
            return true;
        }

        let outcome = runtime
            .rebuild_scout_tasks(
                self.config.listen,
                self.config.autoconnect,
                self.config.multicast_address,
                &self.config.interfaces,
                self.config.multicast_ttl,
            )
            .await;
        if outcome != ScoutStart::Started {
            self.counters
                .failed_rebuilds
                .fetch_add(1, Ordering::Relaxed);

            return false;
        }
        self.counters.rebuilds.fetch_add(1, Ordering::Relaxed);

        true
    }
}

/// Reads the host and derives what the node can reach and scout on.
pub(crate) struct HostProbe {
    runtime: WeakRuntime,
}

impl HostProbe {
    pub(crate) fn new(runtime: WeakRuntime) -> Self {
        Self { runtime }
    }
}

#[async_trait]
impl InterfaceProbe for HostProbe {
    async fn probe(&self, iface_names: &str) -> ZResult<InterfaceSnapshot> {
        let Some(runtime) = self.runtime.upgrade() else {
            bail!("The runtime is gone")
        };
        zenoh_util::net::refresh_interfaces();

        Ok(InterfaceSnapshot {
            locators: runtime.manager().get_locators(),
            multicast: Runtime::get_interfaces_strict(iface_names),
        })
    }
}

/// Enumeration order is the host's business, so a comparable set is sorted and has
/// its duplicates dropped.
fn sorted<T: Ord>(mut values: Vec<T>) -> Vec<T> {
    values.sort_unstable();
    values.dedup();

    values
}

/// The same, for locators, which carry no ordering of their own.
fn sorted_locators(mut locators: Vec<Locator>) -> Vec<Locator> {
    locators.sort_by_cached_key(Locator::to_string);
    locators.dedup();

    locators
}
