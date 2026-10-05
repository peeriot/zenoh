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

//! Zone discovery: find the other members of this node's zone through an
//! iroh-lighthouse topic and connect to them over iroh.
use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio_util::sync::CancellationToken;
use zenoh_config::zone::Zone;
use zenoh_core::zlock;
use zenoh_link::iroh::{
    iroh::{EndpointId, Watcher},
    iroh_lighthouse_client::{parse_url, protocol::Peer, Lighthouse, Topic},
    locator_of, IrohEndpoint, IROH_LOCATOR_PREFIX,
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

/// Spawns the zone discovery task when both a zone and an iroh endpoint are present.
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

/// A client keeps at most one unicast transport. When a zone dial raced another connect path and
/// both won, close the zone-opened (`iroh/<id>` destination) transports until one remains, so the
/// pre-existing transport is kept.
pub(crate) async fn close_extra_zone_transports(runtime: &Runtime) {
    let transports = runtime.manager().get_transports_unicast().await;
    let mut remaining = transports.len();
    for t in transports {
        if remaining <= 1 {
            return;
        }
        let zone_opened = t.get_links().is_ok_and(|links| {
            !links.is_empty()
                && links
                    .iter()
                    .all(|l| l.dst.protocol().as_str() == IROH_LOCATOR_PREFIX)
        });
        if !zone_opened {
            continue;
        }
        tracing::debug!(
            "Closing the extra zone transport to {:?}: a client keeps one transport",
            t.get_zid()
        );
        if let Err(e) = t.close().await {
            tracing::debug!("Cannot close the extra zone transport: {e}");
        }
        remaining -= 1;
    }
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
                Err(e) => tracing::warn!(
                    "Cannot join zone {} on {}: {e}",
                    self.zone.topic,
                    self.zone.lighthouse
                ),
            }
            tokio::select! {
                _ = token.cancelled() => return,
                _ = tokio::time::sleep(backoff) => {}
            }
            backoff = (backoff * 2).min(MAX_BACKOFF);
        };
        tracing::info!(
            "Joined zone {} ({}) on {}",
            self.zone.topic,
            self.topic.id(),
            self.zone.lighthouse
        );
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
                tracing::warn!(
                    "Cannot look up zone {} on {}: {e}",
                    self.zone.topic,
                    self.zone.lighthouse
                );
                return;
            }
        };
        for peer in peers {
            // Another connect path (explicit endpoint, multicast) may have won meanwhile.
            if !manager.get_transports_unicast().await.is_empty() {
                return;
            }
            let id = peer.addr.id;
            self.iroh.set_addr(peer.addr);
            tracing::debug!("zone dial from {} to {id}", self.runtime.zid());
            match manager.open_transport_unicast(locator_of(&id).into()).await {
                Ok(_) => {
                    tracing::debug!("Connected to zone peer {id}");
                    close_extra_zone_transports(&self.runtime).await;
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
            if !zlock!(self.pending).insert(id) {
                continue;
            }
            self.iroh.set_addr(peer.addr.clone());
            tracing::debug!("zone dial from {} to {id}", self.runtime.zid());
            let this = self.clone();
            // Abortable: a dial in flight must not hold up runtime close.
            self.runtime.spawn_abortable(async move {
                match this
                    .runtime
                    .manager()
                    .open_transport_unicast(locator_of(&id).into())
                    .await
                {
                    Ok(_) => tracing::debug!("Connected to zone peer {id}"),
                    Err(e) => tracing::debug!("Cannot connect to zone peer {id}: {e}"),
                }
                zlock!(this.pending).remove(&id);
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use zenoh_link::iroh::iroh::SecretKey;

    use super::should_dial;

    #[test]
    fn exactly_one_side_of_a_member_pair_dials() {
        let (a, b) = (
            SecretKey::generate().public(),
            SecretKey::generate().public(),
        );
        assert_ne!(should_dial(&a, &b), should_dial(&b, &a));
        assert!(!should_dial(&a, &a));
    }
}
