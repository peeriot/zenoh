//
// Copyright (c) 2023 ZettaScale Technology
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
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    ops::DerefMut,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use futures::{prelude::*, stream::FuturesUnordered};
use socket2::{Domain, Socket, Type};
use tokio::{
    net::UdpSocket,
    sync::{futures::Notified, Notify},
};
use tokio_util::sync::CancellationToken;
use zenoh_buffers::{
    reader::{DidntRead, HasReader},
    writer::HasWriter,
};
use zenoh_codec::{RCodec, WCodec, Zenoh080};
use zenoh_config::{
    get_global_connect_timeout, get_global_listener_timeout, unwrap_or_default,
    ConnectionRetryPeriod, ModeDependent,
};
use zenoh_link::{Locator, LocatorInspector};
use zenoh_protocol::{
    core::{
        whatami::WhatAmIMatcher, EndPoint, EndPoints, LocatorsStrategy, Metadata, PriorityRange,
        WhatAmI, ZenohIdProto,
    },
    scouting::{HelloProto, Scout, ScoutingBody, ScoutingMessage},
};
use zenoh_result::{bail, zerror, ZResult};

use super::{
    interface_monitor::{HostProbe, InterfaceMonitor, MonitorConfig},
    Runtime, RuntimeSession, ScoutTasks,
};
use crate::net::{common::AutoConnect, protocol::linkstate::LinkInfo};

const RCV_BUF_SIZE: usize = u16::MAX as usize;
const SCOUT_INITIAL_PERIOD: Duration = Duration::from_millis(1_000);
const SCOUT_MAX_PERIOD: Duration = Duration::from_millis(8_000);
const SCOUT_PERIOD_INCREASE_FACTOR: u32 = 2;
const SCOUT_RECV_ERROR_INITIAL_PERIOD: Duration = Duration::from_millis(100);
const SCOUT_RECV_ERROR_MAX_PERIOD: Duration = Duration::from_millis(5_000);

// TODO(fuzzypixelz): collapse per-interface scout sockets into one wildcard socket
// per address family. Select egress with `set_multicast_if_*` before send;
// serialize set+send because the socket option is mutable.
/// UDP scout socket for one multicast egress interface.
///
/// The socket is wildcard-bound; `iface` pins multicast egress via socket
/// options.[^mcast-if]
///
/// [^mcast-if]: [`Socket::set_multicast_if_v4`], [`Socket::set_multicast_if_v6`].
pub(crate) struct ScoutSocket {
    /// Wildcard-bound UDP socket used for Scout/Hello traffic.
    socket: UdpSocket,
    /// Interface address used for multicast egress and responder matching.
    iface: IpAddr,
}

impl ScoutSocket {
    /// Sends a multicast datagram through this socket's egress interface.
    async fn send_multicast(&self, buffer: &[u8], dst: SocketAddr) -> std::io::Result<usize> {
        self.socket.send_to(buffer, dst).await
    }
}

#[derive(Debug)]
pub enum Loop {
    Continue,
    Break,
}

/// What came of an attempt to start the scout tasks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScoutStart {
    /// The tasks the configuration asks for are running.
    Started,
    /// No configured interface resolves to an address, so nothing was bound.
    NoUsableInterfaces,
    /// No interface could be bound, so no responder was started: answering a scout
    /// needs a socket to answer it on.
    NoUsableSockets,
}

#[derive(Default, Debug)]
pub(crate) struct PeerConnector {
    zid: Option<ZenohIdProto>,
    terminated: bool,
}

#[derive(Default, Debug)]
pub(crate) struct StartConditions {
    notify: Notify,
    // NOTE: this is a sync mutex on purpose: its critical sections never await
    // and it is locked from RX/routing contexts that hold the router
    // ctrl_lock. An async (fair) mutex here can hand ownership to a connector
    // task parked on a starved runtime and deadlock the whole session (see
    // gossip.rs link_states / hat/peer/interests.rs route_declare_final).
    peer_connectors: std::sync::Mutex<Vec<PeerConnector>>,
}

impl StartConditions {
    pub(crate) fn notified(&self) -> Notified<'_> {
        self.notify.notified()
    }

    pub(crate) fn add_peer_connector(&self) -> usize {
        let mut peer_connectors = zlock!(self.peer_connectors);
        peer_connectors.push(PeerConnector::default());
        peer_connectors.len() - 1
    }

    pub(crate) fn add_peer_connector_zid(&self, zid: ZenohIdProto) {
        let mut peer_connectors = zlock!(self.peer_connectors);
        if !peer_connectors.iter().any(|pc| pc.zid == Some(zid)) {
            peer_connectors.push(PeerConnector {
                zid: Some(zid),
                terminated: false,
            })
        }
    }

    pub(crate) fn set_peer_connector_zid(&self, idx: usize, zid: ZenohIdProto) {
        let mut peer_connectors = zlock!(self.peer_connectors);
        if let Some(peer_connector) = peer_connectors.get_mut(idx) {
            peer_connector.zid = Some(zid);
        }
    }

    pub(crate) fn terminate_peer_connector(&self, idx: usize) {
        let mut peer_connectors = zlock!(self.peer_connectors);
        if let Some(peer_connector) = peer_connectors.get_mut(idx) {
            peer_connector.terminated = true;
        }
        if peer_connectors.iter().all(|pc| pc.terminated) {
            self.notify.notify_one()
        }
    }

    pub(crate) fn terminate_peer_connector_zid(&self, zid: ZenohIdProto) {
        let mut peer_connectors = zlock!(self.peer_connectors);
        if let Some(peer_connector) = peer_connectors.iter_mut().find(|pc| pc.zid == Some(zid)) {
            peer_connector.terminated = true;
        } else {
            peer_connectors.push(PeerConnector {
                zid: Some(zid),
                terminated: true,
            })
        }
        if peer_connectors.iter().all(|pc| pc.terminated) {
            self.notify.notify_one()
        }
    }
}

impl Runtime {
    fn warn_if_oneof(peer_group: &EndPoints) {
        if let EndPoints::Locators(group) = peer_group {
            if matches!(group.strategy, LocatorsStrategy::OneOf) {
                tracing::warn!(
                    "connect.endpoints locator groups with strategy=oneOf are not implemented yet; \
                     falling back to current allOf behavior"
                );
            }
        }
    }

    pub async fn start(&mut self) -> ZResult<()> {
        #[cfg(not(feature = "transport_iroh"))]
        if self.config().lock().zone().is_some() {
            tracing::warn!(
                "zone is configured but zenoh was built without the transport_iroh feature; ignoring it"
            );
        }
        match self.whatami() {
            WhatAmI::Client => self.start_client().await,
            WhatAmI::Peer => self.start_peer().await,
            WhatAmI::Router => self.start_router().await,
        }
    }

    async fn start_client(&self) -> ZResult<()> {
        let (listeners, peers, scouting, listen, autoconnect, addr, ifaces, timeout, multicast_ttl) = {
            let guard = &self.state.config.lock();
            (
                guard
                    .listen()
                    .endpoints()
                    .client()
                    .unwrap_or(&vec![])
                    .clone(),
                guard
                    .connect()
                    .endpoints()
                    .client()
                    .unwrap_or(&vec![])
                    .clone(),
                unwrap_or_default!(guard.scouting().multicast().enabled()),
                *unwrap_or_default!(guard.scouting().multicast().listen().client()),
                *unwrap_or_default!(guard.scouting().multicast().autoconnect().client()),
                unwrap_or_default!(guard.scouting().multicast().address()),
                unwrap_or_default!(guard.scouting().multicast().interface()),
                std::time::Duration::from_millis(unwrap_or_default!(guard.scouting().timeout())),
                unwrap_or_default!(guard.scouting().multicast().ttl()),
            )
        };

        self.bind_listeners(&listeners).await?;

        #[cfg(feature = "transport_iroh")]
        let zone_set = self.config().lock().zone().is_some();
        #[cfg(not(feature = "transport_iroh"))]
        let zone_set = false;
        // Without explicit connect endpoints, start before any scouting, so the zone races
        // multicast instead of waiting behind it. With them, start after the explicit connect,
        // so the zone's round sees that transport and idles: a client keeps one transport.
        #[cfg(feature = "transport_iroh")]
        if zone_set && peers.is_empty() {
            super::zone::start(self);
        }

        if scouting {
            if listen || peers.is_empty() {
                let ifaces = Runtime::get_interfaces(&ifaces);
                let mcast_socket = if listen {
                    Some(Runtime::bind_mcast_port(&addr, &ifaces, multicast_ttl).await?)
                } else {
                    None
                };
                if ifaces.is_empty() {
                    bail!("Unable to find multicast interface!")
                } else {
                    let sockets: Vec<ScoutSocket> = ifaces
                        .into_iter()
                        .filter_map(|iface| Runtime::bind_ucast_port(iface, multicast_ttl).ok())
                        .collect();
                    if sockets.is_empty() {
                        bail!("Unable to bind UDP port to any multicast interface!")
                    } else {
                        if peers.is_empty() {
                            let scouted = self.connect_first(&sockets, autoconnect, &addr, timeout);
                            if zone_set {
                                // Either multicast or the zone may find someone first. A scouting
                                // timeout is not fatal while the zone keeps looking.
                                #[cfg(feature = "transport_iroh")]
                                {
                                    tokio::select! {
                                        r = scouted => {
                                            if r.is_err()
                                                && self
                                                    .manager()
                                                    .get_transports_unicast()
                                                    .await
                                                    .is_empty()
                                            {
                                                tracing::warn!(
                                                    "No zone peer connected within the scouting timeout"
                                                );
                                            }
                                        }
                                        _ = self.wait_for_unicast_transport() => {}
                                    }
                                    // The zone's dial in flight cannot be cancelled here.
                                    super::zone::close_extra_zone_transports(self).await;
                                }
                            } else {
                                scouted.await?
                            }
                        }
                        if let Some(mcast_socket) = mcast_socket {
                            let this = self.clone();
                            self.spawn_abortable(async move {
                                this.responder(&mcast_socket, &sockets).await;
                            });
                        }
                    }
                }
            }
            if !peers.is_empty() {
                self.connect_peers_then_zone(&peers, zone_set).await
            } else {
                Ok(())
            }
        } else if peers.is_empty() && !zone_set {
            bail!("No peer specified and multicast scouting deactivated!")
        } else if peers.is_empty() {
            #[cfg(feature = "transport_iroh")]
            if tokio::time::timeout(timeout, self.wait_for_unicast_transport())
                .await
                .is_err()
            {
                tracing::warn!("No zone peer connected within the scouting timeout");
            }
            Ok(())
        } else {
            self.connect_peers_then_zone(&peers, zone_set).await
        }
    }

    /// A client's explicit connect, then the zone (if set), so the zone only looks for a member
    /// when the explicit connect left the client without a transport.
    async fn connect_peers_then_zone(&self, peers: &[EndPoints], zone_set: bool) -> ZResult<()> {
        self.connect_peers(peers, true).await?;
        #[cfg(feature = "transport_iroh")]
        if zone_set {
            super::zone::start(self);
        }
        #[cfg(not(feature = "transport_iroh"))]
        let _ = zone_set;
        Ok(())
    }

    /// Resolves once this runtime has at least one unicast transport.
    #[cfg(feature = "transport_iroh")]
    async fn wait_for_unicast_transport(&self) {
        while self.manager().get_transports_unicast().await.is_empty() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn start_peer(&self) -> ZResult<()> {
        let (
            listeners,
            peers,
            scouting,
            wait_scouting,
            listen,
            autoconnect,
            addr,
            ifaces,
            delay,
            multicast_ttl,
            poll_interval,
        ) = {
            let guard = &self.state.config.lock();
            (
                guard.listen().endpoints().peer().unwrap_or(&vec![]).clone(),
                guard
                    .connect()
                    .endpoints()
                    .peer()
                    .unwrap_or(&vec![])
                    .clone(),
                unwrap_or_default!(guard.scouting().multicast().enabled()),
                unwrap_or_default!(guard.open().return_conditions().connect_scouted()),
                *unwrap_or_default!(guard.scouting().multicast().listen().peer()),
                AutoConnect::multicast(guard, WhatAmI::Peer, self.zid().into()),
                unwrap_or_default!(guard.scouting().multicast().address()),
                unwrap_or_default!(guard.scouting().multicast().interface()),
                Duration::from_millis(unwrap_or_default!(guard.scouting().delay())),
                unwrap_or_default!(guard.scouting().multicast().ttl()),
                Duration::from_millis(
                    unwrap_or_default!(guard.scouting().interface_poll_interval()).into(),
                ),
            )
        };

        #[cfg(feature = "transport_iroh")]
        let listeners = super::iroh_endpoint::with_zone_listener(
            listeners,
            self.config().lock().zone().is_some(),
        );

        self.bind_listeners(&listeners).await?;

        #[cfg(feature = "transport_iroh")]
        super::zone::start(self);

        self.connect_peers(&peers, false).await?;

        if scouting {
            self.start_scout(listen, autoconnect, addr, ifaces.clone())
                .await?;
        }

        self.start_interface_monitor(MonitorConfig {
            poll_interval,
            scouting,
            interfaces: ifaces,
            multicast_address: addr,
            multicast_ttl,
            listen,
            autoconnect,
        });

        if wait_scouting
            && (scouting || !peers.is_empty())
            && tokio::time::timeout(delay, self.state.start_conditions.notified())
                .await
                .is_err()
            && !peers.is_empty()
        {
            tracing::warn!("Scouting delay elapsed before start conditions are met.");
        }
        Ok(())
    }

    async fn start_router(&self) -> ZResult<()> {
        let (
            listeners,
            peers,
            scouting,
            listen,
            autoconnect,
            addr,
            ifaces,
            delay,
            multicast_ttl,
            poll_interval,
        ) = {
            let guard = &self.state.config.lock();
            (
                guard
                    .listen()
                    .endpoints()
                    .router()
                    .unwrap_or(&vec![])
                    .clone(),
                guard
                    .connect()
                    .endpoints()
                    .router()
                    .unwrap_or(&vec![])
                    .clone(),
                unwrap_or_default!(guard.scouting().multicast().enabled()),
                *unwrap_or_default!(guard.scouting().multicast().listen().router()),
                AutoConnect::multicast(guard, WhatAmI::Router, self.zid().into()),
                unwrap_or_default!(guard.scouting().multicast().address()),
                unwrap_or_default!(guard.scouting().multicast().interface()),
                Duration::from_millis(unwrap_or_default!(guard.scouting().delay())),
                unwrap_or_default!(guard.scouting().multicast().ttl()),
                Duration::from_millis(
                    unwrap_or_default!(guard.scouting().interface_poll_interval()).into(),
                ),
            )
        };

        #[cfg(feature = "transport_iroh")]
        let listeners = super::iroh_endpoint::with_zone_listener(
            listeners,
            self.config().lock().zone().is_some(),
        );

        self.bind_listeners(&listeners).await?;

        #[cfg(feature = "transport_iroh")]
        super::zone::start(self);

        self.connect_peers(&peers, false).await?;

        if scouting {
            self.start_scout(listen, autoconnect, addr, ifaces.clone())
                .await?;
        }

        self.start_interface_monitor(MonitorConfig {
            poll_interval,
            scouting,
            interfaces: ifaces,
            multicast_address: addr,
            multicast_ttl,
            listen,
            autoconnect,
        });

        tokio::time::sleep(delay).await;
        Ok(())
    }

    /// Starts the poll that keeps the node's own addresses current.
    ///
    /// An interval of zero leaves it unstarted for the life of the process: that is
    /// the operator turning the capability off, and a later configuration write must
    /// not be able to turn it back on.
    fn start_interface_monitor(&self, config: MonitorConfig) {
        if config.poll_interval.is_zero() {
            tracing::debug!("The host interface poll is turned off");

            return;
        }

        let probe = Arc::new(HostProbe::new(Runtime::downgrade(self)));
        let monitor = InterfaceMonitor::new(Runtime::downgrade(self), config, probe);
        *zlock!(self.state.interface_monitor) = Some(monitor.counters());
        self.spawn_abortable(monitor.run());
    }

    async fn start_scout(
        &self,
        listen: bool,
        autoconnect: AutoConnect,
        addr: SocketAddr,
        ifaces: String,
    ) -> ZResult<ScoutStart> {
        let multicast_ttl = {
            let config_guard = self.config().lock();
            let config = &config_guard;
            unwrap_or_default!(config.scouting().multicast().ttl())
        };
        let ifaces = Runtime::get_interfaces(&ifaces);
        let (mcast_socket, ucast_sockets) =
            Runtime::bind_scout_sockets(&addr, &ifaces, multicast_ttl).await?;
        if ifaces.is_empty() {
            // The callers carry on without scouting, so this is the only place the
            // node says it is not answering scouts at all.
            tracing::warn!("No interface to scout on, not answering scouts on {}", addr);

            return Ok(ScoutStart::NoUsableInterfaces);
        }

        Ok(self.spawn_scout_tasks(mcast_socket, ucast_sockets, listen, autoconnect, addr))
    }

    /// Binds a fresh set of scout sockets and moves the scout tasks onto them.
    ///
    /// The new sockets are bound and their tasks are running before the previous
    /// ones are stopped, so the node keeps answering scouts across the move. A step
    /// that does not work out leaves the running tasks and their sockets alone:
    /// scouting on the old addresses beats scouting on none.
    pub(crate) async fn rebuild_scout_tasks(
        &self,
        listen: bool,
        autoconnect: AutoConnect,
        addr: SocketAddr,
        ifaces: &str,
        multicast_ttl: u32,
    ) -> ScoutStart {
        let ifaces = Runtime::get_interfaces_strict(ifaces);
        if ifaces.is_empty() {
            tracing::warn!("No multicast interface left, keeping the current scout sockets");

            return ScoutStart::NoUsableInterfaces;
        }

        let (mcast_socket, ucast_sockets) =
            match Runtime::bind_scout_sockets(&addr, &ifaces, multicast_ttl).await {
                Ok(sockets) => sockets,
                Err(err) => {
                    tracing::warn!(
                        "Unable to bind new scout sockets, keeping the current ones: {}",
                        err
                    );

                    return ScoutStart::NoUsableSockets;
                }
            };

        let previous_token = self.scout_token();
        let previous_addrs = self.scout_socket_addrs();
        let outcome =
            self.spawn_scout_tasks(mcast_socket, ucast_sockets, listen, autoconnect, addr);
        if outcome != ScoutStart::Started {
            return outcome;
        }

        if let Some(token) = previous_token {
            token.cancel();
        }
        tracing::info!(
            "Scouting moved from {:?} to {:?}",
            previous_addrs,
            self.scout_socket_addrs()
        );

        outcome
    }

    /// Binds the socket the scouts arrive on, and one answering socket per interface.
    ///
    /// The answering set comes back short, or empty, when the host does not currently
    /// hold one of the addresses. The multicast bind is the one that has to succeed.
    /// The time to live is a parameter rather than a configuration read, so that a
    /// caller rebuilding these sockets holds no configuration guard while it binds.
    pub(crate) async fn bind_scout_sockets(
        addr: &SocketAddr,
        ifaces: &[IpAddr],
        multicast_ttl: u32,
    ) -> ZResult<(UdpSocket, Vec<ScoutSocket>)> {
        let mcast_socket = Runtime::bind_mcast_port(addr, ifaces, multicast_ttl).await?;
        let ucast_sockets = ifaces
            .iter()
            .filter_map(|iface| Runtime::bind_ucast_port(*iface, multicast_ttl).ok())
            .collect();

        Ok((mcast_socket, ucast_sockets))
    }

    /// Starts the scout tasks the configuration asks for on already bound sockets.
    ///
    /// Answering a scout means sending from the socket closest to the sender, so a
    /// responder without a single answering socket is refused here rather than
    /// started and left to fail on its first datagram.
    pub(crate) fn spawn_scout_tasks(
        &self,
        mcast_socket: UdpSocket,
        ucast_sockets: Vec<ScoutSocket>,
        listen: bool,
        autoconnect: AutoConnect,
        addr: SocketAddr,
    ) -> ScoutStart {
        if ucast_sockets.is_empty() {
            tracing::warn!("No socket to answer scouts on, not scouting on {}", addr);

            return ScoutStart::NoUsableSockets;
        }

        let socket_addrs = scout_socket_addrs(&ucast_sockets);
        let token = self.get_cancellation_token();
        let task_token = token.clone();
        let this = self.clone();
        match (listen, autoconnect.is_enabled()) {
            (true, true) => {
                self.spawn_abortable(async move {
                    task_token
                        .run_until_cancelled(async move {
                            tokio::select! {
                                _ = this.responder(&mcast_socket, &ucast_sockets) => {},
                                _ = this.autoconnect_all(
                                    &ucast_sockets,
                                    autoconnect,
                                    &addr
                                ) => {},
                            }
                        })
                        .await;
                });
            }
            (true, false) => {
                self.spawn_abortable(async move {
                    task_token
                        .run_until_cancelled(this.responder(&mcast_socket, &ucast_sockets))
                        .await;
                });
            }
            (false, true) => {
                self.spawn_abortable(async move {
                    task_token
                        .run_until_cancelled(this.autoconnect_all(
                            &ucast_sockets,
                            autoconnect,
                            &addr,
                        ))
                        .await;
                });
            }
            _ => {}
        }
        *zlock!(self.state.scout_tasks) = Some(ScoutTasks {
            token,
            socket_addrs,
        });

        ScoutStart::Started
    }

    async fn connect_peers(&self, peers: &[EndPoints], single_link: bool) -> ZResult<()> {
        let timeout = self.get_global_connect_timeout();
        if timeout.is_zero() {
            self.connect_peers_impl(peers, single_link).await
        } else {
            let res = tokio::time::timeout(timeout, async {
                self.connect_peers_impl(peers, single_link).await
            })
            .await;
            match res {
                Ok(r) => r,
                Err(_) => {
                    let e = zerror!("Unable to connect to any of {:?}. Timeout!", peers);
                    tracing::warn!("{}", &e);
                    Err(e.into())
                }
            }
        }
    }

    async fn connect_peers_impl(&self, peers: &[EndPoints], single_link: bool) -> ZResult<()> {
        if single_link {
            self.connect_peers_single_link(peers).await
        } else {
            self.connect_peers_multiply_links(peers).await
        }
    }

    async fn connect_peers_single_link(&self, peers: &[EndPoints]) -> ZResult<()> {
        let mut success_flag = false;
        for peer_group in peers {
            Self::warn_if_oneof(peer_group);
            // try to connect to each peer in the group
            let mut peers_to_retry = Vec::new();
            for peer in peer_group.as_vec() {
                let endpoint = peer.clone();
                let retry_config = self.get_connect_retry_config(&endpoint);
                if retry_config.timeout().is_zero() || self.get_global_connect_timeout().is_zero() {
                    tracing::debug!(
                        "Try to connect: {:?}: global timeout: {:?}, retry: {:?}",
                        endpoint,
                        self.get_global_connect_timeout(),
                        retry_config
                    );
                    // try to connect directly when there is no timeout configuration
                    if self.peer_connector(endpoint).await.is_ok() {
                        success_flag = true;
                    }
                } else {
                    peers_to_retry.push(endpoint);
                }
            }
            // sequentially try to connect to one of the remaining peers
            // respecting connection retry delays
            if self
                .peers_connector_retry(peers_to_retry, false)
                .await
                .is_ok()
            {
                success_flag = true;
            }
            // any endpoint in the group is available, it's marked as success and break
            if success_flag {
                break;
            }
        }

        // return error if none of them succeeded
        if success_flag {
            Ok(())
        } else {
            let e = zerror!("Unable to connect to any of {:?}! ", peers);
            tracing::warn!("{}", &e);
            Err(e.into())
        }
    }

    async fn connect_peers_multiply_links(&self, peers: &[EndPoints]) -> ZResult<()> {
        for peer_group in peers {
            Self::warn_if_oneof(peer_group);
            for peer in peer_group.as_vec() {
                let endpoint = peer.clone();
                let retry_config = self.get_connect_retry_config(&endpoint);
                tracing::debug!(
                    "Try to connect: {:?}: global timeout: {:?}, retry: {:?}",
                    endpoint,
                    self.get_global_connect_timeout(),
                    retry_config
                );
                if retry_config.timeout().is_zero() || self.get_global_connect_timeout().is_zero() {
                    // try to connect and exit immediately without retry
                    if let Err(e) = self.peer_connector(endpoint).await {
                        if retry_config.exit_on_failure {
                            return Err(e);
                        }
                    }
                } else if retry_config.exit_on_failure {
                    // try to connect with retry waiting
                    let _ = self.peer_connector_retry(endpoint).await;
                } else {
                    // try to connect in background
                    if let Err(e) = self.spawn_peer_connector(endpoint.clone()).await {
                        tracing::warn!("Error connecting to {}: {}", endpoint, e);
                        return Err(e);
                    }
                }
            }
        }
        Ok(())
    }

    async fn peer_connector(&self, peer: EndPoint) -> ZResult<()> {
        let result = self
            .manager()
            .open_transport_unicast(peer.clone())
            .await
            .and_then(|transport| -> ZResult<_> {
                let cb = transport
                    .get_callback()?
                    .ok_or_else(|| zerror!("Transport closed immediately"))?;
                let session = cb
                    .as_any()
                    .downcast_ref::<super::RuntimeSession>()
                    .ok_or_else(|| zerror!("Unexpected callback type"))?;
                zwrite!(session.endpoints).insert(peer.clone());
                Ok(())
            });

        if let Err(e) = &result {
            tracing::warn!("Unable to connect to {}! {}", peer, e);
        }
        result
    }

    fn get_listen_retry_config(&self, endpoint: &EndPoint) -> zenoh_config::ConnectionRetryConf {
        let guard = &self.state.config.lock();
        zenoh_config::get_retry_config(guard, Some(endpoint), true)
    }

    fn get_connect_retry_config(&self, endpoint: &EndPoint) -> zenoh_config::ConnectionRetryConf {
        let guard = &self.state.config.lock();
        zenoh_config::get_retry_config(guard, Some(endpoint), false)
    }

    fn get_global_listener_timeout(&self) -> std::time::Duration {
        let guard = &self.state.config.lock();
        get_global_listener_timeout(guard)
    }

    fn get_global_connect_timeout(&self) -> std::time::Duration {
        let guard = &self.state.config.lock();
        get_global_connect_timeout(guard)
    }

    async fn bind_listeners(&self, listeners: &[EndPoint]) -> ZResult<()> {
        if listeners.is_empty() {
            tracing::debug!("Starting with no listener endpoints!");
            return Ok(());
        }
        let timeout = self.get_global_listener_timeout();
        if timeout.is_zero() {
            self.bind_listeners_impl(listeners).await
        } else {
            let res = tokio::time::timeout(timeout, async {
                self.bind_listeners_impl(listeners).await.ok()
            })
            .await;
            match res {
                Ok(_) => Ok(()),
                Err(e) => {
                    tracing::error!("Unable to open listeners: {}", e);
                    Err(Box::new(e))
                }
            }
        }
    }

    async fn bind_listeners_impl(&self, listeners: &[EndPoint]) -> ZResult<()> {
        for listener in listeners {
            let endpoint = listener.clone();
            let retry_config = self.get_listen_retry_config(&endpoint);
            tracing::debug!("Try to add listener: {:?}: {:?}", endpoint, retry_config);
            if retry_config.timeout().is_zero() || self.get_global_listener_timeout().is_zero() {
                // try to add listener and exit immediately without retry
                if let Err(e) = self.add_listener(endpoint).await {
                    if retry_config.exit_on_failure {
                        return Err(e);
                    }
                };
            } else if retry_config.exit_on_failure {
                // try to add listener with retry waiting
                self.add_listener_retry(endpoint, retry_config).await
            } else {
                // try to add listener in background
                self.spawn_add_listener(endpoint, retry_config).await
            }
        }
        self.print_locators();
        Ok(())
    }

    async fn spawn_add_listener(
        &self,
        listener: EndPoint,
        retry_config: zenoh_config::ConnectionRetryConf,
    ) {
        let this = self.clone();
        self.spawn(async move {
            this.add_listener_retry(listener, retry_config).await;
            this.print_locators();
        });
    }

    async fn add_listener_retry(
        &self,
        listener: EndPoint,
        retry_config: zenoh_config::ConnectionRetryConf,
    ) {
        let mut period = retry_config.period();
        loop {
            if self.add_listener(listener.clone()).await.is_ok() {
                break;
            }
            tokio::time::sleep(period.next_duration()).await;
        }
    }

    async fn add_listener(&self, listener: EndPoint) -> ZResult<()> {
        let endpoint = listener.clone();
        match self.manager().add_listener(endpoint).await {
            Ok(listener) => tracing::debug!("Listener added: {}", listener),
            Err(err) => {
                tracing::warn!("Unable to open listener {}: {}", listener, err);
                return Err(err);
            }
        }
        Ok(())
    }

    fn print_locators(&self) {
        self.store_locators(
            self.manager().get_locators(),
            self.manager().get_locators_noloopback(),
        );
    }

    /// Stores the locator sets the node can be reached at, and reports them.
    ///
    /// The caller computes the sets, because computing them blocks the thread and
    /// doing that under these locks stalls every reader of the locator sets.
    pub(crate) fn store_locators(&self, locators: Vec<Locator>, locators_noloopback: Vec<Locator>) {
        *self.state.locators.write().unwrap() = locators;
        let mut stored = self.state.locators_noloopback.write().unwrap();
        *stored = locators_noloopback;
        for locator in &*stored {
            tracing::info!("Zenoh can be reached at: {}", locator);
        }
    }

    pub fn get_interfaces(names: &str) -> Vec<IpAddr> {
        let ifaces = Self::get_interfaces_strict(names);
        if names == "auto" && ifaces.is_empty() {
            tracing::warn!(
                "Unable to find active, non-loopback multicast interface. Will use [::]."
            );

            vec![Ipv6Addr::UNSPECIFIED.into()]
        } else {
            ifaces
        }
    }

    /// Resolves the configured multicast interface names to addresses, with no fallback.
    ///
    /// `get_interfaces` answers `auto` with `[::]` when nothing resolves, which reads
    /// the same as a host that has one usable wildcard interface. A caller that has to
    /// tell those two apart asks here.
    pub(crate) fn get_interfaces_strict(names: &str) -> Vec<IpAddr> {
        if names == "auto" {
            zenoh_util::net::get_multicast_interfaces()
        } else {
            names
                .split(',')
                .filter_map(|name| match name.trim().parse::<IpAddr>() {
                    Ok(addr) => Some(addr),
                    Err(_) => match zenoh_util::net::get_interface(name.trim()) {
                        Ok(opt_addr) => match opt_addr {
                            Some(addr) => Some(addr),
                            None => {
                                tracing::error!("Unable to find interface {}", name);
                                None
                            }
                        },
                        Err(err) => {
                            tracing::error!("Unable to find interface {}: {}", name, err);
                            None
                        }
                    },
                })
                .collect()
        }
    }

    pub async fn bind_mcast_port(
        sockaddr: &SocketAddr,
        ifaces: &[IpAddr],
        multicast_ttl: u32,
    ) -> ZResult<UdpSocket> {
        let socket = match Socket::new(Domain::for_address(*sockaddr), Type::DGRAM, None) {
            Ok(socket) => socket,
            Err(err) => {
                tracing::error!("Unable to create datagram socket: {}", err);
                bail!(err => "Unable to create datagram socket");
            }
        };
        if let Err(err) = socket.set_reuse_address(true) {
            tracing::error!("Unable to set SO_REUSEADDR option: {}", err);
            bail!(err => "Unable to set SO_REUSEADDR option");
        }
        let addr: IpAddr = {
            #[cfg(unix)]
            {
                sockaddr.ip()
            } // See UNIX Network Programmping p.212
            #[cfg(windows)]
            {
                std::net::Ipv4Addr::UNSPECIFIED.into()
            }
        };
        match socket.bind(&SocketAddr::new(addr, sockaddr.port()).into()) {
            Ok(()) => tracing::debug!("UDP port bound to {}", sockaddr),
            Err(err) => {
                tracing::error!("Unable to bind UDP port {}: {}", sockaddr, err);
                bail!(err => "Unable to bind UDP port {}", sockaddr);
            }
        }

        match sockaddr.ip() {
            IpAddr::V6(addr) => match socket.join_multicast_v6(&addr, 0) {
                Ok(()) => {
                    tracing::debug!("Joined multicast group {} on interface 0", sockaddr.ip())
                }
                Err(err) => {
                    tracing::error!(
                        "Unable to join multicast group {} on interface 0: {}",
                        sockaddr.ip(),
                        err
                    );
                    bail!(err =>
                        "Unable to join multicast group {} on interface 0",
                        sockaddr.ip()
                    )
                }
            },
            IpAddr::V4(addr) => {
                for iface in ifaces {
                    if let IpAddr::V4(iface_addr) = iface {
                        match socket.join_multicast_v4(&addr, iface_addr) {
                            Ok(()) => tracing::debug!(
                                "Joined multicast group {} on interface {}",
                                sockaddr.ip(),
                                iface_addr,
                            ),
                            Err(err) => tracing::warn!(
                                "Unable to join multicast group {} on interface {}: {}",
                                sockaddr.ip(),
                                iface_addr,
                                err,
                            ),
                        }
                    } else {
                        tracing::warn!(
                            "Cannot join IpV4 multicast group {} on IpV6 iface {}",
                            sockaddr.ip(),
                            iface
                        );
                    }
                }
            }
        }
        tracing::info!("Listening scout messages on {}", sockaddr);

        // Must set to nonblocking according to the doc of tokio
        // https://docs.rs/tokio/latest/tokio/net/struct.UdpSocket.html#notes
        socket.set_nonblocking(true)?;
        socket.set_multicast_ttl_v4(multicast_ttl)?;

        if sockaddr.is_ipv6() && multicast_ttl > 1 {
            tracing::warn!("UDP Multicast TTL has been set to a value greater than 1 on a socket bound to an IPv6 address. This might not have the desired effect");
        }

        // UdpSocket::from_std requires a runtime even though it's a sync function
        let udp_socket = zenoh_runtime::ZRuntime::Net
            .block_in_place(async { UdpSocket::from_std(socket.into()) })?;
        Ok(udp_socket)
    }

    /// Binds a scout socket for `iface`.
    ///
    /// The socket is bound to the address-family wildcard; `iface` is selected
    /// with multicast egress socket options.[^mcast-if]
    ///
    /// [^mcast-if]: [`Socket::set_multicast_if_v4`], [`Socket::set_multicast_if_v6`].
    pub(crate) fn bind_ucast_port(iface: IpAddr, multicast_ttl: u32) -> ZResult<ScoutSocket> {
        let bind_addr = match iface {
            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let socket = match Socket::new(Domain::for_address(bind_addr), Type::DGRAM, None) {
            Ok(socket) => socket,
            Err(err) => {
                tracing::warn!(
                    "Unable to create UDP scout socket for multicast interface {}: {}",
                    iface,
                    err
                );
                bail!(err => "Unable to create UDP scout socket for multicast interface {}", iface);
            }
        };

        match iface {
            IpAddr::V4(addr) => {
                if !addr.is_unspecified() {
                    socket.set_multicast_if_v4(&addr).map_err(|err| {
                        zerror!(
                            "Unable to select multicast interface {} on UDP scout socket: {}",
                            iface,
                            err
                        )
                    })?;
                }
                socket.set_multicast_ttl_v4(multicast_ttl).map_err(|err| {
                    zerror!(
                        "Unable to set multicast TTL {} on UDP scout socket for multicast interface {}: {}",
                        multicast_ttl,
                        iface,
                        err
                    )
                })?;
            }
            IpAddr::V6(addr) => {
                if !addr.is_unspecified() {
                    let idx = zenoh_util::net::get_index_of_interface(IpAddr::V6(addr))?;
                    socket.set_multicast_if_v6(idx).map_err(|err| {
                        zerror!(
                            "Unable to select multicast interface {} on UDP scout socket: {}",
                            iface,
                            err
                        )
                    })?;
                }
                socket.set_multicast_hops_v6(multicast_ttl).map_err(|err| {
                    zerror!(
                        "Unable to set multicast hop limit {} on UDP scout socket for multicast interface {}: {}",
                        multicast_ttl,
                        iface,
                        err
                    )
                })?;
            }
        }

        match socket.bind(&bind_addr.into()) {
            Ok(()) => {
                #[allow(clippy::or_fun_call)]
                let local_addr = socket
                    .local_addr()
                    .unwrap_or(bind_addr.into())
                    .as_socket()
                    .unwrap_or(bind_addr);
                tracing::debug!(
                    "UDP scout socket bound to {} for multicast interface {}",
                    local_addr,
                    iface
                );
            }
            Err(err) => {
                tracing::warn!(
                    "Unable to bind UDP scout socket to {} for multicast interface {}: {}",
                    bind_addr,
                    iface,
                    err
                );
                bail!(err => "Unable to bind UDP scout socket to {} for multicast interface {}", bind_addr, iface);
            }
        }

        // Must set to nonblocking according to the doc of tokio
        // https://docs.rs/tokio/latest/tokio/net/struct.UdpSocket.html#notes
        socket.set_nonblocking(true).map_err(|err| {
            zerror!(
                "Unable to make UDP scout socket non-blocking for multicast interface {}: {}",
                iface,
                err
            )
        })?;

        // UdpSocket::from_std requires a runtime even though it's a sync function
        let udp_socket = zenoh_runtime::ZRuntime::Net
            .block_in_place(async { UdpSocket::from_std(socket.into()) })
            .map_err(|err| {
                zerror!(
                    "Unable to create async UDP scout socket for multicast interface {}: {}",
                    iface,
                    err
                )
            })?;
        Ok(ScoutSocket {
            socket: udp_socket,
            iface,
        })
    }

    async fn spawn_peer_connector(&self, peer: EndPoint) -> ZResult<()> {
        if !LocatorInspector::default()
            .is_multicast(&peer.to_locator())
            .await?
        {
            let this = self.clone();
            let idx = self.state.start_conditions.add_peer_connector();
            let config_guard = this.config().lock();
            let config = &config_guard;
            let gossip = unwrap_or_default!(config.scouting().gossip().enabled());
            let wait_declares = unwrap_or_default!(config.open().return_conditions().declares());
            drop(config_guard);
            self.spawn(async move {
                if let Ok(zid) = this.peer_connector_retry(peer).await {
                    this.state.start_conditions.set_peer_connector_zid(idx, zid);
                }
                if !gossip && (!wait_declares || this.whatami() != WhatAmI::Peer) {
                    this.state.start_conditions.terminate_peer_connector(idx);
                }
            });
            Ok(())
        } else {
            bail!("Forbidden multicast endpoint in connect list!")
        }
    }

    async fn peers_connector_retry(
        &self,
        peers: Vec<EndPoint>,
        stop_after_first_connection: bool,
    ) -> ZResult<Vec<ZenohIdProto>> {
        async fn wait_next_peer_retry(
            peer: EndPoint,
            period: ConnectionRetryPeriod,
            wait_time: Duration,
            cancellation_token: CancellationToken,
        ) -> Option<(EndPoint, ConnectionRetryPeriod)> {
            tokio::select! {
                _ = tokio::time::sleep(wait_time) => {
                    Some((peer, period))
                }
                _ = cancellation_token.cancelled() => {
                    None
                }
            }
        }

        let mut connected_peers = Vec::new();

        let mut tasks = FuturesUnordered::new();
        let cancellation_token = self.get_cancellation_token();

        for peer in peers {
            let retry_config = self.get_connect_retry_config(&peer);
            let period = retry_config.period();
            tasks.push(wait_next_peer_retry(
                peer,
                period,
                Duration::ZERO,
                cancellation_token.clone(),
            ));
        }

        while let Some(task) = tasks.next().await {
            if let Some((peer, mut period)) = task {
                tracing::debug!(
                    "Try to connect: {:?}: global timeout: {:?}, retry: {:?}",
                    peer,
                    self.get_global_connect_timeout(),
                    self.get_connect_retry_config(&peer)
                );
                let result = self
                    .manager()
                    .open_transport_unicast(peer.clone())
                    .await
                    .and_then(|transport| -> ZResult<_> {
                        let zid = transport.get_zid()?;
                        let cb = transport
                            .get_callback()?
                            .ok_or_else(|| zerror!("Transport closed immediately"))?;
                        let session = cb
                            .as_any()
                            .downcast_ref::<super::RuntimeSession>()
                            .ok_or_else(|| zerror!("Unexpected callback type"))?;
                        zwrite!(session.endpoints).insert(peer.clone());
                        Ok(zid)
                    });

                match result {
                    Ok(zid) => {
                        tracing::debug!("Successfully connected to configured peer {}", peer);
                        connected_peers.push(zid);
                        if stop_after_first_connection {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::debug!(
                            "Unable to connect to configured peer {}! {}. Retry in {:?}.",
                            peer,
                            e,
                            period.duration()
                        );
                        let wait_time = period.next_duration();
                        tasks.push(wait_next_peer_retry(
                            peer,
                            period,
                            wait_time,
                            cancellation_token.clone(),
                        ));
                    }
                }
            }
        }
        if connected_peers.is_empty() {
            bail!("Peer connector terminated without connecting to any endpoint")
        } else {
            Ok(connected_peers)
        }
    }

    async fn peer_connector_retry(&self, peer: EndPoint) -> ZResult<ZenohIdProto> {
        self.peers_connector_retry(vec![peer], true)
            .await
            .map(|peers| peers[0])
    }

    pub(crate) async fn scout<Fut, F>(
        sockets: &[ScoutSocket],
        matcher: WhatAmIMatcher,
        mcast_addr: &SocketAddr,
        f: F,
    ) where
        F: Fn(HelloProto) -> Fut + std::marker::Send + std::marker::Sync + Clone,
        Fut: Future<Output = Loop> + std::marker::Send,
        Self: Sized,
    {
        let send = async {
            let mut delay = SCOUT_INITIAL_PERIOD;

            let scout: ScoutingMessage = Scout {
                version: zenoh_protocol::VERSION,
                what: matcher,
                zid: None,
            }
            .into();
            let mut wbuf = vec![];
            let mut writer = wbuf.writer();
            let codec = Zenoh080::new();
            codec.write(&mut writer, &scout).unwrap();

            loop {
                for socket in sockets {
                    tracing::trace!(
                        "Send {:?} to {} on interface {}",
                        scout.body,
                        mcast_addr,
                        socket.iface
                    );
                    if let Err(err) = socket.send_multicast(wbuf.as_slice(), *mcast_addr).await {
                        tracing::debug!(
                            "Unable to send {:?} to {} on interface {}: {}",
                            scout.body,
                            mcast_addr,
                            socket.iface,
                            err
                        );
                    }
                }
                tokio::time::sleep(delay).await;
                if delay * SCOUT_PERIOD_INCREASE_FACTOR <= SCOUT_MAX_PERIOD {
                    delay *= SCOUT_PERIOD_INCREASE_FACTOR;
                }
            }
        };
        let recvs = futures::future::select_all(sockets.iter().map(move |socket| {
            let f = f.clone();
            async move {
                let mut buf = vec![0; RCV_BUF_SIZE];
                let mut backoff = ScoutRecvBackoff::new();
                loop {
                    match socket.socket.recv_from(&mut buf).await {
                        Ok((n, peer)) => {
                            backoff.reset();
                            let mut reader = buf.as_slice()[..n].reader();
                            let codec = Zenoh080::new();
                            let res: Result<ScoutingMessage, DidntRead> = codec.read(&mut reader);
                            if let Ok(msg) = res {
                                tracing::trace!("Received {:?} from {}", msg.body, peer);
                                if let ScoutingBody::Hello(hello) = &msg.body {
                                    if matcher.matches(hello.whatami) {
                                        if let Loop::Break = f(hello.clone()).await {
                                            break;
                                        }
                                    } else {
                                        tracing::warn!("Received unexpected Hello: {:?}", msg.body);
                                    }
                                }
                            } else {
                                tracing::trace!(
                                    "Received unexpected UDP datagram from {}: {:?}",
                                    peer,
                                    &buf.as_slice()[..n]
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!("Error receiving UDP datagram: {}", e);
                            tokio::time::sleep(backoff.next_delay()).await;
                        }
                    }
                }
            }
            .boxed()
        }));
        tokio::select! {
            _ = send => {},
            _ = recvs => {},
        }
    }

    /// Returns `true` if a new Transport instance is established with `zid` or had already been established.
    #[must_use]
    async fn connect(&self, zid: &ZenohIdProto, scouted_locators: &[Locator]) -> bool {
        if scouted_locators.is_empty() {
            return false;
        }

        if !self.insert_pending_connection(*zid).await {
            tracing::debug!("Already connecting to {}. Ignore.", zid);
            return false;
        }

        const ERR: &str = "Unable to connect to newly scouted peer";

        let configured_locators = self
            .state
            .config
            .lock()
            .connect()
            .endpoints()
            .get(self.whatami())
            .unwrap_or(&vec![])
            .iter()
            .flat_map(|e| e.as_vec())
            .map(|e| e.to_locator())
            .collect::<HashSet<_>>();

        let locators = scouted_locators
            .iter()
            .filter(|l| !configured_locators.contains(l))
            .collect::<Vec<&Locator>>();

        if locators.is_empty() {
            tracing::debug!(
                "Already connecting to locators of {} (connect configuration). Ignore.",
                zid
            );
            self.remove_pending_connection(zid).await;
            return false;
        }

        let manager = self.manager();

        let inspector = LocatorInspector::default();
        for locator in locators {
            let is_multicast = match inspector.is_multicast(locator).await {
                Ok(im) => im,
                Err(e) => {
                    tracing::trace!("{} {} on {}: {}", ERR, zid, locator, e);
                    continue;
                }
            };

            let endpoint = locator.to_owned().into();
            let priorities = locator
                .metadata()
                .get(Metadata::PRIORITIES)
                .and_then(|p| PriorityRange::from_str(p).ok());
            let reliability = inspector.is_reliable(locator).ok();
            if !manager
                .get_transport_unicast(zid)
                .await
                .as_ref()
                .is_some_and(|t| {
                    t.get_links().is_ok_and(|ls| {
                        ls.iter().any(|l| {
                            l.priorities == priorities
                                && inspector.is_reliable(&l.dst).ok() == reliability
                        })
                    })
                })
            {
                if is_multicast {
                    match manager.open_transport_multicast(endpoint).await {
                        Ok(transport) => {
                            tracing::debug!(
                                "Successfully connected to newly scouted peer: {:?}",
                                transport
                            );
                        }
                        Err(e) => tracing::trace!("{} {} on {}: {}", ERR, zid, locator, e),
                    }
                } else {
                    match manager.open_transport_unicast_with_zid(endpoint, zid).await {
                        Ok(transport) => {
                            tracing::debug!(
                                "Successfully connected to newly scouted peer: {:?}",
                                transport
                            );
                        }
                        Err(e) => tracing::trace!("{} {} on {}: {}", ERR, zid, locator, e),
                    }
                }
            } else {
                tracing::trace!(
                    "Will not attempt to connect to {} via {}: already connected to this peer for this PriorityRange-Reliability pair",
                    zid, locator
                );
            }
        }

        self.remove_pending_connection(zid).await;

        if self.manager().get_transport_unicast(zid).await.is_none() {
            tracing::warn!(
                "Unable to connect to any locator of scouted peer {}: {:?}",
                zid,
                scouted_locators
            );
            false
        } else {
            true
        }
    }

    /// Returns `true` if a new Transport instance is established with `zid` or had already been established.
    pub async fn connect_peer(&self, zid: &ZenohIdProto, locators: &[Locator]) -> bool {
        let manager = self.manager();
        if zid != &manager.zid() {
            let has_unicast = manager.get_transport_unicast(zid).await.is_some();
            let has_multicast = {
                let mut hm = manager.get_transport_multicast(zid).await.is_some();
                for t in manager.get_transports_multicast().await {
                    if let Ok(l) = t.get_link() {
                        if let Some(g) = l.group.as_ref() {
                            hm |= locators.iter().any(|l| l == g);
                        }
                    }
                }
                hm
            };

            if !has_unicast && !has_multicast {
                tracing::debug!("Try to connect to peer {} via any of {:?}", zid, locators);
                self.connect(zid, locators).await
            } else {
                tracing::trace!("Already connected scouted peer: {}", zid);
                true
            }
        } else {
            true
        }
    }

    async fn connect_first(
        &self,
        sockets: &[ScoutSocket],
        what: WhatAmIMatcher,
        addr: &SocketAddr,
        timeout: std::time::Duration,
    ) -> ZResult<()> {
        let scout = async {
            Runtime::scout(sockets, what, addr, move |hello| async move {
                tracing::info!("Found {:?}", hello);
                if !hello.locators.is_empty() {
                    if self.connect(&hello.zid, &hello.locators).await {
                        return Loop::Break;
                    }
                } else {
                    tracing::debug!("Received Hello with no locators: {:?}", hello);
                }
                Loop::Continue
            })
            .await;
            Ok(())
        };
        let timeout = async {
            tokio::time::sleep(timeout).await;
            bail!("timeout")
        };
        tokio::select! {
            res = scout => { res },
            res = timeout => { res }
        }
    }

    async fn autoconnect_all(
        &self,
        ucast_sockets: &[ScoutSocket],
        autoconnect: AutoConnect,
        addr: &SocketAddr,
    ) {
        Runtime::scout(
            ucast_sockets,
            autoconnect.matcher(),
            addr,
            move |hello| async move {
                if hello.locators.is_empty() {
                    tracing::debug!("Received Hello with no locators: {:?}", hello);
                } else if autoconnect.should_autoconnect(hello.zid, hello.whatami) {
                    self.connect_peer(&hello.zid, &hello.locators).await;
                }
                Loop::Continue
            },
        )
        .await
    }

    /// Locators advertised in a scouting [`HelloProto`] to `peer`.
    ///
    /// Loopback peers get loopback locators; public locators intentionally
    /// exclude loopback.
    fn get_hello_locators(&self, peer: &SocketAddr) -> Vec<Locator> {
        if peer.ip().is_loopback() {
            self.get_locators()
        } else {
            self.get_locators_noloopback()
        }
    }

    /// Answers a single scout datagram, or reports that there is nothing to answer.
    ///
    /// The answer names the socket it has to leave from, because a peer expects the
    /// reply from the interface closest to it. A datagram from one of the node's own
    /// addresses is its own scout coming back and is never answered.
    pub(crate) fn scout_reply<'a>(
        &self,
        peer: SocketAddr,
        datagram: &[u8],
        local_addrs: &[SocketAddr],
        ucast_sockets: &'a [ScoutSocket],
    ) -> Option<(ScoutingMessage, &'a ScoutSocket)> {
        if local_addrs.contains(&peer) {
            tracing::trace!("Ignore UDP datagram from own socket");
            return None;
        }

        let mut reader = datagram.reader();
        let codec = Zenoh080::new();
        let res: Result<ScoutingMessage, DidntRead> = codec.read(&mut reader);
        let Ok(msg) = res else {
            tracing::trace!(
                "Received unexpected UDP datagram from {}: {:?}",
                peer,
                datagram
            );
            return None;
        };

        tracing::trace!("Received {:?} from {}", msg.body, peer);
        let ScoutingBody::Scout(Scout { what, .. }) = &msg.body else {
            return None;
        };
        if !what.matches(self.whatami()) {
            return None;
        }

        let Some(socket) = get_best_match(&peer.ip(), ucast_sockets) else {
            tracing::warn!(
                "No socket to answer the scout from {} on, dropping it",
                peer
            );
            return None;
        };

        let hello: ScoutingMessage = HelloProto {
            version: zenoh_protocol::VERSION,
            whatami: self.whatami(),
            zid: self.manager().zid(),
            locators: self.get_hello_locators(&peer),
        }
        .into();

        Some((hello, socket))
    }

    async fn responder(&self, mcast_socket: &UdpSocket, ucast_sockets: &[ScoutSocket]) {
        let mut buf = vec![0; RCV_BUF_SIZE];
        let local_addrs = scout_socket_addrs(ucast_sockets);
        let mut backoff = ScoutRecvBackoff::new();
        tracing::debug!("Waiting for UDP datagram...");
        loop {
            let (n, peer) = match mcast_socket.recv_from(&mut buf).await {
                Ok(datagram) => {
                    backoff.reset();
                    datagram
                }
                Err(err) => {
                    tracing::warn!("Error receiving UDP datagram: {}", err);
                    tokio::time::sleep(backoff.next_delay()).await;
                    continue;
                }
            };
            let Some((hello, socket)) =
                self.scout_reply(peer, &buf.as_slice()[..n], &local_addrs, ucast_sockets)
            else {
                continue;
            };

            tracing::trace!(
                "Send {:?} to {} on interface {}",
                hello.body,
                peer,
                socket.iface
            );
            let mut wbuf = vec![];
            let mut writer = wbuf.writer();
            let codec = Zenoh080::new();
            codec.write(&mut writer, &hello).unwrap();

            if let Err(err) = socket.socket.send_to(wbuf.as_slice(), peer).await {
                tracing::error!("Unable to send {:?} to {}: {}", hello.body, peer, err);
            }
        }
    }

    pub(super) fn closed_session(session: &RuntimeSession) {
        if session.runtime.is_closed() {
            return;
        }

        if zread!(session.endpoints).is_empty() {
            return;
        }
        let endpoints = session
            .runtime
            .state
            .config
            .lock()
            .connect()
            .endpoints()
            .get(session.runtime.state.whatami)
            .unwrap_or(&vec![])
            .clone();
        let mut peers = vec![];
        for peer in endpoints {
            peers.extend(peer.flatten());
        }

        if session.runtime.whatami() != WhatAmI::Client {
            let endpoints = std::mem::take(zwrite!(session.endpoints).deref_mut());
            peers.retain(|p| endpoints.contains(p));
        }

        if !peers.is_empty() {
            let runtime = session.runtime.clone();
            session.runtime.spawn(async move {
                runtime
                    .peers_connector_retry(peers, runtime.whatami() == WhatAmI::Client)
                    .await
            });
        }
    }

    pub(super) fn closed_link(session: &RuntimeSession, endpoint: EndPoint) {
        if session.runtime.whatami() == WhatAmI::Client {
            // Currently Client can have only one link,
            // so we process reconnect in closed_session
            return;
        }
        if session.runtime.is_closed() {
            return;
        }
        let endpoints = session
            .runtime
            .state
            .config
            .lock()
            .connect()
            .endpoints()
            .get(session.runtime.state.whatami)
            .unwrap_or(&vec![])
            .clone();
        let mut peers = vec![];
        for peer in endpoints {
            peers.extend(peer.flatten());
        }

        if peers.contains(&endpoint) && zwrite!(session.endpoints).remove(&endpoint) {
            let runtime = session.runtime.clone();
            session.runtime.spawn(async move {
                let _ = runtime.peer_connector_retry(endpoint).await;
            });
        }
    }

    /// Pushes the node's own locator set to every peer whose link is established.
    ///
    /// Takes the control lock and then the tables write lock, the order every other
    /// tables writer uses, so a caller already holding either of them deadlocks.
    pub(crate) fn announce_locators(&self) {
        let router = self.router();
        let _ctrl_lock = zlock!(router.tables.ctrl_lock);
        let mut wtables = zwrite!(router.tables.tables);
        for hat in wtables.hats.values_mut() {
            hat.announce_locators();
        }
    }

    #[allow(dead_code)]
    pub(crate) fn update_network(&self) -> ZResult<()> {
        let router = self.router();
        let _ctrl_lock = zlock!(router.tables.ctrl_lock);
        let mut wtables = zwrite!(router.tables.tables);
        let tables = &mut *wtables;
        for hat in tables.hats.values_mut() {
            hat.update_from_config(&router.tables, self)?;
        }
        Ok(())
    }

    pub(crate) fn get_links_info(&self) -> HashMap<ZenohIdProto, LinkInfo> {
        let router = self.router();
        let tables = zread!(router.tables.tables);
        tables
            .hats
            .values()
            .flat_map(|hat| hat.links_info().into_iter())
            .collect()
    }
}

/// Picks the socket whose address shares the longest prefix with the given one, so
/// an answer leaves from the interface closest to whoever asked.
fn get_best_match<'a>(addr: &IpAddr, sockets: &'a [ScoutSocket]) -> Option<&'a ScoutSocket> {
    fn octets(addr: &IpAddr) -> Vec<u8> {
        match addr {
            IpAddr::V4(addr) => addr.octets().to_vec(),
            IpAddr::V6(addr) => addr.octets().to_vec(),
        }
    }
    fn matching_octets(addr: &IpAddr, sock: &ScoutSocket) -> usize {
        octets(addr)
            .iter()
            .zip(octets(&sock.iface))
            .map(|(x, y)| x.cmp(&y))
            .position(|ord| ord != std::cmp::Ordering::Equal)
            .unwrap_or_else(|| octets(addr).len())
    }
    sockets
        .iter()
        .max_by(|sock1, sock2| matching_octets(addr, sock1).cmp(&matching_octets(addr, sock2)))
}

/// The addresses scout sockets answer from. The sockets are bound to the wildcard
/// address, so each one is named by its interface address and its bound port.
fn scout_socket_addrs(sockets: &[ScoutSocket]) -> Vec<SocketAddr> {
    sockets
        .iter()
        .filter_map(|sock| {
            sock.socket
                .local_addr()
                .ok()
                .map(|addr| SocketAddr::new(sock.iface, addr.port()))
        })
        .collect()
}

/// Retry delay for a failing read on a scout socket. A socket that errors on every
/// read would otherwise spin its receive loop at full speed for as long as it lives.
struct ScoutRecvBackoff(Duration);

impl ScoutRecvBackoff {
    const fn new() -> Self {
        Self(SCOUT_RECV_ERROR_INITIAL_PERIOD)
    }

    /// Returns the delay to wait before the next read, and grows it towards the bound.
    fn next_delay(&mut self) -> Duration {
        let delay = self.0;
        self.0 = (delay * SCOUT_PERIOD_INCREASE_FACTOR).min(SCOUT_RECV_ERROR_MAX_PERIOD);

        delay
    }

    fn reset(&mut self) {
        self.0 = SCOUT_RECV_ERROR_INITIAL_PERIOD;
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::sync::{Mutex, MutexGuard, PoisonError};

    use super::*;
    use crate::{net::runtime::RuntimeBuilder, Config};
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn empty_scouted_locators_do_not_leave_connection_pending() {
        let runtime = RuntimeBuilder::new(Config::default())
            .build()
            .await
            .unwrap();
        let zid = ZenohIdProto::rand();

        assert!(!runtime.connect(&zid, &[]).await);
        assert!(!runtime.remove_pending_connection(&zid).await);
    }

    #[tokio::test]
    async fn configured_scouted_locator_does_not_leave_connection_pending() {
        let mut config = Config::default();
        config
            .insert_json5("connect/endpoints", r#"["tcp/localhost:12345"]"#)
            .unwrap();
        let runtime = RuntimeBuilder::new(config).build().await.unwrap();
        let zid = ZenohIdProto::rand();
        let locator = "tcp/localhost:12345".parse().unwrap();

        assert!(!runtime.connect(&zid, &[locator]).await);
        assert!(!runtime.remove_pending_connection(&zid).await);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn scout_sender_can_multicast_on_loopback() {
        let iface = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let group = IpAddr::V4(Ipv4Addr::new(224, 0, 0, 224));
        let rx = Runtime::bind_mcast_port(&SocketAddr::new(group, 0), &[iface], 1)
            .await
            .unwrap();
        let dst = SocketAddr::new(group, rx.local_addr().unwrap().port());
        let tx = Runtime::bind_ucast_port(iface, 1).unwrap();
        let payload = b"zenoh loopback multicast regression";

        let sent = tx.send_multicast(payload, dst).await.unwrap();
        assert_eq!(sent, payload.len());

        let mut buf = [0; 256];
        let (n, _) = timeout(Duration::from_secs(2), rx.recv_from(&mut buf))
            .await
            .expect("timed out waiting for loopback multicast packet")
            .unwrap();
        assert_eq!(&buf[..n], payload);
    }

    #[cfg(unix)]
    #[test]
    fn auto_interfaces_fall_back_to_unspecified_when_none_resolve() {
        let _guard = lock_interface_cache();

        zenoh_util::net::replace_interfaces(Vec::new());
        assert_eq!(
            Runtime::get_interfaces("auto"),
            vec![IpAddr::from(Ipv6Addr::UNSPECIFIED)]
        );

        zenoh_util::net::refresh_interfaces();
    }

    #[test]
    fn explicit_interfaces_that_resolve_to_nothing_yield_no_address() {
        assert!(Runtime::get_interfaces("no-such-interface-42").is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn the_strict_interface_lookup_never_falls_back() {
        let _guard = lock_interface_cache();

        zenoh_util::net::replace_interfaces(Vec::new());
        assert!(Runtime::get_interfaces_strict("auto").is_empty());
        assert!(Runtime::get_interfaces_strict("no-such-interface-42").is_empty());

        zenoh_util::net::refresh_interfaces();
    }

    #[test]
    fn scout_recv_backoff_grows_to_the_bound_and_resets() {
        let mut backoff = ScoutRecvBackoff::new();
        assert_eq!(backoff.next_delay(), SCOUT_RECV_ERROR_INITIAL_PERIOD);
        assert_eq!(backoff.next_delay(), SCOUT_RECV_ERROR_INITIAL_PERIOD * 2);
        assert_eq!(backoff.next_delay(), SCOUT_RECV_ERROR_INITIAL_PERIOD * 4);

        for _ in 0..10 {
            backoff.next_delay();
        }
        assert_eq!(backoff.next_delay(), SCOUT_RECV_ERROR_MAX_PERIOD);
        assert_eq!(backoff.next_delay(), SCOUT_RECV_ERROR_MAX_PERIOD);

        backoff.reset();
        assert_eq!(backoff.next_delay(), SCOUT_RECV_ERROR_INITIAL_PERIOD);
    }

    /// The interface cache is process global, so no two of these tests may run at once.
    #[cfg(unix)]
    static INTERFACE_CACHE_LOCK: Mutex<()> = Mutex::new(());

    #[cfg(unix)]
    fn lock_interface_cache() -> MutexGuard<'static, ()> {
        INTERFACE_CACHE_LOCK
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}
