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
#![cfg(feature = "internal")]

use std::{
    any::Any,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use tracing::Level;
use tracing_capture::{CaptureLayer, SharedStorage};
use tracing_subscriber::layer::SubscriberExt;
use zenoh_buffers::reader::HasReader;
use zenoh_codec::RCodec;
use zenoh_config::{EndPoint, ModeDependentValue, WhatAmIMatcher, ZenohId};
use zenoh_core::{zread, ztimeout, zwrite};
use zenoh_keyexpr::keyexpr;
use zenoh_protocol::{
    common::ZExtBody,
    core::{Bound, Locator, WhatAmI, ZenohIdProto},
    network::{oam::id::OAM_LINKSTATE, NetworkBodyMut, NetworkMessageMut},
};
use zenoh_transport::{multicast::TransportMulticast, unicast::TransportUnicast};

use crate::{
    init_log_from_env_or,
    net::{
        codec::Zenoh080Routing,
        protocol::linkstate::{LinkState, LinkStateList},
        routing::{
            hat::{
                peer::{Hat as PeerHat, Net, NetMut},
                router::Hat as RouterHat,
            },
            interceptor::*,
        },
        runtime::Runtime,
    },
    open, Config, Session,
};

const TIMEOUT: Duration = Duration::from_secs(60);
/// How long link establishment, and the link-state exchange it causes, is given.
const LINK_SETTLE: Duration = Duration::from_secs(3);
/// How long the announce is given to reach the receivers.
const ANNOUNCE_SETTLE: Duration = Duration::from_secs(1);

/// Announces once and checks what each receiver took in because of it.
///
/// Draining the receivers immediately before the announce is what makes the capture
/// discriminating: link establishment causes a link-state exchange of its own, which
/// already carries the sender's zid and its locators, and would otherwise answer the
/// payload checks in place of the announce under test.
macro_rules! assert_announce_reaches_every_receiver {
    ($sender:expr, $sender_id:expr, $receivers:expr) => {{
        let receivers = $receivers;
        let runtime = $sender.static_runtime().unwrap();
        let sender_zid = ZenohIdProto::from($sender_id);
        let locators = runtime.get_locators();
        let transports_before = transport_zids(runtime).await;
        let sns_before = receivers
            .iter()
            .map(|(receiver, _)| stored_node(receiver, &sender_zid).unwrap().0)
            .collect::<Vec<_>>();

        for (_, capture) in receivers {
            capture.lock().unwrap().clear();
        }

        announce_on_planes(runtime);
        tokio::time::sleep(ANNOUNCE_SETTLE).await;

        for ((receiver, capture), sn_before) in receivers.iter().zip(sns_before) {
            let captured = capture.lock().unwrap();
            assert_eq!(captured.len(), 1, "one send on the established link");
            let link_states = &captured[0].link_states;
            assert_eq!(link_states.len(), 1, "only the node's own entry");
            assert_eq!(link_states[0].zid, Some(sender_zid));
            assert_eq!(link_states[0].locators, Some(locators.clone()));
            assert_eq!(
                link_states[0].links.len(),
                receivers.len(),
                "the sender's own link set"
            );
            drop(captured);

            let (sn_after, stored_locators) = stored_node(receiver, &sender_zid).unwrap();
            assert!(sn_after > sn_before, "the receiver applied the announce");
            assert_eq!(stored_locators, Some(locators.clone()));
        }

        assert_eq!(
            transport_zids(runtime).await,
            transports_before,
            "no dial attempt"
        );
        assert!(
            runtime
                .manager()
                .get_transports_multicast()
                .await
                .is_empty(),
            "no multicast emission"
        );
    }};
}

/// Parks the node's own entry at the value a peer can drive it to, then keeps sending.
macro_rules! assert_self_sequence_numbers_saturate {
    ($sender:expr) => {{
        let runtime = $sender.static_runtime().unwrap();
        let transport = transports(runtime)
            .await
            .into_iter()
            .next()
            .expect("the sender has a link");
        let peer_zid = transport.get_zid().unwrap();
        let planes = self_sequence_numbers(runtime).len();
        assert!(planes > 0, "the sender has a link-state plane");

        set_self_sequence_numbers(runtime, u64::MAX);

        announce_on_planes(runtime);
        assert_eq!(
            self_sequence_numbers(runtime),
            vec![u64::MAX; planes],
            "the announce neither panicked nor wrapped"
        );

        with_planes(runtime, |net| {
            net.add_link(transport.clone(), Bound::North);
        });
        assert_eq!(
            self_sequence_numbers(runtime),
            vec![u64::MAX; planes],
            "add_link neither panicked nor wrapped"
        );

        with_planes(runtime, |net| {
            net.remove_link(&peer_zid);
        });
        assert_eq!(
            self_sequence_numbers(runtime),
            vec![u64::MAX; planes],
            "remove_link neither panicked nor wrapped"
        );
    }};
}

/// Feeds the node a link-state naming its own zid, which is what a peer sends to park
/// the node's own sequence number at the top of the space and silence it for good.
macro_rules! assert_a_peer_cannot_park_the_self_entry {
    ($victim:expr, $victim_id:expr, $receiver:expr) => {{
        let runtime = $victim.static_runtime().unwrap();
        let victim_zid = ZenohIdProto::from($victim_id);
        let peer_zid = transport_zids(runtime)
            .await
            .into_iter()
            .next()
            .expect("the victim has a link");
        let before = self_sequence_numbers(runtime);
        assert!(!before.is_empty(), "the victim has a link-state plane");

        with_planes(runtime, |net| {
            if let NetMut::Network(net) = net {
                net.link_states(vec![own_entry_link_state(victim_zid, u64::MAX)], peer_zid);
            }
        });

        assert_eq!(
            self_sequence_numbers(runtime),
            before,
            "a peer wrote the node's own entry"
        );

        // One announce lands even from a parked entry, because the receiver has not
        // seen that sequence number yet. A second one is what a node whose own number
        // can no longer rise cannot deliver.
        assert_runtime_announce_reaches_receiver!($victim, $victim_id, $receiver);
        assert_runtime_announce_reaches_receiver!($victim, $victim_id, $receiver);
    }};
}

/// Feeds the node two link states about itself and checks which of them is reported at
/// `warn`.
///
/// Both are refused. What separates them is the sequence number: one at or below the
/// node's own is what the graph exchange on a fresh link hands back routinely and could
/// never have moved the entry, while one above it is the only shape that ever wrote.
macro_rules! assert_only_a_harmful_self_link_state_warns {
    ($victim:expr, $victim_id:expr) => {{
        let runtime = $victim.static_runtime().unwrap();
        let victim_zid = ZenohIdProto::from($victim_id);
        let peer_zid = transport_zids(runtime)
            .await
            .into_iter()
            .next()
            .expect("the victim has a link");
        let own_sn = *self_sequence_numbers(runtime)
            .first()
            .expect("the victim has a link-state plane");

        let routine = refusal_levels(runtime, victim_zid, own_sn, peer_zid);
        assert!(!routine.is_empty(), "the routine link state was refused");
        assert!(
            routine.iter().all(|level| *level == Level::DEBUG),
            "a routine graph exchange warned: {routine:?}"
        );

        let harmful = refusal_levels(runtime, victim_zid, u64::MAX, peer_zid);
        assert!(
            harmful.iter().any(|level| *level == Level::WARN),
            "the entry-parking link state did not warn: {harmful:?}"
        );
    }};
}

/// Announces from the runtime and checks that the receiver applied what arrived.
///
/// This is what proves the path from the runtime down to the plane: the hat method
/// carrying it has a default no-op body, so a hat that fails to override it, or
/// overrides it on the wrong plane, compiles cleanly and is silent at runtime.
macro_rules! assert_runtime_announce_reaches_receiver {
    ($sender:expr, $sender_id:expr, $receiver:expr) => {{
        let runtime = $sender.static_runtime().unwrap();
        let sender_zid = ZenohIdProto::from($sender_id);
        let locators = runtime.get_locators();
        let sn_before = stored_node($receiver, &sender_zid).unwrap().0;

        // The runtime entry point takes the tables locks itself, so it is called with
        // no guard of ours alive.
        runtime.announce_locators();
        tokio::time::sleep(ANNOUNCE_SETTLE).await;

        let (sn_after, stored_locators) = stored_node($receiver, &sender_zid).unwrap();
        assert!(sn_after > sn_before, "the receiver applied the announce");
        assert_eq!(stored_locators, Some(locators));
    }};
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gossip_announce_pushes_only_the_local_entry() {
    init_log_from_env_or("error");

    let sender_id = ZenohId::from_str("a1").unwrap();
    let first_id = ZenohId::from_str("a2").unwrap();
    let second_id = ZenohId::from_str("a3").unwrap();

    let first_capture = register_link_state_capture(first_id);
    let second_capture = register_link_state_capture(second_id);

    let sender = ztimeout!(open(peer_config(sender_id, &[33101], &[], false))).unwrap();
    let first = ztimeout!(open(peer_config(first_id, &[], &[33101], false))).unwrap();
    let second = ztimeout!(open(peer_config(second_id, &[], &[33101], false))).unwrap();
    tokio::time::sleep(LINK_SETTLE).await;

    assert_announce_reaches_every_receiver!(
        &sender,
        sender_id,
        &[(&first, &first_capture), (&second, &second_capture)]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn router_announce_pushes_only_the_local_entry() {
    init_log_from_env_or("error");

    let sender_id = ZenohId::from_str("b1").unwrap();
    let first_id = ZenohId::from_str("b2").unwrap();
    let second_id = ZenohId::from_str("b3").unwrap();

    let first_capture = register_link_state_capture(first_id);
    let second_capture = register_link_state_capture(second_id);

    let sender = ztimeout!(open(router_config(sender_id, &[33111], &[]))).unwrap();
    let first = ztimeout!(open(router_config(first_id, &[], &[33111]))).unwrap();
    let second = ztimeout!(open(router_config(second_id, &[], &[33111]))).unwrap();
    tokio::time::sleep(LINK_SETTLE).await;

    assert_announce_reaches_every_receiver!(
        &sender,
        sender_id,
        &[(&first, &first_capture), (&second, &second_capture)]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gossip_self_sequence_number_saturates() {
    init_log_from_env_or("error");

    let sender = ztimeout!(open(peer_config(
        ZenohId::from_str("c1").unwrap(),
        &[33121],
        &[],
        false
    )))
    .unwrap();
    let _peer = ztimeout!(open(peer_config(
        ZenohId::from_str("c2").unwrap(),
        &[],
        &[33121],
        false
    )))
    .unwrap();
    tokio::time::sleep(LINK_SETTLE).await;

    assert_self_sequence_numbers_saturate!(&sender);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn router_self_sequence_number_saturates() {
    init_log_from_env_or("error");

    let sender = ztimeout!(open(router_config(
        ZenohId::from_str("d1").unwrap(),
        &[33131],
        &[]
    )))
    .unwrap();
    let _peer = ztimeout!(open(router_config(
        ZenohId::from_str("d2").unwrap(),
        &[],
        &[33131]
    )))
    .unwrap();
    tokio::time::sleep(LINK_SETTLE).await;

    assert_self_sequence_numbers_saturate!(&sender);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn router_runtime_announce_reaches_the_receiver() {
    init_log_from_env_or("error");

    let sender_id = ZenohId::from_str("e1").unwrap();
    let sender = ztimeout!(open(router_config(sender_id, &[33141], &[]))).unwrap();
    let receiver = ztimeout!(open(router_config(
        ZenohId::from_str("e2").unwrap(),
        &[],
        &[33141]
    )))
    .unwrap();
    tokio::time::sleep(LINK_SETTLE).await;

    assert_runtime_announce_reaches_receiver!(&sender, sender_id, &receiver);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gossip_runtime_announce_reaches_the_receiver() {
    init_log_from_env_or("error");

    let sender_id = ZenohId::from_str("f1").unwrap();
    let sender = ztimeout!(open(peer_config(sender_id, &[33151], &[], false))).unwrap();
    let receiver = ztimeout!(open(peer_config(
        ZenohId::from_str("f2").unwrap(),
        &[],
        &[33151],
        false
    )))
    .unwrap();
    tokio::time::sleep(LINK_SETTLE).await;

    assert_runtime_announce_reaches_receiver!(&sender, sender_id, &receiver);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multihop_runtime_announce_reaches_the_receiver() {
    init_log_from_env_or("error");

    let sender_id = ZenohId::from_str("11").unwrap();
    let sender = ztimeout!(open(peer_config(sender_id, &[33161], &[], true))).unwrap();
    let receiver = ztimeout!(open(peer_config(
        ZenohId::from_str("12").unwrap(),
        &[],
        &[33161],
        true
    )))
    .unwrap();
    tokio::time::sleep(LINK_SETTLE).await;

    assert_runtime_announce_reaches_receiver!(&sender, sender_id, &receiver);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_cannot_park_the_routers_own_entry() {
    init_log_from_env_or("error");

    let victim_id = ZenohId::from_str("21").unwrap();
    let victim = ztimeout!(open(router_config(victim_id, &[33171], &[]))).unwrap();
    let receiver = ztimeout!(open(router_config(
        ZenohId::from_str("22").unwrap(),
        &[],
        &[33171]
    )))
    .unwrap();
    tokio::time::sleep(LINK_SETTLE).await;

    assert_a_peer_cannot_park_the_self_entry!(&victim, victim_id, &receiver);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_a_harmful_self_link_state_warns() {
    init_log_from_env_or("error");

    let victim_id = ZenohId::from_str("23").unwrap();
    let victim = ztimeout!(open(router_config(victim_id, &[33181], &[]))).unwrap();
    let _peer = ztimeout!(open(router_config(
        ZenohId::from_str("24").unwrap(),
        &[],
        &[33181]
    )))
    .unwrap();
    tokio::time::sleep(LINK_SETTLE).await;

    assert_only_a_harmful_self_link_state_warns!(&victim, victim_id);
}

/// Captured link-state payloads, one vector per receiving node.
type LinkStateCapture = Arc<Mutex<Vec<LinkStateList>>>;

/// Makes every link-state message the node with `zid` receives observable.
///
/// Call it before that node is built: the factory map is read once, when the node
/// creates its interceptor chain.
fn register_link_state_capture(zid: ZenohId) -> LinkStateCapture {
    let capture: LinkStateCapture = Arc::new(Mutex::new(Vec::new()));
    let factory_capture = capture.clone();
    let factories = move || -> Vec<InterceptorFactory> {
        vec![Box::new(LinkStateCaptureFactory {
            capture: factory_capture.clone(),
        })]
    };
    crate::net::routing::interceptor::tests::ID_TO_INTERCEPTOR_FACTORIES
        .lock()
        .unwrap()
        .insert(zid, Box::new(factories));

    capture
}

/// Injects one link state about the node itself and returns the level of every refusal
/// it logged.
fn refusal_levels(
    runtime: &Runtime,
    victim_zid: ZenohIdProto,
    sn: u64,
    peer_zid: ZenohIdProto,
) -> Vec<Level> {
    let storage = SharedStorage::default();
    let subscriber = tracing_subscriber::registry().with(CaptureLayer::new(&storage));

    // A thread-local default, so the capture sees the injection - which runs on this
    // thread - and nothing the rest of the process logs meanwhile.
    tracing::subscriber::with_default(subscriber, || {
        with_planes(runtime, |net| {
            if let NetMut::Network(net) = net {
                net.link_states(vec![own_entry_link_state(victim_zid, sn)], peer_zid);
            }
        });
    });

    let captured = storage.lock();

    captured
        .all_events()
        .filter(|event| {
            event
                .message()
                .is_some_and(|message| message.contains("about this node itself"))
        })
        .map(|event| *event.metadata().level())
        .collect()
}

/// A link-state a peer has no business sending: it names the receiving node itself,
/// with an address the node does not hold.
fn own_entry_link_state(victim_zid: ZenohIdProto, sn: u64) -> LinkState {
    LinkState {
        psid: 0,
        sn,
        zid: Some(victim_zid),
        whatami: Some(WhatAmI::Router),
        locators: Some(vec![Locator::from_str("tcp/192.0.2.1:7447").unwrap()]),
        links: vec![],
        link_weights: None,
        is_gateway: false,
    }
}

fn peer_config(zid: ZenohId, listen: &[u16], connect: &[u16], multihop: bool) -> Config {
    let mut config = node_config(zid, WhatAmI::Peer, listen, connect);
    config.scouting.gossip.set_multihop(Some(multihop)).unwrap();

    config
}

fn router_config(zid: ZenohId, listen: &[u16], connect: &[u16]) -> Config {
    node_config(zid, WhatAmI::Router, listen, connect)
}

fn node_config(zid: ZenohId, mode: WhatAmI, listen: &[u16], connect: &[u16]) -> Config {
    let mut config = Config::default();
    config.set_id(Some(zid)).unwrap();
    config.set_mode(Some(mode)).unwrap();
    config.listen.endpoints.set(endpoints(listen)).unwrap();
    config.connect.endpoints.set(endpoints(connect)).unwrap();
    config.scouting.multicast.set_enabled(Some(false)).unwrap();
    config.scouting.gossip.set_enabled(Some(true)).unwrap();
    // Without this the receivers dial each other as soon as they learn about one
    // another, and the sender stops being the only source of link-state traffic.
    config
        .scouting
        .gossip
        .set_autoconnect(Some(ModeDependentValue::Unique(WhatAmIMatcher::empty())))
        .unwrap();

    config
}

fn endpoints(ports: &[u16]) -> Vec<EndPoint> {
    ports
        .iter()
        .map(|port| format!("tcp/127.0.0.1:{port}").parse().unwrap())
        .collect()
}

/// Announces on every link-state plane the node holds, under one held tables guard.
///
/// A plane entry point takes no lock of its own, and the borrow it needs lives only
/// as long as the guard, so the guard stays alive across the call.
fn announce_on_planes(runtime: &Runtime) {
    with_planes(runtime, |net| match net {
        NetMut::Gossip(net) => net.announce_locators(),
        NetMut::Network(net) => net.announce_locators(),
    });
}

fn set_self_sequence_numbers(runtime: &Runtime, sn: u64) {
    with_planes(runtime, |net| match net {
        NetMut::Gossip(net) => net.graph[net.idx].sn = sn,
        NetMut::Network(net) => net.graph[net.idx].sn = sn,
    });
}

fn self_sequence_numbers(runtime: &Runtime) -> Vec<u64> {
    let mut sns = Vec::new();
    with_planes(runtime, |net| match net {
        NetMut::Gossip(net) => sns.push(net.graph[net.idx].sn),
        NetMut::Network(net) => sns.push(net.graph[net.idx].sn),
    });

    sns
}

/// What the node currently holds for `zid`, on the plane that knows it.
fn stored_node(session: &Session, zid: &ZenohIdProto) -> Option<(u64, Option<Vec<Locator>>)> {
    let mut found = None;
    with_planes_ref(session.static_runtime().unwrap(), |net| {
        let node = match net {
            Net::Gossip(net) => net
                .graph
                .node_weights()
                .find(|node| node.zid == *zid)
                .map(|node| (node.sn, node.locators.clone())),
            Net::Network(net) => net
                .graph
                .node_weights()
                .find(|node| node.zid == *zid)
                .map(|node| (node.sn, node.locators.clone())),
        };
        if node.is_some() {
            found = node;
        }
    });

    found
}

fn with_planes(runtime: &Runtime, mut f: impl FnMut(NetMut<'_>)) {
    let router = runtime.router();
    let mut wtables = zwrite!(router.tables.tables);
    for hat in wtables.hats.values_mut() {
        let hat = hat.as_any_mut();
        if hat.is::<PeerHat>() {
            match hat.downcast_mut::<PeerHat>().unwrap() {
                PeerHat::Gossip {
                    gossip: Some(gossip),
                } => f(NetMut::Gossip(gossip)),
                PeerHat::Network {
                    network: Some(network),
                    ..
                } => f(NetMut::Network(network)),
                _ => {}
            }
        } else if hat.is::<RouterHat>() {
            f(NetMut::Network(
                hat.downcast_mut::<RouterHat>().unwrap().net_mut(),
            ));
        }
    }
}

fn with_planes_ref(runtime: &Runtime, mut f: impl FnMut(Net<'_>)) {
    let router = runtime.router();
    let rtables = zread!(router.tables.tables);
    for hat in rtables.hats.values() {
        let hat = hat.as_any();
        if hat.is::<PeerHat>() {
            if let Some(net) = hat.downcast_ref::<PeerHat>().unwrap().net() {
                f(net);
            }
        } else if hat.is::<RouterHat>() {
            f(Net::Network(hat.downcast_ref::<RouterHat>().unwrap().net()));
        }
    }
}

async fn transports(runtime: &Runtime) -> Vec<TransportUnicast> {
    runtime.manager().get_transports_unicast().await
}

async fn transport_zids(runtime: &Runtime) -> Vec<ZenohIdProto> {
    let mut zids = transports(runtime)
        .await
        .iter()
        .filter_map(|transport| transport.get_zid().ok())
        .collect::<Vec<_>>();
    zids.sort();

    zids
}

struct LinkStateCaptureFactory {
    capture: LinkStateCapture,
}

impl InterceptorFactoryTrait for LinkStateCaptureFactory {
    fn new_transport_unicast(
        &self,
        _transport: &TransportUnicast,
    ) -> (Option<IngressInterceptor>, Option<EgressInterceptor>) {
        (
            Some(Box::new(LinkStateCaptureInterceptor {
                capture: self.capture.clone(),
            })),
            None,
        )
    }

    fn new_transport_multicast(
        &self,
        _transport: &TransportMulticast,
    ) -> Option<EgressInterceptor> {
        None
    }

    fn new_peer_multicast(&self, _transport: &TransportMulticast) -> Option<IngressInterceptor> {
        None
    }
}

struct LinkStateCaptureInterceptor {
    capture: LinkStateCapture,
}

impl InterceptorTrait for LinkStateCaptureInterceptor {
    fn compute_keyexpr_cache(&self, _key_expr: &keyexpr) -> Option<Box<dyn Any + Send + Sync>> {
        None
    }

    fn intercept(&self, msg: &mut NetworkMessageMut, _ctx: &mut dyn InterceptorContext) -> bool {
        if let NetworkBodyMut::OAM(oam) = &msg.body {
            if oam.id == OAM_LINKSTATE {
                // The routing plane takes this buffer out of the message, so reading
                // it here has to leave it in place.
                if let ZExtBody::ZBuf(buf) = &oam.body {
                    let codec = Zenoh080Routing::new();
                    if let Ok(list) = codec.read(&mut buf.clone().reader()) {
                        self.capture.lock().unwrap().push(list);
                    }
                }
            }
        }

        true
    }
}
