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
use std::{str::FromStr, time::Duration};

use iroh::Watcher;
use zenoh_link_commons::{LinkManagerUnicastTrait, NewLinkChannelSender};
use zenoh_link_iroh::{
    derive_secret_key, IrohEndpoint, IrohEndpointConfig, LinkManagerUnicastIroh,
};
use zenoh_protocol::core::EndPoint;

async fn endpoint(seed: u8) -> IrohEndpoint {
    IrohEndpoint::bind(IrohEndpointConfig {
        secret_key: derive_secret_key(&[seed; 16]),
        relays: false,
    })
    .await
    .unwrap()
}

/// Wait until `ep` has a direct address, then return its full address.
async fn dialable(ep: &IrohEndpoint) -> iroh::EndpointAddr {
    let mut w = ep.endpoint().watch_addr();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let a = w.get();
            if a.ip_addrs().next().is_some() {
                return a;
            }
            w.updated().await.unwrap();
        }
    })
    .await
    .unwrap()
}

fn manager(
    ep: IrohEndpoint,
) -> (
    LinkManagerUnicastIroh,
    flume::Receiver<zenoh_link_commons::LinkUnicast>,
) {
    let (tx, rx): (NewLinkChannelSender, _) = flume::unbounded();
    (LinkManagerUnicastIroh::new(tx, ep), rx)
}

#[tokio::test(flavor = "multi_thread")]
async fn dial_by_id_and_exchange_bytes() {
    let (a, b) = (endpoint(1).await, endpoint(2).await);
    let (ma, accepted) = manager(a.clone());
    let (mb, _) = manager(b.clone());

    let locator = ma
        .new_listener(EndPoint::from_str("iroh/auto").unwrap())
        .await
        .unwrap();
    assert_eq!(locator.to_string(), format!("iroh/{}", a.id()));

    b.set_addr(dialable(&a).await);
    let dialled = mb
        .new_link(EndPoint::from_str(&format!("iroh/{}", a.id())).unwrap())
        .await
        .unwrap();
    dialled.write_all(b"hello", None).await.unwrap();

    let inbound = tokio::time::timeout(Duration::from_secs(10), accepted.recv_async())
        .await
        .unwrap()
        .unwrap();
    let mut buf = [0u8; 5];
    inbound.read_exact(&mut buf, None).await.unwrap();
    assert_eq!(&buf, b"hello");

    assert_eq!(dialled.get_dst().to_string(), format!("iroh/{}", a.id()));
    assert_eq!(inbound.get_dst().to_string(), format!("iroh/{}", b.id()));
    assert!(dialled.is_streamed() && dialled.is_reliable());
    assert_eq!(
        *inbound.get_auth_id(),
        zenoh_link_commons::LinkAuthId::Iroh(b.id().to_string())
    );

    inbound.write_all(b"back!", None).await.unwrap();
    dialled.read_exact(&mut buf, None).await.unwrap();
    assert_eq!(&buf, b"back!");

    dialled.close().await.unwrap();
    a.close().await;
    b.close().await;
}

#[tokio::test]
async fn listener_rejects_a_foreign_id_and_a_second_listener() {
    let a = endpoint(3).await;
    let other = derive_secret_key(&[4; 16]).public();
    let (ma, _) = manager(a.clone());
    assert!(ma
        .new_listener(EndPoint::from_str(&format!("iroh/{other}")).unwrap())
        .await
        .is_err());
    ma.new_listener(EndPoint::from_str(&format!("iroh/{}", a.id())).unwrap())
        .await
        .unwrap();
    assert!(ma
        .new_listener(EndPoint::from_str("iroh/auto").unwrap())
        .await
        .is_err());
    // An empty address (only expressible with metadata) is rejected too.
    let (fresh, _) = manager(a.clone());
    assert!(fresh
        .new_listener(EndPoint::from_str("iroh/?a=b").unwrap())
        .await
        .is_err());
    a.close().await;
}

#[tokio::test]
async fn dialling_garbage_is_an_error() {
    let a = endpoint(5).await;
    let (ma, _) = manager(a.clone());
    assert!(ma
        .new_link(EndPoint::from_str("iroh/not-an-id").unwrap())
        .await
        .is_err());
    a.close().await;
}
