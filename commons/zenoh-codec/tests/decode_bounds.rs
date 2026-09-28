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

//! A count or length on the wire above what the message holds is refused
//! before it sizes an allocation. Before the bound, one such scouting datagram
//! aborted the process that decoded it.

use zenoh_buffers::{
    reader::{HasReader, Reader},
    writer::HasWriter,
    ZBuf,
};
use zenoh_codec::{RCodec, WCodec, Zenoh080, Zenoh080Bounded};
use zenoh_protocol::{
    core::{Locator, WhatAmI, ZenohIdProto},
    scouting::{HelloProto, ScoutingMessage},
    VERSION,
};

/// A count or length no allocator can serve: 2^45 elements.
const HUGE: usize = 1 << 45;
/// The zid of the Hello: fixed, as `ZenohIdProto::default()` is random.
const ZID: [u8; ZenohIdProto::MAX_SIZE] = [0x5A; ZenohIdProto::MAX_SIZE];
/// A Hello's bytes before its zid: header, version, flags.
const HELLO_PREFIX_LEN: usize = 3;
/// A few bytes, for a reader that holds less than a length claims.
const SHORT: [u8; 4] = [0; 4];

/// `value` as the codec writes a count or length.
fn varint(value: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    Zenoh080::new().write(&mut bytes.writer(), value).unwrap();
    bytes
}

/// A Hello with one locator, and where its locator count sits.
fn hello_with_one_locator() -> (Vec<u8>, usize) {
    let message: ScoutingMessage = HelloProto {
        version: VERSION,
        whatami: WhatAmI::Peer,
        zid: ZenohIdProto::try_from(ZID.as_slice()).unwrap(),
        locators: vec!["tls/127.0.0.1:7447".parse::<Locator>().unwrap()],
        ext_tag: None,
    }
    .into();
    let mut bytes = Vec::new();
    Zenoh080::new()
        .write(&mut bytes.writer(), &message)
        .unwrap();
    let count_at = HELLO_PREFIX_LEN + ZID.len();
    assert_eq!(bytes[count_at], 1, "the locator count follows the zid");
    (bytes, count_at)
}

#[test]
fn a_hello_whose_locator_count_exceeds_the_datagram_is_refused() {
    let (mut bytes, count_at) = hello_with_one_locator();
    let decoded: Result<ScoutingMessage, _> = Zenoh080::new().read(&mut bytes.as_slice().reader());
    assert!(decoded.is_ok(), "the well-formed Hello decodes");

    bytes.truncate(count_at);
    bytes.extend(varint(HUGE));
    let decoded: Result<ScoutingMessage, _> = Zenoh080::new().read(&mut bytes.as_slice().reader());
    assert!(decoded.is_err());
}

#[test]
fn a_byte_string_longer_than_its_message_is_refused() {
    let mut bytes = varint(HUGE);
    bytes.extend(SHORT);
    let decoded: Result<Vec<u8>, _> =
        Zenoh080Bounded::<u64>::new().read(&mut bytes.as_slice().reader());
    assert!(decoded.is_err());
}

#[test]
fn a_slice_longer_than_what_a_reader_holds_is_refused() {
    let mut slice = SHORT.as_slice().reader();
    assert!(slice.read_zslice(HUGE).is_err());
    assert_eq!(slice.remaining(), SHORT.len(), "nothing was consumed");

    let buffer = ZBuf::from(SHORT.to_vec());
    let mut zbuf = buffer.reader();
    assert!(zbuf.read_zslice(HUGE).is_err());
    assert_eq!(zbuf.remaining(), SHORT.len(), "nothing was consumed");
}
