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

//! The scouting tag extension on Scout and Hello: exact bytes, messages
//! without a tag unchanged, and decoders that predate the tag skip it.

use zenoh_buffers::{
    reader::{HasReader, Reader},
    writer::HasWriter,
    ZBuf,
};
use zenoh_codec::{RCodec, WCodec, Zenoh080};
use zenoh_protocol::{
    common::ZExtUnknown,
    core::{whatami::WhatAmIMatcher, WhatAmI, ZenohIdProto},
    scouting::{hello, id, scout, HelloProto, Scout},
    VERSION,
};

/// A tag's length: 16 bytes, a UUID.
const TAG_LEN: usize = 16;
/// The tag every test carries.
const TAG: [u8; TAG_LEN] = [0xA5; TAG_LEN];
/// The tag extension's header byte: ID 0x2, ZBuf encoding (0b10 << 5), not
/// mandatory, no extension after it.
const TAG_HEADER: u8 = 0x42;
/// The same header with the "another extension follows" bit.
const TAG_HEADER_MORE: u8 = 0xC2;
/// A tag's length as the ZBuf encoding writes it: one varint byte.
const TAG_LEN_BYTE: u8 = TAG_LEN as u8;
/// An extension no decoder knows: ID 0x1, unit encoding, not mandatory.
const UNKNOWN_UNIT: u8 = 0x01;
/// The same with the "another extension follows" bit.
const UNKNOWN_UNIT_MORE: u8 = 0x81;
/// The message header's extension flag.
const Z: u8 = 0x80;
/// A Scout's flags byte for "what = peer", without a zid.
const WHAT_PEER: u8 = 0b010;
/// The zid of every Hello: fixed, as `ZenohIdProto::default()` is random.
const ZID: [u8; ZenohIdProto::MAX_SIZE] = [0x5A; ZenohIdProto::MAX_SIZE];

fn tag() -> scout::ext::Tag {
    scout::ext::Tag::new(ZBuf::from(TAG))
}

fn encode_scout(message: &Scout) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut writer = bytes.writer();
    Zenoh080::new().write(&mut writer, message).unwrap();
    bytes
}

fn encode_hello(message: &HelloProto) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut writer = bytes.writer();
    Zenoh080::new().write(&mut writer, message).unwrap();
    bytes
}

fn scout(ext_tag: Option<scout::ext::Tag>) -> Scout {
    Scout {
        version: VERSION,
        what: WhatAmIMatcher::try_from(WHAT_PEER).unwrap(),
        zid: None,
        ext_tag,
    }
}

fn hello(ext_tag: Option<hello::ext::Tag>) -> HelloProto {
    HelloProto {
        version: VERSION,
        whatami: WhatAmI::Peer,
        zid: ZenohIdProto::try_from(ZID.as_slice()).unwrap(),
        locators: Vec::new(),
        ext_tag,
    }
}

/// The tag's bytes on the wire, after the message body.
fn tag_bytes(header: u8) -> Vec<u8> {
    let mut bytes = vec![header, TAG_LEN_BYTE];
    bytes.extend_from_slice(&TAG);
    bytes
}

#[test]
fn a_scout_without_a_tag_is_encoded_as_before() {
    let bytes = encode_scout(&scout(None));
    assert_eq!(bytes, [id::SCOUT, VERSION, WHAT_PEER]);
    let decoded: Scout = Zenoh080::new().read(&mut bytes.reader()).unwrap();
    assert_eq!(decoded, scout(None));
}

#[test]
fn a_tagged_scout_carries_the_tag_after_its_body() {
    let bytes = encode_scout(&scout(Some(tag())));
    let mut expected = vec![id::SCOUT | Z, VERSION, WHAT_PEER];
    expected.extend(tag_bytes(TAG_HEADER));
    assert_eq!(bytes, expected);

    let mut reader = bytes.reader();
    let decoded: Scout = Zenoh080::new().read(&mut reader).unwrap();
    assert_eq!(decoded, scout(Some(tag())));
    assert!(!reader.can_read());
}

#[test]
fn a_hello_without_a_tag_is_encoded_as_before_and_a_tagged_one_round_trips() {
    let plain = encode_hello(&hello(None));
    assert_eq!(plain[0], id::HELLO);
    let decoded: HelloProto = Zenoh080::new().read(&mut plain.reader()).unwrap();
    assert_eq!(decoded, hello(None));

    let tagged = encode_hello(&hello(Some(tag())));
    assert_eq!(tagged[0], id::HELLO | Z);
    assert_eq!(tagged[..plain.len()][1..], plain[1..]);
    assert_eq!(tagged[plain.len()..], tag_bytes(TAG_HEADER)[..]);
    let mut reader = tagged.reader();
    let decoded: HelloProto = Zenoh080::new().read(&mut reader).unwrap();
    assert_eq!(decoded, hello(Some(tag())));
    assert!(!reader.can_read());
}

#[test]
fn a_decoder_that_predates_the_tag_skips_it() {
    // What a decoder without the tag does after the body: read each extension
    // as unknown and drop it.
    let bytes = encode_scout(&scout(Some(tag())));
    let expected_body = [id::SCOUT | Z, VERSION, WHAT_PEER];
    let mut body = expected_body.map(|_| 0);
    let mut reader = bytes.reader();
    reader.read_exact(&mut body).unwrap();
    assert_eq!(body, expected_body);
    let (unknown, more): (ZExtUnknown, bool) = Zenoh080::new().read(&mut reader).unwrap();
    assert!(!unknown.is_mandatory());
    assert!(!more);
    assert!(!reader.can_read());
}

#[test]
fn the_tag_is_found_among_extensions_no_decoder_knows() {
    let mut after = vec![id::SCOUT | Z, VERSION, WHAT_PEER];
    after.extend(tag_bytes(TAG_HEADER_MORE));
    after.push(UNKNOWN_UNIT);

    let mut before = vec![id::SCOUT | Z, VERSION, WHAT_PEER, UNKNOWN_UNIT_MORE];
    before.extend(tag_bytes(TAG_HEADER));

    for bytes in [after, before] {
        let mut reader = bytes.reader();
        let decoded: Scout = Zenoh080::new().read(&mut reader).unwrap();
        assert_eq!(decoded, scout(Some(tag())));
        assert!(!reader.can_read());
    }
}
