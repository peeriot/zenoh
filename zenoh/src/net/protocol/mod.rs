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
pub(crate) mod gossip;
pub(crate) mod linkstate;
pub(crate) mod network;

pub(crate) const ROUTERS_NET_NAME: &str = "[Routers Network]";

/// Advances a node's own link-state sequence number.
///
/// It saturates rather than wraps, because a remote peer can park the local entry at
/// `u64::MAX` through the receive path: an overflow would take the send path down, and
/// a wrap would make every peer drop everything the node sends from then on.
pub(crate) fn advance_self_sn(sn: &mut u64) {
    *sn = sn.saturating_add(1);
}
