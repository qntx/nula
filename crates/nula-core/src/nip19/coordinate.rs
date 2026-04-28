// Copyright (c) 2026 QNTX <https://qntx.fun>
// Distributed under the MIT or Apache-2.0 license.

//! `naddr` — TLV-encoded coordinate `(identifier, author, kind, [relays])`.

use crate::event::Kind;
use crate::key::PublicKey;
use crate::types::RelayUrl;

/// Replaceable-event coordinate (a.k.a. "address" in NIP-01 §parameterized
/// replaceable events): an `(identifier, author, kind)` triple uniquely
/// identifies a parameterized replaceable event.
///
/// Wire form is `bech32("naddr", TLV[(0, identifier), (1, relay)*, (2, author), (3, kind)])`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Nip19Coordinate {
    /// `d`-tag identifier of the parameterized replaceable event.
    pub identifier: String,
    /// Author public key.
    pub author: PublicKey,
    /// Event kind.
    pub kind: Kind,
    /// Hints of relays that store the event.
    pub relays: Vec<RelayUrl>,
}

impl Nip19Coordinate {
    /// Construct a coordinate.
    #[must_use]
    pub fn new(
        identifier: impl Into<String>,
        author: PublicKey,
        kind: Kind,
        relays: impl IntoIterator<Item = RelayUrl>,
    ) -> Self {
        Self {
            identifier: identifier.into(),
            author,
            kind,
            relays: relays.into_iter().collect(),
        }
    }
}
