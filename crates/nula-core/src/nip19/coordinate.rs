// Copyright (c) 2026 QNTX <https://qntx.fun>
// Distributed under the MIT or Apache-2.0 license.

//! `naddr` — TLV-encoded coordinate `(identifier, author, kind, [relays])`.

use crate::event::{Coordinate, Kind};
use crate::key::PublicKey;
use crate::types::RelayUrl;

/// `naddr`-style address: a [`Coordinate`] plus relay hints.
///
/// Wire form is `bech32("naddr", TLV[(0, identifier), (1, relay)*, (2, author), (3, kind)])`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Nip19Coordinate {
    /// `(kind, author, identifier)` address of the replaceable event.
    pub coordinate: Coordinate,
    /// Hints of relays that store the event.
    pub relays: Vec<RelayUrl>,
}

impl Nip19Coordinate {
    /// Construct an `naddr` coordinate.
    #[must_use]
    pub fn new(
        identifier: impl Into<String>,
        author: PublicKey,
        kind: Kind,
        relays: impl IntoIterator<Item = RelayUrl>,
    ) -> Self {
        Self {
            coordinate: Coordinate::new(kind, author, identifier),
            relays: relays.into_iter().collect(),
        }
    }

    /// Build from a pre-existing [`Coordinate`] and a list of relay hints.
    #[must_use]
    pub fn from_coordinate(
        coordinate: Coordinate,
        relays: impl IntoIterator<Item = RelayUrl>,
    ) -> Self {
        Self {
            coordinate,
            relays: relays.into_iter().collect(),
        }
    }

    /// Borrow the inner [`Kind`].
    #[must_use]
    pub const fn kind(&self) -> Kind {
        self.coordinate.kind
    }

    /// Borrow the inner author public key.
    #[must_use]
    pub const fn author(&self) -> &PublicKey {
        &self.coordinate.author
    }

    /// Borrow the inner identifier.
    #[must_use]
    pub fn identifier(&self) -> &str {
        &self.coordinate.identifier
    }
}
