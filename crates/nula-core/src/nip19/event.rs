// Copyright (c) 2026 QNTX <https://qntx.fun>
// Distributed under the MIT or Apache-2.0 license.

//! `nevent` — TLV-encoded `(event_id, [relays], author?, kind?)`.

use crate::event::{EventId, Kind};
use crate::key::PublicKey;
use crate::types::RelayUrl;

/// Event reference: an event id plus optional relay hints, author, and kind.
///
/// Wire form is `bech32("nevent", TLV[(0, id), (1, relay)*, (2, author)?, (3, kind)?])`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Nip19Event {
    /// SHA-256 event id being referenced.
    pub event_id: EventId,
    /// Optional author hint.
    pub author: Option<PublicKey>,
    /// Optional kind hint.
    pub kind: Option<Kind>,
    /// Hints of relays that store the event.
    pub relays: Vec<RelayUrl>,
}

impl Nip19Event {
    /// Construct an event reference with no hints.
    #[must_use]
    pub const fn new(event_id: EventId) -> Self {
        Self {
            event_id,
            author: None,
            kind: None,
            relays: Vec::new(),
        }
    }

    /// Add an author hint.
    #[must_use]
    pub const fn author(mut self, author: PublicKey) -> Self {
        self.author = Some(author);
        self
    }

    /// Add a kind hint.
    #[must_use]
    pub const fn kind(mut self, kind: Kind) -> Self {
        self.kind = Some(kind);
        self
    }

    /// Add relay hints.
    #[must_use]
    pub fn relays(mut self, relays: impl IntoIterator<Item = RelayUrl>) -> Self {
        self.relays.extend(relays);
        self
    }
}
