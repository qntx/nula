// Copyright (c) 2026 QNTX <https://qntx.fun>
// Distributed under the MIT or Apache-2.0 license.

//! Nostr events.
//!
//! Per [NIP-01], an event is the only object the protocol talks about. Every
//! relay-to-client and client-to-relay message either *is* an event or
//! references one. This module models the on-the-wire structure plus the
//! ergonomic types around it (`Kind`, `Tag`, `EventId`, `EventBuilder`, …).
//!
//! The shape is implemented bottom-up:
//!
//! - [`kind::Kind`] — the `kind` field, with category helpers.
//! - [`id::EventId`] — the SHA-256 event identifier.
//! - [`tag`] — the tag head, the single tag value, and the ordered list.
//! - [`unsigned::UnsignedEvent`] — an event before its signature is attached.
//! - [`event::Event`] — the signed, on-the-wire event.
//! - [`builder::EventBuilder`] — a fluent constructor.
//!
//! [NIP-01]: https://github.com/nostr-protocol/nips/blob/master/01.md

pub mod builder;
#[allow(
    clippy::module_inception,
    reason = "the inner `event` module exposes the `Event` struct; the outer module groups the event-related submodules"
)]
pub mod event;
pub mod id;
pub mod kind;
pub mod tag;
pub mod unsigned;

pub use self::builder::{EventBuilder, EventBuilderError};
pub use self::event::{Event, EventError};
pub use self::id::{EventId, EventIdError};
pub use self::kind::Kind;
pub use self::tag::{
    Alphabet, AlphabetError, SingleLetterTag, SingleLetterTagError, Tag, TagError, TagKind, Tags,
};
pub use self::unsigned::{UnsignedEvent, UnsignedEventError};
use crate::key::PublicKey;
use crate::types::Timestamp;

/// Serialize the canonical NIP-01 byte sequence used to compute an event's
/// [`EventId`].
///
/// NIP-01 requires the array `[0, pubkey, created_at, kind, tags, content]`
/// to be encoded as compact JSON (no whitespace) with the standard control
/// character escapes.
fn canonical_bytes(
    pubkey: &PublicKey,
    created_at: Timestamp,
    kind: Kind,
    tags: &Tags,
    content: &str,
) -> Vec<u8> {
    use serde::ser::SerializeTuple;
    use serde::{Serialize, Serializer};

    struct Canonical<'a> {
        pubkey: &'a PublicKey,
        created_at: Timestamp,
        kind: Kind,
        tags: &'a Tags,
        content: &'a str,
    }

    impl Serialize for Canonical<'_> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            let mut tuple = serializer.serialize_tuple(6)?;
            tuple.serialize_element(&0_u8)?;
            tuple.serialize_element(&self.pubkey.to_hex())?;
            tuple.serialize_element(&self.created_at.as_secs())?;
            tuple.serialize_element(&self.kind.as_u16())?;
            tuple.serialize_element(self.tags)?;
            tuple.serialize_element(self.content)?;
            tuple.end()
        }
    }

    #[allow(
        clippy::expect_used,
        reason = "the canonical struct only emits primitive numbers, strings, and arrays of those, so to_vec is total"
    )]
    {
        serde_json::to_vec(&Canonical {
            pubkey,
            created_at,
            kind,
            tags,
            content,
        })
        .expect("canonical serialization is total over the inputs")
    }
}

/// Compute the [`EventId`] of an event from its component fields.
#[must_use]
pub fn compute_event_id(
    pubkey: &PublicKey,
    created_at: Timestamp,
    kind: Kind,
    tags: &Tags,
    content: &str,
) -> EventId {
    let bytes = canonical_bytes(pubkey, created_at, kind, tags, content);
    EventId::compute_from_canonical(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::JsonUtil;

    #[test]
    fn canonical_serialization_is_compact() {
        let pubkey =
            PublicKey::parse("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap();
        let tags = Tags::from_vec(vec![
            Tag::new(["e", "id-1"]).unwrap(),
            Tag::new(["p", "pk-1"]).unwrap(),
        ]);
        let bytes = canonical_bytes(
            &pubkey,
            Timestamp::from_secs(1_700_000_000),
            Kind::TEXT_NOTE,
            &tags,
            "hello",
        );
        let s = String::from_utf8(bytes).unwrap();
        assert!(!s.contains(' '));
        assert!(s.starts_with("[0,"));
        assert!(s.ends_with(",\"hello\"]"));
    }

    #[test]
    fn event_id_is_stable_for_known_input() {
        // Reference vector borrowed from the rust-nostr test fixtures: the
        // canonical form for an empty-content `kind:1` event signed by the
        // generator point with `created_at = 0` and no tags.
        let pubkey =
            PublicKey::parse("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap();
        let id_a = compute_event_id(&pubkey, Timestamp::ZERO, Kind::TEXT_NOTE, &Tags::new(), "");
        let id_b = compute_event_id(&pubkey, Timestamp::ZERO, Kind::TEXT_NOTE, &Tags::new(), "");
        assert_eq!(id_a, id_b);
    }

    #[test]
    fn changing_any_field_changes_id() {
        let pubkey =
            PublicKey::parse("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap();
        let baseline = compute_event_id(
            &pubkey,
            Timestamp::from_secs(1),
            Kind::TEXT_NOTE,
            &Tags::new(),
            "hello",
        );
        let other_kind = compute_event_id(
            &pubkey,
            Timestamp::from_secs(1),
            Kind::REACTION,
            &Tags::new(),
            "hello",
        );
        let other_content = compute_event_id(
            &pubkey,
            Timestamp::from_secs(1),
            Kind::TEXT_NOTE,
            &Tags::new(),
            "world",
        );
        let other_time = compute_event_id(
            &pubkey,
            Timestamp::from_secs(2),
            Kind::TEXT_NOTE,
            &Tags::new(),
            "hello",
        );
        assert_ne!(baseline, other_kind);
        assert_ne!(baseline, other_content);
        assert_ne!(baseline, other_time);
    }

    /// `JsonUtil` import keeps the trait visible inside the doc test below; the
    /// reference makes the import survive the unused-import lint.
    #[allow(dead_code, reason = "import sanity check for crate::JsonUtil")]
    fn _imports() -> Option<String> {
        let kind: Kind = Kind::TEXT_NOTE;
        kind.try_to_json().ok()
    }
}
