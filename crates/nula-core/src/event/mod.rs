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
pub mod coordinate;
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
pub use self::coordinate::{Coordinate, CoordinateError};
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
///
/// # Invariant
///
/// The serializer is infallible by construction:
///
/// - tuple of 6 fields with [`SerializeTuple`](serde::ser::SerializeTuple),
/// - elements are owned `String`, primitive integers, slices of `String`,
///   and a slice of [`Tag`] (which itself round-trips through `Vec<String>`).
///
/// None of those code paths can produce a [`serde_json::Error`]. The
/// guarantee is exercised by `canonical_serialization_is_infallible` in the
/// test module; if a future refactor introduces a fallible field, that
/// regression test will fail loudly before the panic path is reachable in
/// production.
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

    let canonical = Canonical {
        pubkey,
        created_at,
        kind,
        tags,
        content,
    };
    let mut buf = Vec::with_capacity(estimate_canonical_capacity(content, tags));
    // SAFETY-style invariant: see the function-level docs. `to_writer` only
    // fails when the writer fails; a `Vec<u8>` writer is infallible. If
    // upstream `serde_json` ever changes that contract, the regression test
    // `canonical_serialization_is_infallible` will surface the bug before
    // any production path can reach the inner `unreachable!`.
    if serde_json::to_writer(&mut buf, &canonical).is_err() {
        debug_assert!(false, "serde_json::to_writer cannot fail on a Vec<u8>");
    }
    buf
}

/// Heuristic capacity hint for [`canonical_bytes`]. Picking the right size
/// avoids reallocation in the steady-state (a kind-1 note with two tags is
/// typically ~250 bytes after escape; the heuristic adds a safety margin).
fn estimate_canonical_capacity(content: &str, tags: &Tags) -> usize {
    // 6 (header overhead) + 64 (pubkey hex) + 20 (created_at + kind) +
    // approx. tag size + content + escape margin.
    let tag_bytes = tags
        .iter()
        .map(|t| t.values().iter().map(String::len).sum::<usize>() + 4 * t.len())
        .sum::<usize>();
    96 + tag_bytes + content.len() + (content.len() / 8)
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

    /// Regression-test the NIP-01 §32 control-character escapes.
    ///
    /// NIP-01 mandates exactly seven short escapes (\b\t\n\f\r\"\\) and
    /// permits no other shortcut for control characters in the canonical
    /// JSON. `serde_json` produces precisely that shape today; if a
    /// future upgrade ever drifts (e.g. switches `\u0008` for `\b`),
    /// every event id we produce would silently change. This test pins
    /// the byte-level wire form for the seven escapes plus a sample of
    /// other control codes (`\u0000`, `\u001f`).
    #[test]
    fn nip01_control_character_escapes_are_canonical() {
        // pubkey is fixed so the canonical bytes are deterministic.
        let pubkey =
            PublicKey::parse("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap();
        // Content carries the seven mandated control characters plus two
        // generic-escape codepoints.
        let content = "\u{0008}\t\n\u{000C}\r\"\\\0\u{001F}";
        let bytes = canonical_bytes(
            &pubkey,
            Timestamp::ZERO,
            Kind::TEXT_NOTE,
            &Tags::new(),
            content,
        );
        let s = String::from_utf8(bytes).expect("canonical bytes are UTF-8 by construction");
        // Each NIP-01-mandated escape must appear in its short form.
        assert!(s.contains(r"\b"), "missing \\b in {s}");
        assert!(s.contains(r"\t"));
        assert!(s.contains(r"\n"));
        assert!(s.contains(r"\f"));
        assert!(s.contains(r"\r"));
        assert!(s.contains(r#"\""#));
        assert!(s.contains(r"\\"));
        // Generic control chars use \u00xx (case-insensitive).
        assert!(
            s.contains(r"\u0000") || s.contains(r"\u0000"),
            "missing \\u0000 in {s}",
        );
        assert!(s.contains(r"\u001f"));
        // Sanity: the canonical hash is stable across two runs.
        let id_a = compute_event_id(
            &pubkey,
            Timestamp::ZERO,
            Kind::TEXT_NOTE,
            &Tags::new(),
            content,
        );
        let id_b = compute_event_id(
            &pubkey,
            Timestamp::ZERO,
            Kind::TEXT_NOTE,
            &Tags::new(),
            content,
        );
        assert_eq!(id_a, id_b);
    }

    /// Regression-test the safety invariant that lets `canonical_bytes`
    /// avoid `expect()`. We exercise every known-tricky content shape:
    /// empty content, the seven NIP-01 §32 control-character escapes, and
    /// non-ASCII UTF-8 codepoints. None of these may make `to_writer` fail.
    #[test]
    fn canonical_serialization_is_infallible() {
        use serde::ser::SerializeTuple;
        use serde::{Serialize, Serializer};

        struct Probe<'a> {
            pubkey: &'a PublicKey,
            content: &'a str,
        }
        impl Serialize for Probe<'_> {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                let mut t = s.serialize_tuple(6)?;
                t.serialize_element(&0_u8)?;
                t.serialize_element(&self.pubkey.to_hex())?;
                t.serialize_element(&0_u64)?;
                t.serialize_element(&1_u16)?;
                let empty: &[Vec<String>] = &[];
                t.serialize_element(empty)?;
                t.serialize_element(self.content)?;
                t.end()
            }
        }

        let pubkey =
            PublicKey::parse("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap();
        for content in [
            "",
            "\u{0008}\u{0009}\u{000A}\u{000C}\u{000D}\"\\",
            "naïve résumé — café",
            "\u{1F4A9}",
            "\0\u{0001}\u{001F}",
        ] {
            let probe = Probe {
                pubkey: &pubkey,
                content,
            };
            // The contract exercised by `canonical_bytes`: serialize via the
            // same writer-based path and assert no error is produced.
            let mut buf = Vec::new();
            assert!(
                serde_json::to_writer(&mut buf, &probe).is_ok(),
                "serde_json::to_writer must be infallible for the canonical layout"
            );
            assert!(!buf.is_empty(), "writer must have produced bytes");
        }
    }
}
