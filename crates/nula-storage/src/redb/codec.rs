//! On-disk event codec.
//!
//! Every event payload stored in the redb `events` table carries a
//! one-byte version prefix followed by the `postcard`-serialised
//! [`Event`]. The version prefix lets future schema changes be
//! detected at read time without forcing a coordinated downgrade —
//! readers older than the current `STORED_EVENT_VERSION` simply error
//! out with [`crate::redb::Error::UnsupportedCodecVersion`].
//!
//! The codec is deliberately opaque: it round-trips through the
//! upstream `Event` serde impls and adds nothing of its own beyond the
//! version byte. If a future deserialisation needs to read a superset
//! of `Event` (e.g. an indexing hint), that lives in a `StoredEventVN`
//! newtype with its own version byte, not by shoe-horning extra fields
//! onto the wire shape.

use nula_core::event::{Event, EventId, Kind, SingleLetterTag};
use nula_core::filter::MatchableEvent;
use nula_core::types::Timestamp;
use nula_core::util::hex;

use crate::redb::error::Error;

/// Current on-disk format identifier. Bump any time the encoded shape
/// changes in a way old readers cannot understand.
///
/// We start at 1 (not 0) so a zero-byte payload — which a corrupt read
/// could plausibly hand back — is unambiguously invalid.
pub(crate) const STORED_EVENT_VERSION: u8 = 1;

/// Encode `event` for storage.
///
/// Layout: `[version: u8] [postcard(event): &[u8]]`.
pub(crate) fn encode(event: &Event) -> Result<Vec<u8>, Error> {
    let body = postcard::to_allocvec(event).map_err(Error::Encode)?;
    let mut buf = Vec::with_capacity(body.len() + 1);
    buf.push(STORED_EVENT_VERSION);
    buf.extend_from_slice(&body);
    Ok(buf)
}

/// Decode a stored payload back into an [`Event`].
pub(crate) fn decode(bytes: &[u8]) -> Result<Event, Error> {
    let (version, rest) = bytes.split_first().ok_or(Error::EmptyPayload)?;
    match *version {
        STORED_EVENT_VERSION => postcard::from_bytes(rest).map_err(Error::Decode),
        other => Err(Error::UnsupportedCodecVersion(other)),
    }
}

/// Decode only the `created_at` timestamp from a stored payload.
///
/// Conflict-resolution and deletion paths (`resolve_addressable`,
/// `apply_deletion`) need an incumbent event's `created_at` and nothing
/// else. Decoding the full [`Event`] there re-parses the 32-byte x-only
/// pubkey into a curve point — a curve operation orders of magnitude
/// more expensive than the id copy — purely to read an 8-byte integer.
///
/// The stored body is `postcard(Event)`, whose field order is
/// `(id, pubkey, created_at, kind, tags, content, sig)`. postcard encodes
/// structs and tuples identically (sequential, no length prefix), so a
/// 3-tuple reads exactly the leading three fields and
/// [`postcard::take_from_bytes`] stops there. `id` and `pubkey` are
/// stored as hex strings (`collect_str`), so reading them as `&str`
/// borrows from the buffer with no allocation and — crucially — no curve
/// parse.
pub(crate) fn decode_created_at(bytes: &[u8]) -> Result<Timestamp, Error> {
    let (version, rest) = bytes.split_first().ok_or(Error::EmptyPayload)?;
    if *version != STORED_EVENT_VERSION {
        return Err(Error::UnsupportedCodecVersion(*version));
    }
    let ((_id, _pubkey, created_at), _tail) =
        postcard::take_from_bytes::<(&str, &str, Timestamp)>(rest).map_err(Error::Decode)?;
    Ok(created_at)
}

/// A zero-parse projection of a stored event holding exactly the fields
/// [`nula_core::Filter::match_event`] inspects.
///
/// Matching against this instead of a full [`Event`] skips, for every
/// candidate a query *rejects*, the curve pubkey point parse and the
/// content / signature allocations. Surviving candidates are then
/// materialised with [`decode`].
///
/// `id` / `pubkey` are decoded from their stored hex form to raw bytes (a
/// cheap hex pass, **not** a curve parse); `tags` borrow directly from
/// the mapped buffer; `content` and `sig` are skipped entirely.
#[derive(Debug)]
pub(crate) struct EventView<'a> {
    id: [u8; 32],
    pubkey: [u8; 32],
    created_at: Timestamp,
    kind: Kind,
    tags: Vec<Vec<&'a str>>,
}

/// Decode the match-relevant prefix of a stored payload without parsing
/// the pubkey point or allocating `content` / signature.
///
/// `Event`'s postcard layout is `(id, pubkey, created_at, kind, tags,
/// content, sig)`; a 5-tuple reads the leading match fields and
/// [`postcard::take_from_bytes`] stops there. `id` / `pubkey` borrow as
/// `&str` (their hex form) and `tags` borrow straight from the buffer, so
/// no curve parse or allocation occurs.
pub(crate) fn decode_match_view(bytes: &[u8]) -> Result<EventView<'_>, Error> {
    let (version, rest) = bytes.split_first().ok_or(Error::EmptyPayload)?;
    if *version != STORED_EVENT_VERSION {
        return Err(Error::UnsupportedCodecVersion(*version));
    }
    let ((id_hex, pubkey_hex, created_at, kind, tags), _tail) =
        postcard::take_from_bytes::<(&str, &str, Timestamp, Kind, Vec<Vec<&str>>)>(rest)
            .map_err(Error::Decode)?;
    let mut id = [0u8; 32];
    hex::decode_to_slice(id_hex, &mut id)
        .map_err(|_| Error::CorruptRecord("event id is not hex"))?;
    let mut pubkey = [0u8; 32];
    hex::decode_to_slice(pubkey_hex, &mut pubkey)
        .map_err(|_| Error::CorruptRecord("pubkey is not hex"))?;
    Ok(EventView {
        id,
        pubkey,
        created_at,
        kind,
        tags,
    })
}

impl EventView<'_> {
    /// The event id (decoded from the stored hex; no curve parse).
    pub(crate) const fn id(&self) -> EventId {
        EventId::from_byte_array(self.id)
    }

    /// The authored timestamp.
    pub(crate) const fn created_at(&self) -> Timestamp {
        self.created_at
    }
}

impl MatchableEvent for EventView<'_> {
    fn matchable_id(&self) -> EventId {
        self.id()
    }

    fn matchable_pubkey_bytes(&self) -> [u8; 32] {
        self.pubkey
    }

    fn matchable_kind(&self) -> Kind {
        self.kind
    }

    fn matchable_created_at(&self) -> Timestamp {
        self.created_at()
    }

    fn matchable_has_tag(&self, letter: SingleLetterTag, values: &[String]) -> bool {
        // Mirrors `Tags::build_indexes`: a tag satisfies a `#<letter>`
        // constraint when its head (index 0) parses as `letter` and its
        // value (index 1) is one of `values`.
        self.tags.iter().any(|tag| {
            tag.first()
                .copied()
                .and_then(|head| head.parse::<SingleLetterTag>().ok())
                == Some(letter)
                && tag
                    .get(1)
                    .copied()
                    .is_some_and(|content| values.iter().any(|value| value == content))
        })
    }

    fn matchable_expiration(&self) -> Option<Timestamp> {
        // Mirrors `nip40::parse_expiration`: read the first `expiration`
        // tag's value (index 1); a missing or non-integer value yields
        // `None` (treated as "no deadline").
        let tag = self
            .tags
            .iter()
            .find(|tag| tag.first().copied() == Some("expiration"))?;
        tag.get(1)
            .copied()?
            .parse::<u64>()
            .ok()
            .map(Timestamp::from_secs)
    }
}

#[cfg(test)]
mod tests {
    use nula_core::event::{Alphabet, EventBuilder, Tag};
    use nula_core::filter::{Filter, MatchEventOptions};
    use nula_core::key::Keys;
    use nula_core::types::Timestamp;

    use super::*;

    fn fixture() -> Event {
        let keys = Keys::generate().expect("os rng");
        EventBuilder::text_note("round-trip")
            .created_at(Timestamp::from_secs(1_700_000_000))
            .sign_with_keys(&keys)
            .expect("sign")
    }

    #[test]
    fn round_trip_preserves_event() {
        let event = fixture();
        let bytes = encode(&event).expect("encode");
        let decoded = decode(&bytes).expect("decode");
        assert_eq!(decoded, event);
    }

    #[test]
    fn unknown_version_byte_is_rejected() {
        let event = fixture();
        let mut bytes = encode(&event).expect("encode");
        // Bump the version prefix to an unsupported value. The first
        // byte is always present because `encode` writes it up front,
        // so the indexed write is bounds-safe.
        #[expect(
            clippy::indexing_slicing,
            reason = "encode always emits a non-empty buffer; the first byte is the version prefix"
        )]
        {
            bytes[0] = 0xFF;
        }
        let err = decode(&bytes).expect_err("must reject unknown version");
        assert!(matches!(err, Error::UnsupportedCodecVersion(0xFF)));
    }

    #[test]
    fn empty_payload_is_rejected() {
        let err = decode(&[]).expect_err("empty payload");
        assert!(matches!(err, Error::EmptyPayload));
    }

    fn fixture_with_tags() -> Event {
        let keys = Keys::generate().expect("os rng");
        EventBuilder::text_note("content past the header fields")
            .created_at(Timestamp::from_secs(1_710_123_456))
            .tag(Tag::new(["e", &"a".repeat(64)]).expect("e tag"))
            .tag(Tag::new(["p", &"b".repeat(64)]).expect("p tag"))
            .sign_with_keys(&keys)
            .expect("sign")
    }

    #[test]
    fn decode_created_at_matches_full_decode() {
        // A record with tags + content exercises the take-prefix path:
        // the tuple must read exactly `created_at` and ignore everything
        // after it.
        for event in [fixture(), fixture_with_tags()] {
            let bytes = encode(&event).expect("encode");
            let ts = decode_created_at(&bytes).expect("decode created_at");
            assert_eq!(ts, event.created_at);
            assert_eq!(ts, decode(&bytes).expect("full decode").created_at);
        }
    }

    #[test]
    fn decode_created_at_rejects_empty() {
        let err = decode_created_at(&[]).expect_err("empty payload");
        assert!(matches!(err, Error::EmptyPayload));
    }

    #[test]
    fn decode_created_at_rejects_unknown_version() {
        let event = fixture();
        let mut bytes = encode(&event).expect("encode");
        #[expect(
            clippy::indexing_slicing,
            reason = "encode always emits a non-empty buffer; the first byte is the version prefix"
        )]
        {
            bytes[0] = 0xFF;
        }
        let err = decode_created_at(&bytes).expect_err("must reject unknown version");
        assert!(matches!(err, Error::UnsupportedCodecVersion(0xFF)));
    }

    #[test]
    fn match_view_agrees_with_owned_event() {
        // The borrowed projection must return the same verdict as the
        // fully-decoded owned event for every filter shape `match_event`
        // inspects — otherwise queries that match on the view would
        // silently diverge from a full-decode baseline.
        let keys = Keys::generate().expect("os rng");
        let other = Keys::generate().expect("os rng");
        let event = EventBuilder::text_note("hello")
            .created_at(Timestamp::from_secs(1_700_000_000))
            .tag(Tag::new(["t", "rust"]).expect("t tag"))
            .tag(Tag::new(["e", &"a".repeat(64)]).expect("e tag"))
            .sign_with_keys(&keys)
            .expect("sign");
        let bytes = encode(&event).expect("encode");
        let opts = MatchEventOptions::default();
        let filters = [
            Filter::new(),
            Filter::new().id(event.id),
            Filter::new().id(EventId::from_byte_array([0u8; 32])),
            Filter::new().author(*keys.public_key()),
            Filter::new().author(*other.public_key()),
            Filter::new().kind(Kind::TEXT_NOTE),
            Filter::new().kind(Kind::new(7)),
            Filter::new().since(Timestamp::from_secs(1_699_999_999)),
            Filter::new().until(Timestamp::from_secs(1_699_999_999)),
            Filter::new().custom_tag(SingleLetterTag::lowercase(Alphabet::T), "rust"),
            Filter::new().custom_tag(SingleLetterTag::lowercase(Alphabet::T), "nostr"),
            Filter::new().custom_tag(SingleLetterTag::lowercase(Alphabet::E), "a".repeat(64)),
        ];
        for filter in filters {
            let view = decode_match_view(&bytes).expect("view");
            assert_eq!(
                filter.match_event(&event, opts),
                filter.match_event(&view, opts),
                "verdict mismatch for {filter:?}",
            );
        }
    }

    #[test]
    fn match_view_expiration_agrees_with_owned_event() {
        // NIP-40 expiration is read from the borrowed tags; a strict
        // matcher must reject the expired event exactly as it would the
        // owned one.
        let keys = Keys::generate().expect("os rng");
        let event = EventBuilder::text_note("expiring")
            .created_at(Timestamp::from_secs(1_700_000_000))
            .expiration(Timestamp::from_secs(1_700_000_100))
            .sign_with_keys(&keys)
            .expect("sign");
        let bytes = encode(&event).expect("encode");
        let strict = MatchEventOptions::strict(Timestamp::from_secs(1_700_000_500));
        let view = decode_match_view(&bytes).expect("view");
        assert!(
            !Filter::new().match_event(&view, strict),
            "expired event must be rejected via the borrowed view"
        );
        assert_eq!(
            Filter::new().match_event(&event, strict),
            Filter::new().match_event(&view, strict),
        );
    }

    #[test]
    fn decode_match_view_rejects_empty_and_bad_version() {
        assert!(matches!(
            decode_match_view(&[]).expect_err("empty"),
            Error::EmptyPayload
        ));
        let mut bytes = encode(&fixture()).expect("encode");
        #[expect(
            clippy::indexing_slicing,
            reason = "encode always emits a non-empty buffer; the first byte is the version prefix"
        )]
        {
            bytes[0] = 0xFF;
        }
        assert!(matches!(
            decode_match_view(&bytes).expect_err("bad version"),
            Error::UnsupportedCodecVersion(0xFF)
        ));
    }
}
