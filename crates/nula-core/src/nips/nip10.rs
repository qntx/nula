//! [NIP-10] Replies and Mentions in Text Notes.
//!
//! NIP-10 specifies how `kind: 1` notes reference one another to build
//! threads. The recommended ("preferred") form attaches a marker to each
//! `e` tag:
//!
//! ```text
//! ["e", "<event-id>", "<relay-hint>", "<marker>", "<author-pubkey>?"]
//! ```
//!
//! - `root` — the top of the thread.
//! - `reply` — the parent note this one is replying to.
//! - `mention` — a quoted reference, not a reply.
//!
//! `p` tags carry the pubkeys mentioned in the thread (typically the
//! authors of all referenced events). NIP-10 also describes a legacy
//! positional form; this module emits the marker form on the way out and
//! tolerates both on the way in.
//!
//! [NIP-10]: https://github.com/nostr-protocol/nips/blob/master/10.md

use core::fmt;
use core::str::FromStr;

use thiserror::Error;

use crate::event::{
    Alphabet, Event, EventBuilder, EventId, EventIdError, Kind, SingleLetterTag, Tag, TagKind,
};
use crate::key::{PublicKey, PublicKeyError};
use crate::types::{RelayUrl, RelayUrlError};

/// NIP-10 marker for an `e` tag.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum NoteMarker {
    /// Top of the thread.
    Root,
    /// The parent note this one replies to.
    Reply,
    /// Quoted (not replied to).
    Mention,
}

impl NoteMarker {
    /// Static wire string used in the third column of an `e` tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Reply => "reply",
            Self::Mention => "mention",
        }
    }
}

impl fmt::Display for NoteMarker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Errors raised when parsing a [`NoteMarker`].
#[derive(Debug, Clone, Error)]
#[non_exhaustive]
pub enum NoteMarkerError {
    /// The marker string was not one of `root`, `reply`, `mention`.
    #[error("unknown NIP-10 marker `{0}`")]
    Unknown(String),
}

impl FromStr for NoteMarker {
    type Err = NoteMarkerError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "root" => Ok(Self::Root),
            "reply" => Ok(Self::Reply),
            "mention" => Ok(Self::Mention),
            other => Err(NoteMarkerError::Unknown(other.to_owned())),
        }
    }
}

/// Reference to another event from inside a thread.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EventReference {
    /// The id of the referenced event.
    pub event_id: EventId,
    /// Optional relay hint where the event can be fetched.
    pub relay_hint: Option<RelayUrl>,
    /// Optional NIP-10 marker.
    pub marker: Option<NoteMarker>,
    /// Optional hint of the referenced event's author.
    pub author_hint: Option<PublicKey>,
}

impl EventReference {
    /// Construct a reference with no hints or marker.
    #[must_use]
    pub const fn new(event_id: EventId) -> Self {
        Self {
            event_id,
            relay_hint: None,
            marker: None,
            author_hint: None,
        }
    }

    /// Set the relay hint.
    #[must_use]
    pub fn with_relay_hint(mut self, relay: RelayUrl) -> Self {
        self.relay_hint = Some(relay);
        self
    }

    /// Set the NIP-10 marker.
    #[must_use]
    pub const fn with_marker(mut self, marker: NoteMarker) -> Self {
        self.marker = Some(marker);
        self
    }

    /// Set the author hint.
    #[must_use]
    pub const fn with_author_hint(mut self, author: PublicKey) -> Self {
        self.author_hint = Some(author);
        self
    }
}

/// NIP-10 thread metadata for a `kind: 1` note.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ThreadContext {
    /// Every `e` tag, in the order they appear on the wire.
    pub events: Vec<EventReference>,
    /// Pubkeys collected from the `p` tags.
    pub mentioned_pubkeys: Vec<PublicKey>,
}

impl ThreadContext {
    /// Construct an empty context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an event reference and return `self`.
    #[must_use]
    pub fn reference(mut self, reference: EventReference) -> Self {
        self.events.push(reference);
        self
    }

    /// Append a mentioned pubkey.
    #[must_use]
    pub fn mention(mut self, pubkey: PublicKey) -> Self {
        self.mentioned_pubkeys.push(pubkey);
        self
    }

    /// First reference whose marker is [`NoteMarker::Root`], if any.
    #[must_use]
    pub fn root(&self) -> Option<&EventReference> {
        self.events
            .iter()
            .find(|r| r.marker == Some(NoteMarker::Root))
    }

    /// First reference whose marker is [`NoteMarker::Reply`], if any.
    #[must_use]
    pub fn reply(&self) -> Option<&EventReference> {
        self.events
            .iter()
            .find(|r| r.marker == Some(NoteMarker::Reply))
    }

    /// Every reference whose marker is [`NoteMarker::Mention`].
    pub fn mentions(&self) -> impl Iterator<Item = &EventReference> {
        self.events
            .iter()
            .filter(|r| r.marker == Some(NoteMarker::Mention))
    }

    /// Fill in markers on `e` references that came from the *deprecated
    /// positional form* of NIP-10.
    ///
    /// Per NIP-10 §"deprecated positional form": when an event carries
    /// `e` tags without explicit markers, the position determines the
    /// role:
    ///
    /// - 0 unmarked references: nothing to do
    /// - 1 unmarked reference: it is the [`NoteMarker::Root`]
    /// - 2+ unmarked references: first is [`NoteMarker::Root`], last is
    ///   [`NoteMarker::Reply`], every entry in between is
    ///   [`NoteMarker::Mention`]
    ///
    /// Existing markers are never overwritten — references that already
    /// have a marker keep it. This makes the operation safe to call on
    /// any [`ThreadContext`], including ones produced by
    /// [`ThreadContext::from_event`] on a legacy thread mixed with
    /// modern markers.
    #[must_use]
    pub fn infer_legacy_markers(mut self) -> Self {
        let unmarked: Vec<usize> = self
            .events
            .iter()
            .enumerate()
            .filter_map(|(i, r)| if r.marker.is_none() { Some(i) } else { None })
            .collect();
        let assign = |slot: &mut Self, idx: usize, marker: NoteMarker| {
            if let Some(r) = slot.events.get_mut(idx) {
                r.marker = Some(marker);
            }
        };
        match unmarked.as_slice() {
            [] => {}
            [only] => assign(&mut self, *only, NoteMarker::Root),
            [first, middle @ .., last] => {
                assign(&mut self, *first, NoteMarker::Root);
                assign(&mut self, *last, NoteMarker::Reply);
                for &idx in middle {
                    assign(&mut self, idx, NoteMarker::Mention);
                }
            }
        }
        self
    }

    /// Render the context as the [`Tag`]s that go into a `kind: 1` note.
    #[must_use]
    pub fn to_tags(&self) -> Vec<Tag> {
        let e_kind = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::E));
        let p_kind = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::P));

        let mut tags = Vec::with_capacity(self.events.len() + self.mentioned_pubkeys.len());
        for r in &self.events {
            tags.push(build_e_tag(&e_kind, r));
        }
        for pk in &self.mentioned_pubkeys {
            tags.push(Tag::with(&p_kind, [pk.to_hex()]));
        }
        tags
    }

    /// Reconstruct a [`ThreadContext`] from `event`'s tags.
    ///
    /// The parser is tolerant: malformed `e`/`p` tags are skipped instead
    /// of failing the whole event, since real-world clients have produced
    /// many variations over the years. Use [`EventReference::from_tag`]
    /// directly for the strict, fail-fast version.
    #[must_use]
    pub fn from_event(event: &Event) -> Self {
        let e_kind = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::E));
        let p_kind = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::P));

        let mut context = Self::new();
        for tag in &event.tags {
            let head = tag.kind();
            if head == e_kind
                && let Ok(reference) = EventReference::from_tag(tag)
            {
                context.events.push(reference);
            } else if head == p_kind
                && let Some(pk) = tag
                    .values()
                    .get(1)
                    .and_then(|s| s.parse::<PublicKey>().ok())
            {
                context.mentioned_pubkeys.push(pk);
            }
        }
        context
    }
}

impl EventBuilder {
    /// Build a `kind: 1` text note carrying the supplied [`ThreadContext`]
    /// (i.e. a NIP-10 reply or mention).
    #[must_use]
    pub fn note_with_context<S: Into<String>>(content: S, context: &ThreadContext) -> Self {
        Self::new(Kind::TEXT_NOTE, content).tags(context.to_tags())
    }
}

fn build_e_tag(e_kind: &TagKind, reference: &EventReference) -> Tag {
    let event_id = reference.event_id.to_hex();
    let relay = reference
        .relay_hint
        .as_ref()
        .map(|r| r.as_str().to_owned())
        .unwrap_or_default();
    let marker = reference
        .marker
        .map(|m| m.as_str().to_owned())
        .unwrap_or_default();
    let author = reference
        .author_hint
        .map(PublicKey::to_hex)
        .unwrap_or_default();

    if !author.is_empty() {
        Tag::with(e_kind, [event_id, relay, marker, author])
    } else if !marker.is_empty() {
        Tag::with(e_kind, [event_id, relay, marker])
    } else if !relay.is_empty() {
        Tag::with(e_kind, [event_id, relay])
    } else {
        Tag::with(e_kind, [event_id])
    }
}

/// Errors that decoding strict-mode (i.e. fail-fast) NIP-10 references can
/// produce. Currently only used by [`EventReference::from_tag`].
#[derive(Debug, Clone, Error)]
#[non_exhaustive]
pub enum ThreadError {
    /// The tag head was not `e`.
    #[error("expected `e` tag, got `{0}`")]
    NotEventTag(String),
    /// The tag had no event id.
    #[error("`e` tag is missing the event id")]
    MissingEventId,
    /// The event id did not parse.
    #[error(transparent)]
    InvalidEventId(#[from] EventIdError),
    /// The relay hint did not parse.
    #[error(transparent)]
    InvalidRelay(#[from] RelayUrlError),
    /// The marker did not parse.
    #[error(transparent)]
    InvalidMarker(#[from] NoteMarkerError),
    /// The author hint did not parse.
    #[error(transparent)]
    InvalidAuthor(#[from] PublicKeyError),
}

impl EventReference {
    /// Strict, fail-fast version of the per-tag parser used by
    /// [`ThreadContext::from_event`]. Use this when you want to surface
    /// malformed `e` tags instead of silently dropping them.
    ///
    /// # Errors
    ///
    /// Returns the matching [`ThreadError`] for any malformed component.
    pub fn from_tag(tag: &Tag) -> Result<Self, ThreadError> {
        let e_kind = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::E));
        if tag.kind() != e_kind {
            return Err(ThreadError::NotEventTag(tag.kind().as_str().to_owned()));
        }
        let mut values = tag.values().iter().skip(1);
        let id = values
            .next()
            .ok_or(ThreadError::MissingEventId)?
            .parse::<EventId>()?;
        let relay_hint = match values.next() {
            Some(s) if !s.is_empty() => Some(RelayUrl::parse(s)?),
            _ => None,
        };
        let marker = match values.next() {
            Some(s) if !s.is_empty() => Some(s.parse::<NoteMarker>()?),
            _ => None,
        };
        let author_hint = match values.next() {
            Some(s) if !s.is_empty() => Some(s.parse::<PublicKey>()?),
            _ => None,
        };
        Ok(Self {
            event_id: id,
            relay_hint,
            marker,
            author_hint,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;
    use crate::types::Timestamp;

    fn keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    fn event_id(seed: u8) -> EventId {
        EventId::from_byte_array([seed; 32])
    }

    fn pk(seed: u8) -> PublicKey {
        let mut bytes = [0u8; 32];
        bytes[31] = seed;
        let sk = crate::SecretKey::from_byte_array(bytes).unwrap();
        *Keys::from_secret_key(sk).public_key()
    }

    #[test]
    fn marker_round_trip() {
        for marker in [NoteMarker::Root, NoteMarker::Reply, NoteMarker::Mention] {
            let s = marker.as_str();
            assert_eq!(s.parse::<NoteMarker>().unwrap(), marker);
        }
    }

    #[test]
    fn marker_rejects_unknown() {
        let err = "thread".parse::<NoteMarker>().unwrap_err();
        assert!(matches!(err, NoteMarkerError::Unknown(_)));
    }

    #[test]
    fn round_trip_through_event() {
        let context = ThreadContext::new()
            .reference(
                EventReference::new(event_id(0xaa))
                    .with_relay_hint(RelayUrl::parse("wss://relay.example/").unwrap())
                    .with_marker(NoteMarker::Root)
                    .with_author_hint(pk(1)),
            )
            .reference(
                EventReference::new(event_id(0xbb))
                    .with_marker(NoteMarker::Reply)
                    .with_author_hint(pk(2)),
            )
            .reference(EventReference::new(event_id(0xcc)).with_marker(NoteMarker::Mention))
            .mention(pk(3));

        let event = EventBuilder::note_with_context("hi thread", &context)
            .created_at(Timestamp::from_secs(1))
            .sign_with_keys(&keys())
            .unwrap();
        event.verify().unwrap();
        let parsed = ThreadContext::from_event(&event);
        assert_eq!(parsed, context);

        assert_eq!(parsed.root().unwrap().event_id, event_id(0xaa));
        assert_eq!(parsed.reply().unwrap().event_id, event_id(0xbb));
        let mentions: Vec<_> = parsed.mentions().collect();
        assert_eq!(mentions.len(), 1);
        assert_eq!(mentions[0].event_id, event_id(0xcc));
    }

    #[test]
    fn legacy_positional_tags_decode_without_marker() {
        // No marker columns; only the event id.
        let event = EventBuilder::text_note("legacy thread")
            .created_at(Timestamp::from_secs(2))
            .tag(Tag::new(["e", &event_id(0xaa).to_hex()]).unwrap())
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = ThreadContext::from_event(&event);
        assert_eq!(parsed.events.len(), 1);
        assert!(parsed.events[0].marker.is_none());
        assert!(parsed.root().is_none());
    }

    #[test]
    fn malformed_e_tag_is_skipped_in_lenient_parse() {
        let event = EventBuilder::text_note("bad ref")
            .created_at(Timestamp::from_secs(3))
            .tags([
                Tag::new(["e", "not-a-hex-id"]).unwrap(),
                Tag::new(["e", &event_id(0x10).to_hex()]).unwrap(),
            ])
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = ThreadContext::from_event(&event);
        // The bad one is silently dropped, the good one survives.
        assert_eq!(parsed.events.len(), 1);
    }

    #[test]
    fn from_tag_strict_returns_errors() {
        let bad = Tag::new(["e", "not-a-hex-id"]).unwrap();
        let err = EventReference::from_tag(&bad).unwrap_err();
        assert!(matches!(err, ThreadError::InvalidEventId(_)));
    }

    #[test]
    fn from_tag_rejects_non_e_tag() {
        let tag = Tag::new(["p", &pk(1).to_hex()]).unwrap();
        let err = EventReference::from_tag(&tag).unwrap_err();
        assert!(matches!(err, ThreadError::NotEventTag(_)));
    }

    #[test]
    fn legacy_positional_single_e_tag_becomes_root() {
        let context = ThreadContext::new()
            .reference(EventReference::new(event_id(0xaa)))
            .infer_legacy_markers();
        assert_eq!(context.events[0].marker, Some(NoteMarker::Root));
        assert!(context.reply().is_none());
    }

    #[test]
    fn legacy_positional_multi_e_tag_assigns_root_reply_mention() {
        let context = ThreadContext::new()
            .reference(EventReference::new(event_id(0xaa)))
            .reference(EventReference::new(event_id(0xbb)))
            .reference(EventReference::new(event_id(0xcc)))
            .reference(EventReference::new(event_id(0xdd)))
            .infer_legacy_markers();
        assert_eq!(context.events[0].marker, Some(NoteMarker::Root));
        assert_eq!(context.events[1].marker, Some(NoteMarker::Mention));
        assert_eq!(context.events[2].marker, Some(NoteMarker::Mention));
        assert_eq!(context.events[3].marker, Some(NoteMarker::Reply));
    }

    #[test]
    fn legacy_positional_two_e_tags_become_root_and_reply() {
        let context = ThreadContext::new()
            .reference(EventReference::new(event_id(0xaa)))
            .reference(EventReference::new(event_id(0xbb)))
            .infer_legacy_markers();
        assert_eq!(context.events[0].marker, Some(NoteMarker::Root));
        assert_eq!(context.events[1].marker, Some(NoteMarker::Reply));
    }

    #[test]
    fn legacy_positional_inference_preserves_existing_markers() {
        // Mixed thread: an explicit Root plus an unmarked tail. Inference
        // must not overwrite the explicit marker; it labels only the
        // unmarked entries (here: only one, which becomes Root by the
        // single-unmarked rule).
        let context = ThreadContext::new()
            .reference(EventReference::new(event_id(0xaa)).with_marker(NoteMarker::Root))
            .reference(EventReference::new(event_id(0xbb)))
            .infer_legacy_markers();
        assert_eq!(context.events[0].marker, Some(NoteMarker::Root));
        assert_eq!(context.events[1].marker, Some(NoteMarker::Root));
    }

    #[test]
    fn legacy_positional_no_e_tags_is_a_noop() {
        let context = ThreadContext::new().infer_legacy_markers();
        assert!(context.events.is_empty());
    }
}
