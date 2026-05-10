//! [NIP-18] Reposts and quote reposts.
//!
//! Three flavours of "I want my followers to see this" exist on
//! Nostr; this module models all three:
//!
//! - **Repost** — `kind: 6` ([`crate::Kind::REPOST`]). Reserved for
//!   `kind: 1` text notes. The repost's `content` is the
//!   stringified JSON of the reposted note (or empty for NIP-70
//!   protected events). The `e` tag MUST include a relay URL in its
//!   third slot, and a `p` tag SHOULD point at the original author.
//!   Build with [`EventBuilder::repost`].
//! - **Generic repost** — `kind: 16`
//!   ([`crate::Kind::GENERIC_REPOST`]). Reposts a non-`kind: 1`
//!   event. Carries a `k` tag with the reposted kind and either
//!   the full event JSON in `content` (for non-replaceable events)
//!   *or* an `a` tag pointing at the addressable coordinate for
//!   replaceable events. Build with [`EventBuilder::generic_repost`].
//! - **Quote repost** — *any* event kind that wants to reference
//!   another event using NIP-21 entities. Surfaces on the wire as a
//!   `q` tag (`["q", <id-or-coord>, <relay>, <pubkey?>]`). Build the
//!   `q` tag with [`crate::Tag::q`] / [`crate::Tag::q_addressable`].
//!
//! Read helpers ([`reposted_event_id`], [`reposted_event_pubkey`],
//! [`reposted_event_kind`], [`reposted_event_coordinate`]) walk the
//! repost's tags so callers don't need to mirror the spec's
//! quirks (relay-hint slot in `e`, `k`-tag presence-or-absence rules,
//! addressable coordinate detection).
//!
//! [NIP-18]: https://github.com/nostr-protocol/nips/blob/master/18.md

use crate::event::{
    Alphabet, Coordinate, Event, EventBuilder, EventId, Kind, SingleLetterTag, Tag, TagKind, Tags,
};
use crate::key::PublicKey;
use crate::types::RelayUrl;

/// Errors raised by the NIP-18 builders.
///
/// `Serialize` boxes its `serde_json::Error` payload so the enum
/// stays small in the common-success path: the underlying error is
/// 14 bytes whereas every other variant fits in two.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[allow(
    variant_size_differences,
    reason = "Serialize variant is already boxed; its 8-byte pointer is the smallest sound representation against the 2-byte NotATextNote variant"
)]
pub enum RepostError {
    /// [`EventBuilder::repost`] was called with an event whose kind is
    /// not [`Kind::TEXT_NOTE`]. NIP-18 reserves `kind: 6` for `kind: 1`
    /// reposts; use [`EventBuilder::generic_repost`] for everything
    /// else.
    #[error("kind:6 reposts are reserved for kind:1 notes; got kind {0}")]
    NotATextNote(u16),
    /// Serialising the reposted event into the repost's `content`
    /// field failed.
    #[error(transparent)]
    Serialize(Box<serde_json::Error>),
}

impl From<serde_json::Error> for RepostError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialize(Box::new(value))
    }
}

impl EventBuilder {
    /// Build a NIP-18 repost ([`Kind::REPOST`]) for a `kind: 1` note.
    ///
    /// The repost's `content` is the canonical JSON of the reposted
    /// note (or empty when `target` carries the NIP-70 `["-"]`
    /// protected marker). The mandatory `e` tag includes the relay
    /// URL at index 2 — NIP-18 elevates the relay hint from "SHOULD"
    /// to "MUST" specifically for reposts.
    ///
    /// # Errors
    ///
    /// - [`RepostError::NotATextNote`] when `target.kind != Kind::TEXT_NOTE`.
    /// - [`RepostError::Serialize`] if `serde_json` cannot serialise
    ///   `target` (in practice impossible because every signed
    ///   `Event` round-trips through `serde_json` already).
    pub fn repost(target: &Event, relay: &RelayUrl) -> Result<Self, RepostError> {
        if target.kind != Kind::TEXT_NOTE {
            return Err(RepostError::NotATextNote(target.kind.as_u16()));
        }
        let content = if target.is_protected() {
            String::new()
        } else {
            serde_json::to_string(target)?
        };
        let mut builder = Self::new(Kind::REPOST, content);
        builder = builder.tag(repost_e_tag(target.id, relay));
        builder = builder.tag(Tag::p_with_relay(target.pubkey, relay));
        Ok(builder)
    }

    /// Build a NIP-18 generic repost ([`Kind::GENERIC_REPOST`]) for a
    /// non-`kind: 1` event.
    ///
    /// Carries a `k` tag with the original kind. For replaceable /
    /// addressable events, an `a` tag is added with the
    /// `(kind, author, d-tag)` coordinate and the `content` is left
    /// empty per spec; for regular events the full JSON is stuffed
    /// into `content` so the original is recoverable even if the
    /// referenced relays drop it.
    ///
    /// # Errors
    ///
    /// Returns [`RepostError::Serialize`] if `serde_json` cannot
    /// serialise `target`.
    pub fn generic_repost(target: &Event, relay: &RelayUrl) -> Result<Self, RepostError> {
        let coord = if target.kind.is_addressable() {
            extract_d_tag(&target.tags)
                .map(|d| Coordinate::new(target.kind, target.pubkey, d.to_owned()))
        } else {
            None
        };
        let content = if coord.is_some() || target.is_protected() {
            String::new()
        } else {
            serde_json::to_string(target)?
        };
        let mut builder = Self::new(Kind::GENERIC_REPOST, content);
        builder = builder.tag(repost_e_tag(target.id, relay));
        builder = builder.tag(Tag::p_with_relay(target.pubkey, relay));
        builder = builder.tag(Tag::k(target.kind));
        if let Some(coord) = coord {
            builder = builder.tag(Tag::a_with_relay(&coord, relay));
        }
        Ok(builder)
    }
}

fn repost_e_tag(event_id: EventId, relay: &RelayUrl) -> Tag {
    // ["e", id, relay] - NIP-18 mandates the relay slot.
    let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::E));
    Tag::with(&head, [event_id.to_hex(), relay.as_str().to_owned()])
}

fn extract_d_tag(tags: &Tags) -> Option<&str> {
    for tag in tags {
        if matches!(tag.kind(), TagKind::SingleLetter(s) if s.character == Alphabet::D && !s.uppercase)
        {
            return tag.values().get(1).map(String::as_str);
        }
    }
    None
}

/// Return the reposted event id from `tags` (the first `e` tag's
/// second slot).
///
/// Unlike [`super::nip25::target_event_id`], NIP-18 does not allow
/// thread-context `e` tags on a repost, so the **first** `e` tag is
/// authoritative.
#[must_use]
pub fn reposted_event_id(tags: &Tags) -> Option<EventId> {
    for tag in tags {
        if matches!(tag.kind(), TagKind::SingleLetter(s) if s.character == Alphabet::E && !s.uppercase)
        {
            return tag.values().get(1).and_then(|v| EventId::parse(v).ok());
        }
    }
    None
}

/// Return the reposted event author's public key from the first
/// `p` tag, if any.
#[must_use]
pub fn reposted_event_pubkey(tags: &Tags) -> Option<PublicKey> {
    for tag in tags {
        if matches!(tag.kind(), TagKind::SingleLetter(s) if s.character == Alphabet::P && !s.uppercase)
        {
            return tag.values().get(1).and_then(|v| PublicKey::parse(v).ok());
        }
    }
    None
}

/// Return the reposted event kind from the optional `k` tag (only
/// emitted by `kind: 16` generic reposts).
#[must_use]
pub fn reposted_event_kind(tags: &Tags) -> Option<Kind> {
    for tag in tags {
        if matches!(tag.kind(), TagKind::SingleLetter(s) if s.character == Alphabet::K && !s.uppercase)
        {
            return tag
                .values()
                .get(1)
                .and_then(|v| v.parse::<u16>().ok())
                .map(Kind::new);
        }
    }
    None
}

/// Return the reposted addressable coordinate from the optional
/// `a` tag (only emitted for replaceable / addressable targets).
#[must_use]
pub fn reposted_event_coordinate(tags: &Tags) -> Option<Coordinate> {
    for tag in tags {
        let TagKind::SingleLetter(s) = tag.kind() else {
            continue;
        };
        if s.character != Alphabet::A || s.uppercase {
            continue;
        }
        if let Some(value) = tag.values().get(1) {
            return Coordinate::parse(value).ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;

    fn fixture_keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    fn fixture_relay() -> RelayUrl {
        RelayUrl::parse("wss://relay.example/").unwrap()
    }

    #[test]
    fn repost_rejects_non_text_note_kinds() {
        let keys = fixture_keys();
        let target = EventBuilder::new(Kind::CONTACTS, "")
            .sign_with_keys(&keys)
            .unwrap();

        let err = EventBuilder::repost(&target, &fixture_relay()).unwrap_err();
        assert!(matches!(err, RepostError::NotATextNote(3)));
    }

    #[test]
    fn repost_carries_target_json_in_content_and_e_p_tags() {
        let keys = fixture_keys();
        let target = EventBuilder::text_note("hello, world")
            .sign_with_keys(&keys)
            .unwrap();

        let repost = EventBuilder::repost(&target, &fixture_relay())
            .unwrap()
            .sign_with_keys(&keys)
            .unwrap();

        assert_eq!(repost.kind, Kind::REPOST);
        assert!(
            repost.content.contains(r#""content":"hello, world""#),
            "repost content must embed the reposted note's JSON: {}",
            repost.content,
        );
        assert_eq!(reposted_event_id(&repost.tags), Some(target.id));
        assert_eq!(reposted_event_pubkey(&repost.tags), Some(target.pubkey));
        // `kind: 6` reposts do not emit a `k` tag — that's NIP-18
        // §Generic Reposts territory.
        assert_eq!(reposted_event_kind(&repost.tags), None);
        repost.verify().unwrap();
    }

    #[test]
    fn repost_e_tag_carries_relay_at_index_2() {
        let keys = fixture_keys();
        let target = EventBuilder::text_note("post")
            .sign_with_keys(&keys)
            .unwrap();
        let relay = fixture_relay();

        let repost = EventBuilder::repost(&target, &relay)
            .unwrap()
            .sign_with_keys(&keys)
            .unwrap();

        let e_tag = repost
            .tags
            .iter()
            .find(|t| matches!(t.kind(), TagKind::SingleLetter(s) if s.character == Alphabet::E))
            .unwrap();
        assert_eq!(e_tag.get(2), Some(relay.as_str()));
    }

    #[test]
    fn generic_repost_emits_k_tag_for_arbitrary_kind() {
        let keys = fixture_keys();
        let target = EventBuilder::new(Kind::CONTACTS, "")
            .sign_with_keys(&keys)
            .unwrap();

        let repost = EventBuilder::generic_repost(&target, &fixture_relay())
            .unwrap()
            .sign_with_keys(&keys)
            .unwrap();

        assert_eq!(repost.kind, Kind::GENERIC_REPOST);
        assert_eq!(reposted_event_kind(&repost.tags), Some(Kind::CONTACTS));
        // Non-addressable: full JSON in content.
        assert!(repost.content.contains(r#""kind":3"#));
    }

    #[test]
    fn generic_repost_uses_a_tag_and_empty_content_for_addressable() {
        let keys = fixture_keys();
        let target = EventBuilder::new(Kind::LONG_FORM_TEXT_NOTE, "post body")
            .tag(Tag::d("article-1"))
            .sign_with_keys(&keys)
            .unwrap();

        let repost = EventBuilder::generic_repost(&target, &fixture_relay())
            .unwrap()
            .sign_with_keys(&keys)
            .unwrap();

        // Addressable repost: empty content, coordinate carried in `a`.
        assert_eq!(repost.content, "");
        let coord = reposted_event_coordinate(&repost.tags).expect("a-tag must be present");
        assert_eq!(coord.kind, Kind::LONG_FORM_TEXT_NOTE);
        assert_eq!(coord.author, target.pubkey);
        assert_eq!(coord.identifier, "article-1");
    }

    #[test]
    fn quote_repost_q_tag_round_trips() {
        let keys = fixture_keys();
        let target = EventBuilder::text_note("quoted")
            .sign_with_keys(&keys)
            .unwrap();
        let relay = fixture_relay();

        let event = EventBuilder::text_note("see this:")
            .tag(Tag::q(target.id, &relay, target.pubkey))
            .sign_with_keys(&keys)
            .unwrap();

        let q_tag = event
            .tags
            .iter()
            .find(|t| matches!(t.kind(), TagKind::SingleLetter(s) if s.character == Alphabet::Q))
            .unwrap();
        assert_eq!(q_tag.values().len(), 4);
        assert_eq!(q_tag.get(1), Some(target.id.to_hex().as_str()));
        assert_eq!(q_tag.get(2), Some(relay.as_str()));
        assert_eq!(q_tag.get(3), Some(target.pubkey.to_hex().as_str()));
    }

    #[test]
    fn quote_repost_addressable_q_tag_uses_coordinate() {
        let keys = fixture_keys();
        let target = EventBuilder::new(Kind::LONG_FORM_TEXT_NOTE, "post")
            .tag(Tag::d("ident"))
            .sign_with_keys(&keys)
            .unwrap();
        let coord = Coordinate::new(target.kind, target.pubkey, "ident");
        let relay = fixture_relay();

        let event = EventBuilder::text_note("see this article:")
            .tag(Tag::q_addressable(&coord, &relay))
            .sign_with_keys(&keys)
            .unwrap();

        let q_tag = event
            .tags
            .iter()
            .find(|t| matches!(t.kind(), TagKind::SingleLetter(s) if s.character == Alphabet::Q))
            .unwrap();
        // Addressable form: 3 values (q, coordinate, relay) — no
        // separate author column because it is implicit in the coord.
        assert_eq!(q_tag.values().len(), 3);
        assert!(q_tag.get(1).unwrap().starts_with("30023:"));
        assert_eq!(q_tag.get(2), Some(relay.as_str()));
    }
}
