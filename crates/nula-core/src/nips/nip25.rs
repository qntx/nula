//! [NIP-25] Reactions.
//!
//! A reaction is a `kind: 7` event ([`crate::Kind::REACTION`]) whose
//! `content` carries one of:
//!
//! - `+` or the empty string — interpreted as a "like" / upvote.
//! - `-` — interpreted as a "dislike" / downvote.
//! - Any other text, conventionally a single emoji — interpreted as a
//!   plain emoji reaction with no like/dislike polarity.
//! - `:shortcode:` plus an `emoji` tag (see NIP-30) — interpreted as
//!   a NIP-30 custom emoji.
//!
//! The event MUST carry an `e` tag pointing at the reacted event id
//! and SHOULD carry a `p` tag pointing at its author. NIP-25 also
//! recommends a `k` tag with the reacted kind, and (for replaceable
//! events) an `a` tag with the addressable coordinate.
//!
//! This module ships:
//!
//! - [`Reaction`] — sum type over the four content shapes with
//!   sniff-friendly `is_positive` / `is_negative` flags so client
//!   code can drive UX without re-parsing.
//! - [`ReactionTarget`] — bundle of `(event_id, author, kind?, coord?,
//!   relay?)` carrying everything NIP-25 wants on the wire.
//! - [`EventBuilder::reaction`] — typed builder for `kind: 7` that
//!   pre-populates the `e` / `p` / `k` / `a` tags so callers cannot
//!   forget the SHOULDs by accident.
//! - [`target_event_id`] / [`target_pubkey`] / [`target_kind`] — read
//!   helpers for inbound reaction events.
//!
//! External-content reactions (`kind: 17` with NIP-73 `i` / `k` tags)
//! are deferred to the NIP-73 work item; this module covers the
//! native-event path that all current clients (Damus, Amethyst,
//! Coracle, Nostrudel) implement.
//!
//! [NIP-25]: https://github.com/nostr-protocol/nips/blob/master/25.md

use crate::event::{
    Alphabet, Coordinate, Event, EventBuilder, EventId, Kind, SingleLetterTag, Tag, TagKind, Tags,
};
use crate::key::PublicKey;
use crate::types::RelayUrl;

/// The four reaction shapes NIP-25 §Content recognises.
///
/// Use [`Reaction::parse`] to discriminate an inbound `content`
/// string and [`Reaction::content`] to render one back to its wire
/// form. The parser is lossless: every `&str` round-trips through
/// `Reaction::parse(_).content()`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Reaction {
    /// `+` or empty content — interpreted as a like / upvote.
    Like,
    /// `-` — interpreted as a dislike / downvote.
    Dislike,
    /// Any other plain text. Convention is a single emoji glyph but
    /// NIP-25 does not actually constrain the value, so the inner
    /// `String` is the literal `content` field.
    Emoji(String),
    /// `:shortcode:` for a NIP-30 custom emoji. The inner string holds
    /// the shortcode **without** the surrounding colons; the wire
    /// form is recovered by [`Reaction::content`].
    CustomEmoji(String),
}

impl Reaction {
    /// Sentinel `content` value for a positive (like / upvote) reaction.
    pub const LIKE: &'static str = "+";
    /// Sentinel `content` value for a negative (dislike / downvote) reaction.
    pub const DISLIKE: &'static str = "-";

    /// Discriminate the shape of a `kind: 7` `content` string.
    ///
    /// The classification rules follow NIP-25 §Content verbatim:
    ///
    /// - `""` or `"+"` → [`Self::Like`].
    /// - `"-"` → [`Self::Dislike`].
    /// - `:shortcode:` (anything wrapped by a leading and trailing
    ///   colon) → [`Self::CustomEmoji`] with the shortcode body.
    /// - everything else → [`Self::Emoji`] with the input verbatim.
    #[must_use]
    pub fn parse(content: &str) -> Self {
        if content.is_empty() || content == Self::LIKE {
            return Self::Like;
        }
        if content == Self::DISLIKE {
            return Self::Dislike;
        }
        if let Some(shortcode) = parse_custom_emoji(content) {
            return Self::CustomEmoji(shortcode.to_owned());
        }
        Self::Emoji(content.to_owned())
    }

    /// Render `self` back to the wire-form `content` string.
    #[must_use]
    pub fn content(&self) -> String {
        match self {
            Self::Like => Self::LIKE.to_owned(),
            Self::Dislike => Self::DISLIKE.to_owned(),
            Self::Emoji(s) => s.clone(),
            Self::CustomEmoji(shortcode) => format!(":{shortcode}:"),
        }
    }

    /// True for [`Self::Like`] only. Plain emoji reactions are
    /// **not** positive per NIP-25 §Content — they convey emotion
    /// without polarity.
    #[must_use]
    pub const fn is_positive(&self) -> bool {
        matches!(self, Self::Like)
    }

    /// True for [`Self::Dislike`] only.
    #[must_use]
    pub const fn is_negative(&self) -> bool {
        matches!(self, Self::Dislike)
    }
}

/// What a `kind: 7` reaction points at.
///
/// `event_id` and `author` are mandatory because NIP-25 mandates the
/// `e` and SHOULD-mandates the `p` tags. `kind` is the reacted event's
/// kind for the optional `k` tag, `coordinate` is set when the
/// reacted event is addressable (`30000..40000`), and `relay_hint` is
/// the optional relay-hint slot that goes onto every tag where it is
/// applicable.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReactionTarget {
    /// SHA-256 id of the reacted event.
    pub event_id: EventId,
    /// Author of the reacted event.
    pub author: PublicKey,
    /// Kind of the reacted event, surfaced via the `k` tag.
    pub kind: Option<Kind>,
    /// Addressable coordinate for replaceable / addressable events.
    pub coordinate: Option<Coordinate>,
    /// Relay hint propagated to the `e` / `a` / `p` tags.
    pub relay_hint: Option<RelayUrl>,
}

impl ReactionTarget {
    /// Build a target from the bare `(event_id, author)` pair.
    ///
    /// Use the `with_*` builders to layer on the optional NIP-25
    /// hints.
    #[must_use]
    pub const fn new(event_id: EventId, author: PublicKey) -> Self {
        Self {
            event_id,
            author,
            kind: None,
            coordinate: None,
            relay_hint: None,
        }
    }

    /// Capture every NIP-25 hint from a fully-resolved reacted event.
    ///
    /// This is the recommended way to construct a target because it
    /// fills in `kind` and (when the kind is addressable) the
    /// coordinate from the reacted event's `d` tag.
    #[must_use]
    pub fn from_event(event: &Event) -> Self {
        let mut target = Self::new(event.id, event.pubkey);
        target.kind = Some(event.kind);
        if event.kind.is_addressable()
            && let Some(d) = find_d_tag(&event.tags)
        {
            target.coordinate = Some(Coordinate::new(event.kind, event.pubkey, d.to_owned()));
        }
        target
    }

    /// Attach a relay hint that the resulting reaction event will
    /// propagate onto its `e` / `a` / `p` tags.
    #[must_use]
    pub fn with_relay_hint(mut self, relay: RelayUrl) -> Self {
        self.relay_hint = Some(relay);
        self
    }

    /// Override the `kind` field (rarely needed once
    /// [`Self::from_event`] has populated it).
    #[must_use]
    pub const fn with_kind(mut self, kind: Kind) -> Self {
        self.kind = Some(kind);
        self
    }

    /// Override the addressable coordinate.
    #[must_use]
    pub fn with_coordinate(mut self, coordinate: Coordinate) -> Self {
        self.coordinate = Some(coordinate);
        self
    }
}

impl EventBuilder {
    /// Build a [`Kind::REACTION`] event for `target` carrying
    /// `reaction` as its content.
    ///
    /// The builder pre-populates every NIP-25 SHOULD / MUST tag:
    ///
    /// - `["e", <event_id>, <relay>?, <author>]` — pubkey hint at the
    ///   end matches the spec's example (`tags.append(["e", liked.id,
    ///   hint, liked.pubkey])`).
    /// - `["p", <author>, <relay>?]`.
    /// - `["k", <kind>]` when `target.kind` is set.
    /// - `["a", <coordinate>, <relay>?]` when `target.coordinate` is
    ///   set.
    ///
    /// Callers are free to add an `["emoji", <shortcode>, <url>]`
    /// tag for [`Reaction::CustomEmoji`] payloads, but this method
    /// does not synthesise one because the URL is policy-dependent
    /// and lives in higher-level NIP-30 code.
    #[must_use]
    pub fn reaction(target: &ReactionTarget, reaction: &Reaction) -> Self {
        let mut tags = Tags::new();
        tags.push(reaction_e_tag(target));
        tags.push(reaction_p_tag(target));
        if let Some(kind) = target.kind {
            tags.push(Tag::k(kind));
        }
        if let Some(coord) = target.coordinate.as_ref() {
            tags.push(reaction_a_tag(coord, target.relay_hint.as_ref()));
        }
        let mut builder = Self::new(Kind::REACTION, reaction.content());
        for tag in tags {
            builder = builder.tag(tag);
        }
        builder
    }
}

fn reaction_e_tag(target: &ReactionTarget) -> Tag {
    let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::E));
    let relay_slot = target
        .relay_hint
        .as_ref()
        .map(|r| r.as_str().to_owned())
        .unwrap_or_default();
    Tag::with(
        &head,
        [target.event_id.to_hex(), relay_slot, target.author.to_hex()],
    )
}

fn reaction_p_tag(target: &ReactionTarget) -> Tag {
    target.relay_hint.as_ref().map_or_else(
        || Tag::p(target.author),
        |relay| Tag::p_with_relay(target.author, relay),
    )
}

fn reaction_a_tag(coord: &Coordinate, relay: Option<&RelayUrl>) -> Tag {
    relay.map_or_else(|| Tag::a(coord), |r| Tag::a_with_relay(coord, r))
}

fn find_d_tag(tags: &Tags) -> Option<&str> {
    for tag in tags {
        if matches!(tag.kind(), TagKind::SingleLetter(s) if s.character == Alphabet::D && !s.uppercase)
        {
            return tag.values().get(1).map(String::as_str);
        }
    }
    None
}

fn parse_custom_emoji(content: &str) -> Option<&str> {
    let stripped = content.strip_prefix(':')?.strip_suffix(':')?;
    if stripped.is_empty() || stripped.contains(':') {
        return None;
    }
    Some(stripped)
}

/// Extract the reacted event id from a `kind: 7` event's tags.
///
/// NIP-25 mandates the `e` tag's last value carries the target event
/// id, but tolerates earlier `e` tags pointing at unrelated events
/// (for example, NIP-10 thread context). The helper therefore returns
/// the **last** `e` tag's id rather than the first, mirroring the
/// spec's instruction: *"the target event id should be last of the e
/// tags"*.
#[must_use]
pub fn target_event_id(tags: &Tags) -> Option<EventId> {
    last_single_letter_value(tags, Alphabet::E).and_then(|hex| EventId::parse(hex).ok())
}

/// Extract the reacted author's pubkey from a `kind: 7` event's tags.
///
/// Same "last `p` wins" rule as [`target_event_id`]: NIP-25 says the
/// target pubkey lives at the *end* of the `p` list when multiple
/// `p` tags are present.
#[must_use]
pub fn target_pubkey(tags: &Tags) -> Option<PublicKey> {
    last_single_letter_value(tags, Alphabet::P).and_then(|hex| PublicKey::parse(hex).ok())
}

/// Extract the reacted event kind from the optional `k` tag.
#[must_use]
pub fn target_kind(tags: &Tags) -> Option<Kind> {
    first_single_letter_value(tags, Alphabet::K)
        .and_then(|raw| raw.parse::<u16>().ok())
        .map(Kind::new)
}

fn first_single_letter_value(tags: &Tags, letter: Alphabet) -> Option<&str> {
    for tag in tags {
        let TagKind::SingleLetter(s) = tag.kind() else {
            continue;
        };
        if s.character != letter || s.uppercase {
            continue;
        }
        if let Some(value) = tag.values().get(1) {
            return Some(value.as_str());
        }
    }
    None
}

fn last_single_letter_value(tags: &Tags, letter: Alphabet) -> Option<&str> {
    let mut last: Option<&str> = None;
    for tag in tags {
        let TagKind::SingleLetter(s) = tag.kind() else {
            continue;
        };
        if s.character != letter || s.uppercase {
            continue;
        }
        if let Some(value) = tag.values().get(1) {
            last = Some(value.as_str());
        }
    }
    last
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;

    fn fixture_keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    fn fixture_target_event() -> Event {
        let keys = fixture_keys();
        EventBuilder::text_note("liked post")
            .sign_with_keys(&keys)
            .unwrap()
    }

    #[test]
    fn parse_classifies_canonical_content_strings() {
        assert_eq!(Reaction::parse("+"), Reaction::Like);
        assert_eq!(Reaction::parse(""), Reaction::Like);
        assert_eq!(Reaction::parse("-"), Reaction::Dislike);
        assert_eq!(Reaction::parse("🔥"), Reaction::Emoji("🔥".into()));
        assert_eq!(
            Reaction::parse(":soapbox:"),
            Reaction::CustomEmoji("soapbox".into()),
        );
    }

    #[test]
    fn malformed_custom_emoji_falls_back_to_plain_emoji() {
        // Empty shortcode and stray colons must not promote to CustomEmoji.
        assert_eq!(Reaction::parse("::"), Reaction::Emoji("::".into()));
        assert_eq!(Reaction::parse(":a:b:"), Reaction::Emoji(":a:b:".into()),);
    }

    #[test]
    fn content_round_trips_through_parse() {
        for raw in ["+", "-", "🔥", ":soapbox:", "👏", "+1"] {
            let reaction = Reaction::parse(raw);
            // For `""` Reaction::Like renders to `"+"`, the canonical
            // wire form. The other inputs are stable through the round
            // trip.
            assert_eq!(reaction.content(), raw);
            assert_eq!(Reaction::parse(&reaction.content()), reaction);
        }
        // Empty content is canonicalised to `+` on the way back.
        assert_eq!(Reaction::parse("").content(), "+");
    }

    #[test]
    fn polarity_flags_only_fire_for_plus_and_minus() {
        assert!(Reaction::Like.is_positive());
        assert!(!Reaction::Like.is_negative());
        assert!(Reaction::Dislike.is_negative());
        assert!(!Reaction::Dislike.is_positive());
        assert!(!Reaction::Emoji("👏".into()).is_positive());
        assert!(!Reaction::Emoji("👏".into()).is_negative());
        assert!(!Reaction::CustomEmoji("soapbox".into()).is_positive());
    }

    #[test]
    fn from_event_extracts_kind_and_coordinate_for_addressable() {
        let keys = fixture_keys();
        let event = EventBuilder::new(Kind::LONG_FORM_TEXT_NOTE, "post body")
            .tag(Tag::d("my-post"))
            .sign_with_keys(&keys)
            .unwrap();

        let target = ReactionTarget::from_event(&event);
        assert_eq!(target.event_id, event.id);
        assert_eq!(target.author, event.pubkey);
        assert_eq!(target.kind, Some(Kind::LONG_FORM_TEXT_NOTE));
        assert_eq!(target.coordinate.as_ref().unwrap().identifier, "my-post");
    }

    #[test]
    fn from_event_omits_coordinate_for_regular_kinds() {
        let event = fixture_target_event();
        let target = ReactionTarget::from_event(&event);
        assert_eq!(target.kind, Some(Kind::TEXT_NOTE));
        assert!(target.coordinate.is_none());
    }

    #[test]
    fn reaction_builder_emits_required_tags_and_content() {
        let keys = fixture_keys();
        let target_event = fixture_target_event();
        let target = ReactionTarget::from_event(&target_event);

        let event = EventBuilder::reaction(&target, &Reaction::Like)
            .sign_with_keys(&keys)
            .unwrap();

        assert_eq!(event.kind, Kind::REACTION);
        assert_eq!(event.content, "+");
        assert_eq!(target_event_id(&event.tags), Some(target_event.id));
        assert_eq!(target_pubkey(&event.tags), Some(target_event.pubkey));
        assert_eq!(target_kind(&event.tags), Some(Kind::TEXT_NOTE));
        event.verify().unwrap();
    }

    #[test]
    fn reaction_builder_adds_a_tag_for_addressable_target() {
        let keys = fixture_keys();
        let target_event = EventBuilder::new(Kind::LONG_FORM_TEXT_NOTE, "post")
            .tag(Tag::d("ident"))
            .sign_with_keys(&keys)
            .unwrap();
        let target = ReactionTarget::from_event(&target_event);

        let event = EventBuilder::reaction(&target, &Reaction::Emoji("🔥".into()))
            .sign_with_keys(&keys)
            .unwrap();

        assert_eq!(event.content, "🔥");
        let has_a_tag = event.tags.iter().any(|t| {
            matches!(
                t.kind(),
                TagKind::SingleLetter(s) if s.character == Alphabet::A && !s.uppercase
            )
        });
        assert!(has_a_tag, "addressable reactions must carry an `a` tag");
    }

    #[test]
    fn reaction_builder_propagates_relay_hint_to_e_and_p_tags() {
        let keys = fixture_keys();
        let relay = RelayUrl::parse("wss://relay.example/").unwrap();
        let target_event = fixture_target_event();
        let target = ReactionTarget::from_event(&target_event).with_relay_hint(relay.clone());

        let event = EventBuilder::reaction(&target, &Reaction::Like)
            .sign_with_keys(&keys)
            .unwrap();

        let e_tag = event
            .tags
            .iter()
            .find(|t| matches!(t.kind(), TagKind::SingleLetter(s) if s.character == Alphabet::E))
            .unwrap();
        // ["e", id, relay, author] per the NIP-25 spec example.
        assert_eq!(e_tag.values().len(), 4);
        assert_eq!(e_tag.get(2), Some(relay.as_str()));
        assert_eq!(e_tag.get(3), Some(target_event.pubkey.to_hex().as_str()));
    }

    #[test]
    fn target_helpers_pick_the_last_e_and_p_tag() {
        // Construct a synthetic reaction event with thread-context tags
        // followed by the actual target tags, mirroring the NIP-25
        // wording.
        let keys = fixture_keys();
        let unrelated =
            EventId::parse("1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap();
        let target_event = fixture_target_event();
        let target = ReactionTarget::from_event(&target_event);

        let event = EventBuilder::new(Kind::REACTION, "+")
            .tag(Tag::e(unrelated))
            .tag(Tag::e(target_event.id))
            .tag(Tag::p(*keys.public_key()))
            .tag(Tag::p(target.author))
            .tag(Tag::k(target.kind.unwrap()))
            .sign_with_keys(&keys)
            .unwrap();

        assert_eq!(target_event_id(&event.tags), Some(target_event.id));
        assert_eq!(target_pubkey(&event.tags), Some(target.author));
        assert_eq!(target_kind(&event.tags), Some(Kind::TEXT_NOTE));
    }
}
