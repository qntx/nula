//! A single Nostr tag.
//!
//! Per [NIP-01], a tag is a JSON array of strings whose first element names
//! the tag and whose subsequent elements carry tag-specific arguments. The
//! [`Tag`] struct preserves that raw shape while exposing helpers around the
//! head ([`Tag::kind`]) and the most common argument ([`Tag::content`]).
//!
//! [NIP-01]: https://github.com/nostr-protocol/nips/blob/master/01.md

use core::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use super::kind::TagKind;
use super::single_letter::{Alphabet, SingleLetterTag};
use crate::event::coordinate::Coordinate;
use crate::event::id::EventId;
use crate::event::kind::Kind;
use crate::key::PublicKey;
use crate::types::{RelayUrl, Url};

/// Errors raised when constructing a [`Tag`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum TagError {
    /// The tag had no head element.
    #[error("a tag must contain at least one element (the head)")]
    Empty,
}

/// A Nostr tag — a non-empty list of strings whose first element names the
/// tag.
///
/// Parsed-then-typed accessors live in NIP-specific helpers; here we only
/// preserve the raw shape and expose the head as a [`TagKind`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tag {
    /// The raw values; index `0` is the head, the rest are arguments.
    values: Vec<String>,
}

impl Tag {
    /// Construct from a non-empty list of values.
    ///
    /// # Errors
    ///
    /// Returns [`TagError::Empty`] if `values` is empty.
    pub fn new<I, S>(values: I) -> Result<Self, TagError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let values: Vec<String> = values.into_iter().map(Into::into).collect();
        if values.is_empty() {
            return Err(TagError::Empty);
        }
        Ok(Self { values })
    }

    /// Build a tag with a known [`TagKind`] head and string arguments.
    pub fn with<I, S>(head: &TagKind, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let iter = args.into_iter();
        let (lower, _upper) = iter.size_hint();
        let mut values = Vec::with_capacity(lower + 1);
        values.push(head.as_str().to_owned());
        values.extend(iter.map(Into::into));
        Self { values }
    }

    /// Build a NIP-01 `e` tag referencing an event id.
    ///
    /// Wire form: `["e", "<event-id-hex>"]`. Add relay-hint or marker
    /// columns afterwards via [`Tag::with`] if needed; for the common
    /// shapes use [`Tag::e_with_relay`] or [`Tag::e_marker`].
    #[must_use]
    pub fn e(id: EventId) -> Self {
        let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::E));
        Self::with(&head, [id.to_hex()])
    }

    /// Build a NIP-01 `e` tag with a relay hint.
    ///
    /// Wire form: `["e", "<event-id-hex>", "<relay-url>"]`. The
    /// optional fourth marker (`reply` / `root` / `mention`) goes via
    /// [`Tag::e_marker`].
    #[must_use]
    pub fn e_with_relay(id: EventId, relay: &RelayUrl) -> Self {
        let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::E));
        Self::with(&head, [id.to_hex(), relay.as_str().to_owned()])
    }

    /// Build a NIP-10 `e` tag with relay hint and marker.
    ///
    /// Wire form: `["e", "<event-id-hex>", "<relay-url>", "<marker>"]`.
    /// `marker` is one of `"reply"`, `"root"`, or `"mention"` per
    /// NIP-10's threading rules; pass an empty `relay` if no hint is
    /// available (the marker stays at index 3 in that case, as the
    /// spec requires).
    #[must_use]
    pub fn e_marker(id: EventId, relay: &str, marker: &str) -> Self {
        let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::E));
        Self::with(&head, [id.to_hex(), relay.to_owned(), marker.to_owned()])
    }

    /// Build a NIP-01 `p` tag referencing a pubkey.
    ///
    /// Wire form: `["p", "<pubkey-hex>"]`.
    #[must_use]
    pub fn p(pubkey: PublicKey) -> Self {
        let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::P));
        Self::with(&head, [pubkey.to_hex()])
    }

    /// Build a NIP-01 `p` tag with a relay hint.
    ///
    /// Wire form: `["p", "<pubkey-hex>", "<relay-url>"]`.
    #[must_use]
    pub fn p_with_relay(pubkey: PublicKey, relay: &RelayUrl) -> Self {
        let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::P));
        Self::with(&head, [pubkey.to_hex(), relay.as_str().to_owned()])
    }

    /// Build a NIP-01 `a` tag referencing an addressable event coordinate.
    ///
    /// Wire form: `["a", "<kind>:<author-hex>:<identifier>"]`.
    #[must_use]
    pub fn a(coordinate: &Coordinate) -> Self {
        let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::A));
        Self::with(&head, [coordinate.to_wire()])
    }

    /// Build a NIP-01 `a` tag with a relay hint.
    ///
    /// Wire form: `["a", "<coordinate>", "<relay-url>"]`.
    #[must_use]
    pub fn a_with_relay(coordinate: &Coordinate, relay: &RelayUrl) -> Self {
        let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::A));
        Self::with(&head, [coordinate.to_wire(), relay.as_str().to_owned()])
    }

    /// Build a NIP-09 / NIP-22 `k` tag carrying a kind hint.
    ///
    /// Wire form: `["k", "<kind>"]`.
    #[must_use]
    pub fn k(kind: Kind) -> Self {
        let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::K));
        Self::with(&head, [kind.as_u16().to_string()])
    }

    /// Build a NIP-01 / NIP-33 `d` tag carrying a parameterized identifier.
    ///
    /// Wire form: `["d", "<identifier>"]`.
    #[must_use]
    pub fn d<S: Into<String>>(identifier: S) -> Self {
        let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::D));
        Self::with(&head, [identifier.into()])
    }

    /// Build a NIP-24 `t` hashtag tag.
    ///
    /// NIP-24 pins the wire value to a **lowercase** string, so this
    /// constructor applies [`str::to_lowercase`] to the input. Callers
    /// who genuinely need the pre-normalised form can still reach for
    /// [`Tag::new`] and pass the raw bytes explicitly.
    ///
    /// Wire form: `["t", "<lowercase-hashtag>"]`.
    #[must_use]
    pub fn t<S: AsRef<str>>(hashtag: S) -> Self {
        let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::T));
        Self::with(&head, [hashtag.as_ref().to_lowercase()])
    }

    /// Build a NIP-24 `r` reference tag pointing at a web URL.
    ///
    /// The URL's lossless wire form is taken via [`Url::as_str`]; the
    /// type guarantees it is a syntactically valid URL, which defends
    /// downstream consumers from receiving truncated or whitespace-
    /// polluted references.
    ///
    /// Wire form: `["r", "<url>"]`.
    #[must_use]
    pub fn r(url: &Url) -> Self {
        let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::R));
        Self::with(&head, [url.as_str().to_owned()])
    }

    /// Build a NIP-24 / NIP-73 `i` external-id tag with no context
    /// hint.
    ///
    /// The concrete external-id grammar (`podcast:guid:<uuid>`,
    /// `isbn:<digits>`, …) lives in NIP-73; this helper only fixes the
    /// wire shape.
    ///
    /// Wire form: `["i", "<external-id>"]`.
    #[must_use]
    pub fn i<S: Into<String>>(external_id: S) -> Self {
        let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::I));
        Self::with(&head, [external_id.into()])
    }

    /// Build a NIP-24 / NIP-73 `i` external-id tag with an authority
    /// URL (e.g. a relay or resolver that understands the id scheme).
    ///
    /// Wire form: `["i", "<external-id>", "<context>"]`.
    #[must_use]
    pub fn i_with_context<I, C>(external_id: I, context: C) -> Self
    where
        I: Into<String>,
        C: Into<String>,
    {
        let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::I));
        Self::with(&head, [external_id.into(), context.into()])
    }

    /// Build a NIP-24 `title` tag.
    ///
    /// NIP-24 pins `title` as the human-readable name of NIP-51 sets,
    /// NIP-52 calendar events, NIP-53 live events, and NIP-99 listings.
    ///
    /// Wire form: `["title", "<text>"]`.
    #[must_use]
    pub fn title<S: Into<String>>(title: S) -> Self {
        Self::with(&TagKind::Custom("title".to_owned()), [title.into()])
    }

    /// Build a NIP-31 `alt` tag carrying a plain-text fallback
    /// description for unknown event kinds.
    ///
    /// Wire form: `["alt", "<summary>"]`. See
    /// [`crate::nips::nip31`] for the read side
    /// ([`crate::nips::nip31::alt_description`]).
    #[must_use]
    pub fn alt<S: Into<String>>(summary: S) -> Self {
        Self::with(&TagKind::Custom("alt".to_owned()), [summary.into()])
    }

    /// Build a NIP-14 `subject` tag for a `kind: 1` text note.
    ///
    /// Wire form: `["subject", "<text>"]`. NIP-14 recommends keeping
    /// the subject under 80 chars; the helper does not enforce that
    /// because some clients legitimately ship longer subjects and
    /// trimming behaviour is a UI concern. See
    /// [`crate::nips::nip14`] for the read side and reply-replication
    /// helpers.
    #[must_use]
    pub fn subject<S: Into<String>>(subject: S) -> Self {
        Self::with(&TagKind::Custom("subject".to_owned()), [subject.into()])
    }

    /// Build a NIP-18 `q` quote-repost tag for a regular event.
    ///
    /// Wire form: `["q", "<event-id-hex>", "<relay-url>", "<author-hex>"]`.
    /// The author hint is **mandatory** per the NIP-18 §Quote Reposts
    /// schema for regular events; use [`Tag::q_addressable`] when
    /// quoting a replaceable / addressable event by coordinate.
    #[must_use]
    pub fn q(event_id: EventId, relay: &RelayUrl, author: PublicKey) -> Self {
        let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::Q));
        Self::with(
            &head,
            [
                event_id.to_hex(),
                relay.as_str().to_owned(),
                author.to_hex(),
            ],
        )
    }

    /// Build a NIP-18 `q` quote-repost tag for an addressable event.
    ///
    /// Wire form: `["q", "<kind>:<author>:<identifier>", "<relay-url>"]`.
    /// The author is implicit in the coordinate, so unlike [`Tag::q`]
    /// no separate author column is appended.
    #[must_use]
    pub fn q_addressable(coordinate: &Coordinate, relay: &RelayUrl) -> Self {
        let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::Q));
        Self::with(&head, [coordinate.to_wire(), relay.as_str().to_owned()])
    }

    /// Return the tag head as a [`TagKind`].
    #[must_use]
    pub fn kind(&self) -> TagKind {
        // Safe: `values` is guaranteed non-empty by the constructor.
        let head = self.values.first().map_or("", String::as_str);
        TagKind::from_wire(head)
    }

    /// Return the tag head's wire form (the first element).
    #[must_use]
    pub fn name(&self) -> &str {
        self.values.first().map_or("", String::as_str)
    }

    /// Return the second element, if any. Most NIP tags use the element at
    /// index `1` as the primary value (`["e", <event_id>, …]`,
    /// `["p", <pubkey>, …]`, `["alt", <text>]`, …).
    #[must_use]
    pub fn content(&self) -> Option<&str> {
        self.values.get(1).map(String::as_str)
    }

    /// Borrow every value (head + arguments).
    #[must_use]
    pub fn values(&self) -> &[String] {
        &self.values
    }

    /// Return the argument at `index` (0 is the head).
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&str> {
        self.values.get(index).map(String::as_str)
    }

    /// Return the number of values (always at least `1`).
    #[must_use]
    #[allow(
        clippy::len_without_is_empty,
        reason = "Tag is non-empty by construction"
    )]
    pub const fn len(&self) -> usize {
        self.values.len()
    }

    /// Decompose into the underlying `Vec<String>`.
    #[must_use]
    pub fn into_values(self) -> Vec<String> {
        self.values
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[")?;
        for (idx, value) in self.values.iter().enumerate() {
            if idx > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{value:?}")?;
        }
        f.write_str("]")
    }
}

impl Serialize for Tag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.values.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Tag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = Vec::<String>::deserialize(deserializer)?;
        Self::new(values).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::super::single_letter::{Alphabet, SingleLetterTag};
    use super::*;

    #[test]
    fn new_rejects_empty() {
        let err = Tag::new(Vec::<&str>::new()).unwrap_err();
        assert_eq!(err, TagError::Empty);
    }

    #[test]
    fn kind_for_single_letter() {
        let tag = Tag::new(["e", "abc"]).unwrap();
        assert_eq!(
            tag.kind(),
            TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::E))
        );
    }

    #[test]
    fn kind_for_custom() {
        let tag = Tag::new(["expiration", "12345"]).unwrap();
        assert_eq!(tag.kind(), TagKind::custom("expiration"));
    }

    #[test]
    fn content_returns_second_element() {
        let tag = Tag::new(["e", "abc", "wss://example"]).unwrap();
        assert_eq!(tag.content(), Some("abc"));
    }

    #[test]
    fn content_when_only_head() {
        let tag = Tag::new(["alt"]).unwrap();
        assert_eq!(tag.content(), None);
    }

    #[test]
    fn values_are_preserved_in_order() {
        let tag = Tag::new(["p", "<pk>", "wss://r", "alice"]).unwrap();
        assert_eq!(tag.values(), ["p", "<pk>", "wss://r", "alice"]);
    }

    #[test]
    fn len_at_least_one() {
        let tag = Tag::new(["alt"]).unwrap();
        assert_eq!(tag.len(), 1);
    }

    #[test]
    fn with_builds_from_kind() {
        let tag = Tag::with(
            &TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::P)),
            ["pubkey-hex", "wss://relay"],
        );
        assert_eq!(tag.values(), ["p", "pubkey-hex", "wss://relay"]);
    }

    #[test]
    fn serialize_is_array() {
        let tag = Tag::new(["e", "abc"]).unwrap();
        let json = serde_json::to_string(&tag).unwrap();
        assert_eq!(json, r#"["e","abc"]"#);
    }

    #[test]
    fn deserialize_round_trip() {
        let json = r#"["alt","short description"]"#;
        let tag: Tag = serde_json::from_str(json).unwrap();
        assert_eq!(tag.kind(), TagKind::custom("alt"));
        assert_eq!(tag.content(), Some("short description"));
    }

    #[test]
    fn deserialize_rejects_empty_array() {
        let err = serde_json::from_str::<Tag>("[]").unwrap_err();
        assert!(err.to_string().contains("at least one element"));
    }

    fn fixture_event_id() -> EventId {
        EventId::from_byte_array([0x11; 32])
    }

    fn fixture_pubkey() -> PublicKey {
        *crate::Keys::parse("0000000000000000000000000000000000000000000000000000000000000003")
            .unwrap()
            .public_key()
    }

    fn fixture_relay() -> RelayUrl {
        RelayUrl::parse("wss://relay.example/").unwrap()
    }

    #[test]
    fn e_with_relay_carries_url_at_index_2() {
        let tag = Tag::e_with_relay(fixture_event_id(), &fixture_relay());
        assert_eq!(tag.values().len(), 3);
        assert_eq!(tag.get(0), Some("e"));
        assert_eq!(tag.get(1).unwrap().len(), 64);
        assert_eq!(tag.get(2), Some("wss://relay.example/"));
    }

    #[test]
    fn e_marker_keeps_marker_at_index_3() {
        let tag = Tag::e_marker(fixture_event_id(), "wss://r.example/", "reply");
        assert_eq!(tag.values().len(), 4);
        assert_eq!(tag.get(0), Some("e"));
        assert_eq!(tag.get(2), Some("wss://r.example/"));
        assert_eq!(tag.get(3), Some("reply"));
    }

    #[test]
    fn e_marker_with_empty_relay_still_holds_index_3() {
        // NIP-10: when no relay hint is available, the relay slot
        // stays an empty string so the marker can occupy index 3.
        let tag = Tag::e_marker(fixture_event_id(), "", "root");
        assert_eq!(tag.values().len(), 4);
        assert_eq!(tag.get(2), Some(""));
        assert_eq!(tag.get(3), Some("root"));
    }

    #[test]
    fn p_with_relay_carries_url_at_index_2() {
        let tag = Tag::p_with_relay(fixture_pubkey(), &fixture_relay());
        assert_eq!(tag.values().len(), 3);
        assert_eq!(tag.get(0), Some("p"));
        assert_eq!(tag.get(2), Some("wss://relay.example/"));
    }

    #[test]
    fn a_with_relay_carries_url_at_index_2() {
        let coord = Coordinate::new(Kind::from(30_023_u16), fixture_pubkey(), "alpha");
        let tag = Tag::a_with_relay(&coord, &fixture_relay());
        assert_eq!(tag.values().len(), 3);
        assert_eq!(tag.get(0), Some("a"));
        assert!(tag.get(1).unwrap().starts_with("30023:"));
        assert_eq!(tag.get(2), Some("wss://relay.example/"));
    }

    #[test]
    fn t_normalises_hashtag_to_lowercase() {
        let tag = Tag::t("RustLang");
        assert_eq!(tag.values(), ["t", "rustlang"]);
    }

    #[test]
    fn t_passes_already_lowercase_input_through() {
        let tag = Tag::t("nostr");
        assert_eq!(tag.values(), ["t", "nostr"]);
    }

    #[test]
    fn r_takes_typed_url_and_preserves_canonical_form() {
        let url = Url::parse("https://example.com/path?q=1").unwrap();
        let tag = Tag::r(&url);
        assert_eq!(tag.get(0), Some("r"));
        assert_eq!(tag.get(1), Some("https://example.com/path?q=1"));
    }

    #[test]
    fn i_external_id_has_two_element_shape() {
        let tag = Tag::i("podcast:guid:c90e6b9a-1234-5678-9abc-def012345678");
        assert_eq!(tag.values().len(), 2);
        assert_eq!(tag.get(0), Some("i"));
        assert_eq!(
            tag.get(1),
            Some("podcast:guid:c90e6b9a-1234-5678-9abc-def012345678")
        );
    }

    #[test]
    fn i_with_context_has_three_element_shape() {
        let tag = Tag::i_with_context("isbn:9780306406157", "https://openlibrary.org");
        assert_eq!(tag.values().len(), 3);
        assert_eq!(tag.get(0), Some("i"));
        assert_eq!(tag.get(1), Some("isbn:9780306406157"));
        assert_eq!(tag.get(2), Some("https://openlibrary.org"));
    }

    #[test]
    fn title_produces_custom_two_element_tag() {
        let tag = Tag::title("My Blog Post");
        assert_eq!(tag.values(), ["title", "My Blog Post"]);
        assert_eq!(tag.kind(), TagKind::custom("title"));
    }

    #[test]
    fn alt_produces_custom_two_element_tag() {
        let tag = Tag::alt("a music playlist");
        assert_eq!(tag.values(), ["alt", "a music playlist"]);
        assert_eq!(tag.kind(), TagKind::custom("alt"));
    }
}
