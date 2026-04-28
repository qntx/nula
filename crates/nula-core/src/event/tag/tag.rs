// Copyright (c) 2026 QNTX <https://qntx.fun>
// Distributed under the MIT or Apache-2.0 license.

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

/// Errors raised when constructing a [`Tag`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
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
    /// columns afterwards via [`Tag::with`] if needed.
    #[must_use]
    pub fn e(id: EventId) -> Self {
        let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::E));
        Self::with(&head, [id.to_hex()])
    }

    /// Build a NIP-01 `p` tag referencing a pubkey.
    ///
    /// Wire form: `["p", "<pubkey-hex>"]`.
    #[must_use]
    pub fn p(pubkey: PublicKey) -> Self {
        let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::P));
        Self::with(&head, [pubkey.to_hex()])
    }

    /// Build a NIP-01 `a` tag referencing an addressable event coordinate.
    ///
    /// Wire form: `["a", "<kind>:<author-hex>:<identifier>"]`.
    #[must_use]
    pub fn a(coordinate: &Coordinate) -> Self {
        let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::A));
        Self::with(&head, [coordinate.to_wire()])
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
}
