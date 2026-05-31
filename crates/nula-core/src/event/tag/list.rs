//! Ordered collection of [`Tag`]s.
//!
//! [`Tags`] preserves the insertion order — relays and clients rely on the
//! exact order to compute event IDs (NIP-01) and to resolve replies, threads,
//! and addressable events. Helpers like [`Tags::identifier`] and
//! [`Tags::find_first`] give NIP-aware code a one-line lookup without
//! re-implementing the iteration.

use std::collections::HashMap;
use std::fmt;
use std::slice;

use serde::{Deserialize, Serialize};

use super::kind::TagKind;
use super::single_letter::{Alphabet, SingleLetterTag};
use super::tag::Tag;
use crate::event::coordinate::Coordinate;
use crate::event::id::EventId;
use crate::key::PublicKey;
use crate::types::Timestamp;

/// An ordered, mutable collection of [`Tag`]s.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Tags {
    items: Vec<Tag>,
}

impl Tags {
    /// Construct an empty collection.
    #[must_use]
    pub const fn new() -> Self {
        Self { items: Vec::new() }
    }

    /// Construct from a `Vec<Tag>`.
    #[must_use]
    pub const fn from_vec(items: Vec<Tag>) -> Self {
        Self { items }
    }

    /// Return the number of tags.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.items.len()
    }

    /// `true` when the collection has no tags.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Append a tag.
    pub fn push(&mut self, tag: Tag) {
        self.items.push(tag);
    }

    /// Append several tags from any iterator.
    pub fn extend<I>(&mut self, tags: I)
    where
        I: IntoIterator<Item = Tag>,
    {
        self.items.extend(tags);
    }

    /// Replace any existing tag whose head equals `kind` with `tag`, or
    /// append `tag` when no such tag is present.
    ///
    /// This is the building block for builders that maintain an
    /// at-most-one-tag-per-head invariant — NIP-40's `expiration`,
    /// NIP-65's `r` (per-relay), NIP-70's `-`, NIP-13's `nonce`. Centralising
    /// the logic here keeps every builder consistent and avoids the
    /// `iter().filter().cloned().collect() → push → from_vec` template
    /// each one used to inline.
    pub fn replace_or_push(&mut self, kind: &TagKind, tag: Tag) {
        if let Some(slot) = self.items.iter_mut().find(|t| &t.kind() == kind) {
            *slot = tag;
        } else {
            self.items.push(tag);
        }
    }

    /// Append `tag` only if no existing tag has the same head.
    ///
    /// Used by NIP-70 where the protected marker is idempotent.
    pub fn push_unique_kind(&mut self, tag: Tag) {
        if self.items.iter().any(|t| t.kind() == tag.kind()) {
            return;
        }
        self.items.push(tag);
    }

    /// Borrow the tags as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[Tag] {
        &self.items
    }

    /// Iterate over the tags.
    pub fn iter(&self) -> slice::Iter<'_, Tag> {
        self.items.iter()
    }

    /// Return the first tag whose kind matches `kind`.
    #[must_use]
    pub fn find_first(&self, kind: &TagKind) -> Option<&Tag> {
        self.items.iter().find(|tag| tag.kind() == *kind)
    }

    /// Iterate over every tag whose kind matches `kind`.
    pub fn find_all<'a>(&'a self, kind: &'a TagKind) -> impl Iterator<Item = &'a Tag> + 'a {
        self.items.iter().filter(move |tag| tag.kind() == *kind)
    }

    /// Iterate over every tag whose kind is the lowercase single letter
    /// `letter`. Convenience for the very common `e`/`p`/`a` queries.
    pub fn find_letter(&self, letter: Alphabet) -> impl Iterator<Item = &Tag> + '_ {
        let kind = TagKind::single_letter(SingleLetterTag::lowercase(letter));
        self.items.iter().filter(move |tag| tag.kind() == kind)
    }

    /// Return the value of the first `d` tag (the *identifier* used by NIP-01
    /// addressable events).
    #[must_use]
    pub fn identifier(&self) -> Option<&str> {
        self.find_letter(Alphabet::D).next().and_then(Tag::content)
    }

    /// Extract the [`PublicKey`]s referenced by `p` tags, skipping any whose
    /// value is not a valid 32-byte hex key.
    pub fn public_keys(&self) -> impl Iterator<Item = PublicKey> + '_ {
        self.find_letter(Alphabet::P)
            .filter_map(|tag| PublicKey::parse(tag.content()?).ok())
    }

    /// Extract the [`EventId`]s referenced by `e` tags, skipping any whose
    /// value is not a valid 32-byte hex id.
    pub fn event_ids(&self) -> impl Iterator<Item = EventId> + '_ {
        self.find_letter(Alphabet::E)
            .filter_map(|tag| EventId::parse(tag.content()?).ok())
    }

    /// Extract the [`Coordinate`]s referenced by `a` tags, skipping any whose
    /// value is not a valid `<kind>:<author>:<identifier>` triple.
    pub fn coordinates(&self) -> impl Iterator<Item = Coordinate> + '_ {
        self.find_letter(Alphabet::A)
            .filter_map(|tag| Coordinate::parse(tag.content()?).ok())
    }

    /// Extract the hashtag values carried by `t` tags.
    pub fn hashtags(&self) -> impl Iterator<Item = &str> {
        self.find_letter(Alphabet::T).filter_map(Tag::content)
    }

    /// Return the NIP-40 `expiration` [`Timestamp`], if a well-formed
    /// `expiration` tag is present.
    #[must_use]
    pub fn expiration(&self) -> Option<Timestamp> {
        let secs: u64 = self
            .find_first(&TagKind::custom("expiration"))?
            .content()?
            .parse()
            .ok()?;
        Some(Timestamp::from_secs(secs))
    }

    /// Return the NIP-42 `challenge` string, if a `challenge` tag is present.
    #[must_use]
    pub fn challenge(&self) -> Option<&str> {
        self.find_first(&TagKind::custom("challenge"))?.content()
    }

    /// Deduplicate tags in place.
    ///
    /// Two tags are duplicates when they share the same head *and* the same
    /// content (the value at index 1, if any). Among duplicates the longest
    /// tag is retained, placed at the position of the earliest occurrence;
    /// shorter duplicates are dropped. Tag order is otherwise preserved.
    pub fn dedup(&mut self) {
        /// Tracks, per dedup key, the earliest occurrence and the longest
        /// (best) tag seen so far.
        struct DedupVal {
            first_idx: usize,
            best_idx: usize,
        }

        if self.items.is_empty() {
            return;
        }

        let mut map: HashMap<(&str, Option<&str>), DedupVal> =
            HashMap::with_capacity(self.items.len());
        for (idx, tag) in self.items.iter().enumerate() {
            let key = (tag.name(), tag.content());
            let entry = map.entry(key).or_insert(DedupVal {
                first_idx: idx,
                best_idx: idx,
            });
            let best_len = self.items.get(entry.best_idx).map_or(0, Tag::len);
            if tag.len() > best_len {
                entry.best_idx = idx;
            }
        }

        let mut new_list: Vec<Option<Tag>> = vec![None; self.items.len()];
        for DedupVal {
            first_idx,
            best_idx,
        } in map.into_values()
        {
            if let (Some(slot), Some(best)) =
                (new_list.get_mut(first_idx), self.items.get(best_idx))
            {
                *slot = Some(best.clone());
            }
        }
        self.items = new_list.into_iter().flatten().collect();
    }

    /// Decompose into the underlying `Vec<Tag>`.
    #[must_use]
    pub fn into_vec(self) -> Vec<Tag> {
        self.items
    }
}

impl<'a> IntoIterator for &'a Tags {
    type Item = &'a Tag;
    type IntoIter = slice::Iter<'a, Tag>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.iter()
    }
}

impl IntoIterator for Tags {
    type Item = Tag;
    type IntoIter = std::vec::IntoIter<Tag>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.into_iter()
    }
}

impl FromIterator<Tag> for Tags {
    fn from_iter<I: IntoIterator<Item = Tag>>(iter: I) -> Self {
        Self {
            items: iter.into_iter().collect(),
        }
    }
}

impl From<Vec<Tag>> for Tags {
    fn from(items: Vec<Tag>) -> Self {
        Self { items }
    }
}

impl fmt::Display for Tags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[")?;
        for (idx, tag) in self.items.iter().enumerate() {
            if idx > 0 {
                f.write_str(", ")?;
            }
            fmt::Display::fmt(tag, f)?;
        }
        f.write_str("]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tag(values: &[&str]) -> Tag {
        Tag::new(values.iter().copied()).unwrap()
    }

    #[test]
    fn empty_default() {
        let tags = Tags::default();
        assert!(tags.is_empty());
        assert_eq!(tags.len(), 0);
    }

    #[test]
    fn push_and_iterate_preserves_order() {
        let mut tags = Tags::new();
        tags.push(tag(&["e", "id-1"]));
        tags.push(tag(&["p", "pk-1"]));
        tags.push(tag(&["e", "id-2"]));

        let names: Vec<&str> = tags.iter().map(Tag::name).collect();
        assert_eq!(names, ["e", "p", "e"]);
    }

    #[test]
    fn find_first_returns_earliest_match() {
        let tags = Tags::from_vec(vec![
            tag(&["p", "alice"]),
            tag(&["e", "id-1"]),
            tag(&["e", "id-2"]),
        ]);
        let first_e = tags
            .find_first(&TagKind::single_letter(SingleLetterTag::lowercase(
                Alphabet::E,
            )))
            .unwrap();
        assert_eq!(first_e.content(), Some("id-1"));
    }

    #[test]
    fn find_all_yields_each_match() {
        let tags = Tags::from_vec(vec![
            tag(&["e", "id-1"]),
            tag(&["p", "pk"]),
            tag(&["e", "id-2"]),
        ]);
        let kind = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::E));
        let collected: Vec<&str> = tags.find_all(&kind).filter_map(Tag::content).collect();
        assert_eq!(collected, ["id-1", "id-2"]);
    }

    #[test]
    fn identifier_returns_first_d_tag() {
        let tags = Tags::from_vec(vec![
            tag(&["e", "id"]),
            tag(&["d", "primary"]),
            tag(&["d", "secondary"]),
        ]);
        assert_eq!(tags.identifier(), Some("primary"));
    }

    #[test]
    fn identifier_none_when_missing() {
        let tags = Tags::from_vec(vec![tag(&["e", "id"])]);
        assert_eq!(tags.identifier(), None);
    }

    #[test]
    fn serde_round_trip() {
        let tags = Tags::from_vec(vec![tag(&["e", "id-1"]), tag(&["alt", "hello"])]);
        let json = serde_json::to_string(&tags).unwrap();
        assert_eq!(json, r#"[["e","id-1"],["alt","hello"]]"#);
        let parsed: Tags = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, tags);
    }

    #[test]
    fn into_iter_consumes() {
        let tags = Tags::from_vec(vec![tag(&["e", "x"]), tag(&["p", "y"])]);
        assert_eq!(tags.into_iter().count(), 2);
    }

    #[test]
    fn ref_into_iter_borrows() {
        let tags = Tags::from_vec(vec![tag(&["e", "x"])]);
        for t in &tags {
            assert_eq!(t.name(), "e");
        }
    }

    #[test]
    fn replace_or_push_appends_when_absent() {
        let mut tags = Tags::new();
        let kind = TagKind::from_wire("expiration");
        tags.replace_or_push(&kind, tag(&["expiration", "100"]));
        assert_eq!(tags.len(), 1);
        assert_eq!(tags.find_first(&kind).unwrap().content(), Some("100"));
    }

    #[test]
    fn replace_or_push_replaces_existing() {
        let mut tags = Tags::from_vec(vec![tag(&["expiration", "100"])]);
        let kind = TagKind::from_wire("expiration");
        tags.replace_or_push(&kind, tag(&["expiration", "200"]));
        assert_eq!(tags.len(), 1, "must not duplicate");
        assert_eq!(tags.find_first(&kind).unwrap().content(), Some("200"));
    }

    #[test]
    fn push_unique_kind_is_idempotent() {
        let mut tags = Tags::new();
        let marker = tag(&["-"]);
        tags.push_unique_kind(marker.clone());
        tags.push_unique_kind(marker.clone());
        tags.push_unique_kind(marker);
        let head_kind = TagKind::from_wire("-");
        assert_eq!(tags.find_all(&head_kind).count(), 1);
    }

    const PK_HEX: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const ID_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn public_keys_extracts_valid_p_tags_only() {
        let tags = Tags::from_vec(vec![
            tag(&["p", PK_HEX]),
            tag(&["p", "not-hex"]),
            tag(&["e", PK_HEX]),
        ]);
        let keys: Vec<PublicKey> = tags.public_keys().collect();
        assert_eq!(keys, vec![PublicKey::parse(PK_HEX).unwrap()]);
    }

    #[test]
    fn event_ids_extracts_valid_e_tags_only() {
        let tags = Tags::from_vec(vec![tag(&["e", ID_HEX]), tag(&["e", "bad"])]);
        let ids: Vec<EventId> = tags.event_ids().collect();
        assert_eq!(ids, vec![EventId::parse(ID_HEX).unwrap()]);
    }

    #[test]
    fn coordinates_extracts_valid_a_tags_only() {
        let coord = format!("30023:{PK_HEX}:alpha");
        let tags = Tags::from_vec(vec![tag(&["a", &coord]), tag(&["a", "bad"])]);
        let coords: Vec<Coordinate> = tags.coordinates().collect();
        assert_eq!(coords, vec![Coordinate::parse(&coord).unwrap()]);
    }

    #[test]
    fn hashtags_extracts_t_tags() {
        let tags = Tags::from_vec(vec![
            tag(&["t", "nostr"]),
            tag(&["t", "rust"]),
            tag(&["e", "x"]),
        ]);
        let collected: Vec<&str> = tags.hashtags().collect();
        assert_eq!(collected, ["nostr", "rust"]);
    }

    #[test]
    fn expiration_parses_well_formed_tag() {
        let tags = Tags::from_vec(vec![tag(&["expiration", "1700000000"])]);
        assert_eq!(tags.expiration(), Some(Timestamp::from_secs(1_700_000_000)));
        let bad = Tags::from_vec(vec![tag(&["expiration", "not-a-number"])]);
        assert_eq!(bad.expiration(), None);
        assert_eq!(Tags::new().expiration(), None);
    }

    #[test]
    fn challenge_returns_first_challenge_tag() {
        let tags = Tags::from_vec(vec![tag(&["challenge", "abc123"])]);
        assert_eq!(tags.challenge(), Some("abc123"));
        assert_eq!(Tags::new().challenge(), None);
    }

    #[test]
    fn dedup_keeps_longest_at_earliest_position() {
        // Mirrors the upstream rust-nostr `Tags::dedup` doc example.
        let mut tags = Tags::from_vec(vec![
            tag(&["t", "test"]),
            tag(&["t", "test1"]),
            tag(&["t", "test", "wss://relay.damus.io"]),
        ]);
        tags.dedup();
        let expected = Tags::from_vec(vec![
            tag(&["t", "test", "wss://relay.damus.io"]),
            tag(&["t", "test1"]),
        ]);
        assert_eq!(tags, expected);
    }

    #[test]
    fn dedup_distinguishes_by_content() {
        let mut tags = Tags::from_vec(vec![
            tag(&["p", "alice"]),
            tag(&["p", "bob"]),
            tag(&["p", "alice"]),
        ]);
        tags.dedup();
        assert_eq!(tags.len(), 2);
        assert_eq!(tags.as_slice()[0], tag(&["p", "alice"]));
        assert_eq!(tags.as_slice()[1], tag(&["p", "bob"]));
    }
}
