// Copyright (c) 2026 QNTX <https://qntx.fun>
// Distributed under the MIT or Apache-2.0 license.

//! Ordered collection of [`Tag`]s.
//!
//! [`Tags`] preserves the insertion order — relays and clients rely on the
//! exact order to compute event IDs (NIP-01) and to resolve replies, threads,
//! and addressable events. Helpers like [`Tags::identifier`] and
//! [`Tags::find_first`] give NIP-aware code a one-line lookup without
//! re-implementing the iteration.

use core::fmt;
use core::slice;

use serde::{Deserialize, Serialize};

use super::kind::TagKind;
use super::single_letter::{Alphabet, SingleLetterTag};
use super::tag::Tag;

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
    pub fn find_all<'a>(
        &'a self,
        kind: &'a TagKind,
    ) -> impl Iterator<Item = &'a Tag> + 'a {
        self.items.iter().filter(move |tag| tag.kind() == *kind)
    }

    /// Iterate over every tag whose kind is the lowercase single letter
    /// `letter`. Convenience for the very common `e`/`p`/`a` queries.
    pub fn find_letter(&self, letter: Alphabet) -> impl Iterator<Item = &Tag> + '_ {
        let kind = TagKind::single_letter(SingleLetterTag::lowercase(letter));
        self.items
            .iter()
            .filter(move |tag| tag.kind() == kind)
    }

    /// Return the value of the first `d` tag (the *identifier* used by NIP-01
    /// addressable events).
    #[must_use]
    pub fn identifier(&self) -> Option<&str> {
        self.find_letter(Alphabet::D)
            .next()
            .and_then(Tag::content)
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
        let collected: Vec<&str> = tags
            .find_all(&kind)
            .filter_map(Tag::content)
            .collect();
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
}
