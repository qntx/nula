//! Ordered collection of [`Tag`]s.
//!
//! [`Tags`] preserves the insertion order — relays and clients rely on the
//! exact order to compute event IDs (NIP-01) and to resolve replies, threads,
//! and addressable events. Helpers like [`Tags::identifier`] and
//! [`Tags::find_first`] give NIP-aware code a one-line lookup without
//! re-implementing the iteration.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::slice;
use std::sync::OnceLock;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::kind::TagKind;
use super::single_letter::{Alphabet, SingleLetterTag};
use super::tag::Tag;
use crate::event::coordinate::Coordinate;
use crate::event::id::EventId;
use crate::key::PublicKey;
use crate::types::Timestamp;

/// A lazily-built index from each single-letter tag head to the set of
/// its values.
///
/// Mirrors the shape a relay uses to evaluate NIP-01 `#<letter>` filters:
/// the key is the single-letter head (`e`, `p`, `a`, …, including the
/// uppercase variants), the value is the set of that head's tag values.
/// Built once by [`Tags::indexes`] and cached until the collection is
/// mutated.
pub type TagsIndexes = BTreeMap<SingleLetterTag, BTreeSet<String>>;

/// An ordered, mutable collection of [`Tag`]s.
///
/// The wire order is preserved exactly — event IDs (NIP-01) depend on it.
/// A lazily-built single-letter [index](Tags::indexes) accelerates filter
/// matching; the index is a pure cache derived from the tag list and is
/// therefore excluded from equality, hashing, `Debug` and serialization.
pub struct Tags {
    items: Vec<Tag>,
    /// Cached single-letter index, built on first [`Tags::indexes`] call
    /// and erased by every mutator. `OnceLock` keeps `Tags` `Send + Sync`
    /// (events are shared across threads in the relay, pool and storage
    /// layers). The index is boxed so an un-indexed tag list — the common
    /// case — adds only one pointer plus the lock to every [`Event`].
    indexes: OnceLock<Box<TagsIndexes>>,
}

// `Tags` (and therefore `Event`) must stay `Send + Sync`. A `RefCell` or
// `core::cell::OnceCell` cache would silently break this; lock it in.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Tags>();
};

impl Clone for Tags {
    fn clone(&self) -> Self {
        // The index is a derived cache, not identity: rebuild it lazily so
        // `clone` stays O(n) in the tag count regardless of cache state.
        Self::from_vec(self.items.clone())
    }
}

impl Default for Tags {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for Tags {
    fn eq(&self, other: &Self) -> bool {
        self.items == other.items
    }
}

impl Eq for Tags {}

impl Hash for Tags {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.items.hash(state);
    }
}

impl fmt::Debug for Tags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The derived index cache is deliberately omitted: it is not part
        // of the tag list's logical value.
        f.debug_struct("Tags")
            .field("items", &self.items)
            .finish_non_exhaustive()
    }
}

impl Serialize for Tags {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Transparent over the tag list: byte-identical to a bare
        // `Vec<Tag>`, which event-ID computation depends on.
        self.items.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Tags {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self::from_vec(Vec::<Tag>::deserialize(deserializer)?))
    }
}

impl Tags {
    /// Construct an empty collection.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            items: Vec::new(),
            indexes: OnceLock::new(),
        }
    }

    /// Construct from a `Vec<Tag>`.
    #[must_use]
    pub const fn from_vec(items: Vec<Tag>) -> Self {
        Self {
            items,
            indexes: OnceLock::new(),
        }
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

    /// Append a tag. Erases the cached [`TagsIndexes`].
    pub fn push(&mut self, tag: Tag) {
        self.erase_indexes();
        self.items.push(tag);
    }

    /// Append several tags from any iterator.
    pub fn extend<I>(&mut self, tags: I)
    where
        I: IntoIterator<Item = Tag>,
    {
        self.erase_indexes();
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
        self.erase_indexes();
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
        self.erase_indexes();
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

        self.erase_indexes();

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

    /// Borrow the lazily-built single-letter tag index, building and
    /// caching it on first access.
    ///
    /// The index maps each single-letter tag head (`e`, `p`, `a`, …, and
    /// their uppercase variants) to the set of its values — exactly the
    /// shape a relay needs to evaluate NIP-01 `#<letter>` filters. It is
    /// built once and reused until the collection is mutated, so matching
    /// one event against many filters costs a single index build instead
    /// of a full tag scan per filter.
    #[must_use]
    pub fn indexes(&self) -> &TagsIndexes {
        self.indexes.get_or_init(|| Box::new(self.build_indexes()))
    }

    /// Build the single-letter index from the current tag list.
    fn build_indexes(&self) -> TagsIndexes {
        let mut indexes = TagsIndexes::new();
        for tag in &self.items {
            if let (Some(letter), Some(content)) = (tag.single_letter_tag(), tag.content()) {
                indexes
                    .entry(letter)
                    .or_default()
                    .insert(content.to_owned());
            }
        }
        indexes
    }

    /// Drop any cached [`TagsIndexes`] so a stale view is never observed
    /// after a mutation. Cheap no-op when nothing is cached yet.
    fn erase_indexes(&mut self) {
        self.indexes.take();
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
        Self::from_vec(iter.into_iter().collect())
    }
}

impl From<Vec<Tag>> for Tags {
    fn from(items: Vec<Tag>) -> Self {
        Self::from_vec(items)
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

    #[test]
    fn indexes_group_values_by_single_letter_head() {
        let tags = Tags::from_vec(vec![
            tag(&["e", "id-1"]),
            tag(&["e", "id-2"]),
            tag(&["p", PK_HEX]),
            tag(&["alt", "ignored"]), // multi-char head -> excluded
            tag(&["x"]),              // single letter, but no value -> excluded
        ]);
        let idx = tags.indexes();
        let e = idx.get(&SingleLetterTag::lowercase(Alphabet::E)).unwrap();
        assert_eq!(e.len(), 2);
        assert!(e.contains("id-1") && e.contains("id-2"));
        assert!(idx.contains_key(&SingleLetterTag::lowercase(Alphabet::P)));
        assert_eq!(idx.len(), 2, "'alt' and value-less 'x' must not be indexed");
    }

    #[test]
    fn indexes_distinguish_letter_case() {
        let tags = Tags::from_vec(vec![tag(&["e", "lower"]), tag(&["E", "upper"])]);
        let idx = tags.indexes();
        assert!(
            idx.get(&SingleLetterTag::lowercase(Alphabet::E))
                .unwrap()
                .contains("lower")
        );
        assert!(
            idx.get(&SingleLetterTag::uppercase(Alphabet::E))
                .unwrap()
                .contains("upper")
        );
    }

    #[test]
    fn mutation_invalidates_cached_index() {
        let mut tags = Tags::from_vec(vec![tag(&["e", "id-1"])]);
        assert_eq!(tags.indexes().len(), 1); // force the cache to build
        tags.push(tag(&["p", PK_HEX])); // every mutator must erase it
        let idx = tags.indexes();
        assert_eq!(idx.len(), 2);
        assert!(idx.contains_key(&SingleLetterTag::lowercase(Alphabet::P)));
    }

    #[test]
    fn equality_and_hash_ignore_the_cache() {
        use std::collections::hash_map::DefaultHasher;

        let warm = Tags::from_vec(vec![tag(&["e", "id-1"])]);
        let cold = Tags::from_vec(vec![tag(&["e", "id-1"])]);
        assert!(!warm.indexes().is_empty()); // build the cache on exactly one

        assert_eq!(warm, cold, "the index cache must not affect equality");

        let digest = |t: &Tags| {
            let mut hasher = DefaultHasher::new();
            t.hash(&mut hasher);
            hasher.finish()
        };
        assert_eq!(
            digest(&warm),
            digest(&cold),
            "the cache must not affect Hash"
        );
    }

    #[test]
    fn clone_rebuilds_index_from_current_list() {
        let mut tags = Tags::from_vec(vec![tag(&["e", "id-1"])]);
        assert_eq!(tags.indexes().len(), 1); // warm the cache
        tags.push(tag(&["p", PK_HEX])); // invalidate it
        let cloned = tags.clone();
        assert_eq!(
            cloned.indexes().len(),
            2,
            "clone must reflect the live list"
        );
    }
}
