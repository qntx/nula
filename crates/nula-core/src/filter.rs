// Copyright (c) 2026 QNTX <https://qntx.fun>
// Distributed under the MIT or Apache-2.0 license.

//! NIP-01 subscription filter.
//!
//! A [`Filter`] is the JSON object Nostr clients ship inside `REQ` messages
//! to ask a relay for events. Every field is optional; when several are set,
//! a relay returns the events that satisfy *all* of them (logical AND).
//!
//! The wire format is the JSON object described by NIP-01:
//!
//! ```json
//! {
//!   "ids":     ["<id>",     ...],
//!   "authors": ["<pubkey>", ...],
//!   "kinds":   [<kind>,     ...],
//!   "since":   <unix_ts>,
//!   "until":   <unix_ts>,
//!   "limit":   <n>,
//!   "search":  "<text>",
//!   "#a":      ["<value>", ...],
//!   "#e":      ["<id>",    ...],
//!   "#p":      ["<pubkey>", ...]
//! }
//! ```
//!
//! Single-letter tag filter keys use the `#<letter>` form. Both lowercase and
//! uppercase forms are supported (NIP-01 §generic tag queries).

use std::collections::{BTreeMap, BTreeSet};

use serde::de::{self, MapAccess, Visitor};
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Deserializer, Serialize};

use crate::event::{Event, EventId, Kind, SingleLetterTag, Tag, TagKind};
use crate::key::PublicKey;
use crate::types::Timestamp;

/// NIP-01 subscription filter.
///
/// All fields are public so consumers can read them without going through
/// builder accessors when matching events.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Filter {
    /// Event IDs to match.
    pub ids: Option<BTreeSet<EventId>>,
    /// Author public keys to match.
    pub authors: Option<BTreeSet<PublicKey>>,
    /// Event kinds to match.
    pub kinds: Option<BTreeSet<Kind>>,
    /// Inclusive lower bound on `created_at`.
    pub since: Option<Timestamp>,
    /// Inclusive upper bound on `created_at`.
    pub until: Option<Timestamp>,
    /// Maximum number of events to return.
    pub limit: Option<usize>,
    /// Free-form search query (NIP-50).
    pub search: Option<String>,
    /// Single-letter tag filters (`#a`, `#e`, `#p`, …).
    pub generic_tags: BTreeMap<SingleLetterTag, BTreeSet<String>>,
}

impl Filter {
    /// Construct an empty filter that matches every event.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a single event id.
    #[must_use]
    pub fn id(mut self, id: EventId) -> Self {
        self.ids.get_or_insert_with(BTreeSet::new).insert(id);
        self
    }

    /// Add several event ids.
    #[must_use]
    pub fn ids<I>(mut self, ids: I) -> Self
    where
        I: IntoIterator<Item = EventId>,
    {
        self.ids.get_or_insert_with(BTreeSet::new).extend(ids);
        self
    }

    /// Add a single author.
    #[must_use]
    pub fn author(mut self, pubkey: PublicKey) -> Self {
        self.authors.get_or_insert_with(BTreeSet::new).insert(pubkey);
        self
    }

    /// Add several authors.
    #[must_use]
    pub fn authors<I>(mut self, authors: I) -> Self
    where
        I: IntoIterator<Item = PublicKey>,
    {
        self.authors.get_or_insert_with(BTreeSet::new).extend(authors);
        self
    }

    /// Add a single kind.
    #[must_use]
    pub fn kind(mut self, kind: Kind) -> Self {
        self.kinds.get_or_insert_with(BTreeSet::new).insert(kind);
        self
    }

    /// Add several kinds.
    #[must_use]
    pub fn kinds<I>(mut self, kinds: I) -> Self
    where
        I: IntoIterator<Item = Kind>,
    {
        self.kinds.get_or_insert_with(BTreeSet::new).extend(kinds);
        self
    }

    /// Set the inclusive lower bound on `created_at`.
    #[must_use]
    pub const fn since(mut self, since: Timestamp) -> Self {
        self.since = Some(since);
        self
    }

    /// Set the inclusive upper bound on `created_at`.
    #[must_use]
    pub const fn until(mut self, until: Timestamp) -> Self {
        self.until = Some(until);
        self
    }

    /// Set the maximum number of events the relay should return.
    #[must_use]
    pub const fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Set the NIP-50 search query.
    #[must_use]
    pub fn search<S>(mut self, search: S) -> Self
    where
        S: Into<String>,
    {
        self.search = Some(search.into());
        self
    }

    /// Add a single value to a generic single-letter tag filter (`#<letter>`).
    #[must_use]
    pub fn custom_tag<S>(mut self, letter: SingleLetterTag, value: S) -> Self
    where
        S: Into<String>,
    {
        self.generic_tags
            .entry(letter)
            .or_default()
            .insert(value.into());
        self
    }

    /// Add several values to a generic single-letter tag filter.
    #[must_use]
    pub fn custom_tags<I, S>(mut self, letter: SingleLetterTag, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let bucket = self.generic_tags.entry(letter).or_default();
        for v in values {
            bucket.insert(v.into());
        }
        self
    }

    /// Convenience for the `#e` filter key.
    #[must_use]
    pub fn event(self, id: EventId) -> Self {
        self.custom_tag(
            SingleLetterTag::lowercase(crate::event::Alphabet::E),
            id.to_hex(),
        )
    }

    /// Convenience for the `#p` filter key.
    #[must_use]
    pub fn pubkey(self, pubkey: PublicKey) -> Self {
        self.custom_tag(
            SingleLetterTag::lowercase(crate::event::Alphabet::P),
            pubkey.to_hex(),
        )
    }

    /// True when the filter has no constraints.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ids.is_none()
            && self.authors.is_none()
            && self.kinds.is_none()
            && self.since.is_none()
            && self.until.is_none()
            && self.limit.is_none()
            && self.search.is_none()
            && self.generic_tags.is_empty()
    }

    /// True when `event` satisfies every set component of the filter.
    ///
    /// `limit` and `search` are not considered: relays interpret `limit` as
    /// "how many events to deliver", and full-text search is delegated to a
    /// search backend in higher layers.
    #[must_use]
    pub fn matches(&self, event: &Event) -> bool {
        if let Some(ids) = &self.ids
            && !ids.contains(&event.id)
        {
            return false;
        }
        if let Some(authors) = &self.authors
            && !authors.contains(&event.pubkey)
        {
            return false;
        }
        if let Some(kinds) = &self.kinds
            && !kinds.contains(&event.kind)
        {
            return false;
        }
        if let Some(since) = self.since
            && event.created_at < since
        {
            return false;
        }
        if let Some(until) = self.until
            && event.created_at > until
        {
            return false;
        }
        for (letter, expected) in &self.generic_tags {
            if !any_tag_value_matches(&event.tags, *letter, expected) {
                return false;
            }
        }
        true
    }
}

fn any_tag_value_matches(
    tags: &crate::event::Tags,
    letter: SingleLetterTag,
    expected: &BTreeSet<String>,
) -> bool {
    let kind = TagKind::single_letter(letter);
    tags.iter()
        .filter(|tag| tag.kind() == kind)
        .filter_map(Tag::content)
        .any(|value| expected.contains(value))
}

/// Compose `#<letter>` from a [`SingleLetterTag`].
fn tag_filter_key(letter: SingleLetterTag) -> String {
    let mut s = String::with_capacity(2);
    s.push('#');
    s.push(letter.as_char());
    s
}

impl Serialize for Filter {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut field_count = 0;
        if self.ids.is_some() {
            field_count += 1;
        }
        if self.authors.is_some() {
            field_count += 1;
        }
        if self.kinds.is_some() {
            field_count += 1;
        }
        if self.since.is_some() {
            field_count += 1;
        }
        if self.until.is_some() {
            field_count += 1;
        }
        if self.limit.is_some() {
            field_count += 1;
        }
        if self.search.is_some() {
            field_count += 1;
        }
        field_count += self.generic_tags.len();

        let mut map = serializer.serialize_map(Some(field_count))?;

        if let Some(ids) = &self.ids {
            map.serialize_entry("ids", ids)?;
        }
        if let Some(authors) = &self.authors {
            map.serialize_entry("authors", authors)?;
        }
        if let Some(kinds) = &self.kinds {
            map.serialize_entry("kinds", kinds)?;
        }
        if let Some(since) = self.since {
            map.serialize_entry("since", &since.as_secs())?;
        }
        if let Some(until) = self.until {
            map.serialize_entry("until", &until.as_secs())?;
        }
        if let Some(limit) = self.limit {
            map.serialize_entry("limit", &limit)?;
        }
        if let Some(search) = &self.search {
            map.serialize_entry("search", search)?;
        }
        for (letter, values) in &self.generic_tags {
            map.serialize_entry(&tag_filter_key(*letter), values)?;
        }

        map.end()
    }
}

fn deserialize_filter_entry<'de, M>(
    filter: &mut Filter,
    key: &str,
    map: &mut M,
) -> Result<(), M::Error>
where
    M: MapAccess<'de>,
{
    if let Some(letter_str) = key.strip_prefix('#') {
        let letter = letter_str
            .parse::<SingleLetterTag>()
            .map_err(de::Error::custom)?;
        let values: BTreeSet<String> = map.next_value()?;
        filter.generic_tags.insert(letter, values);
        return Ok(());
    }
    match key {
        "ids" => filter.ids = Some(map.next_value()?),
        "authors" => filter.authors = Some(map.next_value()?),
        "kinds" => filter.kinds = Some(map.next_value()?),
        "since" => filter.since = Some(Timestamp::from_secs(map.next_value()?)),
        "until" => filter.until = Some(Timestamp::from_secs(map.next_value()?)),
        "limit" => filter.limit = Some(map.next_value()?),
        "search" => filter.search = Some(map.next_value()?),
        _ => {
            // Unknown fields are skipped silently per the JSON robustness
            // principles called out by NIP-01.
            let _ignored: de::IgnoredAny = map.next_value()?;
        }
    }
    Ok(())
}

struct FilterVisitor;

impl<'de> Visitor<'de> for FilterVisitor {
    type Value = Filter;

    fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("a Nostr filter object")
    }

    fn visit_map<M>(self, mut map: M) -> Result<Filter, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut filter = Filter::default();
        while let Some(key) = map.next_key::<String>()? {
            deserialize_filter_entry(&mut filter, &key, &mut map)?;
        }
        Ok(filter)
    }
}

impl<'de> Deserialize<'de> for Filter {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(FilterVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;
    use crate::event::{Alphabet, EventBuilder, Tag};

    fn keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003")
            .unwrap()
    }

    fn signed_event() -> Event {
        EventBuilder::text_note("hello")
            .tag(Tag::new(["t", "rust"]).unwrap())
            .created_at(Timestamp::from_secs(1_700_000_000))
            .sign_with_keys(&keys())
            .unwrap()
    }

    #[test]
    fn empty_filter_matches_anything() {
        let filter = Filter::new();
        assert!(filter.is_empty());
        assert!(filter.matches(&signed_event()));
    }

    #[test]
    fn id_filter_round_trip() {
        let event = signed_event();
        let filter = Filter::new().id(event.id);
        assert!(filter.matches(&event));
        let other = Filter::new().id(EventId::from_byte_array([0; 32]));
        assert!(!other.matches(&event));
    }

    #[test]
    fn author_filter() {
        let event = signed_event();
        let filter = Filter::new().author(event.pubkey);
        assert!(filter.matches(&event));
    }

    #[test]
    fn since_until_window() {
        let event = signed_event();
        let in_window = Filter::new()
            .since(Timestamp::from_secs(1_699_999_999))
            .until(Timestamp::from_secs(1_700_000_001));
        let too_late = Filter::new().since(Timestamp::from_secs(1_700_000_001));
        let too_early = Filter::new().until(Timestamp::from_secs(1_699_999_999));
        assert!(in_window.matches(&event));
        assert!(!too_late.matches(&event));
        assert!(!too_early.matches(&event));
    }

    #[test]
    fn kind_filter() {
        let event = signed_event();
        assert!(Filter::new().kind(Kind::TEXT_NOTE).matches(&event));
        assert!(!Filter::new().kind(Kind::REACTION).matches(&event));
    }

    #[test]
    fn generic_tag_filter() {
        let event = signed_event();
        let filter = Filter::new()
            .custom_tag(SingleLetterTag::lowercase(Alphabet::T), "rust");
        assert!(filter.matches(&event));
        let no_match = Filter::new()
            .custom_tag(SingleLetterTag::lowercase(Alphabet::T), "nostr");
        assert!(!no_match.matches(&event));
    }

    #[test]
    fn serialize_round_trip() {
        let filter = Filter::new()
            .ids([EventId::from_byte_array([1; 32])])
            .authors([signed_event().pubkey])
            .kinds([Kind::TEXT_NOTE])
            .since(Timestamp::from_secs(1))
            .until(Timestamp::from_secs(2))
            .limit(10)
            .search("rust nostr")
            .custom_tag(SingleLetterTag::lowercase(Alphabet::T), "tag-value");

        let json = serde_json::to_string(&filter).unwrap();
        assert!(json.contains("\"ids\":["));
        assert!(json.contains("\"#t\":[\"tag-value\"]"));

        let parsed: Filter = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, filter);
    }

    #[test]
    fn unknown_keys_are_ignored() {
        let json = r#"{"unknown":42,"limit":5}"#;
        let filter: Filter = serde_json::from_str(json).unwrap();
        assert_eq!(filter.limit, Some(5));
    }

    #[test]
    fn invalid_tag_letter_is_rejected() {
        let json = r##"{"#abc":["x"]}"##;
        let result = serde_json::from_str::<Filter>(json);
        assert!(result.is_err());
    }

    #[test]
    fn ids_filter_dedupes_via_btreeset() {
        let id = EventId::from_byte_array([1; 32]);
        let filter = Filter::new().ids([id, id, id]);
        assert_eq!(filter.ids.as_ref().map(BTreeSet::len), Some(1));
    }
}
