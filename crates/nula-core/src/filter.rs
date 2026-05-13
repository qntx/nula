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

use indexmap::IndexMap;
use serde::de::{self, MapAccess, Visitor};
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Deserializer, Serialize};

use crate::event::{Alphabet, Event, EventId, Kind, SingleLetterTag, Tag, TagKind};
use crate::key::PublicKey;
use crate::types::Timestamp;

/// NIP-01 subscription filter.
///
/// All fields are public so consumers can read them without going through
/// builder accessors when matching events.
///
/// # Wire ordering
///
/// `ids`, `authors`, `kinds` and the values inside `generic_tags` preserve
/// insertion order on the wire. NIP-01 leaves the order unspecified, but
/// every other major implementation (rust-nostr, nostr-tools, go-nostr)
/// keeps insertion order, so byte-level interoperability requires it. We
/// therefore use [`Vec`] rather than `BTreeSet`. Builder methods skip
/// duplicates so the resulting `Vec` still functions as a logical set.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Filter {
    /// Event IDs to match. Insertion order is preserved on the wire.
    pub ids: Option<Vec<EventId>>,
    /// Author public keys to match. Insertion order is preserved on the wire.
    pub authors: Option<Vec<PublicKey>>,
    /// Event kinds to match. Insertion order is preserved on the wire.
    pub kinds: Option<Vec<Kind>>,
    /// Inclusive lower bound on `created_at`.
    pub since: Option<Timestamp>,
    /// Inclusive upper bound on `created_at`.
    pub until: Option<Timestamp>,
    /// Maximum number of events to return.
    pub limit: Option<usize>,
    /// Free-form search query (NIP-50).
    pub search: Option<String>,
    /// Single-letter tag filters (`#a`, `#e`, `#p`, …).
    ///
    /// Both the outer key order and the inner value order preserve
    /// insertion. NIP-01 does not pin the wire order down, but every
    /// major implementation (rust-nostr, nostr-tools, go-nostr) keeps
    /// insertion order; we follow suit so byte-level interop is exact.
    /// We use [`IndexMap`] instead of `BTreeMap` to combine `O(1)` keyed
    /// lookup with stable, deterministic iteration. Duplicate values are
    /// skipped on insert.
    pub generic_tags: IndexMap<SingleLetterTag, Vec<String>>,
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
        let bucket = self.ids.get_or_insert_with(Vec::new);
        if !bucket.contains(&id) {
            bucket.push(id);
        }
        self
    }

    /// Add several event ids.
    #[must_use]
    pub fn ids<I>(mut self, ids: I) -> Self
    where
        I: IntoIterator<Item = EventId>,
    {
        let bucket = self.ids.get_or_insert_with(Vec::new);
        for id in ids {
            if !bucket.contains(&id) {
                bucket.push(id);
            }
        }
        self
    }

    /// Add a single author.
    #[must_use]
    pub fn author(mut self, pubkey: PublicKey) -> Self {
        let bucket = self.authors.get_or_insert_with(Vec::new);
        if !bucket.contains(&pubkey) {
            bucket.push(pubkey);
        }
        self
    }

    /// Add several authors.
    #[must_use]
    pub fn authors<I>(mut self, authors: I) -> Self
    where
        I: IntoIterator<Item = PublicKey>,
    {
        let bucket = self.authors.get_or_insert_with(Vec::new);
        for pubkey in authors {
            if !bucket.contains(&pubkey) {
                bucket.push(pubkey);
            }
        }
        self
    }

    /// Add a single kind.
    #[must_use]
    pub fn kind(mut self, kind: Kind) -> Self {
        let bucket = self.kinds.get_or_insert_with(Vec::new);
        if !bucket.contains(&kind) {
            bucket.push(kind);
        }
        self
    }

    /// Add several kinds.
    #[must_use]
    pub fn kinds<I>(mut self, kinds: I) -> Self
    where
        I: IntoIterator<Item = Kind>,
    {
        let bucket = self.kinds.get_or_insert_with(Vec::new);
        for kind in kinds {
            if !bucket.contains(&kind) {
                bucket.push(kind);
            }
        }
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
    /// Duplicate values are silently dropped to keep the filter as a logical
    /// set even though the wire form preserves insertion order.
    #[must_use]
    pub fn custom_tag<S>(mut self, letter: SingleLetterTag, value: S) -> Self
    where
        S: Into<String>,
    {
        let bucket = self.generic_tags.entry(letter).or_default();
        let value: String = value.into();
        if !bucket.iter().any(|v| v == &value) {
            bucket.push(value);
        }
        self
    }

    /// Add several values to a generic single-letter tag filter.
    /// Duplicates are silently dropped (see [`Self::custom_tag`]).
    #[must_use]
    pub fn custom_tags<I, S>(mut self, letter: SingleLetterTag, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let bucket = self.generic_tags.entry(letter).or_default();
        for v in values {
            let value: String = v.into();
            if !bucket.iter().any(|x| x == &value) {
                bucket.push(value);
            }
        }
        self
    }

    /// Convenience for the `#e` filter key.
    #[must_use]
    pub fn event(self, id: EventId) -> Self {
        self.custom_tag(SingleLetterTag::lowercase(Alphabet::E), id.to_hex())
    }

    /// Convenience for the `#p` filter key.
    #[must_use]
    pub fn pubkey(self, pubkey: PublicKey) -> Self {
        self.custom_tag(SingleLetterTag::lowercase(Alphabet::P), pubkey.to_hex())
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
    expected: &[String],
) -> bool {
    let kind = TagKind::single_letter(letter);
    tags.iter()
        .filter(|tag| tag.kind() == kind)
        .filter_map(Tag::content)
        .any(|value| expected.iter().any(|e| e == value))
}

/// Compose `#<letter>` from a [`SingleLetterTag`].
fn tag_filter_key(letter: SingleLetterTag) -> String {
    let mut s = String::with_capacity(2);
    s.push('#');
    s.push(letter.as_char());
    s
}

/// Drop duplicate entries while preserving the first occurrence's index.
///
/// Used during deserialization so a relay sending a duplicate-tolerant wire
/// form still ends up with a logically-deduplicated [`Filter`].
fn dedup_preserving_order<T: PartialEq>(values: Vec<T>) -> Vec<T> {
    let mut seen: Vec<T> = Vec::with_capacity(values.len());
    for v in values {
        if !seen.iter().any(|existing| existing == &v) {
            seen.push(v);
        }
    }
    seen
}

/// True when `value` is exactly 64 lowercase hex characters (NIP-01 §filters
/// requirement for `#e` and `#p` entries).
fn is_lowercase_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Enforce the NIP-01 hex constraint on `#e` and `#p` filter values. No-op
/// for any other letter.
fn validate_hex_filter_values<'de, M>(
    letter: SingleLetterTag,
    values: &[String],
) -> Result<(), M::Error>
where
    M: MapAccess<'de>,
{
    let needs_hex = matches!(
        letter,
        SingleLetterTag {
            character: Alphabet::E | Alphabet::P,
            uppercase: false,
        }
    );
    if !needs_hex {
        return Ok(());
    }
    for value in values {
        if !is_lowercase_hex_64(value) {
            return Err(de::Error::custom(format!(
                "`#{letter}` filter value `{value}` must be 64 lowercase hex chars"
            )));
        }
    }
    Ok(())
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
        let values: Vec<String> = map.next_value()?;
        // NIP-01: '#e' and '#p' filter lists MUST contain exact 64-char
        // lowercase hex values. Reject any non-conforming entry up front
        // so downstream Filter::matches never has to defend against
        // malformed input.
        validate_hex_filter_values::<M>(letter, &values)?;
        filter
            .generic_tags
            .insert(letter, dedup_preserving_order(values));
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

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
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
        let filter = Filter::new().custom_tag(SingleLetterTag::lowercase(Alphabet::T), "rust");
        assert!(filter.matches(&event));
        let no_match = Filter::new().custom_tag(SingleLetterTag::lowercase(Alphabet::T), "nostr");
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
    fn ids_filter_dedupes_on_insert() {
        let id = EventId::from_byte_array([1; 32]);
        let filter = Filter::new().ids([id, id, id]);
        assert_eq!(filter.ids.as_ref().map(Vec::len), Some(1));
    }

    #[test]
    fn rejects_non_hex_e_filter_value() {
        // NIP-01: '#e' filter MUST contain 64-char lowercase hex only.
        let json = r##"{"#e":["not-a-hex"]}"##;
        let err = serde_json::from_str::<Filter>(json).unwrap_err();
        assert!(err.to_string().contains("must be 64 lowercase hex"));
    }

    #[test]
    fn rejects_short_hex_p_filter_value() {
        let json = r##"{"#p":["abcdef"]}"##;
        let err = serde_json::from_str::<Filter>(json).unwrap_err();
        assert!(err.to_string().contains("must be 64 lowercase hex"));
    }

    #[test]
    fn rejects_uppercase_hex_e_filter_value() {
        let value = "A".repeat(64);
        let json = format!(r##"{{"#e":["{value}"]}}"##);
        let err = serde_json::from_str::<Filter>(&json).unwrap_err();
        assert!(err.to_string().contains("must be 64 lowercase hex"));
    }

    #[test]
    fn accepts_valid_hex_e_filter_value() {
        let value = "0".repeat(64);
        let json = format!(r##"{{"#e":["{value}"]}}"##);
        let filter: Filter = serde_json::from_str(&json).unwrap();
        let bucket = filter
            .generic_tags
            .get(&SingleLetterTag::lowercase(Alphabet::E))
            .unwrap();
        assert_eq!(bucket.len(), 1);
        assert_eq!(bucket[0], value);
    }

    #[test]
    fn non_e_p_letters_skip_hex_validation() {
        // NIP-01 only mandates the hex format for 'e' and 'p'. Other
        // letters carry arbitrary string values such as topic tags.
        let json = r##"{"#t":["rust","not-hex","🦀"]}"##;
        let filter: Filter = serde_json::from_str(json).unwrap();
        let bucket = filter
            .generic_tags
            .get(&SingleLetterTag::lowercase(Alphabet::T))
            .unwrap();
        assert_eq!(bucket.len(), 3);
    }

    #[test]
    fn ids_preserve_insertion_order_on_the_wire() {
        // rust-nostr, nostr-tools and go-nostr all preserve insertion
        // order. Pick three ids that would *swap* under BTreeSet sorting
        // to prove the wire form respects insertion.
        let high = EventId::from_byte_array([0xff; 32]);
        let mid = EventId::from_byte_array([0x80; 32]);
        let low = EventId::from_byte_array([0x01; 32]);
        let filter = Filter::new().ids([high, mid, low]);
        let json = serde_json::to_string(&filter).unwrap();
        let high_pos = json.find(&high.to_hex()).unwrap();
        let mid_pos = json.find(&mid.to_hex()).unwrap();
        let low_pos = json.find(&low.to_hex()).unwrap();
        assert!(
            high_pos < mid_pos && mid_pos < low_pos,
            "ids must appear in insertion order on the wire: {json}"
        );
    }
}
