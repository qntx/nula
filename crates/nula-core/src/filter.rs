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

use crate::event::{Alphabet, Coordinate, Event, EventId, Kind, SingleLetterTag};
use crate::key::PublicKey;
use crate::types::Timestamp;

/// Options that control how strictly [`Filter::match_event`] checks an
/// event against per-NIP runtime constraints that live outside the
/// filter's NIP-01 fields.
///
/// The defaults preserve the historical [`Filter::matches`] semantics:
/// expired events ([NIP-40]) and events created in the future are
/// considered to match. Toggle the flags off when a relay or client
/// wants strict spec-conformant rejection.
///
/// To keep the matcher deterministic and unit-testable, no system clock
/// is read implicitly. Callers wanting expiration / future-date checks
/// MUST seed [`Self::now`] with a [`Timestamp`] (typically
/// [`Timestamp::now`]).
///
/// [NIP-40]: https://github.com/nostr-protocol/nips/blob/master/40.md
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct MatchEventOptions {
    /// When `false`, an event whose NIP-40 `expiration` tag has passed
    /// `now` is rejected. Requires [`Self::now`] to be `Some`.
    pub allow_expired: bool,
    /// When `false`, an event whose `created_at` is strictly after
    /// `now` is rejected. Requires [`Self::now`] to be `Some`.
    pub allow_future_dates: bool,
    /// Reference timestamp for the two checks above. `None` (the
    /// default) makes the checks no-ops regardless of the booleans —
    /// useful for filter-only matching where event lifetime is the
    /// caller's concern.
    pub now: Option<Timestamp>,
}

impl Default for MatchEventOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl MatchEventOptions {
    /// Permissive defaults equivalent to the legacy `Filter::matches`
    /// behaviour: no expiration check, no future-date check, no clock.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            allow_expired: true,
            allow_future_dates: true,
            now: None,
        }
    }

    /// Strict mode: reject expired events and events whose
    /// `created_at` is in the future relative to `now`.
    #[must_use]
    pub const fn strict(now: Timestamp) -> Self {
        Self {
            allow_expired: false,
            allow_future_dates: false,
            now: Some(now),
        }
    }

    /// Builder helper to toggle the [`Self::allow_expired`] flag.
    #[must_use]
    pub const fn allow_expired(mut self, enable: bool) -> Self {
        self.allow_expired = enable;
        self
    }

    /// Builder helper to toggle the [`Self::allow_future_dates`] flag.
    #[must_use]
    pub const fn allow_future_dates(mut self, enable: bool) -> Self {
        self.allow_future_dates = enable;
        self
    }

    /// Seed the reference timestamp used by the expiration and
    /// future-date checks.
    #[must_use]
    pub const fn now(mut self, ts: Timestamp) -> Self {
        self.now = Some(ts);
        self
    }
}

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

/// A canonical, order-independent identity key for a [`Filter`].
///
/// Produced by [`Filter::fingerprint`]. Because [`Filter`] preserves
/// insertion order on the wire it implements neither `Hash` nor `Ord`;
/// `FilterKey` is the hashable/orderable stand-in for deduplicating
/// subscriptions or keying a cache. Two filters that differ only in the
/// order of their `ids` / `authors` / `kinds` / tag values map to the
/// same key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FilterKey(String);

impl FilterKey {
    /// Borrow the canonical string form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for FilterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
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

    /// Convenience for the `#e` filter key (single event id).
    #[must_use]
    pub fn event(self, id: EventId) -> Self {
        self.custom_tag(SingleLetterTag::lowercase(Alphabet::E), id.to_hex())
    }

    /// Convenience for the `#e` filter key (multiple event ids).
    #[must_use]
    pub fn events<I>(self, ids: I) -> Self
    where
        I: IntoIterator<Item = EventId>,
    {
        self.custom_tags(
            SingleLetterTag::lowercase(Alphabet::E),
            ids.into_iter().map(EventId::to_hex),
        )
    }

    /// Convenience for the `#p` filter key (single pubkey).
    #[must_use]
    pub fn pubkey(self, pubkey: PublicKey) -> Self {
        self.custom_tag(SingleLetterTag::lowercase(Alphabet::P), pubkey.to_hex())
    }

    /// Convenience for the `#p` filter key (multiple pubkeys).
    #[must_use]
    pub fn pubkeys<I>(self, pubkeys: I) -> Self
    where
        I: IntoIterator<Item = PublicKey>,
    {
        self.custom_tags(
            SingleLetterTag::lowercase(Alphabet::P),
            pubkeys.into_iter().map(PublicKey::to_hex),
        )
    }

    /// Add a hashtag (`#t` filter) per NIP-12. The spec recommends
    /// lowercase values; callers MUST pre-normalise to keep matching
    /// deterministic.
    #[must_use]
    pub fn hashtag<S>(self, hashtag: S) -> Self
    where
        S: Into<String>,
    {
        self.custom_tag(SingleLetterTag::lowercase(Alphabet::T), hashtag)
    }

    /// Add multiple hashtags (`#t` filter).
    #[must_use]
    pub fn hashtags<I, S>(self, hashtags: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.custom_tags(SingleLetterTag::lowercase(Alphabet::T), hashtags)
    }

    /// Add a single web reference (`#r` filter) per NIP-12 / NIP-24.
    #[must_use]
    pub fn reference<S>(self, reference: S) -> Self
    where
        S: Into<String>,
    {
        self.custom_tag(SingleLetterTag::lowercase(Alphabet::R), reference)
    }

    /// Add multiple web references (`#r` filter).
    #[must_use]
    pub fn references<I, S>(self, references: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.custom_tags(SingleLetterTag::lowercase(Alphabet::R), references)
    }

    /// Add a single identifier (`#d` filter) for addressable events.
    #[must_use]
    pub fn identifier<S>(self, identifier: S) -> Self
    where
        S: Into<String>,
    {
        self.custom_tag(SingleLetterTag::lowercase(Alphabet::D), identifier)
    }

    /// Add multiple identifiers (`#d` filter).
    #[must_use]
    pub fn identifiers<I, S>(self, identifiers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.custom_tags(SingleLetterTag::lowercase(Alphabet::D), identifiers)
    }

    /// Add an addressable-event coordinate (`#a` filter). The wire
    /// value is the canonical `kind:author:identifier` triple.
    #[must_use]
    pub fn coordinate(self, coordinate: &Coordinate) -> Self {
        self.custom_tag(
            SingleLetterTag::lowercase(Alphabet::A),
            coordinate.to_wire(),
        )
    }

    /// Add multiple coordinates (`#a` filter).
    #[must_use]
    pub fn coordinates<'a, I>(self, coordinates: I) -> Self
    where
        I: IntoIterator<Item = &'a Coordinate>,
    {
        self.custom_tags(
            SingleLetterTag::lowercase(Alphabet::A),
            coordinates.into_iter().map(Coordinate::to_wire),
        )
    }

    /// Remove event ids from the [`Self::ids`] bucket.
    #[must_use]
    pub fn remove_ids<I>(mut self, ids: I) -> Self
    where
        I: IntoIterator<Item = EventId>,
    {
        let drop: Vec<EventId> = ids.into_iter().collect();
        if let Some(bucket) = self.ids.as_mut() {
            bucket.retain(|id| !drop.contains(id));
            if bucket.is_empty() {
                self.ids = None;
            }
        }
        self
    }

    /// Remove authors from the [`Self::authors`] bucket.
    #[must_use]
    pub fn remove_authors<I>(mut self, authors: I) -> Self
    where
        I: IntoIterator<Item = PublicKey>,
    {
        let drop: Vec<PublicKey> = authors.into_iter().collect();
        if let Some(bucket) = self.authors.as_mut() {
            bucket.retain(|pk| !drop.contains(pk));
            if bucket.is_empty() {
                self.authors = None;
            }
        }
        self
    }

    /// Remove kinds from the [`Self::kinds`] bucket.
    #[must_use]
    pub fn remove_kinds<I>(mut self, kinds: I) -> Self
    where
        I: IntoIterator<Item = Kind>,
    {
        let drop: Vec<Kind> = kinds.into_iter().collect();
        if let Some(bucket) = self.kinds.as_mut() {
            bucket.retain(|k| !drop.contains(k));
            if bucket.is_empty() {
                self.kinds = None;
            }
        }
        self
    }

    /// Remove specific values from a generic single-letter tag filter.
    /// Empties the bucket out of [`Self::generic_tags`] when no value
    /// is left.
    #[must_use]
    pub fn remove_custom_tags<I, S>(mut self, letter: SingleLetterTag, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let drop: Vec<String> = values.into_iter().map(|s| s.as_ref().to_owned()).collect();
        if let Some(bucket) = self.generic_tags.get_mut(&letter) {
            bucket.retain(|v| !drop.iter().any(|d| d == v));
            if bucket.is_empty() {
                self.generic_tags.shift_remove(&letter);
            }
        }
        self
    }

    /// Remove event ids from the `#e` filter.
    #[must_use]
    pub fn remove_events<I>(self, ids: I) -> Self
    where
        I: IntoIterator<Item = EventId>,
    {
        self.remove_custom_tags(
            SingleLetterTag::lowercase(Alphabet::E),
            ids.into_iter().map(EventId::to_hex),
        )
    }

    /// Remove pubkeys from the `#p` filter.
    #[must_use]
    pub fn remove_pubkeys<I>(self, pubkeys: I) -> Self
    where
        I: IntoIterator<Item = PublicKey>,
    {
        self.remove_custom_tags(
            SingleLetterTag::lowercase(Alphabet::P),
            pubkeys.into_iter().map(PublicKey::to_hex),
        )
    }

    /// Remove hashtags from the `#t` filter.
    #[must_use]
    pub fn remove_hashtags<I, S>(self, hashtags: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.remove_custom_tags(SingleLetterTag::lowercase(Alphabet::T), hashtags)
    }

    /// Remove references from the `#r` filter.
    #[must_use]
    pub fn remove_references<I, S>(self, references: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.remove_custom_tags(SingleLetterTag::lowercase(Alphabet::R), references)
    }

    /// Remove identifiers from the `#d` filter.
    #[must_use]
    pub fn remove_identifiers<I, S>(self, identifiers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.remove_custom_tags(SingleLetterTag::lowercase(Alphabet::D), identifiers)
    }

    /// Remove coordinates from the `#a` filter.
    #[must_use]
    pub fn remove_coordinates<'a, I>(self, coordinates: I) -> Self
    where
        I: IntoIterator<Item = &'a Coordinate>,
    {
        self.remove_custom_tags(
            SingleLetterTag::lowercase(Alphabet::A),
            coordinates.into_iter().map(Coordinate::to_wire),
        )
    }

    /// Drop the [`Self::since`] bound.
    #[must_use]
    pub const fn remove_since(mut self) -> Self {
        self.since = None;
        self
    }

    /// Drop the [`Self::until`] bound.
    #[must_use]
    pub const fn remove_until(mut self) -> Self {
        self.until = None;
        self
    }

    /// Drop the [`Self::limit`] cap.
    #[must_use]
    pub const fn remove_limit(mut self) -> Self {
        self.limit = None;
        self
    }

    /// Drop the [`Self::search`] query (NIP-50).
    #[must_use]
    pub fn remove_search(mut self) -> Self {
        self.search = None;
        self
    }

    /// Collect every [`PublicKey`] referenced by the filter — both
    /// authors and `#p` tag values. Duplicates are removed; insertion
    /// order is preserved (`authors` first, then `#p` entries).
    ///
    /// Hex strings stored in `#p` that fail to parse as 32-byte
    /// x-only public keys are silently skipped.
    #[must_use]
    pub fn extract_public_keys(&self) -> Vec<PublicKey> {
        let p_tag = SingleLetterTag::lowercase(Alphabet::P);
        let from_authors = self.authors.iter().flatten().copied();
        let from_tags = self
            .generic_tags
            .get(&p_tag)
            .into_iter()
            .flatten()
            .filter_map(|hex| PublicKey::parse(hex).ok());
        push_unique(from_authors.chain(from_tags))
    }

    /// Collect every [`EventId`] referenced by the filter — both
    /// [`Self::ids`] entries and `#e` tag values. Duplicates removed,
    /// insertion order preserved.
    ///
    /// Hex strings stored in `#e` that fail to parse as 32-byte event
    /// ids are silently skipped.
    #[must_use]
    pub fn extract_event_ids(&self) -> Vec<EventId> {
        let e_tag = SingleLetterTag::lowercase(Alphabet::E);
        let from_ids = self.ids.iter().flatten().copied();
        let from_tags = self
            .generic_tags
            .get(&e_tag)
            .into_iter()
            .flatten()
            .filter_map(|hex| EventId::parse(hex).ok());
        push_unique(from_ids.chain(from_tags))
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

    /// Derive a canonical, order-independent [`FilterKey`].
    ///
    /// [`Filter`] preserves insertion order on the wire (for byte-level
    /// interop) and therefore implements neither `Hash` nor `Ord`. This
    /// method fills the gap for cache / subscription-dedup keys: every
    /// list is sorted and each component is JSON-encoded, so two filters
    /// that are logically equal (same constraints, any order) produce the
    /// same key, and delimiter-bearing tag values cannot collide.
    #[must_use]
    pub fn fingerprint(&self) -> FilterKey {
        fn array<T: Serialize>(values: &[T]) -> String {
            serde_json::to_string(values).unwrap_or_default()
        }

        let mut parts: Vec<String> = Vec::new();
        if let Some(ids) = &self.ids {
            let mut v: Vec<String> = ids.iter().map(|id| id.to_hex()).collect();
            v.sort();
            parts.push(format!("ids:{}", array(&v)));
        }
        if let Some(authors) = &self.authors {
            let mut v: Vec<String> = authors.iter().map(|pk| pk.to_hex()).collect();
            v.sort();
            parts.push(format!("authors:{}", array(&v)));
        }
        if let Some(kinds) = &self.kinds {
            let mut v: Vec<u16> = kinds.iter().map(|kind| kind.as_u16()).collect();
            v.sort_unstable();
            parts.push(format!("kinds:{}", array(&v)));
        }
        if let Some(since) = self.since {
            parts.push(format!("since:{}", since.as_secs()));
        }
        if let Some(until) = self.until {
            parts.push(format!("until:{}", until.as_secs()));
        }
        if let Some(limit) = self.limit {
            parts.push(format!("limit:{limit}"));
        }
        if let Some(search) = &self.search {
            parts.push(format!("search:{}", array(std::slice::from_ref(search))));
        }
        let mut tag_parts: Vec<String> = self
            .generic_tags
            .iter()
            .map(|(letter, values)| {
                let mut v = values.clone();
                v.sort();
                format!("#{letter}:{}", array(&v))
            })
            .collect();
        tag_parts.sort();
        parts.extend(tag_parts);

        FilterKey(parts.join("\n"))
    }

    /// True when `event` satisfies every set component of the filter.
    ///
    /// `limit` and `search` are not considered: relays interpret
    /// `limit` as "how many events to deliver", and full-text search
    /// is delegated to a search backend in higher layers.
    ///
    /// `opts` controls the optional NIP-40 expiration check and the
    /// future-date guard. See [`MatchEventOptions`].
    #[must_use]
    pub fn match_event<E: MatchableEvent>(&self, event: &E, opts: MatchEventOptions) -> bool {
        if let Some(ids) = &self.ids
            && !ids.contains(&event.matchable_id())
        {
            return false;
        }
        if let Some(authors) = &self.authors {
            // Compare raw bytes rather than parsed `PublicKey`s: a borrowed
            // implementor can answer this without the ~2µs secp256k1 point
            // parse it would otherwise pay for every candidate, including
            // those this filter rejects.
            let pubkey = event.matchable_pubkey_bytes();
            if !authors
                .iter()
                .any(|author| author.to_byte_array() == pubkey)
            {
                return false;
            }
        }
        if let Some(kinds) = &self.kinds
            && !kinds.contains(&event.matchable_kind())
        {
            return false;
        }
        let created_at = event.matchable_created_at();
        if let Some(since) = self.since
            && created_at < since
        {
            return false;
        }
        if let Some(until) = self.until
            && created_at > until
        {
            return false;
        }
        if !generic_tags_match(&self.generic_tags, event) {
            return false;
        }
        // Runtime guards live OUTSIDE the per-NIP-01 fields. They
        // only fire when the caller seeds `opts.now`.
        if let Some(now) = opts.now {
            if !opts.allow_future_dates && created_at > now {
                return false;
            }
            // Mirrors `nip40::is_expired`: a missing or malformed
            // `expiration` tag yields `None`, i.e. never expired.
            if !opts.allow_expired
                && let Some(deadline) = event.matchable_expiration()
                && now >= deadline
            {
                return false;
            }
        }
        true
    }

    /// Permissive matcher equivalent to `match_event(event,
    /// MatchEventOptions::default())`.
    ///
    /// Kept for backwards compatibility with the v0.1.0-rc1 API. New
    /// code SHOULD call [`Self::match_event`] directly so the
    /// expiration / future-date intent is explicit at the call site.
    #[must_use]
    #[deprecated(
        since = "0.1.0-rc2",
        note = "use `Filter::match_event` with `MatchEventOptions`"
    )]
    pub fn matches(&self, event: &Event) -> bool {
        self.match_event(event, MatchEventOptions::new())
    }
}

/// Match an event's tags against a filter's `#<letter>` constraints.
///
/// Returns `true` when, for every single-letter constraint, the event
/// carries at least one of the requested values (NIP-01 AND-of-ORs
/// semantics). An empty constraint set matches everything; a non-empty
/// one against a tag-less event matches nothing — both fall out of the
/// `all` over the (possibly empty) constraints.
fn generic_tags_match<E: MatchableEvent>(
    generic_tags: &IndexMap<SingleLetterTag, Vec<String>>,
    event: &E,
) -> bool {
    generic_tags
        .iter()
        .all(|(letter, expected)| event.matchable_has_tag(*letter, expected))
}

/// A read-only projection of the fields [`Filter::match_event`] inspects.
///
/// Implemented by the owned [`Event`] and by zero-parse borrowed views
/// (e.g. the redb backend's storage projection), so the matcher keeps a
/// single source of truth and the two can never silently diverge.
///
/// The author is exposed as **raw bytes**, never a parsed [`PublicKey`]:
/// a borrowed implementor reading bytes straight from storage can then
/// match without paying the ~2µs secp256k1 x-only point parse (≈2000× an
/// id copy — see `nula-core`'s `event/decode_primitives` bench) for every
/// candidate, including the ones a filter rejects.
pub trait MatchableEvent {
    /// The event id.
    fn matchable_id(&self) -> EventId;
    /// The 32-byte x-only author key, unparsed.
    fn matchable_pubkey_bytes(&self) -> [u8; 32];
    /// The event kind.
    fn matchable_kind(&self) -> Kind;
    /// The authored timestamp.
    fn matchable_created_at(&self) -> Timestamp;
    /// Whether the event carries a `<letter>` tag whose value (index 1)
    /// is one of `values` — NIP-01 `#<letter>` AND-of-ORs semantics.
    fn matchable_has_tag(&self, letter: SingleLetterTag, values: &[String]) -> bool;
    /// The NIP-40 expiration deadline, or `None` when the `expiration`
    /// tag is absent or malformed.
    fn matchable_expiration(&self) -> Option<Timestamp>;
}

impl MatchableEvent for Event {
    fn matchable_id(&self) -> EventId {
        self.id
    }

    fn matchable_pubkey_bytes(&self) -> [u8; 32] {
        self.pubkey.to_byte_array()
    }

    fn matchable_kind(&self) -> Kind {
        self.kind
    }

    fn matchable_created_at(&self) -> Timestamp {
        self.created_at
    }

    fn matchable_has_tag(&self, letter: SingleLetterTag, values: &[String]) -> bool {
        self.tags
            .indexes()
            .get(&letter)
            .is_some_and(|present| values.iter().any(|value| present.contains(value)))
    }

    fn matchable_expiration(&self) -> Option<Timestamp> {
        self.expiration().ok().flatten()
    }
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

/// Collect an iterator into a [`Vec`] while skipping duplicates.
///
/// Insertion order is preserved (first wins). Used by the
/// `extract_*` accessors to merge multiple sources into a single
/// deduplicated view without sorting.
fn push_unique<T, I>(iter: I) -> Vec<T>
where
    T: PartialEq,
    I: IntoIterator<Item = T>,
{
    let iter = iter.into_iter();
    let mut out: Vec<T> = Vec::with_capacity(iter.size_hint().0);
    for value in iter {
        if !out.iter().any(|existing| existing == &value) {
            out.push(value);
        }
    }
    out
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

    fn opts() -> MatchEventOptions {
        MatchEventOptions::new()
    }

    #[test]
    fn empty_filter_matches_anything() {
        let filter = Filter::new();
        assert!(filter.is_empty());
        assert!(filter.match_event(&signed_event(), opts()));
    }

    #[test]
    fn id_filter_round_trip() {
        let event = signed_event();
        let filter = Filter::new().id(event.id);
        assert!(filter.match_event(&event, opts()));
        let other = Filter::new().id(EventId::from_byte_array([0; 32]));
        assert!(!other.match_event(&event, opts()));
    }

    #[test]
    fn author_filter() {
        let event = signed_event();
        let filter = Filter::new().author(event.pubkey);
        assert!(filter.match_event(&event, opts()));
    }

    #[test]
    fn since_until_window() {
        let event = signed_event();
        let in_window = Filter::new()
            .since(Timestamp::from_secs(1_699_999_999))
            .until(Timestamp::from_secs(1_700_000_001));
        let too_late = Filter::new().since(Timestamp::from_secs(1_700_000_001));
        let too_early = Filter::new().until(Timestamp::from_secs(1_699_999_999));
        assert!(in_window.match_event(&event, opts()));
        assert!(!too_late.match_event(&event, opts()));
        assert!(!too_early.match_event(&event, opts()));
    }

    #[test]
    fn kind_filter() {
        let event = signed_event();
        assert!(
            Filter::new()
                .kind(Kind::TEXT_NOTE)
                .match_event(&event, opts())
        );
        assert!(
            !Filter::new()
                .kind(Kind::REACTION)
                .match_event(&event, opts())
        );
    }

    #[test]
    fn generic_tag_filter() {
        let event = signed_event();
        let filter = Filter::new().custom_tag(SingleLetterTag::lowercase(Alphabet::T), "rust");
        assert!(filter.match_event(&event, opts()));
        let no_match = Filter::new().custom_tag(SingleLetterTag::lowercase(Alphabet::T), "nostr");
        assert!(!no_match.match_event(&event, opts()));
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

    fn id_a() -> EventId {
        EventId::from_byte_array([0xaa; 32])
    }
    fn id_b() -> EventId {
        EventId::from_byte_array([0xbb; 32])
    }
    fn id_c() -> EventId {
        EventId::from_byte_array([0xcc; 32])
    }
    fn pk(seed: u8) -> PublicKey {
        // Iterate until a parseable seed lands; the loop terminates for
        // every starting byte because secp256k1 x-coordinates are dense.
        let mut s = [seed; 32];
        loop {
            if let Ok(p) = PublicKey::from_byte_array(s) {
                return p;
            }
            s[0] = s[0].wrapping_add(1);
        }
    }

    #[test]
    fn events_and_pubkeys_plural_helpers_dedup() {
        let f = Filter::new()
            .events([id_a(), id_b(), id_a()])
            .pubkeys([pk(1), pk(2), pk(2)]);
        let e_bucket = f
            .generic_tags
            .get(&SingleLetterTag::lowercase(Alphabet::E))
            .unwrap();
        let p_bucket = f
            .generic_tags
            .get(&SingleLetterTag::lowercase(Alphabet::P))
            .unwrap();
        assert_eq!(e_bucket.len(), 2, "events helper must dedupe across calls");
        assert_eq!(p_bucket.len(), 2, "pubkeys helper must dedupe across calls");
    }

    #[test]
    fn hashtag_reference_identifier_helpers_route_to_correct_letter() {
        let f = Filter::new()
            .hashtag("rust")
            .hashtags(["nostr", "rust"]) // duplicate must collapse
            .reference("https://example.com/article")
            .references(["https://b.example/", "https://example.com/article"])
            .identifier("primary")
            .identifiers(["primary", "secondary"]);
        assert_eq!(
            f.generic_tags
                .get(&SingleLetterTag::lowercase(Alphabet::T))
                .unwrap()
                .as_slice(),
            ["rust", "nostr"],
        );
        assert_eq!(
            f.generic_tags
                .get(&SingleLetterTag::lowercase(Alphabet::R))
                .unwrap()
                .len(),
            2,
        );
        assert_eq!(
            f.generic_tags
                .get(&SingleLetterTag::lowercase(Alphabet::D))
                .unwrap()
                .as_slice(),
            ["primary", "secondary"],
        );
    }

    #[test]
    fn coordinate_helpers_emit_canonical_wire_form() {
        let coord = Coordinate::new(Kind::new(30023), pk(7), "post-1");
        let f = Filter::new().coordinate(&coord);
        let bucket = f
            .generic_tags
            .get(&SingleLetterTag::lowercase(Alphabet::A))
            .unwrap();
        assert_eq!(bucket.len(), 1);
        assert!(
            bucket[0].starts_with("30023:"),
            "coordinate must serialise as `kind:author:identifier`: {bucket:?}"
        );
        let coords = [
            Coordinate::new(Kind::new(30023), pk(7), "post-1"),
            Coordinate::new(Kind::new(30023), pk(7), "post-2"),
        ];
        let f2 = Filter::new().coordinates(coords.iter());
        let bucket2 = f2
            .generic_tags
            .get(&SingleLetterTag::lowercase(Alphabet::A))
            .unwrap();
        assert_eq!(bucket2.len(), 2);
    }

    #[test]
    fn remove_methods_drop_values_and_buckets() {
        let f = Filter::new()
            .ids([id_a(), id_b()])
            .authors([pk(1), pk(2)])
            .kinds([Kind::TEXT_NOTE, Kind::REACTION])
            .hashtags(["rust", "nostr"]);

        let trimmed = f
            .clone()
            .remove_ids([id_a()])
            .remove_authors([pk(1)])
            .remove_kinds([Kind::REACTION])
            .remove_hashtags(["nostr"]);

        assert_eq!(trimmed.ids.as_ref().map(Vec::len), Some(1));
        assert_eq!(trimmed.authors.as_ref().map(Vec::len), Some(1));
        assert_eq!(trimmed.kinds.as_ref().map(Vec::len), Some(1));
        assert_eq!(
            trimmed
                .generic_tags
                .get(&SingleLetterTag::lowercase(Alphabet::T))
                .unwrap()
                .len(),
            1
        );

        // Removing the last entry collapses the bucket out entirely.
        let empty = f.remove_ids([id_a(), id_b()]);
        assert!(empty.ids.is_none());
    }

    #[test]
    fn remove_since_until_limit_search_clear_state() {
        let f = Filter::new()
            .since(Timestamp::from_secs(10))
            .until(Timestamp::from_secs(20))
            .limit(5)
            .search("text");
        let cleared = f
            .remove_since()
            .remove_until()
            .remove_limit()
            .remove_search();
        assert!(cleared.is_empty());
    }

    #[test]
    fn extract_public_keys_unions_authors_and_p_tags() {
        let author = pk(1);
        let tagged = pk(2);
        let f = Filter::new().author(author).pubkey(tagged);
        let extracted = f.extract_public_keys();
        assert_eq!(extracted.len(), 2);
        assert!(extracted.contains(&author));
        assert!(extracted.contains(&tagged));
    }

    #[test]
    fn extract_event_ids_unions_ids_and_e_tags() {
        let from_ids = id_a();
        let from_tag = id_b();
        let f = Filter::new().id(from_ids).event(from_tag);
        let extracted = f.extract_event_ids();
        assert_eq!(extracted.len(), 2);
        assert!(extracted.contains(&from_ids));
        assert!(extracted.contains(&from_tag));
    }

    #[test]
    fn extract_public_keys_skips_invalid_hex() {
        // Bypass the deserializer's hex validator by constructing the
        // filter directly.
        let mut f = Filter::new().author(pk(3));
        f.generic_tags.insert(
            SingleLetterTag::lowercase(Alphabet::P),
            vec!["not-a-hex-pubkey".into()],
        );
        let extracted = f.extract_public_keys();
        assert_eq!(extracted, vec![pk(3)]);
    }

    #[test]
    fn extract_event_ids_drops_duplicates_across_sources() {
        // Same id appears in both `ids` and `#e`; result must dedupe.
        let id = id_c();
        let f = Filter::new().id(id).event(id);
        assert_eq!(f.extract_event_ids(), vec![id]);
    }

    #[test]
    fn fingerprint_is_order_independent() {
        let a = Filter::new()
            .kinds([Kind::new(1), Kind::new(3)])
            .authors([pk(1), pk(2)]);
        let b = Filter::new()
            .kinds([Kind::new(3), Kind::new(1)])
            .authors([pk(2), pk(1)]);
        // Wire order differs, so the filters are not `==` ...
        assert_ne!(a, b);
        // ... but they are logically equal, so the fingerprints match.
        assert_eq!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn fingerprint_distinguishes_different_filters() {
        let a = Filter::new().kind(Kind::new(1));
        let b = Filter::new().kind(Kind::new(2));
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn fingerprint_is_usable_as_a_set_key() {
        let mut seen = std::collections::HashSet::new();
        assert!(seen.insert(Filter::new().kind(Kind::new(1)).fingerprint()));
        // The same logical filter does not insert twice.
        assert!(!seen.insert(Filter::new().kind(Kind::new(1)).fingerprint()));
    }

    #[test]
    fn match_event_default_options_preserves_legacy_semantics() {
        let event = signed_event();
        let strictly_permissive = Filter::new();
        // No `now` ⇒ expiration / future-date guards no-op.
        assert!(strictly_permissive.match_event(&event, MatchEventOptions::default()));
    }

    #[test]
    fn match_event_strict_rejects_future_dated_event() {
        let event = signed_event(); // created_at = 1_700_000_000
        let strict = MatchEventOptions::strict(Timestamp::from_secs(1_699_999_999));
        assert!(
            !Filter::new().match_event(&event, strict),
            "strict mode must reject events from the future"
        );
    }

    #[test]
    fn match_event_strict_accepts_past_event() {
        let event = signed_event();
        let strict = MatchEventOptions::strict(Timestamp::from_secs(1_700_000_500));
        assert!(Filter::new().match_event(&event, strict));
    }

    #[test]
    fn match_event_strict_rejects_expired_event() {
        // Build an event whose NIP-40 `expiration` is in the past.
        let expired_event = EventBuilder::text_note("expiring")
            .created_at(Timestamp::from_secs(1_700_000_000))
            .expiration(Timestamp::from_secs(1_700_000_100))
            .sign_with_keys(&keys())
            .unwrap();
        let strict = MatchEventOptions::strict(Timestamp::from_secs(1_700_000_500));
        assert!(
            !Filter::new().match_event(&expired_event, strict),
            "strict matcher must drop events past their NIP-40 expiration"
        );
    }

    #[test]
    fn match_event_allow_expired_overrides_strict_default() {
        let expired_event = EventBuilder::text_note("expiring")
            .created_at(Timestamp::from_secs(1_700_000_000))
            .expiration(Timestamp::from_secs(1_700_000_100))
            .sign_with_keys(&keys())
            .unwrap();
        let lenient =
            MatchEventOptions::strict(Timestamp::from_secs(1_700_000_500)).allow_expired(true);
        assert!(Filter::new().match_event(&expired_event, lenient));
    }

    #[test]
    #[allow(deprecated, reason = "covers the backwards-compat shim")]
    fn legacy_matches_method_still_works() {
        let event = signed_event();
        let f = Filter::new().author(event.pubkey);
        assert!(f.matches(&event));
    }
}
