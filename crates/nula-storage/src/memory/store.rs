//! In-memory store internals.
//!
//! `MemoryStore` is the inner mutable state behind [`crate::memory::MemoryDatabase`].
//! It owns every index and enforces the protocol-level write rules
//! (NIP-09 deletion, NIP-40 expiration, replaceable / addressable
//! kind routing, NIP-62 vanish) before letting an event into the
//! primary table.
//!
//! The store is **not** thread-safe on its own. [`crate::memory::MemoryDatabase`]
//! wraps it in an `RwLock` so reads scale and writes serialise.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use nula_core::event::{Event, EventId, Kind};
use nula_core::filter::{Filter, MatchEventOptions};
use nula_core::key::PublicKey;
use nula_core::nips::nip09::DeletionRequest;
use nula_core::types::Timestamp;

use crate::memory::options::MemoryDatabaseOptions;
use crate::memory::query::QueryPattern;
use crate::{DatabaseEventStatus, RejectedReason, SaveEventStatus};

/// Composite key used by every sorted index.
///
/// Ordering is `Reverse(created_at) → EventId`, so iterating a
/// `BTreeMap<EventKey, …>` in natural order yields **newest first**,
/// tie-broken by ascending event id (matches NIP-01 wire order).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct EventKey {
    pub(crate) created_at: Reverse<Timestamp>,
    pub(crate) id: EventId,
}

impl EventKey {
    #[inline]
    const fn from_event(event: &Event) -> Self {
        Self {
            created_at: Reverse(event.created_at),
            id: event.id,
        }
    }
}

/// Triple identifying an addressable / parameterized-replaceable
/// event, equivalent to `nula_core::event::Coordinate` but flattened
/// for use as a `HashMap` key without an extra allocation.
type CoordKey = (Kind, PublicKey, String);

#[derive(Debug)]
pub(crate) struct MemoryStore {
    options: MemoryDatabaseOptions,

    /// Primary table: every live event is reachable through here.
    by_id: HashMap<EventId, Arc<Event>>,

    /// Global sorted index — iteration yields newest first.
    by_time: BTreeMap<EventKey, Arc<Event>>,

    /// `author → sorted keys`. Optimises author-only filters.
    by_author: HashMap<PublicKey, BTreeSet<EventKey>>,

    /// `(kind, author) → sorted keys`. Optimises the most common
    /// "author posts of kind X" filter shape.
    by_kind_author: HashMap<(Kind, PublicKey), BTreeSet<EventKey>>,

    /// `(kind, author, d) → live coordinate winner`. NIP-33 keeps a
    /// single event per coordinate; older versions are evicted.
    by_coordinate: HashMap<CoordKey, Arc<Event>>,

    /// NIP-09 tombstones for individual event ids.
    deleted_ids: HashSet<EventId>,

    /// NIP-09 tombstones for addressable coordinates; the timestamp
    /// is the `created_at` of the deletion request, so we can refuse
    /// strictly-older re-publishes only.
    deleted_coordinates: HashMap<CoordKey, Timestamp>,

    /// NIP-62 vanished authors.
    vanished_authors: HashSet<PublicKey>,
}

impl MemoryStore {
    pub(crate) fn new(options: MemoryDatabaseOptions) -> Self {
        Self {
            options,
            by_id: HashMap::new(),
            by_time: BTreeMap::new(),
            by_author: HashMap::new(),
            by_kind_author: HashMap::new(),
            by_coordinate: HashMap::new(),
            deleted_ids: HashSet::new(),
            deleted_coordinates: HashMap::new(),
            vanished_authors: HashSet::new(),
        }
    }

    pub(crate) const fn options(&self) -> &MemoryDatabaseOptions {
        &self.options
    }

    pub(crate) fn check_id(&self, id: &EventId) -> DatabaseEventStatus {
        if self.by_id.contains_key(id) {
            DatabaseEventStatus::Saved
        } else if self.deleted_ids.contains(id) {
            DatabaseEventStatus::Deleted
        } else {
            DatabaseEventStatus::NotExistent
        }
    }

    pub(crate) fn event_by_id(&self, id: &EventId) -> Option<Event> {
        self.by_id.get(id).map(|e| (**e).clone())
    }

    pub(crate) fn len(&self) -> usize {
        self.by_id.len()
    }

    pub(crate) fn wipe(&mut self) {
        self.by_id.clear();
        self.by_time.clear();
        self.by_author.clear();
        self.by_kind_author.clear();
        self.by_coordinate.clear();
        self.deleted_ids.clear();
        self.deleted_coordinates.clear();
        self.vanished_authors.clear();
    }

    /// Persist `event`, applying every protocol-level write rule.
    ///
    /// Returns the outcome as a [`SaveEventStatus`]; protocol-level
    /// rejections (duplicate, ephemeral, expired, deleted, replaced,
    /// vanished) are not errors. Backend errors do not exist in the
    /// in-memory implementation.
    pub(crate) fn save_event(&mut self, event: &Event, now: Timestamp) -> SaveEventStatus {
        // 1. Vanished authors: drop everything they send.
        if self.options.process_nip62 && self.vanished_authors.contains(&event.pubkey) {
            return SaveEventStatus::Rejected(RejectedReason::Vanished);
        }

        // 2. Ephemeral kinds are never persisted.
        if event.kind.is_ephemeral() {
            return SaveEventStatus::Rejected(RejectedReason::Ephemeral);
        }

        // 3. NIP-40 expiration: dead-on-arrival.
        if matches!(event.is_expired(now), Ok(true)) {
            return SaveEventStatus::Rejected(RejectedReason::Expired);
        }

        // 4. Tombstones: refuse re-insertion of deleted ids.
        if self.deleted_ids.contains(&event.id) {
            return SaveEventStatus::Rejected(RejectedReason::Deleted);
        }

        // 5. Tombstones: refuse coordinate re-publish older than the
        //    deletion request.
        if let Some(coord) = addressable_coord(event)
            && let Some(deleted_at) = self.deleted_coordinates.get(&coord)
            && event.created_at <= *deleted_at
        {
            return SaveEventStatus::Rejected(RejectedReason::Deleted);
        }

        // 6. Duplicate id.
        if self.by_id.contains_key(&event.id) {
            return SaveEventStatus::Rejected(RejectedReason::Duplicate);
        }

        // 7. Replaceable / addressable conflict resolution.
        if event.kind.is_replaceable()
            && let Some(loser_id) = self.resolve_replaceable(event)
        {
            if loser_id == event.id {
                return SaveEventStatus::Rejected(RejectedReason::Replaced);
            }
            self.remove_event_by_id(loser_id);
        } else if event.kind.is_addressable()
            && let Some(loser_id) = self.resolve_addressable(event)
        {
            if loser_id == event.id {
                return SaveEventStatus::Rejected(RejectedReason::Replaced);
            }
            self.remove_event_by_id(loser_id);
        }

        // 8. NIP-09 deletion request: tombstone targets, then store
        //    the deletion event itself so reading clients see it.
        if self.options.process_nip09 && event.kind == Kind::EVENT_DELETION {
            self.apply_deletion(event);
        }

        // 9. NIP-62 vanish request: mark the author and (per the spec)
        //    purge their existing events. The vanish event itself is
        //    still stored so other clients can observe the request.
        if self.options.process_nip62 && event.kind == Kind::REQUEST_TO_VANISH {
            self.apply_vanish(event.pubkey);
        }

        // 10. Insert into every index.
        self.insert_event(Arc::new(event.clone()));

        // 11. Honour capacity cap.
        self.enforce_capacity();

        SaveEventStatus::Success
    }

    /// Delete every event matching `filter`. Unlike NIP-09 this does
    /// not tombstone the IDs — a subsequent `save_event` of the same
    /// ID would succeed.
    pub(crate) fn delete_matching(&mut self, filter: &Filter) {
        let to_remove: Vec<EventId> = self.query_keys(filter).map(|key| key.id).collect();
        for id in to_remove {
            self.remove_event_by_id(id);
        }
    }

    /// Iterate over the keys matching `filter` in canonical order.
    pub(crate) fn query_keys<'a>(
        &'a self,
        filter: &'a Filter,
    ) -> Box<dyn Iterator<Item = EventKey> + 'a> {
        let pattern = QueryPattern::from(filter);
        let limit = filter.limit.unwrap_or(usize::MAX);

        // Helper closure: filter events by Filter::match_event and
        // collect their keys. The intermediate iterator is materialised
        // because the match call borrows the event.
        let opts = MatchEventOptions::default();
        let materialise = move |iter: Box<dyn Iterator<Item = &'a Arc<Event>> + 'a>| {
            // `match_event` is generic over `MatchableEvent`, which does not
            // deref-coerce: pin the `&Event` explicitly out of the
            // `&&Arc<Event>` the predicate receives.
            iter.filter(move |e| {
                let event: &Event = e;
                filter.match_event(event, opts)
            })
            .take(limit)
            .map(|e| EventKey::from_event(e))
        };

        match pattern {
            QueryPattern::Generic => {
                let iter: Box<dyn Iterator<Item = &'a Arc<Event>> + 'a> =
                    Box::new(self.by_time.values());
                Box::new(materialise(iter))
            }
            QueryPattern::Author(pk) => match self.by_author.get(&pk) {
                Some(keys) => {
                    let iter: Box<dyn Iterator<Item = &'a Arc<Event>> + 'a> =
                        Box::new(keys.iter().filter_map(|k| self.by_id.get(&k.id)));
                    Box::new(materialise(iter))
                }
                None => Box::new(std::iter::empty()),
            },
            QueryPattern::KindAuthor(kind, pk) => match self.by_kind_author.get(&(kind, pk)) {
                Some(keys) => {
                    let iter: Box<dyn Iterator<Item = &'a Arc<Event>> + 'a> =
                        Box::new(keys.iter().filter_map(|k| self.by_id.get(&k.id)));
                    Box::new(materialise(iter))
                }
                None => Box::new(std::iter::empty()),
            },
            QueryPattern::Coordinate {
                kind,
                author,
                identifier,
            } => match self.by_coordinate.get(&(kind, author, identifier)) {
                Some(arc) if filter.match_event(arc.as_ref(), opts) => {
                    Box::new(std::iter::once(EventKey::from_event(arc)))
                }
                _ => Box::new(std::iter::empty()),
            },
        }
    }

    /// Iterate over events matching `filter`. The iterator is owning
    /// (yields cloned `Event`s) so the caller doesn't have to hold the
    /// store lock for the entire scan.
    pub(crate) fn query_owned(&self, filter: &Filter) -> Vec<Event> {
        self.query_keys(filter)
            .filter_map(|k| self.by_id.get(&k.id).map(|a| (**a).clone()))
            .collect()
    }

    /// Count without materialising.
    pub(crate) fn count(&self, filter: &Filter) -> usize {
        self.query_keys(filter).count()
    }

    fn insert_event(&mut self, event: Arc<Event>) {
        let key = EventKey::from_event(&event);
        let kind = event.kind;
        let author = event.pubkey;

        if let Some(coord) = addressable_coord(&event) {
            self.by_coordinate.insert(coord, Arc::clone(&event));
        }

        self.by_id.insert(event.id, Arc::clone(&event));
        self.by_author.entry(author).or_default().insert(key);
        self.by_kind_author
            .entry((kind, author))
            .or_default()
            .insert(key);
        self.by_time.insert(key, event);
    }

    fn remove_event_by_id(&mut self, id: EventId) {
        let Some(event) = self.by_id.remove(&id) else {
            return;
        };
        let key = EventKey::from_event(&event);
        let kind = event.kind;
        let author = event.pubkey;

        self.by_time.remove(&key);

        if let Some(set) = self.by_author.get_mut(&author) {
            set.remove(&key);
            if set.is_empty() {
                self.by_author.remove(&author);
            }
        }
        if let Some(set) = self.by_kind_author.get_mut(&(kind, author)) {
            set.remove(&key);
            if set.is_empty() {
                self.by_kind_author.remove(&(kind, author));
            }
        }
        if let Some(coord) = addressable_coord(&event)
            && self
                .by_coordinate
                .get(&coord)
                .is_some_and(|winner| winner.id == id)
        {
            self.by_coordinate.remove(&coord);
        }
    }

    /// Pick the loser between `event` and the current `(kind, author)`
    /// incumbent. Returns the loser's id, or `None` if no incumbent
    /// exists.
    fn resolve_replaceable(&self, event: &Event) -> Option<EventId> {
        let incumbent = self
            .by_kind_author
            .get(&(event.kind, event.pubkey))?
            .iter()
            .next()
            .and_then(|k| self.by_id.get(&k.id))?;
        Some(pick_loser(incumbent, event))
    }

    /// Pick the loser between `event` and the current addressable
    /// incumbent at the same coordinate.
    fn resolve_addressable(&self, event: &Event) -> Option<EventId> {
        let coord = addressable_coord(event)?;
        let incumbent = self.by_coordinate.get(&coord)?;
        Some(pick_loser(incumbent, event))
    }

    fn apply_deletion(&mut self, event: &Event) {
        let Ok(request) = DeletionRequest::from_event(event) else {
            return;
        };

        // Only the original author may delete; reject orphan targets
        // by checking authorship at apply time.
        for id in request.event_ids {
            let known_target = self.by_id.get(&id);
            let authored_by_requester =
                known_target.is_some_and(|target| target.pubkey == event.pubkey);
            if authored_by_requester {
                self.remove_event_by_id(id);
                self.deleted_ids.insert(id);
            } else if known_target.is_none() {
                // We don't know the author; tombstone anyway. If the
                // event later arrives we'll refuse it.
                self.deleted_ids.insert(id);
            }
        }

        for coord in request.coordinates {
            // Author check: only delete coordinates we know to belong
            // to the deletion author.
            if coord.author != event.pubkey {
                continue;
            }
            let key: CoordKey = (coord.kind, coord.author, coord.identifier);
            if let Some(incumbent) = self.by_coordinate.get(&key)
                && incumbent.created_at <= event.created_at
            {
                let incumbent_id = incumbent.id;
                self.remove_event_by_id(incumbent_id);
            }
            let stamp = self
                .deleted_coordinates
                .entry(key)
                .or_insert(event.created_at);
            if *stamp < event.created_at {
                *stamp = event.created_at;
            }
        }
    }

    fn apply_vanish(&mut self, author: PublicKey) {
        self.vanished_authors.insert(author);
        // Purge every existing event by this author. The keys live in
        // by_author; collect first to avoid mutating-while-iterating.
        let ids: Vec<EventId> = self
            .by_author
            .get(&author)
            .map(|set| set.iter().map(|k| k.id).collect())
            .unwrap_or_default();
        for id in ids {
            self.remove_event_by_id(id);
        }
    }

    fn enforce_capacity(&mut self) {
        let Some(max) = self.options.max_events else {
            return;
        };
        let max = max.get();
        while self.by_id.len() > max {
            // Evict the oldest: the by_time map iterates newest-first,
            // so the last key is the eviction target.
            let Some((key, _)) = self.by_time.iter().next_back() else {
                break;
            };
            let key = *key;
            self.remove_event_by_id(key.id);
        }
    }
}

/// Return the addressable coordinate of `event` if its kind is in the
/// addressable range (30000..40000) and it carries a `d` tag.
///
/// Per NIP-33 an addressable event without a `d` tag uses the empty
/// string as identifier, so we substitute `""` in that case.
fn addressable_coord(event: &Event) -> Option<CoordKey> {
    if !event.kind.is_addressable() {
        return None;
    }
    let identifier = event.tags.identifier().unwrap_or("").to_owned();
    Some((event.kind, event.pubkey, identifier))
}

/// Pick the loser between two events for replaceable resolution.
///
/// Returns the id of the event that should be dropped. Ties on
/// `created_at` are broken by id (smaller id wins; the lexicographic
/// rule matches every other implementation in the ecosystem).
fn pick_loser(incumbent: &Event, challenger: &Event) -> EventId {
    use std::cmp::Ordering;
    match incumbent.created_at.cmp(&challenger.created_at) {
        Ordering::Greater => challenger.id,
        Ordering::Less => incumbent.id,
        Ordering::Equal => {
            if incumbent.id <= challenger.id {
                challenger.id
            } else {
                incumbent.id
            }
        }
    }
}
