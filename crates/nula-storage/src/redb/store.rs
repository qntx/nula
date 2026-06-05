//! redb-backed event store.
//!
//! `Store` owns a [`redb::Database`] and exposes synchronous
//! read/write methods that operate inside redb transactions. The async
//! façade in [`crate::redb::database`] turns those into `BoxFuture`s by
//! routing them through [`tokio::task::spawn_blocking`].
//!
//! redb is MVCC: many concurrent readers run lock-free against a
//! snapshot, and a single writer is serialised internally by
//! [`redb::Database::begin_write`]. There is therefore no dedicated
//! ingester thread — every mutation simply opens a write transaction
//! on the blocking pool, and redb makes them wait their turn.

// The index-decoding paths slice into raw byte buffers whose length was
// already verified by the surrounding `if key.len() == … {}` guard.
// Clippy still flags every such slice as "may panic"; opting out at the
// module level keeps the index-decoding code readable.
#![allow(
    clippy::indexing_slicing,
    clippy::cognitive_complexity,
    clippy::too_many_lines,
    clippy::excessive_nesting,
    clippy::collapsible_if,
    reason = "index-decoding paths are slice-arithmetic-heavy by nature; bounds are checked by the surrounding length guards"
)]

use std::collections::HashSet;
use std::ops::Bound;
use std::sync::Arc;

use nula_core::event::{Event, EventId, Kind};
use nula_core::filter::{Filter, MatchEventOptions};
use nula_core::key::PublicKey;
use nula_core::nips::nip09::DeletionRequest;
use nula_core::types::Timestamp;
use redb::{ReadableDatabase, ReadableTable};

use crate::redb::codec;
use crate::redb::error::Error;
use crate::redb::keys;
use crate::redb::options::RedbDatabaseOptions;
use crate::{DatabaseEventStatus, RejectedReason, SaveEventStatus};

/// `event_id (32)` → `[version: u8] [postcard(event)]`.
const EVENTS: ::redb::TableDefinition<'static, &[u8], &[u8]> =
    ::redb::TableDefinition::new("events");
/// `[ts_be(8)] [id(32)]` → `()`. Global oldest-first cursor.
const BY_CREATED_AT: ::redb::TableDefinition<'static, &[u8], ()> =
    ::redb::TableDefinition::new("by_created_at");
/// `[pubkey(32)] [ts_be(8)] [id(32)]` → `()`. Per-author scan.
const BY_AUTHOR_TS: ::redb::TableDefinition<'static, &[u8], ()> =
    ::redb::TableDefinition::new("by_author_ts");
/// `[kind_be(2)] [pubkey(32)] [ts_be(8)] [id(32)]` → `()`.
const BY_KIND_AUTHOR_TS: ::redb::TableDefinition<'static, &[u8], ()> =
    ::redb::TableDefinition::new("by_kind_author_ts");
/// `[kind_be(2)] [pubkey(32)] [identifier_utf8]` → `event_id`. NIP-33
/// addressable coordinate index.
const BY_COORDINATE: ::redb::TableDefinition<'static, &[u8], &[u8]> =
    ::redb::TableDefinition::new("by_coordinate");
/// `event_id (32)` → `created_at`. NIP-09 tombstone for event ids.
const DELETED_IDS: ::redb::TableDefinition<'static, &[u8], u64> =
    ::redb::TableDefinition::new("deleted_ids");
/// `[kind_be(2)] [pubkey(32)] [identifier_utf8]` → `created_at`. NIP-09
/// tombstone for addressable coordinates.
const DELETED_COORDINATES: ::redb::TableDefinition<'static, &[u8], u64> =
    ::redb::TableDefinition::new("deleted_coordinates");

type BytesTable<'txn> = ::redb::Table<'txn, &'static [u8], &'static [u8]>;
type IndexTable<'txn> = ::redb::Table<'txn, &'static [u8], ()>;
type StampTable<'txn> = ::redb::Table<'txn, &'static [u8], u64>;

/// Every write-side table handle, opened once per write transaction.
///
/// redb forbids opening the same table twice while a handle is live, so
/// the save / delete paths open all seven up front and thread `&mut
/// WriteTables` through the helpers instead of re-opening per call.
struct WriteTables<'txn> {
    events: BytesTable<'txn>,
    by_created_at: IndexTable<'txn>,
    by_author_ts: IndexTable<'txn>,
    by_kind_author_ts: IndexTable<'txn>,
    by_coordinate: BytesTable<'txn>,
    deleted_ids: StampTable<'txn>,
    deleted_coordinates: StampTable<'txn>,
}

impl<'txn> WriteTables<'txn> {
    fn open(txn: &'txn ::redb::WriteTransaction) -> Result<Self, Error> {
        Ok(Self {
            events: txn.open_table(EVENTS)?,
            by_created_at: txn.open_table(BY_CREATED_AT)?,
            by_author_ts: txn.open_table(BY_AUTHOR_TS)?,
            by_kind_author_ts: txn.open_table(BY_KIND_AUTHOR_TS)?,
            by_coordinate: txn.open_table(BY_COORDINATE)?,
            deleted_ids: txn.open_table(DELETED_IDS)?,
            deleted_coordinates: txn.open_table(DELETED_COORDINATES)?,
        })
    }
}

/// Synchronous redb-backed event store.
///
/// Cloning `Store` is cheap (it bumps the `Database` and options
/// `Arc`s); every clone shares the same on-disk database.
#[derive(Debug, Clone)]
pub(crate) struct Store {
    db: Arc<::redb::Database>,
    options: Arc<RedbDatabaseOptions>,
}

impl Store {
    /// Open (or create) the redb database file at `options.path`.
    ///
    /// # Errors
    ///
    /// Bubbles up [`Error::Io`] when the parent directory cannot be
    /// created and [`Error::Redb`] for any redb-level failure.
    pub(crate) fn open(options: RedbDatabaseOptions) -> Result<Self, Error> {
        if let Some(parent) = options.path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }

        let db = match options.cache_size {
            Some(bytes) => {
                let mut builder = ::redb::Builder::new();
                builder.set_cache_size(bytes);
                builder.create(&options.path)?
            }
            None => ::redb::Database::create(&options.path)?,
        };

        // Pre-create every table so read transactions never hit
        // `TableDoesNotExist` on a fresh database.
        let txn = db.begin_write()?;
        txn.open_table(EVENTS)?;
        txn.open_table(BY_CREATED_AT)?;
        txn.open_table(BY_AUTHOR_TS)?;
        txn.open_table(BY_KIND_AUTHOR_TS)?;
        txn.open_table(BY_COORDINATE)?;
        txn.open_table(DELETED_IDS)?;
        txn.open_table(DELETED_COORDINATES)?;
        txn.commit()?;

        Ok(Self {
            db: Arc::new(db),
            options: Arc::new(options),
        })
    }

    pub(crate) fn check_id(&self, id: &EventId) -> Result<DatabaseEventStatus, Error> {
        let txn = self.db.begin_read()?;
        let key = id.to_byte_array();
        let events = txn.open_table(EVENTS)?;
        if events.get(key.as_slice())?.is_some() {
            return Ok(DatabaseEventStatus::Saved);
        }
        let deleted = txn.open_table(DELETED_IDS)?;
        Ok(if deleted.get(key.as_slice())?.is_some() {
            DatabaseEventStatus::Deleted
        } else {
            DatabaseEventStatus::NotExistent
        })
    }

    pub(crate) fn event_by_id(&self, id: &EventId) -> Result<Option<Event>, Error> {
        let txn = self.db.begin_read()?;
        let events = txn.open_table(EVENTS)?;
        let key = id.to_byte_array();
        let Some(guard) = events.get(key.as_slice())? else {
            return Ok(None);
        };
        Ok(Some(codec::decode(guard.value())?))
    }

    pub(crate) fn query(&self, filter: &Filter) -> Result<Vec<Event>, Error> {
        let txn = self.db.begin_read()?;
        let events = txn.open_table(EVENTS)?;
        let opts = MatchEventOptions::default();
        let limit = filter.limit.unwrap_or(usize::MAX);

        let mut out: Vec<Event> = Vec::new();
        for id in candidate_ids(&txn, filter)? {
            if out.len() >= limit {
                break;
            }
            let Some(guard) = events.get(id.as_slice())? else {
                continue;
            };
            let bytes = guard.value();
            // Match on a zero-parse projection; pay the curve pubkey
            // parse (and content/tag allocation) only for the candidates
            // that survive the filter.
            let view = codec::decode_match_view(bytes)?;
            if filter.match_event(&view, opts) {
                out.push(codec::decode(bytes)?);
            }
        }
        Ok(out)
    }

    pub(crate) fn count(&self, filter: &Filter) -> Result<usize, Error> {
        let txn = self.db.begin_read()?;
        let events = txn.open_table(EVENTS)?;
        let opts = MatchEventOptions::default();
        let limit = filter.limit.unwrap_or(usize::MAX);

        let mut count = 0usize;
        for id in candidate_ids(&txn, filter)? {
            if count >= limit {
                break;
            }
            let Some(guard) = events.get(id.as_slice())? else {
                continue;
            };
            let view = codec::decode_match_view(guard.value())?;
            if filter.match_event(&view, opts) {
                count += 1;
            }
        }
        Ok(count)
    }

    /// `(EventId, created_at)` pairs matching `filter`, for NIP-77
    /// negentropy reconciliation. Matches on the zero-parse projection
    /// so reconciliation never decodes a full [`Event`].
    pub(crate) fn negentropy_items(
        &self,
        filter: &Filter,
    ) -> Result<Vec<(EventId, Timestamp)>, Error> {
        let txn = self.db.begin_read()?;
        let events = txn.open_table(EVENTS)?;
        let opts = MatchEventOptions::default();
        let limit = filter.limit.unwrap_or(usize::MAX);

        let mut items: Vec<(EventId, Timestamp)> = Vec::new();
        for id in candidate_ids(&txn, filter)? {
            if items.len() >= limit {
                break;
            }
            let Some(guard) = events.get(id.as_slice())? else {
                continue;
            };
            let view = codec::decode_match_view(guard.value())?;
            if filter.match_event(&view, opts) {
                items.push((view.id(), view.created_at()));
            }
        }
        Ok(items)
    }

    pub(crate) fn save_event(
        &self,
        event: &Event,
        now: Timestamp,
    ) -> Result<SaveEventStatus, Error> {
        let txn = self.db.begin_write()?;
        let outcome = {
            let mut t = WriteTables::open(&txn)?;
            self.save_with(&mut t, event, now)?
        };
        // Only the success path mutated tables; commit it. Rejections
        // drop `txn` on return, aborting any (absent) changes.
        if matches!(outcome, SaveEventStatus::Success) {
            txn.commit()?;
        }
        Ok(outcome)
    }

    fn save_with(
        &self,
        t: &mut WriteTables<'_>,
        event: &Event,
        now: Timestamp,
    ) -> Result<SaveEventStatus, Error> {
        let id_bytes = event.id.to_byte_array();

        // 1. Ephemeral kinds: drop.
        if event.kind.is_ephemeral() {
            return Ok(SaveEventStatus::Rejected(RejectedReason::Ephemeral));
        }

        // 2. NIP-40 expiration.
        if matches!(event.is_expired(now), Ok(true)) {
            return Ok(SaveEventStatus::Rejected(RejectedReason::Expired));
        }

        // 3. Tombstones: deleted ids.
        if t.deleted_ids.get(id_bytes.as_slice())?.is_some() {
            return Ok(SaveEventStatus::Rejected(RejectedReason::Deleted));
        }

        // 4. Tombstones: addressable coordinate.
        if let Some(identifier) = addressable_identifier(event) {
            let coord_key = keys::by_coordinate(event.kind, &event.pubkey, identifier);
            if let Some(guard) = t.deleted_coordinates.get(coord_key.as_slice())?
                && event.created_at.as_secs() <= guard.value()
            {
                return Ok(SaveEventStatus::Rejected(RejectedReason::Deleted));
            }
        }

        // 5. Duplicate id.
        if t.events.get(id_bytes.as_slice())?.is_some() {
            return Ok(SaveEventStatus::Rejected(RejectedReason::Duplicate));
        }

        // 6. Replaceable / addressable conflict resolution.
        if event.kind.is_replaceable() {
            if let Some(loser_id) = Self::resolve_replaceable(t, event)? {
                if loser_id == event.id {
                    return Ok(SaveEventStatus::Rejected(RejectedReason::Replaced));
                }
                Self::remove_event_inner(t, &loser_id.to_byte_array())?;
            }
        } else if event.kind.is_addressable() {
            if let Some(loser_id) = Self::resolve_addressable(t, event)? {
                if loser_id == event.id {
                    return Ok(SaveEventStatus::Rejected(RejectedReason::Replaced));
                }
                Self::remove_event_inner(t, &loser_id.to_byte_array())?;
            }
        }

        // 7. NIP-09 deletion: tombstone targets, then store the
        //    deletion event itself.
        if self.options.process_nip09 && event.kind == Kind::EVENT_DELETION {
            Self::apply_deletion(t, event)?;
        }

        // 8. Insert into every index.
        Self::insert_event_inner(t, event)?;

        Ok(SaveEventStatus::Success)
    }

    pub(crate) fn delete_matching(&self, filter: &Filter) -> Result<(), Error> {
        // Snapshot the matching ids under a read transaction so we don't
        // mutate the indexes while iterating them.
        let to_remove: Vec<[u8; keys::ID_LEN]> = {
            let txn = self.db.begin_read()?;
            let events = txn.open_table(EVENTS)?;
            let opts = MatchEventOptions::default();
            let mut acc: Vec<[u8; keys::ID_LEN]> = Vec::new();
            for id in candidate_ids(&txn, filter)? {
                let Some(guard) = events.get(id.as_slice())? else {
                    continue;
                };
                let view = codec::decode_match_view(guard.value())?;
                if filter.match_event(&view, opts) {
                    acc.push(id);
                }
            }
            acc
        };

        if to_remove.is_empty() {
            return Ok(());
        }

        let txn = self.db.begin_write()?;
        {
            let mut t = WriteTables::open(&txn)?;
            for id in &to_remove {
                Self::remove_event_inner(&mut t, id)?;
            }
        }
        txn.commit()?;
        Ok(())
    }

    pub(crate) fn wipe(&self) -> Result<(), Error> {
        let txn = self.db.begin_write()?;
        {
            let mut t = WriteTables::open(&txn)?;
            t.events.retain(|_, _| false)?;
            t.by_created_at.retain(|_, ()| false)?;
            t.by_author_ts.retain(|_, ()| false)?;
            t.by_kind_author_ts.retain(|_, ()| false)?;
            t.by_coordinate.retain(|_, _| false)?;
            t.deleted_ids.retain(|_, _| false)?;
            t.deleted_coordinates.retain(|_, _| false)?;
        }
        txn.commit()?;
        Ok(())
    }

    fn insert_event_inner(t: &mut WriteTables<'_>, event: &Event) -> Result<(), Error> {
        let id_bytes = event.id.to_byte_array();
        let encoded = codec::encode(event)?;

        t.events.insert(id_bytes.as_slice(), encoded.as_slice())?;

        let ts_id_key = keys::by_created_at(event.created_at, &event.id);
        t.by_created_at.insert(ts_id_key.as_slice(), ())?;

        let author_key = keys::by_author_ts(&event.pubkey, event.created_at, &event.id);
        t.by_author_ts.insert(author_key.as_slice(), ())?;

        let ka_key =
            keys::by_kind_author_ts(event.kind, &event.pubkey, event.created_at, &event.id);
        t.by_kind_author_ts.insert(ka_key.as_slice(), ())?;

        if let Some(identifier) = addressable_identifier(event) {
            let coord_key = keys::by_coordinate(event.kind, &event.pubkey, identifier);
            t.by_coordinate
                .insert(coord_key.as_slice(), id_bytes.as_slice())?;
        }

        Ok(())
    }

    fn remove_event_inner(t: &mut WriteTables<'_>, id: &[u8; keys::ID_LEN]) -> Result<(), Error> {
        let event = {
            let Some(guard) = t.events.get(id.as_slice())? else {
                return Ok(());
            };
            codec::decode(guard.value())?
        };

        t.events.remove(id.as_slice())?;
        t.by_created_at
            .remove(keys::by_created_at(event.created_at, &event.id).as_slice())?;
        t.by_author_ts
            .remove(keys::by_author_ts(&event.pubkey, event.created_at, &event.id).as_slice())?;
        t.by_kind_author_ts.remove(
            keys::by_kind_author_ts(event.kind, &event.pubkey, event.created_at, &event.id)
                .as_slice(),
        )?;

        if let Some(identifier) = addressable_identifier(&event) {
            let coord_key = keys::by_coordinate(event.kind, &event.pubkey, identifier);
            // Only delete the coordinate index if it still points at
            // this event id — a newer event under the same coordinate
            // would have already claimed it.
            let still_ours = t
                .by_coordinate
                .get(coord_key.as_slice())?
                .is_some_and(|guard| guard.value() == id.as_slice());
            if still_ours {
                t.by_coordinate.remove(coord_key.as_slice())?;
            }
        }
        Ok(())
    }

    fn resolve_replaceable(t: &WriteTables<'_>, event: &Event) -> Result<Option<EventId>, Error> {
        // The replaceable winner for `(kind, author)` is the newest
        // event currently indexed under that prefix; pull it off
        // `by_kind_author_ts` with a single range scan.
        let prefix = keys::kind_author_prefix(event.kind, &event.pubkey);
        let upper = keys::upper_bound(&prefix);
        let prefix_len = keys::KIND_LEN + keys::PUBKEY_LEN;

        let mut newest: Option<(Timestamp, EventId)> = None;
        let range = match upper.as_deref() {
            Some(hi) => t
                .by_kind_author_ts
                .range::<&[u8]>((Bound::Included(&prefix[..]), Bound::Excluded(hi)))?,
            None => t
                .by_kind_author_ts
                .range::<&[u8]>((Bound::Included(&prefix[..]), Bound::Unbounded))?,
        };
        for entry in range {
            let (key, _) = entry?;
            let key = key.value();
            if key.len() != prefix_len + keys::TS_LEN + keys::ID_LEN {
                continue;
            }
            let mut ts_bytes = [0u8; keys::TS_LEN];
            ts_bytes.copy_from_slice(&key[prefix_len..prefix_len + keys::TS_LEN]);
            let ts = Timestamp::from_secs(u64::from_be_bytes(ts_bytes));
            let mut id_bytes = [0u8; keys::ID_LEN];
            id_bytes.copy_from_slice(&key[prefix_len + keys::TS_LEN..]);
            let id = EventId::from_byte_array(id_bytes);
            match newest {
                None => newest = Some((ts, id)),
                Some((cur_ts, _)) if ts > cur_ts => newest = Some((ts, id)),
                _ => {}
            }
        }
        let Some((cur_ts, cur_id)) = newest else {
            return Ok(None);
        };
        Ok(Some(pick_loser_id(cur_ts, &cur_id, event)))
    }

    fn resolve_addressable(t: &WriteTables<'_>, event: &Event) -> Result<Option<EventId>, Error> {
        let Some(identifier) = addressable_identifier(event) else {
            return Ok(None);
        };
        let coord_key = keys::by_coordinate(event.kind, &event.pubkey, identifier);
        let existing_id = {
            let Some(guard) = t.by_coordinate.get(coord_key.as_slice())? else {
                return Ok(None);
            };
            let value = guard.value();
            if value.len() != keys::ID_LEN {
                return Ok(None);
            }
            let mut id_bytes = [0u8; keys::ID_LEN];
            id_bytes.copy_from_slice(value);
            id_bytes
        };
        let existing_event_id = EventId::from_byte_array(existing_id);
        let existing_created_at = {
            let Some(guard) = t.events.get(existing_id.as_slice())? else {
                return Ok(None);
            };
            codec::decode_created_at(guard.value())?
        };
        Ok(Some(pick_loser_id(
            existing_created_at,
            &existing_event_id,
            event,
        )))
    }

    fn apply_deletion(t: &mut WriteTables<'_>, event: &Event) -> Result<(), Error> {
        let Ok(request) = DeletionRequest::from_event(event) else {
            return Ok(());
        };

        let mut to_remove: HashSet<[u8; keys::ID_LEN]> = HashSet::new();
        let mut to_tombstone: HashSet<[u8; keys::ID_LEN]> = HashSet::new();
        for id in &request.event_ids {
            let key = id.to_byte_array();
            let existing_pubkey = match t.events.get(key.as_slice())? {
                Some(guard) => Some(codec::decode(guard.value())?.pubkey),
                None => None,
            };
            match existing_pubkey {
                // Tombstone in case the event arrives later.
                None => {
                    to_tombstone.insert(key);
                }
                Some(pubkey) if pubkey == event.pubkey => {
                    to_remove.insert(key);
                    to_tombstone.insert(key);
                }
                Some(_) => {}
            }
        }

        for key in &to_remove {
            Self::remove_event_inner(t, key)?;
        }
        for key in to_tombstone {
            t.deleted_ids
                .insert(key.as_slice(), event.created_at.as_secs())?;
        }

        // Coordinate deletions.
        for coord in &request.coordinates {
            if coord.author != event.pubkey {
                continue;
            }
            let coord_key = keys::by_coordinate(coord.kind, &coord.author, &coord.identifier);
            let existing_id: Option<[u8; keys::ID_LEN]> = t
                .by_coordinate
                .get(coord_key.as_slice())?
                .and_then(|guard| {
                    let value = guard.value();
                    (value.len() == keys::ID_LEN).then(|| {
                        let mut id_arr = [0u8; keys::ID_LEN];
                        id_arr.copy_from_slice(value);
                        id_arr
                    })
                });
            if let Some(id_arr) = existing_id {
                let existing_created_at = match t.events.get(id_arr.as_slice())? {
                    Some(guard) => Some(codec::decode_created_at(guard.value())?),
                    None => None,
                };
                if let Some(ts) = existing_created_at
                    && ts <= event.created_at
                {
                    Self::remove_event_inner(t, &id_arr)?;
                }
            }

            let prev = t
                .deleted_coordinates
                .get(coord_key.as_slice())?
                .map(|guard| guard.value());
            let bump = prev.is_none_or(|p| p < event.created_at.as_secs());
            if bump {
                t.deleted_coordinates
                    .insert(coord_key.as_slice(), event.created_at.as_secs())?;
            }
        }

        Ok(())
    }
}

/// Stream candidate event ids in newest-first order, picking the most
/// selective secondary index for the filter shape.
fn candidate_ids(
    txn: &::redb::ReadTransaction,
    filter: &Filter,
) -> Result<Vec<[u8; keys::ID_LEN]>, Error> {
    // `Filter::ids` carries the explicit answer; honour it directly and
    // skip every index.
    if let Some(ids) = filter.ids.as_ref()
        && !ids.is_empty()
    {
        return Ok(ids.iter().map(|id| id.to_byte_array()).collect());
    }

    let authors_one = filter
        .authors
        .as_ref()
        .and_then(|v| (v.len() == 1).then(|| v[0]));
    let kinds_one = filter
        .kinds
        .as_ref()
        .and_then(|v| (v.len() == 1).then(|| v[0]));

    if let (Some(author), Some(kind)) = (authors_one, kinds_one) {
        let table = txn.open_table(BY_KIND_AUTHOR_TS)?;
        return scan_kind_author(&table, kind, &author);
    }
    if let Some(author) = authors_one {
        let table = txn.open_table(BY_AUTHOR_TS)?;
        return scan_author(&table, &author);
    }

    // Fallback: full scan via the global timestamp index.
    let table = txn.open_table(BY_CREATED_AT)?;
    let mut ids = Vec::new();
    for entry in table.iter()? {
        let (key, _) = entry?;
        let key = key.value();
        if key.len() != keys::TS_LEN + keys::ID_LEN {
            continue;
        }
        let mut id = [0u8; keys::ID_LEN];
        id.copy_from_slice(&key[keys::TS_LEN..]);
        ids.push(id);
    }
    // `by_created_at` iterates ascending; reverse for newest-first.
    ids.reverse();
    Ok(ids)
}

fn scan_author<T>(table: &T, pubkey: &PublicKey) -> Result<Vec<[u8; keys::ID_LEN]>, Error>
where
    T: ReadableTable<&'static [u8], ()>,
{
    let prefix = keys::author_prefix(pubkey);
    let upper = keys::upper_bound(&prefix);
    let mut ids = Vec::new();
    let range = match upper.as_deref() {
        Some(hi) => table.range::<&[u8]>((Bound::Included(&prefix[..]), Bound::Excluded(hi)))?,
        None => table.range::<&[u8]>((Bound::Included(&prefix[..]), Bound::Unbounded))?,
    };
    for entry in range {
        let (key, _) = entry?;
        let key = key.value();
        if key.len() != keys::PUBKEY_LEN + keys::TS_LEN + keys::ID_LEN {
            continue;
        }
        let mut id = [0u8; keys::ID_LEN];
        id.copy_from_slice(&key[keys::PUBKEY_LEN + keys::TS_LEN..]);
        ids.push(id);
    }
    ids.reverse();
    Ok(ids)
}

fn scan_kind_author<T>(
    table: &T,
    kind: Kind,
    pubkey: &PublicKey,
) -> Result<Vec<[u8; keys::ID_LEN]>, Error>
where
    T: ReadableTable<&'static [u8], ()>,
{
    let prefix = keys::kind_author_prefix(kind, pubkey);
    let upper = keys::upper_bound(&prefix);
    let prefix_len = keys::KIND_LEN + keys::PUBKEY_LEN + keys::TS_LEN;
    let mut ids = Vec::new();
    let range = match upper.as_deref() {
        Some(hi) => table.range::<&[u8]>((Bound::Included(&prefix[..]), Bound::Excluded(hi)))?,
        None => table.range::<&[u8]>((Bound::Included(&prefix[..]), Bound::Unbounded))?,
    };
    for entry in range {
        let (key, _) = entry?;
        let key = key.value();
        if key.len() != prefix_len + keys::ID_LEN {
            continue;
        }
        let mut id = [0u8; keys::ID_LEN];
        id.copy_from_slice(&key[prefix_len..]);
        ids.push(id);
    }
    ids.reverse();
    Ok(ids)
}

/// Identifier (`d` tag value) of an addressable event, or `None` if the
/// event is not in the addressable kind range.
fn addressable_identifier(event: &Event) -> Option<&str> {
    if !event.kind.is_addressable() {
        return None;
    }
    Some(event.tags.identifier().unwrap_or(""))
}

/// Pick the loser between an incumbent and a challenger for replaceable
/// / addressable kinds.
fn pick_loser_id(incumbent_ts: Timestamp, incumbent_id: &EventId, challenger: &Event) -> EventId {
    use std::cmp::Ordering;
    match incumbent_ts.cmp(&challenger.created_at) {
        Ordering::Greater => challenger.id,
        Ordering::Less => *incumbent_id,
        Ordering::Equal => {
            if *incumbent_id <= challenger.id {
                challenger.id
            } else {
                *incumbent_id
            }
        }
    }
}
