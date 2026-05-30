//! LMDB-backed event store.
//!
//! `Store` owns the [`heed::Env`] plus the seven secondary-index
//! [`heed::Database`] handles. It exposes synchronous read/write
//! methods that operate inside [`heed`] transactions; the async
//! façade in [`crate::lmdb::database`] turns those into `BoxFuture`s by
//! routing them through the ingester worker or
//! [`tokio::task::spawn_blocking`].

// The index-decoding paths slice into raw byte buffers whose length
// was already verified by the surrounding `if key.len() == … {}`
// guard. Clippy still flags every such slice as "may panic"; opting
// out at the module level keeps the index-decoding code readable.
#![allow(
    clippy::indexing_slicing,
    clippy::cognitive_complexity,
    clippy::too_many_lines,
    clippy::excessive_nesting,
    clippy::collapsible_if,
    reason = "LMDB index-decoding paths are slice-arithmetic-heavy by nature; bounds are checked by the surrounding length guards"
)]

use std::collections::HashSet;
use std::sync::Arc;

use heed::types::{Bytes, U64, Unit};
use heed::{Database, Env, EnvOpenOptions};
use nula_core::event::{Event, EventId, Kind};
use nula_core::filter::{Filter, MatchEventOptions};
use nula_core::key::PublicKey;
use nula_core::nips::nip09::DeletionRequest;
use nula_core::types::Timestamp;

use crate::lmdb::codec;
use crate::lmdb::error::Error;
use crate::lmdb::keys;
use crate::lmdb::options::LmdbDatabaseOptions;
use crate::{DatabaseEventStatus, RejectedReason, SaveEventStatus};

/// Number of named secondary databases used by this backend.
///
/// The unnamed root database is reserved by LMDB for the env itself,
/// so `max_dbs` must be at least this many.
const NAMED_DBS: u32 = 7;

/// Native-endian unsigned 64-bit integer alias from heed.
type NativeU64 = U64<heed::byteorder::NativeEndian>;

/// Synchronous LMDB-backed event store.
///
/// Cloning `Store` is cheap (it bumps the `Env` and `Database`
/// reference counts); every clone shares the same on-disk database
/// and the same reader slot pool.
#[derive(Debug, Clone)]
pub(crate) struct Store {
    env: Env,
    options: Arc<LmdbDatabaseOptions>,

    /// `event_id (32)` → `[version: u8] [postcard(event)]`.
    events: Database<Bytes, Bytes>,

    /// `[ts_be(8)] [id(32)]` → `()`. Global newest-first cursor.
    by_created_at: Database<Bytes, Unit>,

    /// `[pubkey(32)] [ts_be(8)] [id(32)]` → `()`. Per-author scan.
    by_author_ts: Database<Bytes, Unit>,

    /// `[kind_be(2)] [pubkey(32)] [ts_be(8)] [id(32)]` → `()`.
    by_kind_author_ts: Database<Bytes, Unit>,

    /// `[kind_be(2)] [pubkey(32)] [identifier_utf8]` → `event_id`.
    /// NIP-33 addressable coordinate index.
    by_coordinate: Database<Bytes, Bytes>,

    /// `event_id (32)` → `ts_be(8)`. NIP-09 tombstone for event ids;
    /// the value is the deletion request's `created_at`.
    deleted_ids: Database<Bytes, NativeU64>,

    /// `[kind_be(2)] [pubkey(32)] [identifier_utf8]` → `ts_be(8)`.
    /// NIP-09 tombstone for addressable coordinates.
    deleted_coordinates: Database<Bytes, NativeU64>,
}

impl Store {
    /// Open (or create) the LMDB environment at `options.path`.
    ///
    /// # Errors
    ///
    /// Bubbles up [`Error::Io`] when the directory cannot be created
    /// and [`Error::Heed`] for any LMDB-level failure (env / dbi /
    /// txn).
    pub(crate) fn open(options: LmdbDatabaseOptions) -> Result<Self, Error> {
        std::fs::create_dir_all(&options.path)?;

        #[allow(
            unsafe_code,
            reason = "heed::EnvOpenOptions::open requires unsafe per its safety contract; ADR-0007 documents the audit."
        )]
        // SAFETY: `heed::EnvOpenOptions::open` is unsafe because the
        // returned `Env` mmaps the database file; the file must not
        // be concurrently mutated by another process and the
        // configured `map_size` must fit in the address space. Both
        // invariants hold here: `LmdbDatabase` is the sole writer
        // for the directory it owns, and the default 1 GiB map size
        // is far below the 64-bit address space. ADR-0007 records
        // this exemption.
        let env = unsafe {
            EnvOpenOptions::new()
                .max_dbs(NAMED_DBS)
                .max_readers(options.max_readers.get())
                .map_size(options.map_size)
                .open(&options.path)?
        };

        let mut txn = env.write_txn()?;
        let events = env.create_database::<Bytes, Bytes>(&mut txn, Some("events"))?;
        let by_created_at = env.create_database::<Bytes, Unit>(&mut txn, Some("by_created_at"))?;
        let by_author_ts = env.create_database::<Bytes, Unit>(&mut txn, Some("by_author_ts"))?;
        let by_kind_author_ts =
            env.create_database::<Bytes, Unit>(&mut txn, Some("by_kind_author_ts"))?;
        let by_coordinate = env.create_database::<Bytes, Bytes>(&mut txn, Some("by_coordinate"))?;
        let deleted_ids = env.create_database::<Bytes, NativeU64>(&mut txn, Some("deleted_ids"))?;
        let deleted_coordinates =
            env.create_database::<Bytes, NativeU64>(&mut txn, Some("deleted_coordinates"))?;
        txn.commit()?;

        Ok(Self {
            env,
            options: Arc::new(options),
            events,
            by_created_at,
            by_author_ts,
            by_kind_author_ts,
            by_coordinate,
            deleted_ids,
            deleted_coordinates,
        })
    }

    #[allow(
        dead_code,
        reason = "kept for future telemetry hooks; consumed once LmdbDatabase exposes Features::BOUNDED_CAPACITY"
    )]
    pub(crate) fn options(&self) -> &LmdbDatabaseOptions {
        &self.options
    }

    // -- read paths ----------------------------------------------------------

    pub(crate) fn check_id(&self, id: &EventId) -> Result<DatabaseEventStatus, Error> {
        let txn = self.env.read_txn()?;
        let key = id.to_byte_array();
        let saved = self.events.get(&txn, &key)?.is_some();
        if saved {
            return Ok(DatabaseEventStatus::Saved);
        }
        let tombstoned = self.deleted_ids.get(&txn, &key)?.is_some();
        Ok(if tombstoned {
            DatabaseEventStatus::Deleted
        } else {
            DatabaseEventStatus::NotExistent
        })
    }

    pub(crate) fn event_by_id(&self, id: &EventId) -> Result<Option<Event>, Error> {
        let txn = self.env.read_txn()?;
        let key = id.to_byte_array();
        let Some(bytes) = self.events.get(&txn, &key)? else {
            return Ok(None);
        };
        Ok(Some(codec::decode(bytes)?))
    }

    pub(crate) fn query(&self, filter: &Filter) -> Result<Vec<Event>, Error> {
        let txn = self.env.read_txn()?;
        let opts = MatchEventOptions::default();
        let limit = filter.limit.unwrap_or(usize::MAX);

        let candidate_ids = self.candidate_ids(&txn, filter)?;
        let mut events: Vec<Event> = Vec::new();
        for id in candidate_ids {
            if events.len() >= limit {
                break;
            }
            let Some(bytes) = self.events.get(&txn, &id)? else {
                continue;
            };
            let event = codec::decode(bytes)?;
            if filter.match_event(&event, opts) {
                events.push(event);
            }
        }
        Ok(events)
    }

    pub(crate) fn count(&self, filter: &Filter) -> Result<usize, Error> {
        Ok(self.query(filter)?.len())
    }

    /// Stream candidate event ids in newest-first order, picking the
    /// most selective secondary index for the filter shape.
    fn candidate_ids(
        &self,
        txn: &heed::RoTxn<'_>,
        filter: &Filter,
    ) -> Result<Vec<[u8; keys::ID_LEN]>, Error> {
        // Filter::ids carries the explicit answer; honour it
        // directly and skip every index.
        if let Some(ids) = filter.ids.as_ref()
            && !ids.is_empty()
        {
            return Ok(ids.iter().map(|i| i.to_byte_array()).collect());
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
            return self.scan_kind_author(txn, kind, &author);
        }
        if let Some(author) = authors_one {
            return self.scan_author(txn, &author);
        }

        // Fallback: full table scan via the global timestamp index.
        let mut ids = Vec::new();
        for entry in self.by_created_at.iter(txn)? {
            let (key, ()) = entry?;
            if key.len() != keys::TS_LEN + keys::ID_LEN {
                continue;
            }
            let mut id = [0u8; keys::ID_LEN];
            id.copy_from_slice(&key[keys::TS_LEN..]);
            ids.push(id);
        }
        // by_created_at iterates ascending; reverse for newest-first.
        ids.reverse();
        Ok(ids)
    }

    fn scan_author(
        &self,
        txn: &heed::RoTxn<'_>,
        pubkey: &PublicKey,
    ) -> Result<Vec<[u8; keys::ID_LEN]>, Error> {
        let prefix = keys::author_prefix(pubkey);
        let upper = keys::upper_bound(&prefix);
        let range: (std::ops::Bound<&[u8]>, std::ops::Bound<&[u8]>) = (
            std::ops::Bound::Included(&prefix[..]),
            upper
                .as_deref()
                .map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded),
        );
        let mut ids = Vec::new();
        for entry in self.by_author_ts.range(txn, &range)? {
            let (key, ()) = entry?;
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

    fn scan_kind_author(
        &self,
        txn: &heed::RoTxn<'_>,
        kind: Kind,
        pubkey: &PublicKey,
    ) -> Result<Vec<[u8; keys::ID_LEN]>, Error> {
        let prefix = keys::kind_author_prefix(kind, pubkey);
        let upper = keys::upper_bound(&prefix);
        let range: (std::ops::Bound<&[u8]>, std::ops::Bound<&[u8]>) = (
            std::ops::Bound::Included(&prefix[..]),
            upper
                .as_deref()
                .map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded),
        );
        let mut ids = Vec::new();
        for entry in self.by_kind_author_ts.range(txn, &range)? {
            let (key, ()) = entry?;
            let prefix_len = keys::KIND_LEN + keys::PUBKEY_LEN + keys::TS_LEN;
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

    // -- write paths ---------------------------------------------------------

    pub(crate) fn save_event(
        &self,
        event: &Event,
        now: Timestamp,
    ) -> Result<SaveEventStatus, Error> {
        let mut txn = self.env.write_txn()?;
        let id_bytes = event.id.to_byte_array();

        // 1. Vanish: NIP-62 is opt-in; we do not maintain a vanish
        //    dbi yet because no Layer-4 caller consumes it. The
        //    process_nip62 flag is reserved for forward compat.

        // 2. Ephemeral kinds: drop.
        if event.kind.is_ephemeral() {
            return Ok(SaveEventStatus::Rejected(RejectedReason::Ephemeral));
        }

        // 3. NIP-40 expiration.
        if matches!(event.is_expired(now), Ok(true)) {
            return Ok(SaveEventStatus::Rejected(RejectedReason::Expired));
        }

        // 4. Tombstones: deleted ids.
        if self.deleted_ids.get(&txn, &id_bytes)?.is_some() {
            return Ok(SaveEventStatus::Rejected(RejectedReason::Deleted));
        }

        // 5. Tombstones: addressable coordinate.
        if let Some(identifier) = addressable_identifier(event) {
            let coord_key = keys::by_coordinate(event.kind, &event.pubkey, identifier);
            if let Some(t) = self.deleted_coordinates.get(&txn, &coord_key)?
                && event.created_at.as_secs() <= t
            {
                return Ok(SaveEventStatus::Rejected(RejectedReason::Deleted));
            }
        }

        // 6. Duplicate id.
        if self.events.get(&txn, &id_bytes)?.is_some() {
            return Ok(SaveEventStatus::Rejected(RejectedReason::Duplicate));
        }

        // 7. Replaceable / addressable conflict resolution.
        if event.kind.is_replaceable() {
            if let Some(loser_id) = self.resolve_replaceable(&txn, event)? {
                if loser_id == event.id {
                    return Ok(SaveEventStatus::Rejected(RejectedReason::Replaced));
                }
                self.remove_event_inner(&mut txn, &loser_id.to_byte_array())?;
            }
        } else if event.kind.is_addressable() {
            if let Some(loser_id) = self.resolve_addressable(&txn, event)? {
                if loser_id == event.id {
                    return Ok(SaveEventStatus::Rejected(RejectedReason::Replaced));
                }
                self.remove_event_inner(&mut txn, &loser_id.to_byte_array())?;
            }
        }

        // 8. NIP-09 deletion: tombstone targets, then store the
        //    deletion event itself.
        if self.options.process_nip09 && event.kind == Kind::EVENT_DELETION {
            self.apply_deletion(&mut txn, event)?;
        }

        // 9. Insert into every index.
        self.insert_event_inner(&mut txn, event)?;

        txn.commit()?;
        Ok(SaveEventStatus::Success)
    }

    pub(crate) fn delete_matching(&self, filter: &Filter) -> Result<(), Error> {
        // Snapshot the matching ids under a read txn so we don't
        // mutate the indexes while we're iterating them.
        let to_remove: Vec<[u8; keys::ID_LEN]> = {
            let txn = self.env.read_txn()?;
            let opts = MatchEventOptions::default();
            let mut acc: Vec<[u8; keys::ID_LEN]> = Vec::new();
            for id in self.candidate_ids(&txn, filter)? {
                let Some(bytes) = self.events.get(&txn, &id)? else {
                    continue;
                };
                let event = codec::decode(bytes)?;
                if filter.match_event(&event, opts) {
                    acc.push(id);
                }
            }
            acc
        };

        if to_remove.is_empty() {
            return Ok(());
        }

        let mut txn = self.env.write_txn()?;
        for id in &to_remove {
            self.remove_event_inner(&mut txn, id)?;
        }
        txn.commit()?;
        Ok(())
    }

    pub(crate) fn wipe(&self) -> Result<(), Error> {
        let mut txn = self.env.write_txn()?;
        self.events.clear(&mut txn)?;
        self.by_created_at.clear(&mut txn)?;
        self.by_author_ts.clear(&mut txn)?;
        self.by_kind_author_ts.clear(&mut txn)?;
        self.by_coordinate.clear(&mut txn)?;
        self.deleted_ids.clear(&mut txn)?;
        self.deleted_coordinates.clear(&mut txn)?;
        txn.commit()?;
        Ok(())
    }

    // -- internal helpers ----------------------------------------------------

    fn insert_event_inner(&self, txn: &mut heed::RwTxn<'_>, event: &Event) -> Result<(), Error> {
        let id_bytes = event.id.to_byte_array();
        let encoded = codec::encode(event)?;

        self.events.put(txn, &id_bytes, &encoded)?;

        let ts_id_key = keys::by_created_at(event.created_at, &event.id);
        self.by_created_at.put(txn, &ts_id_key, &())?;

        let author_key = keys::by_author_ts(&event.pubkey, event.created_at, &event.id);
        self.by_author_ts.put(txn, &author_key, &())?;

        let ka_key =
            keys::by_kind_author_ts(event.kind, &event.pubkey, event.created_at, &event.id);
        self.by_kind_author_ts.put(txn, &ka_key, &())?;

        if let Some(identifier) = addressable_identifier(event) {
            let coord_key = keys::by_coordinate(event.kind, &event.pubkey, identifier);
            self.by_coordinate.put(txn, &coord_key, &id_bytes)?;
        }

        Ok(())
    }

    fn remove_event_inner(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: &[u8; keys::ID_LEN],
    ) -> Result<(), Error> {
        let Some(bytes) = self.events.get(txn, id)? else {
            return Ok(());
        };
        let event = codec::decode(bytes)?;

        self.events.delete(txn, id)?;
        self.by_created_at
            .delete(txn, &keys::by_created_at(event.created_at, &event.id))?;
        self.by_author_ts.delete(
            txn,
            &keys::by_author_ts(&event.pubkey, event.created_at, &event.id),
        )?;
        self.by_kind_author_ts.delete(
            txn,
            &keys::by_kind_author_ts(event.kind, &event.pubkey, event.created_at, &event.id),
        )?;
        if let Some(identifier) = addressable_identifier(&event) {
            let coord_key = keys::by_coordinate(event.kind, &event.pubkey, identifier);
            // Only delete the coordinate index if it still points at
            // this event id — a newer event under the same coordinate
            // would have already claimed it.
            if let Some(existing) = self.by_coordinate.get(txn, &coord_key)?
                && existing == id
            {
                self.by_coordinate.delete(txn, &coord_key)?;
            }
        }
        Ok(())
    }

    fn resolve_replaceable(
        &self,
        txn: &heed::RoTxn<'_>,
        event: &Event,
    ) -> Result<Option<EventId>, Error> {
        // The replaceable winner for `(kind, author)` is the newest
        // event currently indexed under that prefix. We can pull it
        // off `by_kind_author_ts` with a single range scan.
        let prefix = keys::kind_author_prefix(event.kind, &event.pubkey);
        let upper = keys::upper_bound(&prefix);
        let range: (std::ops::Bound<&[u8]>, std::ops::Bound<&[u8]>) = (
            std::ops::Bound::Included(&prefix[..]),
            upper
                .as_deref()
                .map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded),
        );
        let mut newest: Option<(Timestamp, EventId)> = None;
        for entry in self.by_kind_author_ts.range(txn, &range)? {
            let (key, ()) = entry?;
            let prefix_len = keys::KIND_LEN + keys::PUBKEY_LEN;
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

    fn resolve_addressable(
        &self,
        txn: &heed::RoTxn<'_>,
        event: &Event,
    ) -> Result<Option<EventId>, Error> {
        let Some(identifier) = addressable_identifier(event) else {
            return Ok(None);
        };
        let coord_key = keys::by_coordinate(event.kind, &event.pubkey, identifier);
        let Some(existing) = self.by_coordinate.get(txn, &coord_key)? else {
            return Ok(None);
        };
        if existing.len() != keys::ID_LEN {
            return Ok(None);
        }
        let mut id_bytes = [0u8; keys::ID_LEN];
        id_bytes.copy_from_slice(existing);
        let existing_id = EventId::from_byte_array(id_bytes);
        // Read the existing event to get its created_at.
        let Some(bytes) = self.events.get(txn, &id_bytes)? else {
            return Ok(None);
        };
        let existing_event = codec::decode(bytes)?;
        Ok(Some(pick_loser_id(
            existing_event.created_at,
            &existing_id,
            event,
        )))
    }

    fn apply_deletion(&self, txn: &mut heed::RwTxn<'_>, event: &Event) -> Result<(), Error> {
        let Ok(request) = DeletionRequest::from_event(event) else {
            return Ok(());
        };

        // Snapshot existence checks so we can defer mutation safely.
        // (We're in a write txn, so iterating self.events / by_id is
        // fine; we just want to keep the logic in two phases for
        // clarity.)
        let mut to_remove: HashSet<[u8; keys::ID_LEN]> = HashSet::new();
        let mut to_tombstone: HashSet<[u8; keys::ID_LEN]> = HashSet::new();
        for id in &request.event_ids {
            let key = id.to_byte_array();
            let Some(bytes) = self.events.get(txn, &key)? else {
                // Tombstone in case the event arrives later.
                to_tombstone.insert(key);
                continue;
            };
            let existing = codec::decode(bytes)?;
            if existing.pubkey == event.pubkey {
                to_remove.insert(key);
                to_tombstone.insert(key);
            }
        }

        for key in &to_remove {
            self.remove_event_inner(txn, key)?;
        }
        for key in to_tombstone {
            self.deleted_ids
                .put(txn, &key, &event.created_at.as_secs())?;
        }

        // Coordinate deletions.
        for coord in &request.coordinates {
            if coord.author != event.pubkey {
                continue;
            }
            let coord_key = keys::by_coordinate(coord.kind, &coord.author, &coord.identifier);
            if let Some(existing_id) = self.by_coordinate.get(txn, &coord_key)? {
                let existing_id = existing_id.to_vec();
                if existing_id.len() == keys::ID_LEN {
                    let mut id_arr = [0u8; keys::ID_LEN];
                    id_arr.copy_from_slice(&existing_id);
                    if let Some(bytes) = self.events.get(txn, &id_arr)? {
                        let existing_event = codec::decode(bytes)?;
                        if existing_event.created_at <= event.created_at {
                            self.remove_event_inner(txn, &id_arr)?;
                        }
                    }
                }
            }

            let prev = self.deleted_coordinates.get(txn, &coord_key)?;
            let bump = prev.is_none_or(|p| p < event.created_at.as_secs());
            if bump {
                self.deleted_coordinates
                    .put(txn, &coord_key, &event.created_at.as_secs())?;
            }
        }

        Ok(())
    }
}

/// Identifier (`d` tag value) of an addressable event, or `None` if
/// the event is not in the addressable kind range.
fn addressable_identifier(event: &Event) -> Option<&str> {
    if !event.kind.is_addressable() {
        return None;
    }
    Some(event.tags.identifier().unwrap_or(""))
}

/// Pick the loser between an incumbent and a challenger for
/// replaceable / addressable kinds.
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
