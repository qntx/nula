//! The [`NostrDatabase`] trait — the single seam every storage backend
//! implements and every upper-layer consumer talks to.
//!
//! The shape is deliberately small. Convenience helpers (metadata
//! lookups, contact-list expansion, NIP-65 relay-list aggregation) live
//! in [`crate::NostrDatabaseExt`] as default-implemented extension
//! methods, so backends only need to implement the eight terminal
//! methods below.
//!
//! # Object safety
//!
//! Every method returns [`nula_core::BoxFuture`] rather than `impl
//! Future`, so the trait is dyn-safe. Callers commonly own backends
//! through `Arc<dyn NostrDatabase>`. This matches the seam shape used
//! by the relay-layer `WebSocketTransport` one layer down.

use std::fmt::Debug;

use nula_core::boxed::BoxFuture;
use nula_core::event::{Event, EventId};
use nula_core::filter::Filter;
use nula_core::types::Timestamp;

use crate::error::Error;
use crate::events::Events;
use crate::features::{Backend, Features};
use crate::status::{DatabaseEventStatus, SaveEventStatus};

/// Storage seam for Nostr events.
///
/// Implementations enforce the protocol-level write semantics
/// (NIP-09 deletion, NIP-40 expiration, replaceable / addressable
/// / ephemeral kind routing, NIP-62 vanish) so callers above this
/// trait never touch raw indexes.
///
/// # Trait shape rationale
///
/// All methods take `&self` and return `BoxFuture<'_, Result<…, Error>>`.
/// The pattern is identical to the relay-layer `WebSocketTransport` one
/// layer down: it keeps the trait object-safe (so backends can be
/// stored as `Arc<dyn NostrDatabase>`) and wasm-friendly (the
/// `BoxFuture` alias drops the `Send` bound on `wasm32` targets).
///
/// # Cancellation
///
/// Dropping the returned future after the backend has begun writing
/// must not corrupt the store. Backends that do their own work on a
/// background thread (e.g. the LMDB ingester) treat the future as a
/// receipt for the commit decision; the write itself still completes.
pub trait NostrDatabase: Debug + Send + Sync {
    /// Identifier for the concrete backend (used for telemetry).
    fn backend(&self) -> Backend;

    /// Capability flags advertised by this backend.
    ///
    /// See [`Features`] for the meaning of each flag. The set is
    /// constant for the lifetime of the handle.
    fn features(&self) -> Features;

    /// Persist `event` and return the outcome.
    ///
    /// The backend **assumes the event is already cryptographically
    /// valid** — callers must invoke [`Event::verify`] (or rely on
    /// `nula-relay` having done so) before reaching this method. The
    /// backend still enforces the protocol-level write rules listed in
    /// the trait docs.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Backend`] if the underlying store fails (I/O,
    /// transaction abort). Protocol-level rejections come back as
    /// `Ok(SaveEventStatus::Rejected(…))` rather than `Err`.
    fn save_event<'a>(&'a self, event: &'a Event) -> BoxFuture<'a, Result<SaveEventStatus, Error>>;

    /// Look up the current state of an event ID.
    ///
    /// Returns [`DatabaseEventStatus::Saved`] if the event is live,
    /// [`DatabaseEventStatus::Deleted`] if a NIP-09 deletion has
    /// tombstoned it (or an addressable kind has replaced it), and
    /// [`DatabaseEventStatus::NotExistent`] if the ID is unknown.
    fn check_id<'a>(
        &'a self,
        event_id: &'a EventId,
    ) -> BoxFuture<'a, Result<DatabaseEventStatus, Error>>;

    /// Fetch a single live event by ID.
    ///
    /// Returns `Ok(None)` if the event was never seen or has been
    /// tombstoned. Use [`Self::check_id`] when you need to distinguish
    /// those two cases.
    fn event_by_id<'a>(
        &'a self,
        event_id: &'a EventId,
    ) -> BoxFuture<'a, Result<Option<Event>, Error>>;

    /// Count the events matching `filter` without materialising them.
    ///
    /// Backends are free to implement this on top of [`Self::query`] —
    /// the LMDB backend uses index-only scans for a much faster count.
    fn count(&self, filter: Filter) -> BoxFuture<'_, Result<usize, Error>>;

    /// Materialise the events matching `filter`.
    ///
    /// The returned [`Events`] is already sorted in NIP-01 wire order
    /// (newest first, ties broken by ID), so callers can iterate
    /// straight into `["EVENT", ...]` frames.
    fn query(&self, filter: Filter) -> BoxFuture<'_, Result<Events, Error>>;

    /// Negentropy reconciliation pairs `(EventId, created_at)`.
    ///
    /// Used by `nula-relay-pool` to implement NIP-77 reconciliation.
    /// The default impl materialises via [`Self::query`]; backends
    /// that can serve this from a secondary index override the method
    /// and advertise [`Features::FAST_NEGENTROPY`].
    fn negentropy_items(
        &self,
        filter: Filter,
    ) -> BoxFuture<'_, Result<Vec<(EventId, Timestamp)>, Error>> {
        Box::pin(async move {
            let events = self.query(filter).await?;
            Ok(events.into_iter().map(|e| (e.id, e.created_at)).collect())
        })
    }

    /// Delete every event matching `filter`.
    ///
    /// Unlike NIP-09 deletion this is an administrative operation:
    /// the backend removes the events outright and **does not**
    /// tombstone their IDs. A subsequent `save_event` of the same ID
    /// would succeed.
    fn delete(&self, filter: Filter) -> BoxFuture<'_, Result<(), Error>>;

    /// Erase the entire store, including tombstones and vanish records.
    ///
    /// Equivalent to dropping the handle and constructing a fresh one
    /// against the same backing storage, except the operation can be
    /// awaited.
    fn wipe(&self) -> BoxFuture<'_, Result<(), Error>>;
}
