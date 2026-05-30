//! Public [`MemoryDatabase`] handle.
//!
//! The handle is a thin `Arc<RwLock<MemoryStore>>`; cloning is free
//! and every operation takes an explicit lock for the duration of the
//! synchronous critical section. Lock guards never cross an `await`,
//! so the futures returned by every trait method are `Send` even on
//! platforms where `std::sync::RwLockReadGuard` is not.

use std::sync::{Arc, RwLock};

use nula_core::boxed::BoxFuture;
use nula_core::event::{Event, EventId};
use nula_core::filter::Filter;
use nula_core::types::Timestamp;

use crate::memory::options::MemoryDatabaseOptions;
use crate::memory::store::MemoryStore;
use crate::{
    Backend, DatabaseEventStatus, Error, Events, Features, NostrDatabase, SaveEventStatus,
};

/// In-memory [`NostrDatabase`] backed by `BTreeMap` + `HashMap`
/// indexes.
///
/// `MemoryDatabase` is `Send + Sync + Clone`. Cloning the handle does
/// **not** clone the data — every clone shares the same backing store
/// through `Arc`.
#[derive(Debug, Clone)]
pub struct MemoryDatabase {
    inner: Arc<RwLock<MemoryStore>>,
}

impl MemoryDatabase {
    /// Construct an empty database with default options
    /// ([`MemoryDatabaseOptions::default`]).
    #[must_use]
    pub fn new() -> Self {
        Self::with_options(MemoryDatabaseOptions::default())
    }

    /// Construct an empty database with the supplied options.
    #[must_use]
    pub fn with_options(options: MemoryDatabaseOptions) -> Self {
        Self {
            inner: Arc::new(RwLock::new(MemoryStore::new(options))),
        }
    }

    /// Fluent builder. Equivalent to
    /// `MemoryDatabaseBuilder::new()` and exists so callers do not
    /// need a separate import.
    pub fn builder() -> crate::memory::builder::MemoryDatabaseBuilder {
        crate::memory::builder::MemoryDatabaseBuilder::new()
    }

    /// Current number of live (non-tombstoned) events.
    ///
    /// Useful for tests; production code rarely needs this number
    /// since the store advertises [`Features::BOUNDED_CAPACITY`] when
    /// it might evict.
    #[must_use]
    pub fn len(&self) -> usize {
        self.read(MemoryStore::len)
    }

    /// Whether the store contains no live events.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn read<R>(&self, f: impl FnOnce(&MemoryStore) -> R) -> R {
        // RwLock poison only happens if a writer panicked mid-mutation.
        // The store can no longer guarantee consistent state at that
        // point, so propagating the panic is the only correct option.
        #[allow(
            clippy::expect_used,
            reason = "poisoned MemoryStore RwLock means unrecoverable inconsistency; propagate as a panic"
        )]
        let guard = self
            .inner
            .read()
            .expect("MemoryStore RwLock is poisoned (panic in writer)");
        f(&guard)
    }

    fn write<R>(&self, f: impl FnOnce(&mut MemoryStore) -> R) -> R {
        #[allow(
            clippy::expect_used,
            reason = "poisoned MemoryStore RwLock means unrecoverable inconsistency; propagate as a panic"
        )]
        let mut guard = self
            .inner
            .write()
            .expect("MemoryStore RwLock is poisoned (panic in writer)");
        f(&mut guard)
    }
}

impl Default for MemoryDatabase {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl NostrDatabase for MemoryDatabase {
    fn backend(&self) -> Backend {
        Backend::Memory
    }

    fn features(&self) -> Features {
        let mut flags = Features::empty();
        if self.read(|s| s.options().max_events.is_some()) {
            flags |= Features::BOUNDED_CAPACITY;
        }
        flags
    }

    fn save_event<'a>(&'a self, event: &'a Event) -> BoxFuture<'a, Result<SaveEventStatus, Error>> {
        Box::pin(async move {
            // `Timestamp::now` is fallible only when the system clock
            // is before the Unix epoch; treat that as a backend error.
            let now = Timestamp::now().map_err(Error::backend)?;
            let status = self.write(|store| store.save_event(event, now));
            Ok(status)
        })
    }

    fn check_id<'a>(
        &'a self,
        event_id: &'a EventId,
    ) -> BoxFuture<'a, Result<DatabaseEventStatus, Error>> {
        Box::pin(async move { Ok(self.read(|store| store.check_id(event_id))) })
    }

    fn event_by_id<'a>(
        &'a self,
        event_id: &'a EventId,
    ) -> BoxFuture<'a, Result<Option<Event>, Error>> {
        Box::pin(async move { Ok(self.read(|store| store.event_by_id(event_id))) })
    }

    fn count(&self, filter: Filter) -> BoxFuture<'_, Result<usize, Error>> {
        Box::pin(async move { Ok(self.read(|store| store.count(&filter))) })
    }

    fn query(&self, filter: Filter) -> BoxFuture<'_, Result<Events, Error>> {
        Box::pin(async move {
            let events = self.read(|store| store.query_owned(&filter));
            Ok(Events::from_sorted(events))
        })
    }

    fn delete(&self, filter: Filter) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            self.write(|store| store.delete_matching(&filter));
            Ok(())
        })
    }

    fn wipe(&self) -> BoxFuture<'_, Result<(), Error>> {
        Box::pin(async move {
            self.write(MemoryStore::wipe);
            Ok(())
        })
    }
}
