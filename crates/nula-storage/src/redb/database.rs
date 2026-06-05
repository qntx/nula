//! Public [`RedbDatabase`] handle.

use std::path::PathBuf;
use std::sync::Arc;

use nula_core::boxed::BoxFuture;
use nula_core::event::{Event, EventId};
use nula_core::filter::Filter;
use nula_core::types::Timestamp;

use crate::redb::builder::RedbDatabaseBuilder;
use crate::redb::error::Error;
use crate::redb::options::RedbDatabaseOptions;
use crate::redb::store::Store;
use crate::{
    Backend, DatabaseEventStatus, Error as StorageError, Events, Features, NostrDatabase,
    SaveEventStatus,
};

/// Persistent redb-backed [`NostrDatabase`].
///
/// Cloning the handle is `Arc`-cheap; every clone shares the same redb
/// database. redb's MVCC engine serialises writers internally, so reads
/// and writes both run on tokio's blocking pool with no dedicated
/// writer thread.
#[derive(Debug, Clone)]
pub struct RedbDatabase {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    store: Store,
}

impl RedbDatabase {
    /// Start the fluent builder anchored at `path` (the database file).
    pub fn builder(path: impl Into<PathBuf>) -> RedbDatabaseBuilder {
        RedbDatabaseBuilder::new(path)
    }

    /// Open a redb-backed store with the supplied options.
    ///
    /// # Errors
    ///
    /// See [`Error`].
    pub async fn open(options: RedbDatabaseOptions) -> Result<Self, Error> {
        let store = tokio::task::spawn_blocking(move || Store::open(options)).await??;
        Ok(Self {
            inner: Arc::new(Inner { store }),
        })
    }
}

impl NostrDatabase for RedbDatabase {
    fn backend(&self) -> Backend {
        Backend::Redb
    }

    fn features(&self) -> Features {
        Features::PERSISTENT
    }

    fn save_event<'a>(
        &'a self,
        event: &'a Event,
    ) -> BoxFuture<'a, Result<SaveEventStatus, StorageError>> {
        let event = event.clone();
        let store = self.inner.store.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let now = Timestamp::now()
                    .map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;
                store.save_event(&event, now)
            })
            .await
            .map_err(|e| StorageError::backend(Error::from(e)))?
            .map_err(StorageError::from)
        })
    }

    fn check_id<'a>(
        &'a self,
        event_id: &'a EventId,
    ) -> BoxFuture<'a, Result<DatabaseEventStatus, StorageError>> {
        let id = *event_id;
        let store = self.inner.store.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || store.check_id(&id))
                .await
                .map_err(|e| StorageError::backend(Error::from(e)))?
                .map_err(StorageError::from)
        })
    }

    fn event_by_id<'a>(
        &'a self,
        event_id: &'a EventId,
    ) -> BoxFuture<'a, Result<Option<Event>, StorageError>> {
        let id = *event_id;
        let store = self.inner.store.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || store.event_by_id(&id))
                .await
                .map_err(|e| StorageError::backend(Error::from(e)))?
                .map_err(StorageError::from)
        })
    }

    fn count(&self, filter: Filter) -> BoxFuture<'_, Result<usize, StorageError>> {
        let store = self.inner.store.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || store.count(&filter))
                .await
                .map_err(|e| StorageError::backend(Error::from(e)))?
                .map_err(StorageError::from)
        })
    }

    // Override the trait default (which materialises every match via
    // `query`): the store serves negentropy items from the zero-parse
    // match projection, so reconciliation never pays the curve pubkey
    // parse or content / tag allocation per event.
    fn negentropy_items(
        &self,
        filter: Filter,
    ) -> BoxFuture<'_, Result<Vec<(EventId, Timestamp)>, StorageError>> {
        let store = self.inner.store.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || store.negentropy_items(&filter))
                .await
                .map_err(|e| StorageError::backend(Error::from(e)))?
                .map_err(StorageError::from)
        })
    }

    fn query(&self, filter: Filter) -> BoxFuture<'_, Result<Events, StorageError>> {
        let store = self.inner.store.clone();
        Box::pin(async move {
            let events = tokio::task::spawn_blocking(move || store.query(&filter))
                .await
                .map_err(|e| StorageError::backend(Error::from(e)))?
                .map_err(StorageError::from)?;
            Ok(Events::from_unsorted(events))
        })
    }

    fn delete(&self, filter: Filter) -> BoxFuture<'_, Result<(), StorageError>> {
        let store = self.inner.store.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || store.delete_matching(&filter))
                .await
                .map_err(|e| StorageError::backend(Error::from(e)))?
                .map_err(StorageError::from)
        })
    }

    fn wipe(&self) -> BoxFuture<'_, Result<(), StorageError>> {
        let store = self.inner.store.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || store.wipe())
                .await
                .map_err(|e| StorageError::backend(Error::from(e)))?
                .map_err(StorageError::from)
        })
    }
}
