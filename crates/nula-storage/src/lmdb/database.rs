//! Public [`LmdbDatabase`] handle.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use flume::Sender;
use nula_core::boxed::BoxFuture;
use nula_core::event::{Event, EventId};
use nula_core::filter::Filter;
use nula_core::types::Timestamp;
use tokio::sync::oneshot;

use crate::lmdb::builder::LmdbDatabaseBuilder;
use crate::lmdb::error::Error;
use crate::lmdb::ingester::{self, IngestCmd};
use crate::lmdb::options::LmdbDatabaseOptions;
use crate::lmdb::store::Store;
use crate::{
    Backend, DatabaseEventStatus, Error as StorageError, Events, Features, NostrDatabase,
    SaveEventStatus,
};

/// Persistent LMDB-backed [`NostrDatabase`].
///
/// Cloning the handle is `Arc`-cheap; every clone shares the same
/// LMDB environment and the same single-writer ingester thread.
/// Dropping the last clone sends a `Shutdown` command to the
/// ingester and joins the thread.
#[derive(Debug, Clone)]
pub struct LmdbDatabase {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    store: Store,
    ingester_tx: Sender<IngestCmd>,
    ingester_handle: Mutex<Option<JoinHandle<()>>>,
}

impl LmdbDatabase {
    /// Start the fluent builder anchored at `path`.
    pub fn builder(path: impl Into<PathBuf>) -> LmdbDatabaseBuilder {
        LmdbDatabaseBuilder::new(path)
    }

    /// Open an LMDB-backed store with the supplied options.
    ///
    /// # Errors
    ///
    /// See [`Error`].
    pub async fn open(options: LmdbDatabaseOptions) -> Result<Self, Error> {
        let store = tokio::task::spawn_blocking(move || Store::open(options)).await??;
        let (ingester_tx, handle) = ingester::spawn(store.clone());
        Ok(Self {
            inner: Arc::new(Inner {
                store,
                ingester_tx,
                ingester_handle: Mutex::new(Some(handle)),
            }),
        })
    }

    async fn send_save(&self, event: Event) -> Result<SaveEventStatus, Error> {
        let (reply, rx) = oneshot::channel();
        self.inner
            .ingester_tx
            .send(IngestCmd::Save { event, reply })
            .map_err(|_| Error::WriterGone)?;
        rx.await.map_err(|_| Error::WriterGone)?
    }

    async fn send_delete(&self, filter: Filter) -> Result<(), Error> {
        let (reply, rx) = oneshot::channel();
        self.inner
            .ingester_tx
            .send(IngestCmd::Delete { filter, reply })
            .map_err(|_| Error::WriterGone)?;
        rx.await.map_err(|_| Error::WriterGone)?
    }

    async fn send_wipe(&self) -> Result<(), Error> {
        let (reply, rx) = oneshot::channel();
        self.inner
            .ingester_tx
            .send(IngestCmd::Wipe { reply })
            .map_err(|_| Error::WriterGone)?;
        rx.await.map_err(|_| Error::WriterGone)?
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Best-effort: ask the ingester to exit cleanly.
        let (reply, _rx) = oneshot::channel();
        if self.ingester_tx.send(IngestCmd::Shutdown { reply }).is_ok()
            && let Some(handle) = self.ingester_handle.lock().ok().and_then(|mut g| g.take())
        {
            // Join the writer thread so the LMDB env is closed
            // before the directory may be removed by the caller.
            // join() returns Result<(), Box<dyn Any>>; we discard
            // it since the worker either exited cleanly or
            // panicked, and we cannot do anything useful with the
            // panic payload during Drop.
            drop(handle.join());
        }
    }
}

impl NostrDatabase for LmdbDatabase {
    fn backend(&self) -> Backend {
        Backend::Lmdb
    }

    fn features(&self) -> Features {
        Features::PERSISTENT
    }

    fn save_event<'a>(
        &'a self,
        event: &'a Event,
    ) -> BoxFuture<'a, Result<SaveEventStatus, StorageError>> {
        let event = event.clone();
        Box::pin(async move { self.send_save(event).await.map_err(StorageError::from) })
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
    // match projection, so reconciliation never pays the secp pubkey
    // parse or content/tag allocation per event.
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
        Box::pin(async move { self.send_delete(filter).await.map_err(StorageError::from) })
    }

    fn wipe(&self) -> BoxFuture<'_, Result<(), StorageError>> {
        Box::pin(async move { self.send_wipe().await.map_err(StorageError::from) })
    }
}
