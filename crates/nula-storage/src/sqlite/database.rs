//! [`SqliteDatabase`] -- the public handle.
//!
//! Pairs a vendored `SQLite` file (durable append-only event log)
//! with an in-process [`nula_storage::memory::MemoryDatabase`] (hot
//! read path + protocol enforcement).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::memory::MemoryDatabase;
use crate::{Backend, DatabaseEventStatus, Events, Features, NostrDatabase, SaveEventStatus};
use nula_core::boxed::BoxFuture;
use nula_core::event::{Event, EventId};
use nula_core::filter::Filter;
use nula_core::types::Timestamp;
use rusqlite::{Connection, params};
use tokio::task;

use crate::sqlite::codec;
use crate::sqlite::error::Error;

/// `SQLite`-backed [`NostrDatabase`].
///
/// Cheap to clone; every clone shares the same `SQLite` connection
/// and in-memory replica through `Arc`.
#[derive(Debug, Clone)]
pub struct SqliteDatabase {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    /// Hot read path. Owns every protocol rule (NIP-09, NIP-40,
    /// replaceable, addressable, NIP-62) and gates which events
    /// earn a `SQLite` write.
    memory: MemoryDatabase,
    /// Single connection wrapped in a `std::sync::Mutex` so calls
    /// across `&self` serialise. The lock is acquired only inside
    /// `spawn_blocking` closures, so the guard never crosses an
    /// `await` point.
    connection: Arc<Mutex<Connection>>,
    /// Resolved on-disk path (or `:memory:`) for diagnostics.
    path: PathBuf,
}

impl SqliteDatabase {
    /// Open or create a `SQLite` database at `path` and replay
    /// every stored event into a fresh in-memory replica.
    ///
    /// # Errors
    ///
    /// Propagates [`rusqlite::Error`] from the open / migration path
    /// and [`postcard::Error`] from any corrupted payload.
    pub async fn open<P>(path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref().to_path_buf();
        Self::build(SqliteSource::Path(path)).await
    }

    /// Open an in-memory `SQLite` database. Events vanish on drop
    /// -- useful for tests.
    ///
    /// # Errors
    ///
    /// Same surface as [`Self::open`].
    pub async fn open_in_memory() -> Result<Self, Error> {
        Self::build(SqliteSource::Memory).await
    }

    async fn build(source: SqliteSource) -> Result<Self, Error> {
        let (path, conn) = task::spawn_blocking(move || -> Result<(PathBuf, Connection), Error> {
            let (path, conn) = match source {
                SqliteSource::Path(path) => {
                    if let Some(dir) = path.parent()
                        && !dir.as_os_str().is_empty()
                    {
                        std::fs::create_dir_all(dir)?;
                    }
                    let conn = Connection::open(&path)?;
                    (path, conn)
                }
                SqliteSource::Memory => (PathBuf::from(":memory:"), Connection::open_in_memory()?),
            };
            init_schema(&conn)?;
            Ok((path, conn))
        })
        .await??;

        let memory = MemoryDatabase::new();
        let connection = Arc::new(Mutex::new(conn));
        replay(&connection, &memory).await?;

        Ok(Self {
            inner: Arc::new(Inner {
                memory,
                connection,
                path,
            }),
        })
    }

    /// Path the `SQLite` file lives at, or `":memory:"` for an
    /// in-memory database.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.inner.path
    }

    /// Number of events currently in the in-memory replica. Cheap;
    /// runs against the in-process index, not `SQLite`.
    #[must_use]
    pub fn cached_len(&self) -> usize {
        self.inner.memory.len()
    }
}

/// Internal: where the connection is rooted.
enum SqliteSource {
    /// On-disk file. Created if missing.
    Path(PathBuf),
    /// `:memory:` database, dropped with the handle.
    Memory,
}

fn init_schema(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.pragma_update(None, "journal_mode", "WAL").ok();
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS events (
            id BLOB PRIMARY KEY NOT NULL CHECK(length(id) = 32),
            payload BLOB NOT NULL
        ) WITHOUT ROWID;",
    )?;
    Ok(())
}

async fn replay(connection: &Arc<Mutex<Connection>>, memory: &MemoryDatabase) -> Result<(), Error> {
    let conn_clone = Arc::clone(connection);
    let payloads: Vec<Vec<u8>> = task::spawn_blocking(move || -> Result<_, Error> {
        let conn = conn_clone
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut stmt = conn.prepare("SELECT payload FROM events")?;
        let mut rows = stmt.query([])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let payload: Vec<u8> = row.get(0)?;
            out.push(payload);
        }
        Ok(out)
    })
    .await??;
    for payload in payloads {
        let event = codec::decode(&payload)?;
        // The memory replica enforces every protocol rule. Replay
        // failures (Rejected) are silently dropped: the SQLite log
        // may carry events that an out-of-order replay temporarily
        // rejects (e.g. a duplicate of an already-replaced version),
        // and the Memory backend's behaviour stays consistent with a
        // freshly running process.
        memory.save_event(&event).await.ok();
    }
    Ok(())
}

impl NostrDatabase for SqliteDatabase {
    fn backend(&self) -> Backend {
        Backend::Sqlite
    }

    fn features(&self) -> Features {
        self.inner.memory.features()
    }

    fn save_event<'a>(
        &'a self,
        event: &'a Event,
    ) -> BoxFuture<'a, Result<SaveEventStatus, crate::Error>> {
        Box::pin(async move {
            let status = self.inner.memory.save_event(event).await?;
            if matches!(status, SaveEventStatus::Success) {
                let payload = codec::encode(event).map_err(map_storage_err)?;
                let event_id_bytes = event.id.as_bytes().to_vec();
                run_sql(&self.inner.connection, move |conn| {
                    conn.execute(
                        "INSERT OR REPLACE INTO events (id, payload) VALUES (?1, ?2)",
                        params![event_id_bytes, payload],
                    )?;
                    Ok(())
                })
                .await?;
            }
            Ok(status)
        })
    }

    fn check_id<'a>(
        &'a self,
        event_id: &'a EventId,
    ) -> BoxFuture<'a, Result<DatabaseEventStatus, crate::Error>> {
        self.inner.memory.check_id(event_id)
    }

    fn event_by_id<'a>(
        &'a self,
        event_id: &'a EventId,
    ) -> BoxFuture<'a, Result<Option<Event>, crate::Error>> {
        self.inner.memory.event_by_id(event_id)
    }

    fn count(&self, filter: Filter) -> BoxFuture<'_, Result<usize, crate::Error>> {
        self.inner.memory.count(filter)
    }

    fn query(&self, filter: Filter) -> BoxFuture<'_, Result<Events, crate::Error>> {
        self.inner.memory.query(filter)
    }

    fn negentropy_items(
        &self,
        filter: Filter,
    ) -> BoxFuture<'_, Result<Vec<(EventId, Timestamp)>, crate::Error>> {
        self.inner.memory.negentropy_items(filter)
    }

    fn delete(&self, filter: Filter) -> BoxFuture<'_, Result<(), crate::Error>> {
        Box::pin(async move {
            // Snapshot the matching event ids from the memory replica
            // before delegating the in-memory delete, so we know
            // exactly which SQLite rows to drop.
            let matched = self.inner.memory.query(filter.clone()).await?;
            let ids: Vec<Vec<u8>> = matched.iter().map(|e| e.id.as_bytes().to_vec()).collect();

            self.inner.memory.delete(filter).await?;

            if !ids.is_empty() {
                run_sql(&self.inner.connection, move |conn| {
                    let mut stmt = conn.prepare_cached("DELETE FROM events WHERE id = ?1")?;
                    for id in ids {
                        stmt.execute(params![id])?;
                    }
                    Ok(())
                })
                .await?;
            }
            Ok(())
        })
    }

    fn wipe(&self) -> BoxFuture<'_, Result<(), crate::Error>> {
        Box::pin(async move {
            self.inner.memory.wipe().await?;
            run_sql(&self.inner.connection, |conn| {
                conn.execute_batch("DELETE FROM events")?;
                Ok(())
            })
            .await?;
            Ok(())
        })
    }
}

/// Run a blocking SQL closure against the shared connection on the
/// blocking pool. Centralises the `Arc::clone` + `spawn_blocking` +
/// `MutexGuard` boilerplate every mutating trait method shares.
async fn run_sql<F>(conn: &Arc<Mutex<Connection>>, op: F) -> Result<(), crate::Error>
where
    F: FnOnce(&Connection) -> Result<(), Error> + Send + 'static,
{
    let conn = Arc::clone(conn);
    task::spawn_blocking(move || -> Result<(), Error> {
        let guard = conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        op(&guard)
    })
    .await
    .map_err(|e| map_storage_err(Error::from(e)))?
    .map_err(map_storage_err)
}

fn map_storage_err(e: Error) -> crate::Error {
    crate::Error::Backend(Box::new(e))
}
