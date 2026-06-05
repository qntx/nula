//! Fluent builder for [`crate::redb::RedbDatabase`].

use std::path::PathBuf;

use crate::redb::database::RedbDatabase;
use crate::redb::error::Error;
use crate::redb::options::RedbDatabaseOptions;

/// Builder for a redb-backed event store.
///
/// ```rust,no_run
/// # async fn doc() -> Result<(), Box<dyn std::error::Error>> {
/// use nula_storage::redb::RedbDatabase;
///
/// let db = RedbDatabase::builder("./data/nula.redb")
///     .cache_size_bytes(256 * 1024 * 1024) // 256 MiB page cache
///     .build()
///     .await?;
/// # let _ = db;
/// # Ok(()) }
/// ```
#[derive(Debug, Clone)]
#[must_use = "builder does nothing until `.build()` is called"]
pub struct RedbDatabaseBuilder {
    options: RedbDatabaseOptions,
}

impl RedbDatabaseBuilder {
    /// New builder anchored at the given database **file** path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            options: RedbDatabaseOptions::new(path),
        }
    }

    /// Set redb's in-memory page-cache budget in bytes. Unset by
    /// default (redb picks its own default).
    pub const fn cache_size_bytes(mut self, bytes: usize) -> Self {
        self.options.cache_size = Some(bytes);
        self
    }

    /// Whether to honour NIP-09 deletion events. On by default.
    pub const fn process_nip09(mut self, enabled: bool) -> Self {
        self.options.process_nip09 = enabled;
        self
    }

    /// Whether to honour NIP-62 vanish events. On by default.
    pub const fn process_nip62(mut self, enabled: bool) -> Self {
        self.options.process_nip62 = enabled;
        self
    }

    /// Finalise the builder and open the redb database.
    ///
    /// The file open + table creation runs on a blocking task so the
    /// call site stays cooperative.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] when the parent directory cannot be
    /// created, and [`Error::Redb`] for any redb-level failure.
    pub async fn build(self) -> Result<RedbDatabase, Error> {
        RedbDatabase::open(self.options).await
    }
}
