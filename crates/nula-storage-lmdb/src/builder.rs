//! Fluent builder for [`crate::LmdbDatabase`].

use std::num::NonZeroU32;
use std::path::PathBuf;

use crate::database::LmdbDatabase;
use crate::error::Error;
use crate::options::LmdbDatabaseOptions;

/// Builder for an LMDB-backed event store.
///
/// ```rust,no_run
/// # async fn doc() -> Result<(), Box<dyn std::error::Error>> {
/// use nula_storage_lmdb::LmdbDatabase;
///
/// let db = LmdbDatabase::builder("./data/nula")
///     .map_size_bytes(2 * 1024 * 1024 * 1024) // 2 GiB
///     .build()
///     .await?;
/// # let _ = db;
/// # Ok(()) }
/// ```
#[derive(Debug, Clone)]
#[must_use = "builder does nothing until `.build()` is called"]
pub struct LmdbDatabaseBuilder {
    options: LmdbDatabaseOptions,
}

impl LmdbDatabaseBuilder {
    /// New builder anchored at the given on-disk directory.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            options: LmdbDatabaseOptions::new(path),
        }
    }

    /// Set the LMDB map size in bytes. The default is platform-
    /// dependent (1 GiB on 64-bit, 256 MiB on 32-bit).
    pub const fn map_size_bytes(mut self, bytes: usize) -> Self {
        self.options.map_size = bytes;
        self
    }

    /// Maximum number of concurrent reader slots. The default is 32.
    pub const fn max_readers(mut self, slots: NonZeroU32) -> Self {
        self.options.max_readers = slots;
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

    /// Finalise the builder and open the LMDB environment.
    ///
    /// The actual `mmap` + dbi creation runs on a blocking task so
    /// the call site stays cooperative.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] when the database directory cannot be
    /// created, and [`Error::Heed`] for any LMDB-level failure.
    pub async fn build(self) -> Result<LmdbDatabase, Error> {
        LmdbDatabase::open(self.options).await
    }
}
