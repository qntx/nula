//! Configuration for [`crate::redb::RedbDatabase`].

use std::path::PathBuf;

/// Tunable knobs for [`crate::redb::RedbDatabase`].
///
/// The struct is `#[non_exhaustive]`; build it through
/// [`crate::redb::RedbDatabaseBuilder`] rather than the field-style
/// constructor.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RedbDatabaseOptions {
    /// Path to the redb database **file** (redb stores a single file,
    /// unlike LMDB's directory). Created if it does not exist; the
    /// parent directory is created on open.
    pub path: PathBuf,

    /// In-memory page-cache budget in bytes. `None` lets redb pick its
    /// default. A larger cache trades RAM for fewer page reads on
    /// large stores.
    pub cache_size: Option<usize>,

    /// Whether to honour NIP-09 deletion events.
    pub process_nip09: bool,

    /// Whether to honour NIP-62 vanish events.
    pub process_nip62: bool,
}

impl RedbDatabaseOptions {
    /// Construct options anchored at `path` with safe defaults.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            cache_size: None,
            process_nip09: true,
            process_nip62: true,
        }
    }
}
