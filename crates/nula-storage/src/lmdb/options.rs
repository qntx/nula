//! Configuration for [`crate::lmdb::LmdbDatabase`].

use std::num::NonZeroU32;
use std::path::PathBuf;

/// Default LMDB map size on 64-bit platforms: 1 GiB.
///
/// Generous enough for a per-user client without committing virtual
/// address space ten environments deep. Production deployments tune
/// via [`LmdbDatabaseOptions::map_size`].
const DEFAULT_MAP_SIZE_64: usize = 1024 * 1024 * 1024;

/// Default LMDB map size on 32-bit platforms: 256 MiB.
///
/// 32-bit address spaces cannot host the 64-bit default. The smaller
/// figure leaves headroom for the rest of the process.
#[cfg(not(target_pointer_width = "64"))]
const DEFAULT_MAP_SIZE_32: usize = 256 * 1024 * 1024;

/// Default upper bound on concurrent reader slots.
///
/// LMDB allocates this many slots in the lock file regardless of
/// actual usage. The library default of 126 is generous; we trim it
/// to 32 to keep the lock table small on resource-constrained
/// devices.
const DEFAULT_MAX_READERS: u32 = 32;

const fn default_map_size() -> usize {
    #[cfg(target_pointer_width = "64")]
    {
        DEFAULT_MAP_SIZE_64
    }
    #[cfg(not(target_pointer_width = "64"))]
    {
        DEFAULT_MAP_SIZE_32
    }
}

/// Tunable knobs for [`crate::lmdb::LmdbDatabase`].
///
/// The struct is `#[non_exhaustive]`; build it through
/// [`crate::lmdb::LmdbDatabaseBuilder`] rather than the field-style
/// constructor.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct LmdbDatabaseOptions {
    /// Directory the LMDB environment lives in. Created if it does
    /// not exist.
    pub path: PathBuf,

    /// LMDB map size in bytes. Defaults to 1 GiB on 64-bit, 256 MiB
    /// on 32-bit.
    pub map_size: usize,

    /// Maximum number of reader slots.
    pub max_readers: NonZeroU32,

    /// Whether to honour NIP-09 deletion events.
    pub process_nip09: bool,

    /// Whether to honour NIP-62 vanish events.
    pub process_nip62: bool,
}

impl LmdbDatabaseOptions {
    /// Construct options anchored at `path` with safe defaults.
    ///
    /// # Panics
    ///
    /// Never. The `expect` on `DEFAULT_MAX_READERS` is fed a
    /// compile-time `u32` whose value is enforced to be non-zero by
    /// this module, so the call is total in practice.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        #[allow(
            clippy::expect_used,
            reason = "DEFAULT_MAX_READERS is a non-zero constant"
        )]
        let max_readers = NonZeroU32::new(DEFAULT_MAX_READERS).expect("DEFAULT_MAX_READERS != 0");
        Self {
            path: path.into(),
            map_size: default_map_size(),
            max_readers,
            process_nip09: true,
            process_nip62: true,
        }
    }
}
