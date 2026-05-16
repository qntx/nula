//! Fluent builder for [`crate::MemoryDatabase`].
//!
//! The builder is re-exported from the crate root, so callers reach
//! it through `nula_storage_memory::MemoryDatabaseBuilder` without
//! ever touching this module directly.

use std::num::NonZeroUsize;

use crate::database::MemoryDatabase;
use crate::options::MemoryDatabaseOptions;

/// Fluent builder for [`MemoryDatabase`].
///
/// Construct a `MemoryDatabase` either with [`MemoryDatabase::new`]
/// for defaults or via this builder when you want to tune capacity or
/// NIP semantics:
///
/// ```rust
/// use std::num::NonZeroUsize;
///
/// use nula_storage_memory::MemoryDatabase;
///
/// let db = MemoryDatabase::builder()
///     .max_events(NonZeroUsize::new(10_000).expect("non-zero"))
///     .process_nip62(false)
///     .build();
/// # let _ = db;
/// ```
#[derive(Debug, Clone)]
#[must_use = "builder does nothing until `.build()` is called"]
pub struct MemoryDatabaseBuilder {
    options: MemoryDatabaseOptions,
}

impl MemoryDatabaseBuilder {
    /// New builder seeded with [`MemoryDatabaseOptions::default`].
    pub fn new() -> Self {
        Self {
            options: MemoryDatabaseOptions::default(),
        }
    }

    /// Cap the number of live events the store will retain.
    ///
    /// When the cap is reached subsequent inserts evict the oldest
    /// event by `created_at`. Tombstones (`deleted_ids`) and vanish
    /// records are **not** counted against the cap.
    pub const fn max_events(mut self, max: NonZeroUsize) -> Self {
        self.options.max_events = Some(max);
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

    /// Finalise the builder and return a [`MemoryDatabase`].
    #[must_use]
    pub fn build(self) -> MemoryDatabase {
        MemoryDatabase::with_options(self.options)
    }
}

impl Default for MemoryDatabaseBuilder {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
