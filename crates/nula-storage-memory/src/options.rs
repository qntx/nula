//! Configuration for [`crate::MemoryDatabase`].
//!
//! The defaults match a "typical relay client" profile: NIP-09
//! deletion is honoured, NIP-62 vanish is honoured, and there is no
//! upper bound on the number of events the store will keep.

use std::num::NonZeroUsize;

/// Tunable knobs for the in-memory backend.
///
/// All fields have safe defaults; the builder pattern is preferred over
/// constructing the struct literal so the option set can grow without
/// breaking callers (the struct is `#[non_exhaustive]`).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct MemoryDatabaseOptions {
    /// Maximum number of live (non-tombstoned) events to retain.
    ///
    /// When the store is at capacity and a new event is accepted, the
    /// oldest event by `created_at` is evicted. `None` disables the
    /// cap, which is the default.
    pub max_events: Option<NonZeroUsize>,

    /// Whether to honour NIP-09 deletion events.
    ///
    /// When `true`, kind-5 events delete the targeted IDs / addressable
    /// coordinates and tombstone them so subsequent inserts of the same
    /// ID are rejected with [`nula_storage::RejectedReason::Deleted`].
    /// When `false`, kind-5 events are stored as regular events.
    pub process_nip09: bool,

    /// Whether to honour NIP-62 vanish requests.
    ///
    /// When `true`, a kind-62 event from `author` causes every later
    /// insert from `author` to be rejected with
    /// [`nula_storage::RejectedReason::Vanished`]. When `false`,
    /// kind-62 events are stored as regular events.
    pub process_nip62: bool,
}

impl MemoryDatabaseOptions {
    /// Construct the default option set (NIP-09 + NIP-62 enabled, no
    /// capacity cap).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_events: None,
            process_nip09: true,
            process_nip62: true,
        }
    }

    /// Set the maximum number of live events the store will retain.
    ///
    /// Pass `Some(NonZeroUsize::new(N).unwrap())` to enable bounded
    /// capacity with eviction; pass `None` for unbounded storage.
    #[must_use]
    pub const fn with_max_events(mut self, max: Option<NonZeroUsize>) -> Self {
        self.max_events = max;
        self
    }

    /// Toggle NIP-09 deletion processing.
    #[must_use]
    pub const fn with_process_nip09(mut self, enabled: bool) -> Self {
        self.process_nip09 = enabled;
        self
    }

    /// Toggle NIP-62 vanish processing.
    #[must_use]
    pub const fn with_process_nip62(mut self, enabled: bool) -> Self {
        self.process_nip62 = enabled;
        self
    }
}

impl Default for MemoryDatabaseOptions {
    /// Equivalent to [`MemoryDatabaseOptions::new`].
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
