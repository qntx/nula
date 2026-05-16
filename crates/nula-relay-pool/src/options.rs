//! Tunables for [`crate::RelayPool`].

use std::num::NonZeroUsize;

/// Defaults captured as named constants so the [`Default`] impl and
/// the module-level docs cannot drift.
mod defaults {
    use std::num::NonZeroUsize;

    /// 4096 in-flight pool notifications. Plenty of headroom for the
    /// status / notice traffic of even a 50-relay pool while keeping
    /// the worst-case memory bound predictable. Slow consumers get
    /// `RecvError::Lagged` rather than back-pressuring the pool.
    pub(super) const NOTIFICATION_CHANNEL_SIZE: NonZeroUsize =
        NonZeroUsize::new(4096).expect("4096 != 0");

    /// 100 000 distinct `EventId`s remembered for cross-relay
    /// dedup. At ~64 B per entry the LRU caps at ~6 MiB, which is
    /// still a rounding error compared to the underlying event
    /// payloads.
    pub(super) const DEDUP_CACHE_SIZE: NonZeroUsize =
        NonZeroUsize::new(100_000).expect("100_000 != 0");
}

/// Configuration for a [`crate::RelayPool`] instance.
///
/// Construct via [`Self::new`] and chain method calls, or hand the
/// fully-populated struct to [`crate::RelayPoolBuilder::options`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayPoolOptions {
    /// Hard cap on the number of relays the pool will hold. `None`
    /// means unlimited. Hitting the cap surfaces
    /// [`crate::Error::TooManyRelays`].
    pub max_relays: Option<NonZeroUsize>,

    /// Buffer size for the [`crate::PoolNotification`] broadcast
    /// channel. A slow consumer receives `RecvError::Lagged` once
    /// the buffer fills, dropping the oldest notifications first.
    pub notification_channel_size: NonZeroUsize,

    /// Maximum number of distinct `EventId`s remembered by the
    /// cross-relay dedup cache used by
    /// [`crate::RelayPool::stream_events`]. Older entries fall out
    /// in LRU order once the cache is full.
    pub dedup_cache_size: NonZeroUsize,

    /// When `true` the pool calls
    /// [`nula_storage::NostrDatabase::save_event`] for every event
    /// that flows through [`crate::RelayPool::stream_events`]. The
    /// hook runs after the cross-relay dedup gate so each unique
    /// event is persisted at most once. Failures are swallowed (the
    /// event is still observable on the returned stream).
    pub auto_save_events: bool,
}

impl Default for RelayPoolOptions {
    fn default() -> Self {
        Self {
            max_relays: None,
            notification_channel_size: defaults::NOTIFICATION_CHANNEL_SIZE,
            dedup_cache_size: defaults::DEDUP_CACHE_SIZE,
            auto_save_events: true,
        }
    }
}

impl RelayPoolOptions {
    /// Construct with all defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the relay count cap. Pass `None` for no limit.
    #[must_use]
    pub const fn max_relays(mut self, max: Option<NonZeroUsize>) -> Self {
        self.max_relays = max;
        self
    }

    /// Override the broadcast channel buffer size.
    #[must_use]
    pub const fn notification_channel_size(mut self, size: NonZeroUsize) -> Self {
        self.notification_channel_size = size;
        self
    }

    /// Override the cross-relay dedup cache size.
    #[must_use]
    pub const fn dedup_cache_size(mut self, size: NonZeroUsize) -> Self {
        self.dedup_cache_size = size;
        self
    }

    /// Override the auto-save behaviour.
    #[must_use]
    pub const fn auto_save_events(mut self, value: bool) -> Self {
        self.auto_save_events = value;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let opts = RelayPoolOptions::new();
        assert!(opts.max_relays.is_none());
        assert_eq!(opts.notification_channel_size.get(), 4096);
        assert_eq!(opts.dedup_cache_size.get(), 100_000);
        assert!(opts.auto_save_events);
    }

    #[test]
    fn fluent_overrides_apply() {
        let opts = RelayPoolOptions::new()
            .max_relays(Some(NonZeroUsize::new(16).expect("16 != 0")))
            .notification_channel_size(NonZeroUsize::new(64).expect("64 != 0"))
            .dedup_cache_size(NonZeroUsize::new(1024).expect("1024 != 0"))
            .auto_save_events(false);

        assert_eq!(opts.max_relays.map(NonZeroUsize::get), Some(16));
        assert_eq!(opts.notification_channel_size.get(), 64);
        assert_eq!(opts.dedup_cache_size.get(), 1024);
        assert!(!opts.auto_save_events);
    }
}
