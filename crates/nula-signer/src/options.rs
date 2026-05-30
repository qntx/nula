//! Tunables for [`crate::NostrConnect`].

use std::time::Duration;

/// Defaults captured as named constants so the [`Default`] impl and
/// the module-level docs cannot drift.
mod defaults {
    use std::time::Duration;

    /// 60 seconds for every RPC call. Bunkers vary widely in
    /// responsiveness (especially when they prompt the user); 60s is
    /// a generous-but-not-infinite ceiling.
    pub(super) const TIMEOUT: Duration = Duration::from_mins(1);

    /// 5 seconds is enough for the in-memory channel handoff to
    /// complete on every realistic deployment. Anything longer
    /// indicates the dispatcher actor itself is wedged.
    pub(super) const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
}

/// Aggregate configuration for [`crate::NostrConnect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NostrConnectOptions {
    /// Maximum wall-clock time to wait for any single RPC reply.
    pub timeout: Duration,
    /// How long [`crate::NostrConnect::shutdown`] gives the
    /// dispatcher actor to drain pending RPCs before forcefully
    /// aborting it.
    pub shutdown_grace: Duration,
}

impl Default for NostrConnectOptions {
    fn default() -> Self {
        Self {
            timeout: defaults::TIMEOUT,
            shutdown_grace: defaults::SHUTDOWN_GRACE,
        }
    }
}

impl NostrConnectOptions {
    /// Construct with all defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the per-call timeout.
    #[must_use]
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Override the shutdown drain grace.
    #[must_use]
    pub const fn shutdown_grace(mut self, grace: Duration) -> Self {
        self.shutdown_grace = grace;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let opts = NostrConnectOptions::new();
        assert_eq!(opts.timeout, Duration::from_mins(1));
        assert_eq!(opts.shutdown_grace, Duration::from_secs(5));
    }

    #[test]
    fn fluent_overrides_apply() {
        let opts = NostrConnectOptions::new()
            .timeout(Duration::from_millis(500))
            .shutdown_grace(Duration::from_millis(100));
        assert_eq!(opts.timeout, Duration::from_millis(500));
        assert_eq!(opts.shutdown_grace, Duration::from_millis(100));
    }
}
