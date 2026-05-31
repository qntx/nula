//! Tunables for [`crate::NostrWalletConnect`].

use std::time::Duration;

use nula_core::nips::nip47::Encryption;

/// Defaults captured as named constants so the [`Default`] impl and the
/// docs cannot drift.
mod defaults {
    use std::time::Duration;

    /// 30 seconds per RPC. Wallet services answer most calls quickly,
    /// but `pay_invoice` may wait on Lightning routing.
    pub(super) const TIMEOUT: Duration = Duration::from_secs(30);

    /// Buffer depth for the notification broadcast channel. A slow
    /// consumer that lags past this many notifications will observe a
    /// `Lagged` error and resync rather than stalling the dispatcher.
    pub(super) const NOTIFICATION_BUFFER: usize = 256;
}

/// Aggregate configuration for [`crate::NostrWalletConnect`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NwcOptions {
    /// Maximum wall-clock time to wait for any single RPC reply.
    pub timeout: Duration,
    /// Encryption scheme used for every request body.
    ///
    /// Defaults to [`Encryption::Nip44V2`] — the spec-mandated modern
    /// scheme that every current wallet service supports. Set to
    /// [`Encryption::Nip04`] only when targeting a legacy wallet whose
    /// `kind:13194` info event omits the `encryption` tag. Callers can
    /// confirm support up front with
    /// [`crate::NostrWalletConnect::get_info_event`].
    pub encryption: Encryption,
    /// Depth of the notification broadcast buffer.
    pub notification_buffer: usize,
}

impl Default for NwcOptions {
    fn default() -> Self {
        Self {
            timeout: defaults::TIMEOUT,
            encryption: Encryption::Nip44V2,
            notification_buffer: defaults::NOTIFICATION_BUFFER,
        }
    }
}

impl NwcOptions {
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

    /// Override the request encryption scheme.
    #[must_use]
    pub const fn encryption(mut self, encryption: Encryption) -> Self {
        self.encryption = encryption;
        self
    }

    /// Override the notification broadcast buffer depth.
    #[must_use]
    pub const fn notification_buffer(mut self, buffer: usize) -> Self {
        self.notification_buffer = buffer;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let opts = NwcOptions::new();
        assert_eq!(opts.timeout, Duration::from_secs(30));
        assert_eq!(opts.encryption, Encryption::Nip44V2);
        assert_eq!(opts.notification_buffer, 256);
    }

    #[test]
    fn fluent_overrides_apply() {
        let opts = NwcOptions::new()
            .timeout(Duration::from_secs(5))
            .encryption(Encryption::Nip04)
            .notification_buffer(16);
        assert_eq!(opts.timeout, Duration::from_secs(5));
        assert_eq!(opts.encryption, Encryption::Nip04);
        assert_eq!(opts.notification_buffer, 16);
    }
}
