//! Tunables for [`crate::Relay`] — connection mode, reconnect, and
//! per-call defaults.

use std::time::Duration;

use crate::transport::ConnectionMode;

use crate::limits::RelayLimits;
use crate::policy::ReconnectPolicy;

/// Defaults that match what hosted relays expect in practice. Move
/// the constants into a single place so the `Default` impl and the
/// builder's getters stay in sync.
mod defaults {
    use std::time::Duration;

    /// 30 s connect deadline. Anything longer is almost always a
    /// firewall / DNS sinkhole rather than a slow relay.
    pub(super) const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

    /// 60 s publish ack window. Most relays reply within ~50 ms;
    /// the long tail covers IBC-style relay chains.
    pub(super) const PUBLISH_TIMEOUT: Duration = Duration::from_mins(1);
}

/// Configuration for a [`crate::Relay`] instance.
///
/// Construct via [`Self::new`] and chain method calls, or hand to
/// [`crate::RelayBuilder::options`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayOptions {
    /// How the underlying transport should reach the relay (direct,
    /// proxy, …). Mirrors [`nula_relay::transport::ConnectionMode`].
    pub connection_mode: ConnectionMode,

    /// What to do when the connection drops. Defaults to AWS-style
    /// full-jitter exponential backoff.
    pub reconnect_policy: ReconnectPolicy,

    /// Maximum time to wait for a single connect attempt before
    /// surfacing [`crate::Error::ConnectTimeout`]. Independent of
    /// the reconnect timer — exceeding this cancels the in-flight
    /// connect and triggers the next backoff cycle.
    pub connect_timeout: Duration,

    /// Default deadline for [`crate::Relay::publish`] when the
    /// caller does not override it via
    /// [`crate::PublishOptions::timeout`].
    pub publish_timeout: Duration,

    /// Per-relay protocol caps (max message size, …).
    pub limits: RelayLimits,
}

impl Default for RelayOptions {
    fn default() -> Self {
        Self {
            connection_mode: ConnectionMode::Direct,
            reconnect_policy: ReconnectPolicy::default(),
            connect_timeout: defaults::CONNECT_TIMEOUT,
            publish_timeout: defaults::PUBLISH_TIMEOUT,
            limits: RelayLimits::new(),
        }
    }
}

impl RelayOptions {
    /// Construct with all defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the connection mode.
    #[must_use]
    pub const fn connection_mode(mut self, mode: ConnectionMode) -> Self {
        self.connection_mode = mode;
        self
    }

    /// Override the reconnect policy. Pass [`ReconnectPolicy::Never`]
    /// to disable automatic reconnection altogether.
    #[must_use]
    pub const fn reconnect_policy(mut self, policy: ReconnectPolicy) -> Self {
        self.reconnect_policy = policy;
        self
    }

    /// Override the per-attempt connect timeout.
    #[must_use]
    pub const fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Override the default publish ack window.
    #[must_use]
    pub const fn publish_timeout(mut self, timeout: Duration) -> Self {
        self.publish_timeout = timeout;
        self
    }

    /// Override the protocol caps.
    #[must_use]
    pub const fn limits(mut self, limits: RelayLimits) -> Self {
        self.limits = limits;
        self
    }
}

/// Per-call options for [`crate::Relay::subscribe`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SubscribeOptions {
    /// When `true`, the [`crate::SubscriptionHandle`] yields the
    /// `Eose` item once and closes itself. Equivalent to a one-shot
    /// historical query.
    pub close_on_eose: bool,
}

impl SubscribeOptions {
    /// Default subscription: stays open after EOSE so the caller can
    /// receive live events.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            close_on_eose: false,
        }
    }

    /// Auto-close the subscription after the relay sends EOSE. Use
    /// this for one-shot historical queries.
    #[must_use]
    pub const fn close_on_eose(mut self, value: bool) -> Self {
        self.close_on_eose = value;
        self
    }
}

/// Per-call options for [`crate::Relay::publish`].
///
/// Publishing while disconnected always fails fast with
/// [`crate::Error::NotConnected`]; cross-connection retries belong
/// in the relay-pool layer where multiple endpoints can share work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PublishOptions {
    /// Override the default [`RelayOptions::publish_timeout`] for
    /// this single call. `None` means "use the relay default".
    pub timeout: Option<Duration>,
}

impl PublishOptions {
    /// Default: use the relay's `publish_timeout`.
    #[must_use]
    pub const fn new() -> Self {
        Self { timeout: None }
    }

    /// Override the publish timeout for this single call.
    #[must_use]
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}
