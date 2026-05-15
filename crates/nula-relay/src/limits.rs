//! Per-relay protocol limits enforced by [`crate::Relay`].
//!
//! These limits are purely caller-driven safeguards — relays may
//! still send payloads up to whatever the WebSocket frame limit
//! allows. The values below let the caller refuse to deliver an
//! oversized frame to upper layers (and refuse to even attempt
//! publishing an oversized event).

/// Per-relay caps on protocol object sizes.
///
/// Values are deliberately generous; the spec sets no hard maximum
/// and operators trade strictness for compatibility on a per-relay
/// basis. Set tighter caps via
/// [`RelayOptions::limits`](crate::RelayOptions::limits) and feed
/// the result through [`RelayBuilder::options`](crate::RelayBuilder::options)
/// when running in embedded environments with strict memory
/// budgets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayLimits {
    /// Maximum size, in bytes, of a single inbound JSON message
    /// (`["EVENT", …]`, `["NOTICE", …]`, …). Frames larger than this
    /// are dropped with a `tracing::warn!` event and the connection
    /// is left intact.
    pub max_message_bytes: usize,

    /// Maximum number of in-flight subscriptions. Subscribe calls
    /// over this cap fail with [`crate::Error::TooManySubscriptions`].
    /// Default `512` matches what relay.damus.io and several large
    /// hosted relays accept in practice.
    pub max_subscriptions: usize,

    /// Maximum number of distinct in-flight publish acks the relay
    /// will track. Publish calls beyond this cap fail with
    /// [`crate::Error::TooManyPendingPublishes`]. Defaults to `1024`.
    pub max_pending_publishes: usize,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            max_message_bytes: 5 * 1024 * 1024, // 5 MiB
            max_subscriptions: 512,
            max_pending_publishes: 1024,
        }
    }
}

impl RelayLimits {
    /// Construct with all defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the maximum inbound message size.
    #[must_use]
    pub const fn max_message_bytes(mut self, bytes: usize) -> Self {
        self.max_message_bytes = bytes;
        self
    }

    /// Override the maximum number of concurrent subscriptions.
    #[must_use]
    pub const fn max_subscriptions(mut self, n: usize) -> Self {
        self.max_subscriptions = n;
        self
    }

    /// Override the maximum number of in-flight publishes.
    #[must_use]
    pub const fn max_pending_publishes(mut self, n: usize) -> Self {
        self.max_pending_publishes = n;
        self
    }
}
