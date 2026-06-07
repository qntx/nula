//! Tunables for [`crate::server::MockRelay`].

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// When the relay enforces NIP-42 client authentication.
///
/// The relay offers a challenge whenever a mode other than
/// [`Self::Disabled`] is set; the mode then decides which operations
/// stay blocked until the client returns a valid signed `kind:22242`
/// event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Nip42Mode {
    /// No authentication required (the default). No challenge is sent.
    #[default]
    Disabled,
    /// Require authentication before serving reads (`REQ`, `COUNT`,
    /// NIP-77 `NEG-OPEN`). Writes (`EVENT`) are unaffected.
    Read,
    /// Require authentication before accepting writes (`EVENT`). Reads
    /// are unaffected.
    Write,
    /// Require authentication for both reads and writes.
    Both,
}

impl Nip42Mode {
    /// `true` for any mode other than [`Self::Disabled`].
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        !matches!(self, Self::Disabled)
    }

    /// `true` when reads must be authenticated.
    #[must_use]
    pub const fn requires_for_read(self) -> bool {
        matches!(self, Self::Read | Self::Both)
    }

    /// `true` when writes must be authenticated.
    #[must_use]
    pub const fn requires_for_write(self) -> bool {
        matches!(self, Self::Write | Self::Both)
    }
}

/// Per-connection, per-minute rate limits for the relay server.
///
/// Each sub-limit caps how many of a message type one connection may
/// send within a rolling 60-second window. `None` leaves that limit
/// unbounded. Mirrors upstream `nostr-relay-builder`'s `RateLimit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RateLimit {
    /// Max `EVENT` messages per minute. `None` is unlimited.
    pub notes_per_minute: Option<u32>,
    /// Max `REQ` messages per minute. `None` is unlimited.
    pub reqs_per_minute: Option<u32>,
}

impl RateLimit {
    /// A limit with no sub-limits set — everything unbounded.
    pub const DISABLED: Self = Self {
        notes_per_minute: None,
        reqs_per_minute: None,
    };

    /// `true` when at least one sub-limit is set.
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        self.notes_per_minute.is_some() || self.reqs_per_minute.is_some()
    }
}

/// Configuration for a [`crate::server::MockRelay`] instance.
///
/// Construct via [`Self::new`] and chain method calls, or hand the
/// fully-populated struct to [`crate::server::MockRelayBuilder::options`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MockRelayOptions {
    /// Address to bind. Defaults to `127.0.0.1:0` so the OS picks an
    /// ephemeral port — convenient for parallel CI test runs.
    pub bind_addr: SocketAddr,

    /// NIP-42 authentication enforcement mode. [`Nip42Mode::Disabled`]
    /// (the default) serves everyone; other modes send an
    /// `["AUTH", <challenge>]` on connect and gate reads, writes, or
    /// both until the client returns a valid signed `kind:22242` event
    /// (signature, `relay`/`challenge` tags, and freshness are all
    /// verified).
    pub nip42_mode: Nip42Mode,

    /// Minimum NIP-13 proof-of-work difficulty (leading zero bits)
    /// demanded of inbound `EVENT`s. `None` (the default) accepts any
    /// difficulty; `Some(d)` rejects events whose id has fewer than
    /// `d` leading zero bits with a `pow:` reason — mirroring upstream
    /// `nostr-relay-builder`'s `min_pow` admission gate.
    pub min_pow: Option<u8>,

    /// Maximum number of concurrent connections the relay accepts.
    /// `None` (the default) is unlimited; once `Some(n)` connections
    /// are live, further TCP connections are dropped before the
    /// WebSocket handshake completes.
    pub max_connections: Option<usize>,

    /// Maximum length (in characters) of a client subscription id.
    /// `None` (the default) is unlimited; a longer id in `REQ` /
    /// NIP-77 `NEG-OPEN` is rejected with an `invalid:` reason.
    pub max_subid_length: Option<usize>,

    /// Upper bound clamped onto every `REQ` / NIP-77 filter `limit`.
    /// `None` (the default) leaves client limits untouched; `Some(n)`
    /// rewrites any larger — or absent — `limit` down to `n` before
    /// the query runs.
    pub max_filter_limit: Option<usize>,

    /// Per-connection, per-minute rate limits. Both sub-limits default
    /// to unlimited.
    pub rate_limit: RateLimit,

    /// Test fault injection: when `true`, the relay completes the
    /// WebSocket handshake but never replies to any `EVENT` / `REQ` /
    /// other NIP-01 frame (control pings still pong). Used to exercise
    /// client read-timeout and resilience paths. Default `false`.
    pub unresponsive: bool,

    /// Test fault injection: when `Some(n)`, every `REQ` is answered
    /// with `n` freshly-generated random events followed by `EOSE`,
    /// instead of querying storage. Used to exercise client handling of
    /// unsolicited events. Default `None`.
    pub send_random_events: Option<u16>,
}

impl Default for MockRelayOptions {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            nip42_mode: Nip42Mode::Disabled,
            min_pow: None,
            max_connections: None,
            max_subid_length: None,
            max_filter_limit: None,
            rate_limit: RateLimit::DISABLED,
            unresponsive: false,
            send_random_events: None,
        }
    }
}

impl MockRelayOptions {
    /// Construct with all defaults (`127.0.0.1:0`, no NIP-42).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the bind address.
    #[must_use]
    pub const fn bind_addr(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = addr;
        self
    }

    /// Set the NIP-42 authentication mode. See [`Nip42Mode`].
    #[must_use]
    pub const fn nip42_mode(mut self, mode: Nip42Mode) -> Self {
        self.nip42_mode = mode;
        self
    }

    /// Require a minimum NIP-13 proof-of-work difficulty for inbound
    /// events. A difficulty of `0` clears the requirement.
    #[must_use]
    pub const fn min_pow(mut self, difficulty: u8) -> Self {
        self.min_pow = if difficulty > 0 {
            Some(difficulty)
        } else {
            None
        };
        self
    }

    /// Cap the number of concurrent connections. `0` clears the cap.
    #[must_use]
    pub const fn max_connections(mut self, max: usize) -> Self {
        self.max_connections = if max > 0 { Some(max) } else { None };
        self
    }

    /// Cap the length of a client subscription id. `0` clears the cap.
    #[must_use]
    pub const fn max_subid_length(mut self, max: usize) -> Self {
        self.max_subid_length = if max > 0 { Some(max) } else { None };
        self
    }

    /// Clamp every filter `limit` to at most `max`. `0` clears the cap.
    #[must_use]
    pub const fn max_filter_limit(mut self, max: usize) -> Self {
        self.max_filter_limit = if max > 0 { Some(max) } else { None };
        self
    }

    /// Set the per-connection, per-minute [`RateLimit`].
    #[must_use]
    pub const fn rate_limit(mut self, limit: RateLimit) -> Self {
        self.rate_limit = limit;
        self
    }

    /// Test fault injection: make the relay unresponsive to NIP-01
    /// frames. See [`Self::unresponsive`].
    #[must_use]
    pub const fn unresponsive(mut self, value: bool) -> Self {
        self.unresponsive = value;
        self
    }

    /// Test fault injection: answer every `REQ` with `count` random
    /// events. `0` clears the mode. See [`Self::send_random_events`].
    #[must_use]
    pub const fn send_random_events(mut self, count: u16) -> Self {
        self.send_random_events = if count > 0 { Some(count) } else { None };
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_localhost_ephemeral() {
        let opts = MockRelayOptions::new();
        assert_eq!(opts.bind_addr.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(opts.bind_addr.port(), 0);
        assert_eq!(opts.nip42_mode, Nip42Mode::Disabled);
        assert!(opts.min_pow.is_none());
        assert!(opts.max_connections.is_none());
        assert!(opts.max_subid_length.is_none());
        assert!(opts.max_filter_limit.is_none());
        assert!(!opts.rate_limit.is_enabled());
        assert!(!opts.unresponsive);
        assert!(opts.send_random_events.is_none());
    }

    #[test]
    fn caps_zero_clears_requirement() {
        assert_eq!(
            MockRelayOptions::new().max_connections(8).max_connections,
            Some(8)
        );
        assert_eq!(
            MockRelayOptions::new().max_connections(0).max_connections,
            None
        );
        assert_eq!(
            MockRelayOptions::new()
                .max_subid_length(64)
                .max_subid_length,
            Some(64)
        );
        assert_eq!(
            MockRelayOptions::new()
                .max_filter_limit(500)
                .max_filter_limit,
            Some(500)
        );
    }

    #[test]
    fn min_pow_zero_clears_requirement() {
        assert_eq!(MockRelayOptions::new().min_pow(8).min_pow, Some(8));
        assert_eq!(MockRelayOptions::new().min_pow(0).min_pow, None);
    }
}
