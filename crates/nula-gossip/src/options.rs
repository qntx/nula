//! Tunables for [`crate::Gossip`].
//!
//! Three orthogonal concerns:
//!
//! - [`GossipLimits`] caps how many relays each selection bucket may
//!   contribute (read / write / hint / most-received / dm).
//! - [`AllowedRelays`] is the policy gate (onion / local / insecure
//!   toggles).
//! - The freshness / refresher knobs (`list_ttl`,
//!   `refresher_interval`, `min_fetch_interval`) live on
//!   [`GossipOptions`] itself.

use std::num::NonZeroU8;
use std::time::Duration;

use nula_core::RelayUrl;

/// Defaults captured as named constants so the [`Default`] impl and
/// the module-level docs cannot drift.
mod defaults {
    use std::num::NonZeroU8;
    use std::time::Duration;

    /// 12 hours: how long a NIP-65 / NIP-17 list is considered fresh
    /// before [`crate::PublicKeyStatus::Outdated`] kicks in.
    pub(super) const LIST_TTL: Duration = Duration::from_hours(12);

    /// 30 seconds: minimum gap between fetch attempts on the same
    /// `(pubkey, list_kind)` pair. Stops the background refresher
    /// from hammering relays when one user's list is permanently
    /// missing.
    pub(super) const MIN_FETCH_INTERVAL: Duration = Duration::from_secs(30);

    /// 60 seconds: how often the background refresher wakes up to
    /// scan for outdated keys.
    pub(super) const REFRESHER_INTERVAL: Duration = Duration::from_mins(1);

    /// Up to 32 outdated keys per refresher tick. Beyond that a
    /// single tick would generate too many concurrent subscriptions.
    pub(super) const REFRESHER_BATCH: usize = 32;

    /// Per-user write-relay cap. NIP-65 §Size recommends keeping
    /// the publish set tight (2-4 relays).
    pub(super) const WRITE_RELAYS_PER_USER: NonZeroU8 = NonZeroU8::new(3).expect("3 != 0");

    /// Per-user read-relay cap.
    pub(super) const READ_RELAYS_PER_USER: NonZeroU8 = NonZeroU8::new(3).expect("3 != 0");

    /// Per-user hint cap. Hints are a softer signal so we keep them
    /// smaller than the explicit NIP-65 buckets.
    pub(super) const HINT_RELAYS_PER_USER: NonZeroU8 = NonZeroU8::new(2).expect("2 != 0");

    /// Per-user most-received cap.
    pub(super) const MOST_RECEIVED_PER_USER: NonZeroU8 = NonZeroU8::new(2).expect("2 != 0");

    /// Per-user DM-relay cap. NIP-17 lists tend to be very small
    /// (1-3 relays), so 3 is a safe upper bound.
    pub(super) const DM_RELAYS_PER_USER: NonZeroU8 = NonZeroU8::new(3).expect("3 != 0");
}

/// Per-bucket cap on how many relays each selection contributes.
///
/// Defaults follow NIP-65 §Size and the empirical defaults from
/// `rust-nostr`'s gossip resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GossipLimits {
    /// Max relays from the user's NIP-65 read list.
    pub read_relays_per_user: NonZeroU8,
    /// Max relays from the user's NIP-65 write list.
    pub write_relays_per_user: NonZeroU8,
    /// Max relays from the inline-hint histogram.
    pub hint_relays_per_user: NonZeroU8,
    /// Max relays from the most-received histogram.
    pub most_received_per_user: NonZeroU8,
    /// Max relays from the user's NIP-17 DM list.
    pub dm_relays_per_user: NonZeroU8,
}

impl Default for GossipLimits {
    fn default() -> Self {
        Self {
            read_relays_per_user: defaults::READ_RELAYS_PER_USER,
            write_relays_per_user: defaults::WRITE_RELAYS_PER_USER,
            hint_relays_per_user: defaults::HINT_RELAYS_PER_USER,
            most_received_per_user: defaults::MOST_RECEIVED_PER_USER,
            dm_relays_per_user: defaults::DM_RELAYS_PER_USER,
        }
    }
}

/// Policy gate over relay URLs. Applied **after** selection — every
/// candidate URL is run through [`Self::is_allowed`] before the
/// final relay set is returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllowedRelays {
    /// Allow `*.onion` hostnames. Default: `true`.
    pub onion: bool,
    /// Allow loopback / RFC1918 hostnames. Default: `false` —
    /// production routing should not leak to local relays.
    pub local: bool,
    /// Allow `ws://` (no TLS). Default: `true` — many tor / lan
    /// deployments still run plaintext.
    pub insecure: bool,
}

impl Default for AllowedRelays {
    fn default() -> Self {
        Self {
            onion: true,
            local: false,
            insecure: true,
        }
    }
}

impl AllowedRelays {
    /// Lock everything down: only TLS public-network relays.
    #[must_use]
    pub const fn locked_down() -> Self {
        Self {
            onion: false,
            local: false,
            insecure: false,
        }
    }

    /// Accept all relays. Useful for tests / local development.
    #[must_use]
    pub const fn permissive() -> Self {
        Self {
            onion: true,
            local: true,
            insecure: true,
        }
    }

    /// Returns `true` when `url` passes every active policy bit.
    #[must_use]
    pub fn is_allowed(self, url: &RelayUrl) -> bool {
        if !self.onion && url.is_onion() {
            return false;
        }
        if !self.local && is_local_addr(url) {
            return false;
        }
        if !self.insecure && !url.is_secure() {
            return false;
        }
        true
    }
}

/// Heuristic for "this relay is on a private network and should not
/// receive cross-account traffic". Mirrors the `rust-nostr` gossip
/// rule:
///
/// - hostname is `localhost`,
/// - host is an IPv4 in `127.0.0.0/8`, `10.0.0.0/8`,
///   `172.16.0.0/12`, or `192.168.0.0/16`, or
/// - host is an IPv6 loopback (`::1`) or unique-local address
///   (`fc00::/7`).
fn is_local_addr(url: &RelayUrl) -> bool {
    let host = url.host();
    if host == "localhost" {
        return true;
    }
    if let Ok(ipv4) = host.parse::<std::net::Ipv4Addr>() {
        return ipv4.is_loopback() || ipv4.is_private();
    }
    // url::Url renders bracketed IPv6 hosts without brackets via
    // `host_str`, so the parse below already handles that form.
    if let Ok(ipv6) = host.parse::<std::net::Ipv6Addr>() {
        return ipv6.is_loopback() || matches!(ipv6.segments()[0] & 0xfe00, 0xfc00);
    }
    false
}

/// Aggregate configuration for [`crate::Gossip`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GossipOptions {
    /// Lists older than `list_ttl` count as
    /// [`crate::PublicKeyStatus::Outdated`].
    pub list_ttl: Duration,

    /// Minimum gap between two `refresh()` attempts on the same
    /// `(user, list_kind)` pair. Stops the refresher from hammering
    /// relays when one user has no list at all.
    pub min_fetch_interval: Duration,

    /// How often the background refresher wakes up. `None` disables
    /// the background task; callers can still drive
    /// [`crate::Gossip::refresh`] manually.
    pub refresher_interval: Option<Duration>,

    /// Soft cap on the number of outdated keys the refresher
    /// processes per tick.
    pub refresher_batch: usize,

    /// Per-bucket relay caps.
    pub limits: GossipLimits,

    /// Onion / local / insecure policy.
    pub allowed: AllowedRelays,
}

impl Default for GossipOptions {
    fn default() -> Self {
        Self {
            list_ttl: defaults::LIST_TTL,
            min_fetch_interval: defaults::MIN_FETCH_INTERVAL,
            refresher_interval: Some(defaults::REFRESHER_INTERVAL),
            refresher_batch: defaults::REFRESHER_BATCH,
            limits: GossipLimits::default(),
            allowed: AllowedRelays::default(),
        }
    }
}

impl GossipOptions {
    /// Construct with all defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the freshness window.
    #[must_use]
    pub const fn list_ttl(mut self, ttl: Duration) -> Self {
        self.list_ttl = ttl;
        self
    }

    /// Override the per-`(user, list)` fetch debounce.
    #[must_use]
    pub const fn min_fetch_interval(mut self, gap: Duration) -> Self {
        self.min_fetch_interval = gap;
        self
    }

    /// Set the background refresher tick interval, or `None` to
    /// disable the background task.
    #[must_use]
    pub const fn refresher_interval(mut self, interval: Option<Duration>) -> Self {
        self.refresher_interval = interval;
        self
    }

    /// Override the per-tick batch cap.
    #[must_use]
    pub const fn refresher_batch(mut self, n: usize) -> Self {
        self.refresher_batch = n;
        self
    }

    /// Replace the relay-bucket caps.
    #[must_use]
    pub const fn limits(mut self, limits: GossipLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Replace the relay-policy gate.
    #[must_use]
    pub const fn allowed(mut self, allowed: AllowedRelays) -> Self {
        self.allowed = allowed;
        self
    }
}

/// Discriminator over the two list kinds the gossip layer
/// understands.
///
/// We deliberately do not track NIP-78 / NIP-89 / etc. as separate
/// list kinds: the gossip layer ingests their relay hints through
/// the generic `r` tag path, not through a dedicated list event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ListKind {
    /// NIP-65 relay list metadata (`kind:10002`). Read & write
    /// markers parsed via [`nula_core::nips::nip65`].
    Nip65,
    /// NIP-17 DM relays (`kind:10050`). Parsed via
    /// [`nula_core::nips::nip17`].
    Nip17,
}

impl ListKind {
    /// Map back to the wire `Kind` constant for filter construction.
    #[must_use]
    pub const fn event_kind(self) -> nula_core::Kind {
        match self {
            Self::Nip65 => nula_core::Kind::RELAY_LIST,
            Self::Nip17 => nula_core::Kind::DM_RELAYS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> RelayUrl {
        RelayUrl::parse(s).expect("hardcoded test url")
    }

    #[test]
    fn defaults_are_sane() {
        let opts = GossipOptions::default();
        assert_eq!(opts.list_ttl.as_secs(), 12 * 60 * 60);
        assert_eq!(opts.min_fetch_interval.as_secs(), 30);
        assert_eq!(
            opts.refresher_interval,
            Some(Duration::from_mins(1)),
            "default refresher interval is 60s"
        );
        assert_eq!(opts.refresher_batch, 32);
        assert_eq!(opts.limits.read_relays_per_user.get(), 3);
        assert!(opts.allowed.onion);
        assert!(!opts.allowed.local);
        assert!(opts.allowed.insecure);
    }

    #[test]
    fn fluent_overrides_apply() {
        let limits = GossipLimits {
            read_relays_per_user: NonZeroU8::new(8).expect("8 != 0"),
            ..GossipLimits::default()
        };
        let opts = GossipOptions::new()
            .list_ttl(Duration::from_mins(1))
            .min_fetch_interval(Duration::from_secs(5))
            .refresher_interval(None)
            .refresher_batch(2)
            .limits(limits)
            .allowed(AllowedRelays::locked_down());

        assert_eq!(opts.list_ttl, Duration::from_mins(1));
        assert_eq!(opts.refresher_interval, None);
        assert_eq!(opts.refresher_batch, 2);
        assert_eq!(opts.limits.read_relays_per_user.get(), 8);
        assert_eq!(opts.allowed, AllowedRelays::locked_down());
    }

    #[test]
    fn allowed_clearnet_passes_default() {
        let policy = AllowedRelays::default();
        assert!(policy.is_allowed(&url("wss://relay.damus.io")));
    }

    #[test]
    fn allowed_blocks_local_by_default() {
        let policy = AllowedRelays::default();
        assert!(!policy.is_allowed(&url("ws://127.0.0.1:7777")));
    }

    #[test]
    fn allowed_locked_down_blocks_insecure_and_onion() {
        let policy = AllowedRelays::locked_down();
        assert!(policy.is_allowed(&url("wss://relay.damus.io")));
        assert!(!policy.is_allowed(&url("ws://relay.damus.io")));
        assert!(!policy.is_allowed(&url(
            "ws://oxtrdevav64z64yb7x6rjg4ntzqjhedm5b5zjqulugknhzr46ny2qbad.onion"
        )));
    }

    #[test]
    fn allowed_permissive_lets_everything_through() {
        let policy = AllowedRelays::permissive();
        assert!(policy.is_allowed(&url("ws://192.168.1.10:7777")));
        assert!(policy.is_allowed(&url("wss://relay.damus.io")));
        assert!(policy.is_allowed(&url(
            "ws://oxtrdevav64z64yb7x6rjg4ntzqjhedm5b5zjqulugknhzr46ny2qbad.onion"
        )));
    }

    #[test]
    fn list_kind_round_trips_to_event_kind() {
        assert_eq!(ListKind::Nip65.event_kind(), nula_core::Kind::RELAY_LIST);
        assert_eq!(ListKind::Nip17.event_kind(), nula_core::Kind::DM_RELAYS);
    }
}
