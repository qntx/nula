//! Tunables for [`crate::MockRelay`].

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Configuration for a [`crate::MockRelay`] instance.
///
/// Construct via [`Self::new`] and chain method calls, or hand the
/// fully-populated struct to [`crate::MockRelayBuilder::options`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MockRelayOptions {
    /// Address to bind. Defaults to `127.0.0.1:0` so the OS picks an
    /// ephemeral port — convenient for parallel CI test runs.
    pub bind_addr: SocketAddr,

    /// When `true` the relay sends `["AUTH", <challenge>]` immediately
    /// after the WebSocket handshake and rejects every `REQ` /
    /// `EVENT` until the client replies with a `["AUTH", <event>]`.
    /// **Note**: the AUTH event signature is *not* verified — this is
    /// a transport-layer test hook, not a real auth gate.
    pub require_nip42: bool,
}

impl Default for MockRelayOptions {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            require_nip42: false,
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

    /// Toggle the NIP-42 challenge gate. See
    /// [`Self::require_nip42`] for caveats.
    #[must_use]
    pub const fn require_nip42(mut self, value: bool) -> Self {
        self.require_nip42 = value;
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
        assert!(!opts.require_nip42);
    }
}
