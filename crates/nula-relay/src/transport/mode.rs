//! Connection mode declared at `connect()` time.
//!
//! `Direct` always ships. `Socks5` is honoured by the default transport
//! only when the `socks` feature is enabled; other transports (and the
//! default transport built without `socks`) reject it with
//! [`crate::transport::Error::UnsupportedMode`]. The enum is
//! `#[non_exhaustive]` so further proxied modes (HTTP CONNECT, …) can be
//! added in a minor release without breaking downstream matches.

use std::net::SocketAddr;

/// How a transport should reach the relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum ConnectionMode {
    /// Open a direct TCP connection to the relay's host, upgrading to
    /// TLS when the URL scheme is `wss`.
    #[default]
    Direct,

    /// Tunnel the connection through a SOCKS5 proxy listening at
    /// `proxy`. The relay **hostname** (not a pre-resolved IP) is sent
    /// to the proxy so it performs remote DNS resolution — required for
    /// Tor `.onion` relays. TLS is still negotiated end-to-end with the
    /// relay over the tunnel when the URL scheme is `wss`.
    Socks5 {
        /// Address of the SOCKS5 proxy (e.g. Tor's `127.0.0.1:9050`).
        proxy: SocketAddr,
    },
}

impl ConnectionMode {
    /// Convenience constructor matching the variant name; useful when
    /// you want to spell the mode out at a call site without importing
    /// the variant.
    #[must_use]
    pub const fn direct() -> Self {
        Self::Direct
    }

    /// Tunnel through the SOCKS5 proxy at `proxy` (e.g. Tor's
    /// `127.0.0.1:9050`).
    #[must_use]
    pub const fn socks5(proxy: SocketAddr) -> Self {
        Self::Socks5 { proxy }
    }
}
