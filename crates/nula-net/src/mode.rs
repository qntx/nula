//! Connection mode declared at `connect()` time.
//!
//! Today only `Direct` ships. The enum is `#[non_exhaustive]` so we
//! can add proxied modes (SOCKS5, HTTP CONNECT, Tor) in a future
//! minor release without breaking downstream pattern matches.

/// How a transport should reach the relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum ConnectionMode {
    /// Open a direct TCP connection to the relay's host, upgrading to
    /// TLS when the URL scheme is `wss`.
    #[default]
    Direct,
}

impl ConnectionMode {
    /// Convenience constructor matching the variant name; useful when
    /// you want to spell the mode out at a call site without importing
    /// the variant.
    #[must_use]
    pub const fn direct() -> Self {
        Self::Direct
    }
}
