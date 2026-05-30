//! Transport-level error surface.
//!
//! `Error` follows the workspace error contract documented in
//! [ADR-0004](../../docs/adr/0004-error-handling-thiserror.md): it is
//! `#[non_exhaustive]`, every variant carries typed data, and every
//! boxed source is `Send + Sync + 'static`.

use std::io;

use thiserror::Error;

use crate::transport::mode::ConnectionMode;

/// Errors raised by a [`crate::transport::WebSocketTransport`].
#[allow(
    clippy::error_impl_error,
    reason = "`Error` is the idiomatic crate-level error name (see std::io::Error, reqwest::Error)"
)]
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The underlying I/O layer raised an error (DNS, TCP, write
    /// failure, …). The original [`io::Error`] is preserved so
    /// callers can match on its [`io::ErrorKind`].
    #[error("transport I/O error: {0}")]
    Io(#[from] io::Error),

    /// The TLS layer raised an error (certificate validation,
    /// handshake decryption, …).
    #[error("transport TLS error: {0}")]
    Tls(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

    /// The HTTP upgrade response from the relay did not match the
    /// WebSocket handshake contract (e.g. the relay returned `403
    /// Forbidden` instead of `101 Switching Protocols`).
    #[error("handshake rejected: HTTP {status}{}", .message.as_deref().map_or(String::new(), |m| format!(": {m}")))]
    Handshake {
        /// HTTP status the relay responded with.
        status: u16,
        /// Optional human-readable message extracted from the response
        /// body. `None` when the body was empty or could not be
        /// decoded as UTF-8.
        message: Option<String>,
    },

    /// The peer closed the connection. This is observed as the end of
    /// the inbound stream rather than an `Err` in most flows, but
    /// some backends raise it as an explicit error variant.
    #[error("connection closed by peer")]
    ConnectionClosed,

    /// The peer sent a frame that violated the WebSocket / Nostr
    /// protocol invariant (e.g. an oversized fragment, a continuation
    /// frame outside a fragmented message). The static `reason`
    /// describes the rule that was broken.
    #[error("protocol violation: {reason}")]
    ProtocolViolation {
        /// The invariant that was violated.
        reason: &'static str,
    },

    /// The caller requested a [`ConnectionMode`] this transport does
    /// not understand. The `Direct` mode is always supported; proxy /
    /// Tor modes are advertised by future transport implementations.
    #[error("connection mode {0:?} is not supported by this transport")]
    UnsupportedMode(ConnectionMode),

    /// Backend-specific error that does not fit the variants above.
    /// Callers should treat this as opaque — the inner source is
    /// only useful for logging.
    #[error("transport backend error: {0}")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl Error {
    /// Wrap an arbitrary error in [`Error::Backend`].
    pub fn backend<E>(error: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self::Backend(error.into())
    }

    /// Wrap an arbitrary error in [`Error::Tls`].
    pub fn tls<E>(error: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self::Tls(error.into())
    }
}
