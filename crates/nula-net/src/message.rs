//! Wire-shaped frames carried over a [`WebSocketTransport`].
//!
//! [`WebSocketTransport`]: crate::WebSocketTransport
//!
//! `Message` mirrors the on-the-wire WebSocket frame variants without
//! adopting any particular backend's type for them. Backends that hold
//! their own `Message` enum (e.g. `tokio-tungstenite`) implement the
//! conversion inside this crate's `default` module so the public
//! surface stays backend-free.

use std::borrow::Cow;

/// A WebSocket frame in the form callers exchange with a transport.
///
/// The variants follow [RFC 6455 §5.5–5.6][rfc] one-for-one:
///
/// - [`Self::Text`] is a UTF-8 text frame.
/// - [`Self::Binary`] is an opaque binary frame.
/// - [`Self::Ping`] is a ping frame; replies arrive as [`Self::Pong`].
/// - [`Self::Pong`] is a pong frame (typically only observed when the
///   peer initiates a ping).
/// - [`Self::Close`] is the bidirectional close handshake; the
///   optional [`CloseFrame`] carries the status code and reason.
///
/// The enum is `#[non_exhaustive]` so RFC 6455 extensions (e.g. raw
/// frame access for upper layers that need to inspect the wire bytes)
/// can be added without a major bump.
///
/// [rfc]: https://www.rfc-editor.org/rfc/rfc6455#section-5
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Message {
    /// A UTF-8 text frame. This is the Nostr default — every NIP-01
    /// command/response is exchanged as a JSON text frame.
    Text(String),
    /// An opaque binary frame. Reserved for future NIPs that opt out
    /// of JSON (e.g. negentropy reconciliation in `nostr-database`).
    Binary(Vec<u8>),
    /// A ping frame initiated by us. The peer must reply with
    /// [`Self::Pong`] carrying the same payload.
    Ping(Vec<u8>),
    /// A pong frame. Observed in the stream when the peer pings us.
    Pong(Vec<u8>),
    /// A close handshake frame. The optional [`CloseFrame`] carries the
    /// close code and reason; an absent frame matches a `Close(None)`
    /// initiated by either side.
    Close(Option<CloseFrame>),
}

impl Message {
    /// Construct a text frame.
    pub fn text(content: impl Into<String>) -> Self {
        Self::Text(content.into())
    }

    /// Construct a binary frame.
    pub fn binary(payload: impl Into<Vec<u8>>) -> Self {
        Self::Binary(payload.into())
    }

    /// Construct a ping frame.
    pub fn ping(payload: impl Into<Vec<u8>>) -> Self {
        Self::Ping(payload.into())
    }

    /// Construct a pong frame.
    pub fn pong(payload: impl Into<Vec<u8>>) -> Self {
        Self::Pong(payload.into())
    }

    /// Construct an empty close frame (no code, no reason). Use this
    /// when the application closure has no protocol-level meaning.
    #[must_use]
    pub const fn close() -> Self {
        Self::Close(None)
    }

    /// Construct a close frame carrying a status code and reason.
    pub fn close_with(code: u16, reason: impl Into<Cow<'static, str>>) -> Self {
        Self::Close(Some(CloseFrame::new(code, reason)))
    }

    /// `true` when the variant is [`Self::Text`] or [`Self::Binary`]
    /// — frames an application typically wants to read.
    #[must_use]
    pub const fn is_data(&self) -> bool {
        matches!(self, Self::Text(_) | Self::Binary(_))
    }

    /// `true` when the variant is a control frame (ping/pong/close).
    #[must_use]
    pub const fn is_control(&self) -> bool {
        matches!(self, Self::Ping(_) | Self::Pong(_) | Self::Close(_))
    }
}

/// Payload of a WebSocket close handshake.
///
/// The `code` follows [RFC 6455 §7.4][rfc] — common values:
///
/// | Code | Meaning                  |
/// | ---: | ------------------------ |
/// | 1000 | Normal closure           |
/// | 1001 | Going away               |
/// | 1002 | Protocol error           |
/// | 1003 | Unsupported data         |
/// | 1008 | Policy violation         |
/// | 1011 | Server-internal error    |
///
/// [rfc]: https://www.rfc-editor.org/rfc/rfc6455#section-7.4
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseFrame {
    /// Status code per RFC 6455 §7.4.
    pub code: u16,
    /// Human-readable reason. Stored as `Cow` so callers can pass
    /// static strings without allocating.
    pub reason: Cow<'static, str>,
}

impl CloseFrame {
    /// Construct a close frame from a status code and reason.
    pub fn new(code: u16, reason: impl Into<Cow<'static, str>>) -> Self {
        Self {
            code,
            reason: reason.into(),
        }
    }

    /// `code = 1000`, `reason = "normal closure"`.
    #[must_use]
    pub const fn normal() -> Self {
        Self {
            code: 1000,
            reason: Cow::Borrowed("normal closure"),
        }
    }

    /// `code = 1001`, `reason = "going away"`.
    #[must_use]
    pub const fn going_away() -> Self {
        Self {
            code: 1001,
            reason: Cow::Borrowed("going away"),
        }
    }

    /// `code = 1002`, `reason = "protocol error"`.
    #[must_use]
    pub const fn protocol_error() -> Self {
        Self {
            code: 1002,
            reason: Cow::Borrowed("protocol error"),
        }
    }
}
