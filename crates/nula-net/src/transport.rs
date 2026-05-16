//! Object-safe WebSocket transport trait.
//!
//! Layer 2 of the workspace exposes one shape: hand a `Url` and a
//! `ConnectionMode`, receive a `(Sink, Stream)` pair of `Message`
//! frames. Concrete implementations live in [`crate::default`] (the
//! `tokio-tungstenite`-backed `DefaultTransport`) and [`crate::mock`]
//! (the in-memory `MockTransport`); downstream users plug in their own
//! by implementing this trait.

use std::fmt::Debug;
use std::pin::Pin;
use std::sync::Arc;

use futures::sink::Sink;
use futures::stream::Stream;
use nula_core::RelayUrl;

use crate::boxed::BoxFuture;
use crate::error::Error;
use crate::message::Message;
use crate::mode::ConnectionMode;

/// Outbound half of a WebSocket connection.
///
/// `Send` on every non-wasm target so the sink can be moved into a
/// `tokio::spawn`ed task; `!Send` on `wasm32` because browser-side
/// sinks rarely satisfy the bound.
#[cfg(not(target_arch = "wasm32"))]
pub type WebSocketSink = Pin<Box<dyn Sink<Message, Error = Error> + Send>>;

/// Outbound half of a WebSocket connection. `wasm32` variant without
/// the `Send` bound.
#[cfg(target_arch = "wasm32")]
pub type WebSocketSink = Pin<Box<dyn Sink<Message, Error = Error>>>;

/// Inbound half of a WebSocket connection.
#[cfg(not(target_arch = "wasm32"))]
pub type WebSocketStream = Pin<Box<dyn Stream<Item = Result<Message, Error>> + Send>>;

/// Inbound half of a WebSocket connection. `wasm32` variant without
/// the `Send` bound.
#[cfg(target_arch = "wasm32")]
pub type WebSocketStream = Pin<Box<dyn Stream<Item = Result<Message, Error>>>>;

/// Object-safe WebSocket transport.
///
/// Implementations expose two pieces of information beyond raw
/// connectivity:
///
/// - [`Self::supports_ping`] tells callers whether they may send
///   [`Message::Ping`] frames. On browser transports the answer is
///   `false`; on `tokio-tungstenite` it is `true`.
/// - [`Self::connect`] performs the handshake and returns the
///   `(sink, stream)` pair.
///
/// The trait is `Send + Sync` so an `Arc<dyn WebSocketTransport>` can
/// be shared across tasks. The returned future is a [`BoxFuture`] for
/// the same reason — `async fn` in traits is not yet object-safe on
/// stable Rust.
///
/// [`Message::Ping`]: crate::Message::Ping
pub trait WebSocketTransport: Debug + Send + Sync {
    /// Whether [`Message::Ping`] frames are honoured by the underlying
    /// backend. Browser transports return `false`; `tokio-tungstenite`
    /// returns `true`.
    ///
    /// [`Message::Ping`]: crate::Message::Ping
    fn supports_ping(&self) -> bool;

    /// Open a WebSocket connection.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] for DNS / TCP failures,
    /// [`Error::Tls`] for TLS errors when the URL scheme is `wss`,
    /// [`Error::Handshake`] when the server rejects the upgrade with
    /// a non-`101` HTTP status, and [`Error::UnsupportedMode`] when
    /// the implementation does not understand the requested
    /// [`ConnectionMode`].
    fn connect<'a>(
        &'a self,
        url: &'a RelayUrl,
        mode: &'a ConnectionMode,
    ) -> BoxFuture<'a, Result<(WebSocketSink, WebSocketStream), Error>>;
}

/// Sugar trait for accepting "anything you can call `connect()` on" at
/// API boundaries.
///
/// Implemented for:
///
/// - any concrete `T: WebSocketTransport + 'static` (boxes it),
/// - `Arc<T>` where `T: WebSocketTransport + 'static` (re-erases the
///   pointer),
/// - `Arc<dyn WebSocketTransport>` (pass-through).
///
/// Library code typically takes `impl IntoWebSocketTransport` so
/// callers can hand it any of the above without ceremony.
pub trait IntoWebSocketTransport {
    /// Erase the implementation behind an `Arc<dyn …>`.
    fn into_transport(self) -> Arc<dyn WebSocketTransport>;
}

impl IntoWebSocketTransport for Arc<dyn WebSocketTransport> {
    fn into_transport(self) -> Arc<dyn WebSocketTransport> {
        self
    }
}

impl<T> IntoWebSocketTransport for T
where
    T: WebSocketTransport + 'static,
{
    fn into_transport(self) -> Arc<dyn WebSocketTransport> {
        Arc::new(self)
    }
}

impl<T> IntoWebSocketTransport for Arc<T>
where
    T: WebSocketTransport + 'static,
{
    fn into_transport(self) -> Arc<dyn WebSocketTransport> {
        self
    }
}
