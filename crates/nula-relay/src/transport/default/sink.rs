//! Custom `Sink` wrapper around a `tokio-tungstenite` split sink.
//!
//! The naïve implementation — `tx.sink_map_err(map_err)` — panics in
//! some teardown paths because `SinkMapErr` borrows the underlying
//! sink across `.poll_close()`. Upstream documented the issue at
//! [rust-nostr#984](https://github.com/rust-nostr/nostr/issues/984);
//! the fix is to forward each `Sink` method explicitly so the
//! underlying type is pinned cleanly.

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::SinkExt;
use futures::sink::Sink;
use futures::stream::SplitSink;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::WebSocketStream as TgWebSocketStream;
use tokio_tungstenite::tungstenite::protocol::Message as TgMessage;

use crate::transport::default::convert::{from_tungstenite_error, to_tungstenite};
use crate::transport::error::Error;
use crate::transport::message::Message;

type TgSink<S> = SplitSink<TgWebSocketStream<S>, TgMessage>;

/// Adapter that maps `nula-net`'s [`Message`] / [`Error`] onto the
/// `tungstenite` sink without the `SinkMapErr` panic.
///
/// Generic over the underlying byte stream `S` so the same adapter wraps
/// both a direct `MaybeTlsStream<TcpStream>` (the `Direct` mode) and a
/// SOCKS5-tunnelled stream (the `Socks5` mode).
pub(super) struct TransportSink<S> {
    inner: TgSink<S>,
}

impl<S> TransportSink<S> {
    pub(super) const fn new(inner: TgSink<S>) -> Self {
        Self { inner }
    }
}

impl<S> Sink<Message> for TransportSink<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    type Error = Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_ready_unpin(cx)
            .map_err(from_tungstenite_error)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        self.inner
            .start_send_unpin(to_tungstenite(item))
            .map_err(from_tungstenite_error)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_flush_unpin(cx)
            .map_err(from_tungstenite_error)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner
            .poll_close_unpin(cx)
            .map_err(from_tungstenite_error)
    }
}
