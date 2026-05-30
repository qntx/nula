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
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::protocol::Message as TgMessage;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream as TgWebSocketStream};

use crate::transport::default::convert::{from_tungstenite_error, to_tungstenite};
use crate::transport::error::Error;
use crate::transport::message::Message;

type TgSink = SplitSink<TgWebSocketStream<MaybeTlsStream<TcpStream>>, TgMessage>;

/// Adapter that maps `nula-net`'s [`Message`] / [`Error`] onto the
/// `tungstenite` sink without the `SinkMapErr` panic.
pub(super) struct TransportSink {
    inner: TgSink,
}

impl TransportSink {
    pub(super) const fn new(inner: TgSink) -> Self {
        Self { inner }
    }
}

impl Sink<Message> for TransportSink {
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
