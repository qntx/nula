//! `MockTransport` — feeds frames to and from a test body via
//! unbounded tokio mpsc channels.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll};

use futures::sink::Sink;
use futures::stream::Stream;
use nula_core::RelayUrl;
use tokio::sync::mpsc;

use crate::transport::error::Error;
use crate::transport::message::Message;
use crate::transport::mode::ConnectionMode;
use crate::transport::ws::{WebSocketSink, WebSocketStream, WebSocketTransport};
use nula_core::boxed::BoxFuture;

/// Test handle paired with one `MockTransport::connect()` invocation.
///
/// The handle is the "server side" of a pretend WebSocket: write
/// inbound frames with [`MockHandle::push_inbound`], read the frames
/// the system-under-test sent with [`MockHandle::next_outbound`].
#[derive(Debug)]
pub struct MockHandle {
    inbound_tx: mpsc::UnboundedSender<Result<Message, Error>>,
    outbound_rx: mpsc::UnboundedReceiver<Message>,
}

impl MockHandle {
    /// Push a frame into the transport's stream half.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConnectionClosed`] when the transport stream
    /// receiver has been dropped.
    pub fn push_inbound(&self, msg: Message) -> Result<(), Error> {
        self.inbound_tx
            .send(Ok(msg))
            .map_err(|_| Error::ConnectionClosed)
    }

    /// Push a transport error into the stream half. Use this to
    /// simulate I/O or protocol failures.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConnectionClosed`] when the transport stream
    /// receiver has been dropped.
    pub fn push_inbound_error(&self, err: Error) -> Result<(), Error> {
        self.inbound_tx
            .send(Err(err))
            .map_err(|_| Error::ConnectionClosed)
    }

    /// Receive the next frame the system-under-test wrote. Returns
    /// `None` when the sink half has been dropped.
    pub async fn next_outbound(&mut self) -> Option<Message> {
        self.outbound_rx.recv().await
    }

    /// Drop the inbound sender, signalling the system-under-test that
    /// the peer has closed the connection. After this call subsequent
    /// `push_inbound` invocations will return
    /// [`Error::ConnectionClosed`].
    pub fn close_inbound(&mut self) {
        let (tx, _rx) = mpsc::unbounded_channel();
        // Replace the live sender with a fresh one whose receiver is
        // dropped immediately; future sends will fail.
        self.inbound_tx = tx;
    }
}

/// In-memory [`WebSocketTransport`] that records every `connect()`
/// invocation and pairs it with a [`MockHandle`].
///
/// Threading note: cheap to clone via `Arc<MockTransport>`. Channels
/// are unbounded so there is no backpressure simulation — that is by
/// design, since the typical test driver does not need it.
#[derive(Debug, Default)]
pub struct MockTransport {
    subscribers: Mutex<HashMap<String, mpsc::UnboundedSender<MockHandle>>>,
}

impl MockTransport {
    /// Construct an empty mock.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Subscribe to the handles produced by `connect()` calls for `url`.
    ///
    /// The returned receiver yields one [`MockHandle`] per matching
    /// `connect()` invocation, in arrival order. Drop the receiver to
    /// stop intercepting handles for that URL.
    pub fn subscribe(&self, url: &RelayUrl) -> mpsc::UnboundedReceiver<MockHandle> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.lock_subscribers().insert(url.as_str().to_owned(), tx);
        rx
    }

    /// Lock the subscriber map, transparently recovering from a
    /// poisoned mutex. The map only holds `Sender`s, so seeing a
    /// previous panic mid-lock is harmless.
    fn lock_subscribers(
        &self,
    ) -> MutexGuard<'_, HashMap<String, mpsc::UnboundedSender<MockHandle>>> {
        self.subscribers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

impl WebSocketTransport for MockTransport {
    fn supports_ping(&self) -> bool {
        false
    }

    fn connect<'a>(
        &'a self,
        url: &'a RelayUrl,
        _mode: &'a ConnectionMode,
    ) -> BoxFuture<'a, Result<(WebSocketSink, WebSocketStream), Error>> {
        #[cfg(feature = "tracing")]
        let span = tracing::debug_span!(
            "nula_relay.transport.mock.connect",
            nostr.relay.url = %url.as_str(),
        );
        let fut = async move {
            let subscriber = self.lock_subscribers().get(url.as_str()).cloned();
            let subscriber = subscriber.ok_or(Error::ProtocolViolation {
                reason: "MockTransport: no subscriber registered for this URL",
            })?;

            let (inbound_tx, inbound_rx) = mpsc::unbounded_channel::<Result<Message, Error>>();
            let (outbound_tx, outbound_rx) = mpsc::unbounded_channel::<Message>();

            let handle = MockHandle {
                inbound_tx,
                outbound_rx,
            };
            subscriber
                .send(handle)
                .map_err(|_| Error::ConnectionClosed)?;

            let sink: WebSocketSink = Box::pin(MockSink { inner: outbound_tx });
            let stream: WebSocketStream = Box::pin(MockStream { inner: inbound_rx });

            Ok((sink, stream))
        };

        #[cfg(feature = "tracing")]
        let fut = tracing::Instrument::instrument(fut, span);

        Box::pin(fut)
    }
}

struct MockSink {
    inner: mpsc::UnboundedSender<Message>,
}

impl Sink<Message> for MockSink {
    type Error = Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        self.inner.send(item).map_err(|_| Error::ConnectionClosed)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

struct MockStream {
    inner: mpsc::UnboundedReceiver<Result<Message, Error>>,
}

impl Stream for MockStream {
    type Item = Result<Message, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.inner.poll_recv(cx)
    }
}
