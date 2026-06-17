//! Public [`Relay`] handle — the only type callers ever construct.
//!
//! `Relay` is a thin `Arc<Inner>` wrapper. All mutation runs in a
//! `tokio::spawn`ed actor task; the handle simply exchanges
//! commands and replies with that task. Cloning is cheap (one `Arc`
//! bump). Dropping the last clone shuts the actor down via
//! [`Inner::Drop`].

use std::sync::{Arc, Mutex};

use nula_core::{ClientMessage, Event, Filter, RelayUrl, SubscriptionId};
use tokio::sync::{mpsc, oneshot};

use crate::error::Error;
use crate::inner::{ActorContext, Command, spawn_actor};
use crate::notification::RelayNotification;
use crate::options::{PublishOptions, RelayOptions, SubscribeOptions};
use crate::stats::RelayStats;
use crate::status::{AtomicRelayStatus, RelayStatus};
use crate::subscription::SubscriptionHandle;
use crate::transport::IntoWebSocketTransport;

/// Single-relay NIP-01 client.
///
/// Construct with [`Relay::new`] (when `default-transport` is on) or
/// [`Relay::builder`] for full control.
#[derive(Debug, Clone)]
pub struct Relay {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    url: RelayUrl,
    command_tx: mpsc::UnboundedSender<Command>,
    close_tx: mpsc::UnboundedSender<SubscriptionId>,
    /// Notification stream is single-consumer. We hand out a
    /// `Mutex`-guarded handle so a second [`Relay::notifications`]
    /// caller observably gets `None` rather than silently splitting
    /// the stream. A `std::sync::Mutex` is enough — the lock is
    /// only held for a single `Option::take()` and never across an
    /// await point.
    notification_rx: Mutex<Option<mpsc::UnboundedReceiver<RelayNotification>>>,
    status: Arc<AtomicRelayStatus>,
    stats: Arc<RelayStats>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Best-effort: the actor may have already terminated, in
        // which case the send fails silently — exactly what we want.
        drop(self.command_tx.send(Command::Shutdown));
    }
}

impl Relay {
    /// Construct with the default `tokio-tungstenite` transport.
    ///
    /// Convenience constructor available when the
    /// `default-transport` feature is enabled (it is on by default).
    /// Disable it and reach for [`Self::builder`] when supplying a
    /// custom transport.
    #[cfg(feature = "default-transport")]
    #[cfg_attr(docsrs, doc(cfg(feature = "default-transport")))]
    #[must_use]
    pub fn new(url: RelayUrl) -> Self {
        Self::from_context(ActorContext {
            url,
            transport: Arc::new(crate::transport::default::DefaultTransport::new()),
            options: RelayOptions::default(),
        })
    }

    /// Begin configuring a relay.
    ///
    /// When the `default-transport` feature is on the builder is
    /// pre-populated with [`crate::transport::default::DefaultTransport`];
    /// otherwise the caller must call
    /// [`RelayBuilder::transport`] before [`RelayBuilder::build`].
    pub fn builder(url: RelayUrl) -> RelayBuilder {
        RelayBuilder::new(url)
    }

    /// The relay's URL.
    #[must_use]
    pub fn url(&self) -> &RelayUrl {
        &self.inner.url
    }

    /// Current connection status.
    #[must_use]
    pub fn status(&self) -> RelayStatus {
        self.inner.status.load()
    }

    /// Read-only access to lifetime statistics.
    #[must_use]
    pub fn stats(&self) -> &RelayStats {
        &self.inner.stats
    }

    /// Take the notification stream. Returns `None` after the first
    /// caller has already consumed it.
    #[must_use]
    pub fn notifications(&self) -> Option<mpsc::UnboundedReceiver<RelayNotification>> {
        // The mutex is held only for the duration of `take()`; no
        // user code runs while it is locked, so a poisoned mutex
        // can be transparently recovered from.
        let mut guard = self
            .inner
            .notification_rx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.take()
    }

    /// Connect (or reconnect) and wait until the handshake completes.
    ///
    /// # Errors
    ///
    /// - [`Error::Transport`] for handshake / TLS failures.
    /// - [`Error::ConnectTimeout`] when the configured
    ///   [`crate::RelayOptions::connect_timeout`] elapses.
    /// - [`Error::Shutdown`] when the actor has already exited.
    pub async fn connect(&self) -> Result<(), Error> {
        let (tx, rx) = oneshot::channel();
        self.inner
            .command_tx
            .send(Command::Connect { reply: tx })
            .map_err(|_| Error::Shutdown)?;
        rx.await.map_err(|_| Error::Shutdown)?
    }

    /// Tear down the current socket without terminating the actor.
    /// A subsequent [`Self::connect`] call brings the relay back
    /// online with the same subscription set.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Shutdown`] when the actor has already
    /// exited.
    pub async fn disconnect(&self) -> Result<(), Error> {
        let (tx, rx) = oneshot::channel();
        self.inner
            .command_tx
            .send(Command::Disconnect { reply: tx })
            .map_err(|_| Error::Shutdown)?;
        rx.await.map_err(|_| Error::Shutdown)
    }

    /// Open a subscription against the relay.
    ///
    /// The returned [`SubscriptionHandle`] is a `Stream` of
    /// [`crate::SubscriptionItem`]; dropping it auto-issues a
    /// `["CLOSE", id]` to the relay.
    ///
    /// # Errors
    ///
    /// - [`Error::DuplicateSubscription`] if `id` is already in
    ///   flight on this relay.
    /// - [`Error::TooManySubscriptions`] when the configured cap is
    ///   reached.
    /// - [`Error::Transport`] when the wire send fails.
    /// - [`Error::Shutdown`] when the actor has already exited.
    pub async fn subscribe(
        &self,
        id: SubscriptionId,
        filters: Vec<Filter>,
        options: SubscribeOptions,
    ) -> Result<SubscriptionHandle, Error> {
        let (item_tx, item_rx) = mpsc::unbounded_channel();
        let (reply_tx, reply_rx) = oneshot::channel();
        self.inner
            .command_tx
            .send(Command::Subscribe {
                id: id.clone(),
                filters,
                options,
                sink: item_tx,
                reply: reply_tx,
            })
            .map_err(|_| Error::Shutdown)?;
        reply_rx.await.map_err(|_| Error::Shutdown)??;
        Ok(SubscriptionHandle::new(
            id,
            item_rx,
            self.inner.close_tx.clone(),
        ))
    }

    /// Open a NIP-77 reconciliation session against the relay.
    ///
    /// Equivalent to a `subscribe` whose outbound frame is a
    /// `["NEG-OPEN", id, filter, initial_message_hex]` instead of
    /// `["REQ", …]`. The returned [`SubscriptionHandle`] yields
    /// [`crate::SubscriptionItem::NegMsg`] /
    /// [`crate::SubscriptionItem::NegErr`] frames the relay sends
    /// back; the higher-level `nula` driver folds each
    /// `NegMsg` into a `nula_sync::Reconciliation` and emits the
    /// next `NEG-MSG` via [`Self::send_msg`].
    ///
    /// Sessions are **not** re-issued across reconnects -- the
    /// Negentropy state machine cannot resume across a fresh
    /// socket. Drop the handle (or call `send_msg` with a
    /// `NegClose`) to terminate the session.
    ///
    /// # Errors
    ///
    /// - [`Error::DuplicateSubscription`] if `id` is already in
    ///   flight on this relay.
    /// - [`Error::TooManySubscriptions`] when the configured cap
    ///   is reached.
    /// - [`Error::NotConnected`] when the relay is currently
    ///   down.
    /// - [`Error::Transport`] when the wire send fails.
    /// - [`Error::Shutdown`] when the actor has already exited.
    pub async fn subscribe_neg(
        &self,
        id: SubscriptionId,
        filter: Filter,
        initial_message_hex: String,
    ) -> Result<SubscriptionHandle, Error> {
        let (item_tx, item_rx) = mpsc::unbounded_channel();
        let (reply_tx, reply_rx) = oneshot::channel();
        self.inner
            .command_tx
            .send(Command::SubscribeNeg {
                id: id.clone(),
                filter,
                initial_message_hex,
                sink: item_tx,
                reply: reply_tx,
            })
            .map_err(|_| Error::Shutdown)?;
        reply_rx.await.map_err(|_| Error::Shutdown)??;
        Ok(SubscriptionHandle::new(
            id,
            item_rx,
            self.inner.close_tx.clone(),
        ))
    }

    /// Publish an event and wait for the relay's `OK` reply.
    ///
    /// # Errors
    ///
    /// - [`Error::PublishRejected`] when the relay's `OK` payload is
    ///   `false`.
    /// - [`Error::PublishTimeout`] when the relay does not reply
    ///   within the configured deadline.
    /// - [`Error::NotConnected`] when the relay is currently down.
    /// - [`Error::TooManyPendingPublishes`] when the configured cap
    ///   is reached.
    /// - [`Error::Shutdown`] when the actor has already exited.
    pub async fn publish(&self, event: Event, options: PublishOptions) -> Result<(), Error> {
        let (tx, rx) = oneshot::channel();
        self.inner
            .command_tx
            .send(Command::Publish {
                event,
                options,
                reply: tx,
            })
            .map_err(|_| Error::Shutdown)?;
        rx.await.map_err(|_| Error::Shutdown)?
    }

    /// Reply to a NIP-42 challenge with a signed kind-22242 event.
    ///
    /// # Errors
    ///
    /// Same errors as [`Self::publish`], scoped to AUTH frames.
    #[cfg(feature = "nip42")]
    #[cfg_attr(docsrs, doc(cfg(feature = "nip42")))]
    pub async fn authenticate(&self, event: Event) -> Result<(), Error> {
        let (tx, rx) = oneshot::channel();
        self.inner
            .command_tx
            .send(Command::Authenticate { event, reply: tx })
            .map_err(|_| Error::Shutdown)?;
        rx.await.map_err(|_| Error::Shutdown)?
    }

    /// Ship an arbitrary [`ClientMessage`] frame over the current
    /// connection.
    ///
    /// Use this for message variants this crate does not have a
    /// bespoke `publish` / `subscribe` / `authenticate` method
    /// for, e.g. NIP-77 `NegOpen` / `NegMsg` / `NegClose` driving
    /// a sync session. The actor performs the serialise + write
    /// then replies; there is **no per-message `OK` correlation**.
    /// Reply traffic the relay sends back (NIP-77 `NegMsg` /
    /// `NegErr` etc.) is delivered through the relay's normal
    /// subscription notification stream — the caller is
    /// responsible for opening the matching subscription channel
    /// before issuing the send.
    ///
    /// # Errors
    ///
    /// - [`Error::NotConnected`] when the relay is currently down.
    /// - [`Error::Json`] / [`Error::SerializeClientMessage`] when
    ///   the message cannot be serialised (effectively unreachable
    ///   for round-trip-safe [`ClientMessage`] variants).
    /// - [`Error::Transport`] when the underlying WebSocket sink
    ///   refuses the write.
    /// - [`Error::Shutdown`] when the actor has already exited.
    pub async fn send_msg(&self, message: ClientMessage) -> Result<(), Error> {
        let (tx, rx) = oneshot::channel();
        self.inner
            .command_tx
            .send(Command::SendMsg { message, reply: tx })
            .map_err(|_| Error::Shutdown)?;
        rx.await.map_err(|_| Error::Shutdown)?
    }

    fn from_context(ctx: ActorContext) -> Self {
        let url = ctx.url.clone();
        let channels = spawn_actor(ctx);
        Self {
            inner: Arc::new(Inner {
                url,
                command_tx: channels.command_tx,
                close_tx: channels.close_tx,
                notification_rx: Mutex::new(Some(channels.notification_rx)),
                status: channels.status,
                stats: channels.stats,
            }),
        }
    }
}

/// Builder for [`Relay`].
///
/// The transport defaults to [`crate::transport::default::DefaultTransport`]
/// when the `default-transport` feature is on; otherwise
/// [`Self::transport`] **must** be called before [`Self::build`].
#[derive(Debug)]
#[must_use]
pub struct RelayBuilder {
    url: RelayUrl,
    transport: Option<Arc<dyn crate::transport::WebSocketTransport>>,
    options: RelayOptions,
}

impl RelayBuilder {
    /// Begin configuring a relay against `url`.
    pub fn new(url: RelayUrl) -> Self {
        Self {
            url,
            transport: None,
            options: RelayOptions::default(),
        }
    }

    /// Override the WebSocket transport.
    pub fn transport<T: IntoWebSocketTransport>(mut self, transport: T) -> Self {
        self.transport = Some(transport.into_transport());
        self
    }

    /// Override the relay options.
    pub const fn options(mut self, options: RelayOptions) -> Self {
        self.options = options;
        self
    }

    /// Finalise the builder and spawn the actor task.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingTransport`] when the
    /// `default-transport` feature is **off** and no transport was
    /// supplied via [`Self::transport`]. With `default-transport`
    /// on, this never fails — the default transport is constructed
    /// lazily.
    #[cfg_attr(
        feature = "default-transport",
        allow(
            clippy::unnecessary_wraps,
            reason = "MissingTransport branch is cfg-gated; the `Result` shape stays in the stable surface so callers compile across feature toggles"
        )
    )]
    pub fn build(self) -> Result<Relay, Error> {
        let transport: Arc<dyn crate::transport::WebSocketTransport> = match self.transport {
            Some(t) => t,
            None => {
                #[cfg(feature = "default-transport")]
                {
                    Arc::new(crate::transport::default::DefaultTransport::new())
                }
                #[cfg(not(feature = "default-transport"))]
                {
                    return Err(Error::MissingTransport);
                }
            }
        };
        Ok(Relay::from_context(ActorContext {
            url: self.url,
            transport,
            options: self.options,
        }))
    }
}
