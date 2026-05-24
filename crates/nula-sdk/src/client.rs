//! [`Client`] — the Layer-5 facade users wire their applications
//! against.
//!
//! Layer 5 itself is small: every Layer-4 collaborator (signer,
//! pool, gossip, sync) already exposes its own well-factored API.
//! What [`Client`] adds is composition (the same pool, signer,
//! database, gossip table backing every call site) and ergonomics
//! (lookups by `&str`, `Into<RelayUrl>`, fluent builder).
//!
//! ADR-0011 records the public-surface decisions, including the
//! deliberate departures from the upstream `nostr_sdk::Client`
//! shape.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use nula_core::event::{Event, EventBuilder, EventId};
use nula_core::filter::Filter;
use nula_core::message::SubscriptionId;
use nula_core::signer::NostrSigner;
use nula_core::types::RelayUrl;
#[cfg(feature = "gossip")]
use nula_gossip::Gossip;
use nula_net::BoxStream;
use nula_relay::{Relay, SubscribeOptions};
use nula_relay_pool::{Output, RelayCapabilities, RelayPool};
use nula_storage::{Events, NostrDatabase};

use crate::builder::ClientBuilder;
use crate::error::Error;
use crate::util::{IntoRelayUrl, collect_relay_urls};

/// Runtime configuration shared by every [`Client`] method.
#[derive(Debug, Clone)]
pub(crate) struct ClientConfig {
    pub(crate) automatic_authentication: bool,
}

/// Cheap-to-clone handle to a fully-wired Nostr client.
///
/// `Client` is a thin `Arc` wrapper over its (private) inner state —
/// every clone shares the same relay pool, signer, database, and
/// (when enabled) gossip router. Drop the last clone to tear
/// everything down; call [`Self::shutdown`] when you need a
/// deterministic shutdown (e.g. before exiting `main`).
#[derive(Debug, Clone)]
pub struct Client {
    pub(crate) inner: Arc<InnerClient>,
}

#[derive(Debug)]
pub(crate) struct InnerClient {
    pub(crate) pool: RelayPool,
    pub(crate) signer: Option<Arc<dyn NostrSigner>>,
    #[cfg(feature = "gossip")]
    pub(crate) gossip: Option<Gossip>,
    pub(crate) config: ClientConfig,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    /// Construct a default client. Equivalent to
    /// `Client::builder().build().expect(...)`.
    ///
    /// # Panics
    ///
    /// Panics if the default [`ClientBuilder::build`] fails. With
    /// the default `memory-fallback` + `default-transport` features
    /// turned on this cannot happen; if you disabled those, use
    /// [`Self::builder`] and `?` instead.
    #[must_use]
    #[allow(
        clippy::expect_used,
        reason = "infallible with the default feature set; documented panic path"
    )]
    pub fn new() -> Self {
        Self::builder()
            .build()
            .expect("default client builds with the default feature set")
    }

    /// Begin configuring a client.
    #[must_use]
    pub fn builder() -> ClientBuilder {
        ClientBuilder::default()
    }

    /// Underlying [`RelayPool`].
    ///
    /// Exposed so power users can reach the lower-level surface
    /// (custom subscribe options, raw `send_msg`) without
    /// the facade getting in the way.
    #[must_use]
    pub fn pool(&self) -> &RelayPool {
        &self.inner.pool
    }

    /// Configured signer, if any.
    #[must_use]
    pub fn signer(&self) -> Option<&Arc<dyn NostrSigner>> {
        self.inner.signer.as_ref()
    }

    /// Backing [`NostrDatabase`].
    #[must_use]
    pub fn database(&self) -> &Arc<dyn NostrDatabase> {
        self.inner.pool.database()
    }

    /// NIP-65 gossip router, if attached during build.
    #[cfg(feature = "gossip")]
    #[cfg_attr(docsrs, doc(cfg(feature = "gossip")))]
    #[must_use]
    pub fn gossip(&self) -> Option<&Gossip> {
        self.inner.gossip.as_ref()
    }

    /// Whether NIP-42 auto-authentication is enabled.
    #[must_use]
    pub fn automatic_authentication(&self) -> bool {
        self.inner.config.automatic_authentication
    }

    /// Whether the underlying pool has shut down (no further
    /// operation will make progress).
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.inner.pool.is_shutdown()
    }

    /// Pool-level notification receiver. See
    /// [`nula_relay_pool::PoolNotification`] for the event variants.
    #[must_use]
    pub fn notifications(
        &self,
    ) -> tokio::sync::broadcast::Receiver<nula_relay_pool::PoolNotification> {
        self.inner.pool.notifications()
    }

    /// Shut every relay down and wait for all driver tasks to drain.
    ///
    /// After this returns, every subsequent call that touches the
    /// pool will error with [`nula_relay_pool::Error::Shutdown`].
    pub async fn shutdown(&self) {
        self.inner.pool.shutdown().await;
    }

    /// Register a relay with `READ | WRITE` capabilities.
    ///
    /// Accepts anything that parses into a [`RelayUrl`] — `&str`,
    /// `String`, or a pre-parsed `RelayUrl`.
    ///
    /// Returns `Ok(true)` when the relay is freshly added,
    /// `Ok(false)` when it was already present (the new
    /// capabilities are merged into the existing entry).
    ///
    /// # Errors
    ///
    /// - [`Error::Pool`] if the pool was shut down or its
    ///   `max_relays` cap is hit.
    pub async fn add_relay<U>(&self, url: U) -> Result<bool, Error>
    where
        U: IntoRelayUrl,
    {
        let url = url.into_relay_url()?;
        self.add_relay_with_capabilities(url, RelayCapabilities::default())
            .await
    }

    /// Same as [`Self::add_relay`] but lets the caller pin specific
    /// capabilities (e.g. discovery-only, write-only).
    ///
    /// # Errors
    ///
    /// See [`Self::add_relay`].
    pub async fn add_relay_with_capabilities(
        &self,
        url: RelayUrl,
        capabilities: RelayCapabilities,
    ) -> Result<bool, Error> {
        Ok(self.inner.pool.add_relay(url, capabilities).await?)
    }

    /// Disconnect and forget a relay.
    ///
    /// # Errors
    ///
    /// - [`Error::Pool`] when the url is not in the pool.
    pub async fn remove_relay(&self, url: &RelayUrl) -> Result<(), Error> {
        Ok(self.inner.pool.remove_relay(url, false).await?)
    }

    /// Force-remove a relay regardless of any lingering
    /// subscriptions.
    ///
    /// # Errors
    ///
    /// See [`Self::remove_relay`].
    pub async fn force_remove_relay(&self, url: &RelayUrl) -> Result<(), Error> {
        Ok(self.inner.pool.remove_relay(url, true).await?)
    }

    /// Look up a relay by url. Returns a clone of the [`Relay`]
    /// handle (cheap, shares the same actor).
    pub async fn relay(&self, url: &RelayUrl) -> Option<Relay> {
        self.inner.pool.relay(url).await
    }

    /// Snapshot every relay currently in the pool.
    pub async fn relays(&self) -> Vec<RelayUrl> {
        self.inner.pool.relays().await.into_keys().collect()
    }

    /// Best-effort connect every relay in the pool concurrently.
    ///
    /// Per-relay errors are recorded in the returned [`Output`]; an
    /// individual failure does **not** abort the others.
    pub async fn connect(&self) -> Output<()> {
        self.inner.pool.connect().await
    }

    /// Connect every relay with a per-attempt timeout.
    pub async fn try_connect(&self, per_relay_timeout: Duration) -> Output<()> {
        self.inner.pool.try_connect(per_relay_timeout).await
    }

    /// Disconnect every relay.
    pub async fn disconnect(&self) -> Output<()> {
        self.inner.pool.disconnect().await
    }

    /// Sign an [`EventBuilder`] with the client's configured signer.
    ///
    /// Constructs the [`UnsignedEvent`](nula_core::UnsignedEvent)
    /// with `created_at` taken from the builder (or `now`) and the
    /// signer's public key, then awaits
    /// [`NostrSigner::sign_event`].
    ///
    /// # Errors
    ///
    /// - [`Error::SignerNotConfigured`] if no signer was attached to
    ///   the [`ClientBuilder`].
    /// - [`Error::EventBuilder`] if `build_unsigned` failed (clock /
    ///   pubkey mismatch).
    /// - [`Error::Pool`] if the signer's `sign_event` future returned
    ///   an error (wrapped in
    ///   [`nula_relay_pool::Error`] via the signer adapter).
    pub async fn sign_event_builder(&self, builder: EventBuilder) -> Result<Event, Error> {
        let signer = self
            .inner
            .signer
            .as_ref()
            .ok_or(Error::SignerNotConfigured)?;
        let pubkey = signer.get_public_key().await.map_err(Error::Signer)?;
        let unsigned = builder.build_unsigned(pubkey)?;
        let event = signer.sign_event(unsigned).await.map_err(Error::Signer)?;
        Ok(event)
    }

    /// Publish `event` to every relay carrying
    /// [`RelayCapabilities::WRITE`].
    ///
    /// # Errors
    ///
    /// - [`Error::Pool`] when the pool has no WRITE-capable relays.
    pub async fn send_event(&self, event: Event) -> Result<Output<EventId>, Error> {
        Ok(self.inner.pool.send_event(event).await?)
    }

    /// Publish `event` to a caller-chosen relay set.
    ///
    /// # Errors
    ///
    /// - [`Error::RelayUrl`] if any element of `urls` fails to parse.
    /// - [`Error::Pool`] for empty url sets or unknown relays.
    pub async fn send_event_to<I, U>(&self, urls: I, event: Event) -> Result<Output<EventId>, Error>
    where
        I: IntoIterator<Item = U>,
        U: IntoRelayUrl,
    {
        let urls = collect_relay_urls(urls)?;
        Ok(self.inner.pool.send_event_to(urls, event).await?)
    }

    /// Sign the builder with the configured signer, then publish to
    /// every WRITE-capable relay.
    ///
    /// # Errors
    ///
    /// Combined surface of [`Self::sign_event_builder`] and
    /// [`Self::send_event`].
    pub async fn send_event_builder(
        &self,
        builder: EventBuilder,
    ) -> Result<Output<EventId>, Error> {
        let event = self.sign_event_builder(builder).await?;
        self.send_event(event).await
    }

    /// Sign and publish to a caller-chosen relay set.
    ///
    /// # Errors
    ///
    /// Combined surface of [`Self::sign_event_builder`] and
    /// [`Self::send_event_to`].
    pub async fn send_event_builder_to<I, U>(
        &self,
        urls: I,
        builder: EventBuilder,
    ) -> Result<Output<EventId>, Error>
    where
        I: IntoIterator<Item = U>,
        U: IntoRelayUrl,
    {
        let event = self.sign_event_builder(builder).await?;
        self.send_event_to(urls, event).await
    }

    /// One-shot fetch: opens a subscription with `close_on_eose`,
    /// collects every event delivered before the optional `timeout`
    /// or EOSE, and returns the deduplicated result set.
    ///
    /// Events arriving from multiple relays are deduplicated by
    /// [`EventId`] (LRU-bounded by
    /// [`nula_relay_pool::RelayPoolOptions::dedup_cache_size`]) and
    /// the returned [`Events`] is in canonical newest-first order.
    ///
    /// # Errors
    ///
    /// - [`Error::Pool`] if no READ-capable relay is registered or
    ///   if any relay's `subscribe` future fails.
    pub async fn fetch_events(
        &self,
        filter: Filter,
        timeout: Option<Duration>,
    ) -> Result<Events, Error> {
        let stream = self.stream_events(filter, timeout).await?;
        Ok(collect_events(stream).await)
    }

    /// [`Self::fetch_events`] restricted to a caller-chosen relay set.
    ///
    /// # Errors
    ///
    /// - [`Error::RelayUrl`] if any element of `urls` fails to parse.
    /// - [`Error::Pool`] for the usual empty-set / unknown-url paths.
    pub async fn fetch_events_from<I, U>(
        &self,
        urls: I,
        filter: Filter,
        timeout: Option<Duration>,
    ) -> Result<Events, Error>
    where
        I: IntoIterator<Item = U>,
        U: IntoRelayUrl,
    {
        let stream = self.stream_events_from(urls, filter, timeout).await?;
        Ok(collect_events(stream).await)
    }

    /// Open a subscription with `close_on_eose = true` and surface
    /// the (relay, event-or-error) stream directly.
    ///
    /// Use this when the caller wants to react to events as they
    /// arrive rather than materialising the full [`Events`] set;
    /// otherwise prefer [`Self::fetch_events`].
    ///
    /// # Errors
    ///
    /// See [`nula_relay_pool::RelayPool::stream_events`].
    pub async fn stream_events(
        &self,
        filter: Filter,
        timeout: Option<Duration>,
    ) -> Result<BoxStream<'static, (RelayUrl, Result<Event, nula_relay::Error>)>, Error> {
        let options = SubscribeOptions::default().close_on_eose(true);
        Ok(self
            .inner
            .pool
            .stream_events(vec![filter], options, timeout)
            .await?)
    }

    /// [`Self::stream_events`] restricted to a caller-chosen relay set.
    ///
    /// # Errors
    ///
    /// - [`Error::RelayUrl`] for unparseable urls.
    /// - [`Error::Pool`] / [`Error::Relay`] from the per-relay drivers.
    pub async fn stream_events_from<I, U>(
        &self,
        urls: I,
        filter: Filter,
        timeout: Option<Duration>,
    ) -> Result<BoxStream<'static, (RelayUrl, Result<Event, nula_relay::Error>)>, Error>
    where
        I: IntoIterator<Item = U>,
        U: IntoRelayUrl,
    {
        let urls = collect_relay_urls(urls)?;
        let options = SubscribeOptions::default().close_on_eose(true);
        Ok(self
            .inner
            .pool
            .stream_events_to(urls, vec![filter], options, timeout)
            .await?)
    }

    /// Open a long-lived subscription on every READ-capable relay
    /// with a fresh [`SubscriptionId`]. Returns the id wrapped in an
    /// [`Output`] so the caller can correlate per-relay success or
    /// failure.
    ///
    /// The subscription is auto-closed by the pool when the
    /// returned id is passed to [`Self::unsubscribe`] or when the
    /// [`Client`] is dropped.
    ///
    /// # Errors
    ///
    /// - [`Error::Pool`] when no READ-capable relay is registered or
    ///   when [`SubscriptionId::generate`] fails (RNG exhausted).
    pub async fn subscribe(
        &self,
        filter: Filter,
        options: SubscribeOptions,
    ) -> Result<Output<SubscriptionId>, Error> {
        let id = SubscriptionId::generate()?;
        self.subscribe_with_id(id, filter, options).await
    }

    /// [`Self::subscribe`] with a caller-supplied subscription id.
    ///
    /// Useful when the application needs to issue the same id to
    /// several relays in lock-step (e.g. for downstream NIP-29 group
    /// coordination).
    ///
    /// # Errors
    ///
    /// See [`Self::subscribe`].
    pub async fn subscribe_with_id(
        &self,
        id: SubscriptionId,
        filter: Filter,
        options: SubscribeOptions,
    ) -> Result<Output<SubscriptionId>, Error> {
        Ok(self.inner.pool.subscribe(id, vec![filter], options).await?)
    }

    /// [`Self::subscribe`] restricted to a caller-chosen relay set.
    ///
    /// # Errors
    ///
    /// - [`Error::RelayUrl`] for unparseable urls.
    /// - [`Error::Pool`] for empty / unknown relay sets and for
    ///   subscription-id generation failures.
    pub async fn subscribe_to<I, U>(
        &self,
        urls: I,
        filter: Filter,
        options: SubscribeOptions,
    ) -> Result<Output<SubscriptionId>, Error>
    where
        I: IntoIterator<Item = U>,
        U: IntoRelayUrl,
    {
        let id = SubscriptionId::generate()?;
        let urls = collect_relay_urls(urls)?;
        Ok(self
            .inner
            .pool
            .subscribe_to(urls, id, vec![filter], options)
            .await?)
    }

    /// Cancel a subscription on every relay that carries it.
    ///
    /// Returns an [`Output`] reflecting per-relay observability of
    /// the unsubscribe; relays without the subscription are silently
    /// ignored.
    pub async fn unsubscribe(&self, id: &SubscriptionId) -> Output<()> {
        self.inner.pool.unsubscribe(id).await
    }
}

/// Drain a `(RelayUrl, Result<Event, _>)` stream into a single
/// canonical-order [`Events`] set, dropping per-relay errors.
///
/// Equivalent to the `fetch_events` collector in upstream
/// `nostr_sdk::Client`. Per-relay errors are swallowed because they
/// have already been surfaced to the pool's notification channel;
/// the fetch path's contract is "best-effort union".
async fn collect_events(
    mut stream: BoxStream<'static, (RelayUrl, Result<Event, nula_relay::Error>)>,
) -> Events {
    let mut events: Vec<Event> = Vec::new();
    while let Some((_url, item)) = stream.next().await {
        if let Ok(event) = item {
            events.push(event);
        }
    }
    Events::from_unsorted(events)
}
