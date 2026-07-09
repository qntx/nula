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

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use nula_core::BoxStream;
use nula_core::event::{Event, EventBuilder, EventId};
use nula_core::filter::Filter;
use nula_core::message::{ClientMessage, SubscriptionId};
use nula_core::signer::NostrSigner;
use nula_core::types::RelayUrl;
#[cfg(feature = "gossip")]
use nula_gossip::Gossip;
use nula_relay::pool::{Output, PoolNotification, RelayCapabilities, RelayPool};
use nula_relay::{Relay, RelayOptions, RelayStatus, SubscribeOptions};
use nula_storage::{Events, NostrDatabase};
use tokio::sync::Mutex;

use crate::builder::ClientBuilder;
use crate::error::Error;
use crate::monitor::Monitor;
use crate::policy::{AdmitPolicy, AdmitStatus};
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
    /// Background NIP-65 / NIP-17 refresher task. `Some` when gossip
    /// is configured with a non-`None`
    /// [`refresher_interval`](nula_gossip::GossipOptions::refresher_interval);
    /// dropping it (with the last [`Client`] clone) aborts the loop.
    #[cfg(feature = "gossip")]
    #[expect(
        dead_code,
        reason = "drop guard: the field is never read, its Drop aborts the refresher task"
    )]
    pub(crate) gossip_refresher: Option<crate::gossip::GossipRefresher>,
    pub(crate) config: ClientConfig,
    /// Client-side registry of every active subscription. Keyed by
    /// `SubscriptionId`, the value records which relays the
    /// subscription was issued against and the filter set used.
    pub(crate) subscriptions: Mutex<HashMap<SubscriptionId, SubscriptionRecord>>,
    /// Status broadcaster + forwarder abort handle, when the caller
    /// opted in via [`ClientBuilder::monitor`].
    pub(crate) monitor: Option<MonitorState>,
    /// Optional client-side admission policy. When `None` every
    /// admission gate short-circuits to [`AdmitStatus::Success`].
    pub(crate) admit_policy: Option<Arc<dyn AdmitPolicy>>,
}

/// Per-subscription bookkeeping kept on the [`Client`] side.
///
/// `RelayPool` itself is intentionally registry-less (every
/// `SubscriptionHandle` carries its own auto-close lifecycle);
/// the SDK layer adds this map so callers can list active
/// subscriptions and broadcast cancellations without keeping the
/// handles alive themselves.
#[derive(Debug, Clone)]
pub struct SubscriptionRecord {
    /// Relays the subscription targets.
    pub relays: Vec<RelayUrl>,
    /// Filter set the subscription was issued with.
    pub filters: Vec<Filter>,
}

/// State for the optional [`Monitor`] forwarder.
#[derive(Debug)]
pub(crate) struct MonitorState {
    /// Broadcaster handed back to callers.
    pub(crate) monitor: Monitor,
    /// Forwarder task; aborted on shutdown.
    pub(crate) forwarder: tokio::task::AbortHandle,
}

impl Drop for MonitorState {
    fn drop(&mut self) {
        self.forwarder.abort();
    }
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
    #[expect(
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
    /// [`nula_relay::pool::PoolNotification`] for the event variants.
    #[must_use]
    pub fn notifications(&self) -> tokio::sync::broadcast::Receiver<PoolNotification> {
        self.inner.pool.notifications()
    }

    /// Shut every relay down and wait for all driver tasks to drain.
    ///
    /// After this returns, every subsequent call that touches the
    /// pool will error with [`nula_relay::pool::Error::Shutdown`].
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
        self.check_admit_relay(&url).await?;
        Ok(self.inner.pool.add_relay(url, capabilities).await?)
    }

    /// Same as [`Self::add_relay_with_capabilities`] but pins per-relay
    /// [`RelayOptions`] (e.g. a SOCKS5 / Tor
    /// [`nula_relay::transport::ConnectionMode`], reconnect policy, or
    /// timeout) instead of the pool-wide default.
    ///
    /// Use this when one relay needs a different proxy or policy than
    /// the rest. To route **every** relay through the same proxy, prefer
    /// [`ClientBuilder::relay_options`](crate::ClientBuilder::relay_options)
    /// so gossip-discovered relays inherit it too.
    ///
    /// # Errors
    ///
    /// See [`Self::add_relay`].
    pub async fn add_relay_with_options(
        &self,
        url: RelayUrl,
        capabilities: RelayCapabilities,
        options: RelayOptions,
    ) -> Result<bool, Error> {
        self.check_admit_relay(&url).await?;
        Ok(self
            .inner
            .pool
            .add_relay_with_options(url, capabilities, options)
            .await?)
    }

    /// Disconnect and forget a relay, dropping any subscriptions it
    /// still carries.
    ///
    /// # Errors
    ///
    /// - [`Error::Pool`] when the url is not in the pool.
    pub async fn remove_relay(&self, url: &RelayUrl) -> Result<(), Error> {
        Ok(self.inner.pool.remove_relay(url).await?)
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
    ///   [`nula_relay::pool::Error`] via the signer adapter).
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

    /// Publish `event`.
    ///
    /// When a gossip router is configured (the `gossip` feature plus
    /// `ClientBuilder::gossip`) the event is routed via the NIP-65
    /// outbox model — the author's outbox relays unioned with each
    /// `#p` recipient's inbox relays (DM relays for NIP-17 gift
    /// wraps) — auto-adding and connecting any relay the pool does not
    /// yet know. Otherwise it broadcasts to every relay carrying
    /// [`RelayCapabilities::WRITE`].
    ///
    /// # Errors
    ///
    /// - `Error::PrivateMessageRelaysNotFound` (gossip only) when
    ///   routing a NIP-17 gift wrap whose recipients advertise no DM
    ///   relays.
    /// - [`Error::Pool`] when the pool has no WRITE-capable relays.
    pub async fn send_event(&self, event: Event) -> Result<Output<EventId>, Error> {
        #[cfg(feature = "gossip")]
        if let Some(gossip) = &self.inner.gossip {
            return self.gossip_send_event(gossip, event).await;
        }
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
    /// [`nula_relay::pool::RelayPoolOptions::dedup_cache_size`]) and
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
    /// When a gossip router is configured (the `gossip` feature plus
    /// `ClientBuilder::gossip`) the filter is broken into per-relay
    /// sub-filters via the NIP-65 inbox/outbox model and the
    /// resulting per-relay streams are merged; relays the pool does
    /// not yet know are added and connected on demand. Filters with
    /// no public-key routing signal stream from the generic READ pool.
    ///
    /// # Errors
    ///
    /// See [`nula_relay::pool::RelayPool::stream_events`].
    pub async fn stream_events(
        &self,
        filter: Filter,
        timeout: Option<Duration>,
    ) -> Result<BoxStream<'static, (RelayUrl, Result<Event, nula_relay::Error>)>, Error> {
        #[cfg(feature = "gossip")]
        if let Some(gossip) = &self.inner.gossip {
            return self.gossip_stream_events(gossip, filter, timeout).await;
        }
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
        #[cfg(feature = "gossip")]
        if let Some(gossip) = &self.inner.gossip {
            return self.gossip_subscribe(gossip, id, filter, options).await;
        }
        let output = self
            .inner
            .pool
            .subscribe(id.clone(), vec![filter.clone()], options)
            .await?;
        let relays: Vec<RelayUrl> = output.success.iter().cloned().collect();
        if !relays.is_empty() {
            let mut subs = self.inner.subscriptions.lock().await;
            subs.insert(
                id.clone(),
                SubscriptionRecord {
                    relays,
                    filters: vec![filter],
                },
            );
        }
        Ok(output)
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
        let output = self
            .inner
            .pool
            .subscribe_to(urls.clone(), id.clone(), vec![filter.clone()], options)
            .await?;
        if !output.success.is_empty() {
            let mut subs = self.inner.subscriptions.lock().await;
            subs.insert(
                id.clone(),
                SubscriptionRecord {
                    relays: urls.into_iter().collect(),
                    filters: vec![filter],
                },
            );
        }
        Ok(output)
    }

    /// Cancel a subscription on every relay that carries it.
    ///
    /// Returns an [`Output`] reflecting per-relay observability of
    /// the unsubscribe; relays without the subscription are silently
    /// ignored.
    pub async fn unsubscribe(&self, id: &SubscriptionId) -> Output<()> {
        {
            let mut subs = self.inner.subscriptions.lock().await;
            subs.remove(id);
        }
        self.inner.pool.unsubscribe(id).await
    }

    /// Cancel every active subscription on every relay it touches.
    /// Returns the merged per-relay [`Output`].
    pub async fn unsubscribe_all(&self) -> Output<()> {
        let ids: Vec<SubscriptionId> = {
            let subs = self.inner.subscriptions.lock().await;
            subs.keys().cloned().collect()
        };
        let mut merged: Output<()> = Output::default();
        for id in ids {
            let per_id = self.unsubscribe(&id).await;
            merged.success.extend(per_id.success);
            for (url, reason) in per_id.failed {
                merged.failed.insert(url, reason);
            }
        }
        merged
    }

    /// Snapshot of every active subscription, keyed by id, with the
    /// per-subscription relay set and filter list.
    pub async fn subscriptions(&self) -> HashMap<SubscriptionId, SubscriptionRecord> {
        let subs = self.inner.subscriptions.lock().await;
        subs.clone()
    }

    /// Look up a single subscription by id.
    pub async fn subscription(&self, id: &SubscriptionId) -> Option<SubscriptionRecord> {
        let subs = self.inner.subscriptions.lock().await;
        subs.get(id).cloned()
    }

    /// Status-only broadcaster. `None` when the
    /// [`ClientBuilder::monitor`] opt-in was not invoked.
    ///
    /// [`ClientBuilder::monitor`]: crate::ClientBuilder::monitor
    #[must_use]
    pub fn monitor(&self) -> Option<&Monitor> {
        self.inner.monitor.as_ref().map(|state| &state.monitor)
    }

    /// Block until every relay registered on the pool is
    /// [`RelayStatus::Connected`] or `timeout` elapses.
    ///
    /// Returns `true` when every relay reached `Connected` within
    /// the deadline; `false` when the timeout fired with at least
    /// one relay still in another state. Listens on the pool's
    /// notification channel so the call wakes up as soon as the
    /// last laggard transitions.
    pub async fn wait_for_connection(&self, timeout: Duration) -> bool {
        // Fast path: poll the current state once before subscribing
        // to notifications.
        let mut rx = self.inner.pool.notifications();
        if self.all_relays_connected().await {
            return true;
        }
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return false;
            }
            let remaining = deadline - now;
            let recv = tokio::time::timeout(remaining, rx.recv()).await;
            match recv {
                Ok(Ok(PoolNotification::Status { .. })) if self.all_relays_connected().await => {
                    return true;
                }
                Ok(Ok(_)) => {}
                Ok(Err(_)) | Err(_) => return false,
            }
        }
    }

    async fn all_relays_connected(&self) -> bool {
        let relays = self.inner.pool.relays().await;
        if relays.is_empty() {
            return false;
        }
        relays
            .values()
            .all(|relay| relay.status() == RelayStatus::Connected)
    }

    /// Fan-out an arbitrary [`ClientMessage`] to every relay in the
    /// pool. Returns the merged per-relay [`Output`].
    ///
    /// Use this for message variants the SDK's bespoke
    /// `send_event` / `subscribe` / `sync` paths do not model -- the
    /// most common case being NIP-77 `NegMsg` / `NegClose` frames
    /// the sync driver ships.
    pub async fn send_msg(&self, message: ClientMessage) -> Output<()> {
        self.inner.pool.send_msg(message).await
    }

    /// Register a relay with [`RelayCapabilities::DISCOVERY`].
    ///
    /// Convenience wrapper around
    /// [`Self::add_relay_with_capabilities`] for relays the caller
    /// wants to use only for NIP-65 discovery (peers' inbox/outbox
    /// metadata).
    ///
    /// # Errors
    ///
    /// See [`Self::add_relay`].
    pub async fn add_discovery_relay<U>(&self, url: U) -> Result<bool, Error>
    where
        U: IntoRelayUrl,
    {
        let url = url.into_relay_url()?;
        self.add_relay_with_capabilities(url, RelayCapabilities::DISCOVERY)
            .await
    }

    /// Register a relay with [`RelayCapabilities::READ`].
    ///
    /// # Errors
    ///
    /// See [`Self::add_relay`].
    pub async fn add_read_relay<U>(&self, url: U) -> Result<bool, Error>
    where
        U: IntoRelayUrl,
    {
        let url = url.into_relay_url()?;
        self.add_relay_with_capabilities(url, RelayCapabilities::READ)
            .await
    }

    /// Register a relay with [`RelayCapabilities::WRITE`].
    ///
    /// # Errors
    ///
    /// See [`Self::add_relay`].
    pub async fn add_write_relay<U>(&self, url: U) -> Result<bool, Error>
    where
        U: IntoRelayUrl,
    {
        let url = url.into_relay_url()?;
        self.add_relay_with_capabilities(url, RelayCapabilities::WRITE)
            .await
    }

    /// Register a relay with [`RelayCapabilities::GOSSIP`].
    ///
    /// Use this for relays the caller explicitly pins for NIP-65
    /// routing. Compare with [`Self::add_discovery_relay`], which
    /// flags relays as merely seen on a peer's published list.
    ///
    /// # Errors
    ///
    /// See [`Self::add_relay`].
    pub async fn add_gossip_relay<U>(&self, url: U) -> Result<bool, Error>
    where
        U: IntoRelayUrl,
    {
        let url = url.into_relay_url()?;
        self.add_relay_with_capabilities(url, RelayCapabilities::GOSSIP)
            .await
    }

    /// Remove every relay currently in the pool. Errors that fire on
    /// individual relays are accumulated in the returned
    /// [`Output`]; an individual failure does **not** abort the
    /// rest.
    pub async fn remove_all_relays(&self) -> Output<()> {
        let urls = self.inner.pool.relays().await;
        let mut output: Output<()> = Output::default();
        for url in urls.into_keys() {
            match self.inner.pool.remove_relay(&url).await {
                Ok(()) => {
                    output.success.insert(url);
                }
                Err(e) => {
                    output.failed.insert(url, e.to_string());
                }
            }
        }
        output
    }

    /// Connect a single relay.
    ///
    /// # Errors
    ///
    /// - [`Error::UnknownRelay`] when `url` is not registered.
    /// - [`Error::PolicyRejected`] when the configured
    ///   [`AdmitPolicy`] vetoes the connection.
    /// - [`Error::Relay`] propagated from the actor's `connect` future.
    pub async fn connect_relay(&self, url: &RelayUrl) -> Result<(), Error> {
        let relay = self
            .inner
            .pool
            .relay(url)
            .await
            .ok_or_else(|| Error::UnknownRelay { url: url.clone() })?;
        self.check_admit_connection(url).await?;
        relay.connect().await?;
        Ok(())
    }

    /// Connect a single relay with a per-attempt timeout.
    ///
    /// # Errors
    ///
    /// See [`Self::connect_relay`].
    pub async fn try_connect_relay(&self, url: &RelayUrl, timeout: Duration) -> Result<(), Error> {
        let relay = self
            .inner
            .pool
            .relay(url)
            .await
            .ok_or_else(|| Error::UnknownRelay { url: url.clone() })?;
        self.check_admit_connection(url).await?;
        tokio::time::timeout(timeout, relay.connect())
            .await
            .map_err(|_| Error::ConnectTimeout { url: url.clone() })
            .and_then(|res| res.map_err(Error::Relay))?;
        Ok(())
    }

    /// Borrow the configured [`AdmitPolicy`], if any. Useful for
    /// callers consuming raw subscription / fetch streams that
    /// want to apply [`AdmitPolicy::admit_event`] themselves.
    #[must_use]
    pub fn admit_policy(&self) -> Option<&Arc<dyn AdmitPolicy>> {
        self.inner.admit_policy.as_ref()
    }

    /// Run [`AdmitPolicy::admit_relay`] on the configured policy,
    /// returning [`Error::PolicyRejected`] on `Rejected` and
    /// [`Error::Policy`] on backend errors.
    pub(crate) async fn check_admit_relay(&self, url: &RelayUrl) -> Result<(), Error> {
        let Some(policy) = &self.inner.admit_policy else {
            return Ok(());
        };
        match policy.admit_relay(url).await? {
            AdmitStatus::Success => Ok(()),
            AdmitStatus::Rejected { reason } => Err(Error::PolicyRejected {
                stage: "relay",
                reason,
            }),
        }
    }

    /// Run [`AdmitPolicy::admit_connection`].
    pub(crate) async fn check_admit_connection(&self, url: &RelayUrl) -> Result<(), Error> {
        let Some(policy) = &self.inner.admit_policy else {
            return Ok(());
        };
        match policy.admit_connection(url).await? {
            AdmitStatus::Success => Ok(()),
            AdmitStatus::Rejected { reason } => Err(Error::PolicyRejected {
                stage: "connection",
                reason,
            }),
        }
    }

    /// Run [`AdmitPolicy::admit_event`].
    ///
    /// # Errors
    ///
    /// - [`Error::PolicyRejected`] when the policy rejects.
    /// - [`Error::Policy`] on backend errors.
    pub async fn check_admit_event(
        &self,
        relay_url: &RelayUrl,
        subscription_id: &SubscriptionId,
        event: &Event,
    ) -> Result<(), Error> {
        let Some(policy) = &self.inner.admit_policy else {
            return Ok(());
        };
        match policy
            .admit_event(relay_url, subscription_id, event)
            .await?
        {
            AdmitStatus::Success => Ok(()),
            AdmitStatus::Rejected { reason } => Err(Error::PolicyRejected {
                stage: "event",
                reason,
            }),
        }
    }

    /// Disconnect a single relay.
    ///
    /// # Errors
    ///
    /// - [`Error::UnknownRelay`] when `url` is not registered.
    /// - [`Error::Relay`] from the underlying actor.
    pub async fn disconnect_relay(&self, url: &RelayUrl) -> Result<(), Error> {
        let relay = self
            .inner
            .pool
            .relay(url)
            .await
            .ok_or_else(|| Error::UnknownRelay { url: url.clone() })?;
        relay.disconnect().await?;
        Ok(())
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
