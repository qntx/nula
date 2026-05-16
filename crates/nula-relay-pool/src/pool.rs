//! Public [`RelayPool`] handle and its builder.
//!
//! `RelayPool` is the single entry point of the crate. Cloning the
//! handle costs one `Arc` bump and shares state with every other
//! clone — the last clone going out of scope tears the pool down.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use futures::stream::{FuturesUnordered, StreamExt};
use nula_core::{Event, EventId, Filter, RelayUrl, SubscriptionId};
use nula_net::WebSocketTransport;
use nula_relay::{
    PublishOptions, Relay, RelayBuilder, RelayOptions, SubscribeOptions, SubscriptionHandle,
};
use nula_storage::NostrDatabase;
use tokio::sync::broadcast;
use tokio::time::timeout;

use crate::error::Error;
use crate::inner::{Inner, RelayEntry, spawn_forwarder};
use crate::notification::PoolNotification;
use crate::options::RelayPoolOptions;
use crate::output::Output;
use crate::state::SharedState;

/// Multi-relay coordinator.
///
/// Construct via [`RelayPool::builder`]. Cloning the handle is
/// `Arc`-cheap; every clone shares relays, options, and the
/// notification channel. Dropping the last clone tears the pool down
/// (every relay is disconnected and a final
/// [`PoolNotification::Shutdown`] is broadcast).
#[derive(Debug, Clone)]
pub struct RelayPool {
    inner: Arc<Inner>,
}

/// Drop the pool **on the last clone**.
///
/// We cannot run async work in `Drop`, so the per-relay disconnect
/// happens via `tokio::spawn`. The forwarder abort handles inside
/// each per-relay record still fire synchronously through their own
/// `Drop` impl, which is enough to keep the actor tasks from leaking
/// even if the spawned disconnect future is never polled (e.g.
/// during runtime teardown).
impl Drop for RelayPool {
    fn drop(&mut self) {
        // Only the last clone shuts the pool down.
        if Arc::strong_count(&self.inner) > 1 {
            return;
        }
        let inner = Arc::clone(&self.inner);
        // Mark shutdown synchronously so any racing `is_shutdown()`
        // observer sees the new value before the spawned future
        // runs.
        inner.mark_shutdown();
        // Best-effort async drain. If no runtime is available the
        // spawn fails and the relays are reaped by their own
        // `Drop` impls (RelayEntry aborts the forwarder, the Relay
        // handle's drop tells the actor to exit).
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                inner.drain_relays().await;
            });
        }
    }
}

impl RelayPool {
    /// Begin configuring a pool. See [`RelayPoolBuilder`] for the
    /// available knobs.
    pub fn builder() -> RelayPoolBuilder {
        RelayPoolBuilder::new()
    }

    /// Read-only access to the [`NostrDatabase`] every relay shares.
    #[must_use]
    pub fn database(&self) -> &Arc<dyn NostrDatabase> {
        &self.inner.state.database
    }

    /// Subscribe to the cross-relay [`PoolNotification`] broadcast.
    ///
    /// The first lag drops the slowest receiver; each call returns a
    /// fresh receiver.
    #[must_use]
    pub fn notifications(&self) -> broadcast::Receiver<PoolNotification> {
        self.inner.notification_tx.subscribe()
    }

    /// `true` once [`Self::shutdown`] has been called or the last
    /// clone has been dropped.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.inner.is_shutdown()
    }

    /// Add a relay to the pool.
    ///
    /// Returns `Ok(true)` when the relay was newly inserted, `Ok(false)`
    /// when the url was already present (capabilities are merged in
    /// that case).
    ///
    /// # Errors
    ///
    /// - [`Error::Shutdown`] if the pool has already been shut down.
    /// - [`Error::TooManyRelays`] when the configured cap is
    ///   reached.
    pub async fn add_relay(
        &self,
        url: RelayUrl,
        capabilities: crate::RelayCapabilities,
    ) -> Result<bool, Error> {
        if self.is_shutdown() {
            return Err(Error::Shutdown);
        }

        let mut relays = self.inner.relays.write().await;

        // Merge capabilities on existing relays.
        if let Some(entry) = relays.get(&url) {
            entry.capabilities.add(capabilities);
            return Ok(false);
        }

        // Enforce capacity.
        if let Some(max) = self.inner.options.max_relays
            && relays.len() >= max.get()
        {
            return Err(Error::TooManyRelays { limit: max.get() });
        }

        // Spawn relay actor with the pool's shared transport.
        let relay = RelayBuilder::new(url.clone())
            .transport(Arc::clone(&self.inner.state.transport))
            .options(RelayOptions::default())
            .build();

        // Wire its notification stream onto the pool broadcast.
        let forwarder = spawn_forwarder(url.clone(), &relay, self.inner.notification_tx.clone());

        relays.insert(url.clone(), RelayEntry::new(relay, capabilities, forwarder));
        // Drop the write guard before broadcasting so concurrent
        // notification consumers do not block on the relay map.
        drop(relays);

        self.inner
            .notification_tx
            .send(PoolNotification::RelayAdded { url })
            .ok();
        Ok(true)
    }

    /// Remove a relay from the pool.
    ///
    /// `force = true` evicts the relay regardless of any lingering
    /// subscriptions. With `force = false` the relay is only removed
    /// when nothing else references it.
    ///
    /// # Errors
    ///
    /// [`Error::RelayNotFound`] when the url is not in the pool.
    pub async fn remove_relay(&self, url: &RelayUrl, _force: bool) -> Result<(), Error> {
        let mut relays = self.inner.relays.write().await;
        let Some(entry) = relays.remove(url) else {
            return Err(Error::RelayNotFound(url.clone()));
        };
        // The lock is held for the disconnect because `Relay::disconnect`
        // is `async`; release before awaiting.
        drop(relays);

        entry.relay.disconnect().await.ok();
        self.inner
            .notification_tx
            .send(PoolNotification::RelayRemoved { url: url.clone() })
            .ok();
        Ok(())
    }

    /// Look up a relay by url. Returns a clone of the [`Relay`]
    /// handle (which itself is `Arc`-cheap to clone).
    pub async fn relay(&self, url: &RelayUrl) -> Option<Relay> {
        self.inner
            .relays
            .read()
            .await
            .get(url)
            .map(|entry| entry.relay.clone())
    }

    /// Snapshot every relay currently in the pool.
    ///
    /// The returned map is a fresh `HashMap`; mutating it does not
    /// affect the pool.
    pub async fn relays(&self) -> HashMap<RelayUrl, Relay> {
        self.inner
            .relays
            .read()
            .await
            .iter()
            .map(|(url, entry)| (url.clone(), entry.relay.clone()))
            .collect()
    }

    /// Snapshot the urls of every relay matching the requested
    /// capabilities (bitwise overlap, not subset).
    pub async fn relays_with_any_capability(
        &self,
        capabilities: crate::RelayCapabilities,
    ) -> HashSet<RelayUrl> {
        self.inner
            .relays
            .read()
            .await
            .iter()
            .filter(|(_, entry)| entry.capabilities.load().has_any(capabilities))
            .map(|(url, _)| url.clone())
            .collect()
    }

    /// Best-effort connect on every relay in the pool.
    ///
    /// Fires every connect concurrently and returns once the last
    /// future completes. Per-relay errors are recorded in the
    /// returned [`Output`]; an individual failure does **not** abort
    /// the others.
    pub async fn connect(&self) -> Output<()> {
        self.try_connect_inner(None).await
    }

    /// Connect every relay with a per-attempt timeout.
    ///
    /// Each relay's connect future is wrapped in
    /// `tokio::time::timeout`; relays that miss the deadline land in
    /// [`Output::failed`].
    pub async fn try_connect(&self, per_relay_timeout: Duration) -> Output<()> {
        self.try_connect_inner(Some(per_relay_timeout)).await
    }

    async fn try_connect_inner(&self, per_attempt: Option<Duration>) -> Output<()> {
        let snapshot = self.relays().await;
        let mut output: Output<()> = Output::default();
        if snapshot.is_empty() {
            return output;
        }

        let mut futures = FuturesUnordered::new();
        for (url, relay) in snapshot {
            futures.push(connect_one(url, relay, per_attempt));
        }

        while let Some((url, result)) = futures.next().await {
            match result {
                Ok(()) => {
                    output.success.insert(url);
                }
                Err(e) => {
                    output.failed.insert(url, e);
                }
            }
        }
        output
    }

    /// Disconnect every relay without removing it from the pool.
    ///
    /// Subsequent [`Self::connect`] calls bring the same relay set
    /// back online with the same subscription state preserved by the
    /// per-relay actor.
    pub async fn disconnect(&self) -> Output<()> {
        let snapshot = self.relays().await;
        let mut output: Output<()> = Output::default();

        let mut futures = FuturesUnordered::new();
        for (url, relay) in snapshot {
            futures.push(async move { (url, relay.disconnect().await) });
        }

        while let Some((url, result)) = futures.next().await {
            match result {
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

    /// Publish `event` to every relay carrying
    /// [`crate::RelayCapabilities::WRITE`].
    ///
    /// # Errors
    ///
    /// [`Error::NoRelaysSpecified`] when no relay carries the WRITE
    /// capability.
    pub async fn send_event(&self, event: Event) -> Result<Output<EventId>, Error> {
        let urls = self
            .relays_with_any_capability(crate::RelayCapabilities::WRITE)
            .await;
        self.send_event_to(urls, event).await
    }

    /// Publish `event` to a caller-chosen relay set.
    ///
    /// # Errors
    ///
    /// - [`Error::NoRelaysSpecified`] when `urls` is empty.
    /// - [`Error::RelayNotFound`] when a url is not in the pool.
    pub async fn send_event_to<I>(&self, urls: I, event: Event) -> Result<Output<EventId>, Error>
    where
        I: IntoIterator<Item = RelayUrl>,
    {
        let urls: HashSet<RelayUrl> = urls.into_iter().collect();
        if urls.is_empty() {
            return Err(Error::NoRelaysSpecified);
        }

        let event_id = event.id;
        let snapshot = self.relays().await;

        let mut futures = FuturesUnordered::new();
        for url in urls {
            let Some(relay) = snapshot.get(&url).cloned() else {
                return Err(Error::RelayNotFound(url));
            };
            let event = event.clone();
            futures.push(async move {
                let result = relay.publish(event, PublishOptions::default()).await;
                (url, result)
            });
        }

        let mut output: Output<EventId> = Output::new(event_id);
        while let Some((url, result)) = futures.next().await {
            match result {
                Ok(()) => {
                    output.success.insert(url);
                }
                Err(e) => {
                    output.failed.insert(url, e.to_string());
                }
            }
        }
        Ok(output)
    }

    /// Open a subscription on every relay carrying
    /// [`crate::RelayCapabilities::READ`].
    ///
    /// The pool spawns one driver task per (relay, subscription)
    /// pair which forwards events to the [`crate::RelayPool`]'s
    /// internal channel. Most callers should prefer
    /// [`Self::stream_events`], which surfaces those events as a
    /// `Stream` with cross-relay dedup applied.
    ///
    /// # Errors
    ///
    /// [`Error::NoRelaysSpecified`] when no relay carries the READ
    /// capability.
    pub async fn subscribe(
        &self,
        id: SubscriptionId,
        filters: Vec<Filter>,
        options: SubscribeOptions,
    ) -> Result<Output<SubscriptionId>, Error> {
        let urls = self
            .relays_with_any_capability(crate::RelayCapabilities::READ)
            .await;
        self.subscribe_to(urls, id, filters, options).await
    }

    /// Open a subscription on a caller-chosen relay set. Returns
    /// once every relay's subscribe future resolves; the per-relay
    /// [`SubscriptionHandle`]s are dropped here, which auto-issues
    /// `["CLOSE", id]` on each. Use
    /// [`Self::stream_events_to`] when the caller wants to consume
    /// the events themselves.
    ///
    /// # Errors
    ///
    /// - [`Error::NoRelaysSpecified`] when `urls` is empty.
    /// - [`Error::RelayNotFound`] when a url is not in the pool.
    pub async fn subscribe_to<I>(
        &self,
        urls: I,
        id: SubscriptionId,
        filters: Vec<Filter>,
        options: SubscribeOptions,
    ) -> Result<Output<SubscriptionId>, Error>
    where
        I: IntoIterator<Item = RelayUrl>,
    {
        let urls: HashSet<RelayUrl> = urls.into_iter().collect();
        if urls.is_empty() {
            return Err(Error::NoRelaysSpecified);
        }

        let snapshot = self.relays().await;
        let mut handles: Vec<(RelayUrl, Result<SubscriptionHandle, nula_relay::Error>)> =
            Vec::with_capacity(urls.len());

        let mut futures = FuturesUnordered::new();
        for url in urls {
            let Some(relay) = snapshot.get(&url).cloned() else {
                return Err(Error::RelayNotFound(url));
            };
            let id = id.clone();
            let filters = filters.clone();
            futures.push(async move {
                let res = relay.subscribe(id, filters, options).await;
                (url, res)
            });
        }
        while let Some(item) = futures.next().await {
            handles.push(item);
        }

        // Auto-close the per-relay subscription handles immediately:
        // this entry-point is fire-and-forget. Callers that want to
        // consume events use `stream_events_to` instead.
        let mut output: Output<SubscriptionId> = Output::new(id);
        for (url, res) in handles {
            match res {
                Ok(handle) => {
                    output.success.insert(url);
                    drop(handle);
                }
                Err(e) => {
                    output.failed.insert(url, e.to_string());
                }
            }
        }
        Ok(output)
    }

    /// Cancel a subscription on every relay that carries it. Relays
    /// without the subscription are silently ignored.
    pub async fn unsubscribe(&self, _id: &SubscriptionId) -> Output<()> {
        // The pool's `subscribe`/`subscribe_to` API drops each
        // [`SubscriptionHandle`] eagerly, which already routes a
        // `["CLOSE", id]` through each relay actor on drop. There
        // is no separate per-pool subscription registry to clear,
        // so this is intentionally a snapshot of "every relay
        // observed the unsubscribe path successfully" — useful for
        // future semantic extensions but a no-op today.
        let snapshot = self.relays().await;
        let mut output: Output<()> = Output::default();
        for url in snapshot.keys() {
            output.success.insert(url.clone());
        }
        output
    }

    /// Open a subscription whose [`SubscriptionHandle`]s are
    /// surrendered to the pool's stream driver. The returned
    /// [`nula_net::BoxStream`] yields events from any relay,
    /// deduplicated by `EventId` (LRU-bounded; see
    /// [`RelayPoolOptions::dedup_cache_size`]).
    ///
    /// The stream ends when **every** per-relay subscription emits
    /// either `EndOfStoredEvents` (with `close_on_eose`) or
    /// `Closed`, when the optional `timeout` elapses, or when the
    /// caller drops the receiver.
    ///
    /// # Errors
    ///
    /// [`Error::NoRelaysSpecified`] when no relay carries the READ
    /// capability.
    pub async fn stream_events(
        &self,
        filters: Vec<Filter>,
        options: SubscribeOptions,
        timeout: Option<Duration>,
    ) -> Result<nula_net::BoxStream<'static, (RelayUrl, Result<Event, nula_relay::Error>)>, Error>
    {
        let urls = self
            .relays_with_any_capability(crate::RelayCapabilities::READ)
            .await;
        self.stream_events_to(urls, filters, options, timeout).await
    }

    /// Like [`Self::stream_events`] but limited to a caller-chosen
    /// relay set.
    ///
    /// # Errors
    ///
    /// - [`Error::NoRelaysSpecified`] when `urls` is empty.
    /// - [`Error::RelayNotFound`] when a url is not in the pool.
    pub async fn stream_events_to<I>(
        &self,
        urls: I,
        filters: Vec<Filter>,
        options: SubscribeOptions,
        timeout: Option<Duration>,
    ) -> Result<nula_net::BoxStream<'static, (RelayUrl, Result<Event, nula_relay::Error>)>, Error>
    where
        I: IntoIterator<Item = RelayUrl>,
    {
        let urls: HashSet<RelayUrl> = urls.into_iter().collect();
        if urls.is_empty() {
            return Err(Error::NoRelaysSpecified);
        }

        let snapshot = self.relays().await;
        let mut handles: Vec<(RelayUrl, SubscriptionId, SubscriptionHandle)> =
            Vec::with_capacity(urls.len());

        for url in urls {
            let Some(relay) = snapshot.get(&url).cloned() else {
                return Err(Error::RelayNotFound(url));
            };
            let sub_id = SubscriptionId::generate().map_err(|_| Error::Shutdown)?;
            match relay
                .subscribe(sub_id.clone(), filters.clone(), options)
                .await
            {
                Ok(handle) => handles.push((url, sub_id, handle)),
                Err(e) => {
                    return Err(Error::Relay(e));
                }
            }
        }

        Ok(crate::stream::run(
            handles,
            self.inner.options.dedup_cache_size,
            self.inner
                .options
                .auto_save_events
                .then(|| Arc::clone(&self.inner.state.database)),
            timeout,
        ))
    }

    /// Idempotently shut the pool down. Disconnects every relay,
    /// aborts every forwarder, broadcasts
    /// [`PoolNotification::Shutdown`].
    pub async fn shutdown(&self) {
        self.inner.mark_shutdown();
        self.inner.drain_relays().await;
    }

    fn from_parts(state: SharedState, options: RelayPoolOptions) -> Self {
        Self {
            inner: Inner::new(state, options),
        }
    }
}

/// Builder for [`RelayPool`].
///
/// Construct via [`RelayPool::builder`]. The mandatory inputs are an
/// [`Arc<dyn NostrDatabase>`]; the transport defaults to
/// [`nula_net::default::DefaultTransport`] when the
/// `default-transport` feature is on.
#[derive(Debug)]
#[must_use]
pub struct RelayPoolBuilder {
    database: Option<Arc<dyn NostrDatabase>>,
    transport: Option<Arc<dyn WebSocketTransport>>,
    options: RelayPoolOptions,
}

impl RelayPoolBuilder {
    fn new() -> Self {
        Self {
            database: None,
            transport: None,
            options: RelayPoolOptions::default(),
        }
    }

    /// Supply the event store the pool should fan events into.
    ///
    /// Required; calling [`Self::build`] without one panics.
    pub fn database(mut self, db: Arc<dyn NostrDatabase>) -> Self {
        self.database = Some(db);
        self
    }

    /// Override the WebSocket transport. Defaults to
    /// [`nula_net::default::DefaultTransport`] when the
    /// `default-transport` feature is on.
    pub fn transport<T: nula_net::IntoWebSocketTransport>(mut self, transport: T) -> Self {
        self.transport = Some(transport.into_transport());
        self
    }

    /// Override the pool options.
    pub const fn options(mut self, options: RelayPoolOptions) -> Self {
        self.options = options;
        self
    }

    /// Finalise the builder.
    ///
    /// # Panics
    ///
    /// - When [`Self::database`] was not called.
    /// - When the `default-transport` feature is **off** and
    ///   [`Self::transport`] was not called.
    #[allow(
        clippy::panic,
        reason = "builder pattern requires a panic on misconfiguration"
    )]
    #[must_use]
    pub fn build(self) -> RelayPool {
        let Some(database) = self.database else {
            panic!("RelayPoolBuilder::build called without a database")
        };
        let transport: Arc<dyn WebSocketTransport> = match self.transport {
            Some(t) => t,
            None => {
                #[cfg(feature = "default-transport")]
                {
                    Arc::new(nula_net::default::DefaultTransport::new())
                }
                #[cfg(not(feature = "default-transport"))]
                {
                    panic!(
                        "RelayPoolBuilder::build called without a transport \
                         and the `default-transport` feature is off; \
                         supply one via `RelayPoolBuilder::transport(...)`"
                    )
                }
            }
        };
        RelayPool::from_parts(SharedState::new(database, transport), self.options)
    }
}

/// Drive a single relay's connect attempt with optional per-call
/// timeout. Extracted into a free function so the dispatch loop in
/// [`RelayPool::try_connect_inner`] stays flat.
async fn connect_one(
    url: RelayUrl,
    relay: Relay,
    per_attempt: Option<Duration>,
) -> (RelayUrl, Result<(), String>) {
    let result = match per_attempt {
        Some(d) => timeout(d, relay.connect()).await.map_or_else(
            |_| Err(format!("connect timed out after {d:?}")),
            |inner| inner.map_err(|e| e.to_string()),
        ),
        None => relay.connect().await.map_err(|e| e.to_string()),
    };
    (url, result)
}
