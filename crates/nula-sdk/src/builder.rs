//! [`ClientBuilder`] — the fluent configurator for [`crate::Client`].
//!
//! Every collaborator the [`Client`] needs (signer, database,
//! transport, gossip, …) is wired here. The builder mirrors the
//! shape of `nostr_sdk::ClientBuilder` from the upstream
//! `rust-nostr` reference but stays minimal: each Layer-4 add-on
//! sits behind its own feature flag, and slots that are only
//! useful in tests (mock transports) live in `nula-net`.

use std::collections::HashMap;
use std::sync::Arc;

use nula_core::signer::NostrSigner;
#[cfg(feature = "gossip")]
use nula_gossip::Gossip;
use nula_relay::pool::{PoolNotification, RelayPool, RelayPoolOptions};
use nula_storage::NostrDatabase;
use tokio::sync::Mutex;

use crate::client::{Client, ClientConfig, InnerClient, MonitorState};
use crate::error::Error;
use crate::monitor::{DEFAULT_MONITOR_CAPACITY, Monitor, MonitorNotification};
use crate::policy::AdmitPolicy;

/// Fluent configurator for [`Client`].
///
/// Construct via [`Client::builder`] or [`ClientBuilder::default`],
/// chain setters, and finalise with [`Self::build`].
#[derive(Debug, Default)]
pub struct ClientBuilder {
    pub(crate) signer: Option<Arc<dyn NostrSigner>>,
    pub(crate) database: Option<Arc<dyn NostrDatabase>>,
    #[cfg(feature = "gossip")]
    pub(crate) gossip: Option<Gossip>,
    pub(crate) pool_options: RelayPoolOptions,
    pub(crate) websocket_transport: Option<Arc<dyn nula_relay::transport::WebSocketTransport>>,
    pub(crate) automatic_authentication: bool,
    /// `Some(capacity)` when [`Self::monitor`] was called; `None`
    /// when callers do not want the status broadcaster.
    pub(crate) monitor_capacity: Option<usize>,
    /// Optional client-side admission policy.
    pub(crate) admit_policy: Option<Arc<dyn AdmitPolicy>>,
}

impl ClientBuilder {
    /// Start a fresh builder. Same as [`Self::default`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach a signer.
    ///
    /// Accepts any value that converts into `Arc<dyn NostrSigner>`,
    /// so both `Keys`, `Arc<MySigner>`, and an existing
    /// `Arc<dyn NostrSigner>` work.
    #[must_use]
    pub fn signer<T>(mut self, signer: T) -> Self
    where
        T: NostrSigner + 'static,
    {
        self.signer = Some(Arc::new(signer));
        self
    }

    /// Attach a signer that is already wrapped in `Arc<dyn …>`.
    ///
    /// Useful when the signer is shared across multiple clients
    /// (e.g. a NIP-46 bunker driving more than one app surface).
    #[must_use]
    pub fn signer_arc(mut self, signer: Arc<dyn NostrSigner>) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Attach an event database.
    ///
    /// Required: every Layer-5 read path (cache hits, NIP-77
    /// reconciliation, NIP-65 routing) needs a place to look events
    /// up. Use [`nula_storage::memory::MemoryDatabase`] for ephemeral
    /// processes and `nula_storage::lmdb::LmdbDatabase` for
    /// long-running ones.
    #[must_use]
    pub fn database<D>(mut self, database: D) -> Self
    where
        D: NostrDatabase + 'static,
    {
        self.database = Some(Arc::new(database));
        self
    }

    /// Attach an event database that is already wrapped in
    /// `Arc<dyn NostrDatabase>`.
    ///
    /// Use when the same database needs to be shared with code
    /// outside the [`Client`] (e.g. a test harness that pre-seeds
    /// events through the same handle the client will read from,
    /// or an application that hands the database out to a
    /// background worker).
    #[must_use]
    pub fn database_arc(mut self, database: Arc<dyn NostrDatabase>) -> Self {
        self.database = Some(database);
        self
    }

    /// Attach a pre-built [`Gossip`] router for NIP-65 outbox /
    /// inbox / DM-relay aggregation.
    ///
    /// Optional. Without it the client treats every relay as a
    /// generic READ/WRITE peer.
    #[cfg(feature = "gossip")]
    #[cfg_attr(docsrs, doc(cfg(feature = "gossip")))]
    #[must_use]
    pub fn gossip(mut self, gossip: Gossip) -> Self {
        self.gossip = Some(gossip);
        self
    }

    /// Override the WebSocket transport.
    ///
    /// Defaults to [`nula_relay::transport::default::DefaultTransport`] when the
    /// `default-transport` feature is on; mandatory otherwise.
    #[must_use]
    pub fn websocket_transport<T>(mut self, transport: T) -> Self
    where
        T: nula_relay::transport::WebSocketTransport + 'static,
    {
        self.websocket_transport = Some(Arc::new(transport));
        self
    }

    /// Replace the [`RelayPoolOptions`] used by the underlying
    /// [`RelayPool`].
    #[must_use]
    pub const fn pool_options(mut self, options: RelayPoolOptions) -> Self {
        self.pool_options = options;
        self
    }

    /// Enable / disable NIP-42 automatic authentication.
    ///
    /// When enabled, the client transparently signs and replies to
    /// every `AUTH` challenge a connected relay issues.
    #[must_use]
    pub const fn automatic_authentication(mut self, enabled: bool) -> Self {
        self.automatic_authentication = enabled;
        self
    }

    /// Opt into the status-broadcasting [`crate::Monitor`]. Without
    /// this call [`crate::Client::monitor`] returns `None`.
    ///
    /// Uses a 64-slot channel by default; for a custom capacity see
    /// [`Self::monitor_with_capacity`].
    #[must_use]
    pub const fn monitor(mut self) -> Self {
        self.monitor_capacity = Some(DEFAULT_MONITOR_CAPACITY);
        self
    }

    /// Same as [`Self::monitor`] but with a caller-chosen broadcast
    /// channel capacity.
    #[must_use]
    pub const fn monitor_with_capacity(mut self, capacity: usize) -> Self {
        self.monitor_capacity = Some(capacity);
        self
    }

    /// Install a client-side [`AdmitPolicy`].
    ///
    /// Without this call the SDK applies no admission gate and
    /// every relay / connection / inbound event is admitted.
    /// Accepts anything convertible into `Arc<dyn AdmitPolicy>`,
    /// so both bare values and pre-built `Arc`s work.
    #[must_use]
    pub fn admit_policy<P>(mut self, policy: P) -> Self
    where
        P: Into<Arc<dyn AdmitPolicy>>,
    {
        self.admit_policy = Some(policy.into());
        self
    }

    /// Build the [`Client`].
    ///
    /// When the `memory-fallback` feature is enabled (default) and
    /// the caller omitted [`Self::database`], the builder substitutes
    /// a fresh [`nula_storage::memory::MemoryDatabase`] so first-touch
    /// users get a working client out of the box. With the feature
    /// disabled, omitting the database surfaces as
    /// [`nula_relay::pool::Error::MissingDatabase`].
    ///
    /// # Errors
    ///
    /// - [`Error::Pool`] if the underlying
    ///   [`nula_relay::pool::RelayPoolBuilder`] refused the
    ///   configuration (missing transport on a build without
    ///   `default-transport`, missing database on a build without
    ///   `memory-fallback`, …).
    pub fn build(self) -> Result<Client, Error> {
        let database: Option<Arc<dyn NostrDatabase>> = self.database.clone().or_else(|| {
            #[cfg(feature = "memory-fallback")]
            {
                Some(Arc::new(nula_storage::memory::MemoryDatabase::new()))
            }
            #[cfg(not(feature = "memory-fallback"))]
            {
                None
            }
        });

        // When an admission policy is installed, the pool's
        // auto-save fast path would persist events before
        // [`AdmitPolicy::admit_event`] runs, defeating the gate.
        // Disable it so SDK paths that own the persistence
        // decision (sync download, future fetch_events) call
        // `database.save_event` themselves *after* the admit
        // verdict.
        let mut pool_options = self.pool_options;
        if self.admit_policy.is_some() {
            pool_options = pool_options.auto_save_events(false);
        }
        let mut pool_builder = RelayPool::builder().options(pool_options);
        if let Some(db) = database {
            pool_builder = pool_builder.database(db);
        }
        if let Some(transport) = self.websocket_transport.clone() {
            pool_builder = pool_builder.transport(transport);
        }
        let pool = pool_builder.build()?;

        let monitor = self.monitor_capacity.map(|capacity| {
            let monitor = Monitor::with_capacity(capacity);
            let sender = monitor.sender().clone();
            let rx = pool.notifications();
            let task = tokio::spawn(forward_monitor_notifications(rx, sender));
            MonitorState {
                monitor,
                forwarder: task.abort_handle(),
            }
        });

        // Spawn the background NIP-65/17 refresher when gossip is
        // configured with a tick interval. Reads discovery relays from
        // the live pool each tick, so it tracks relays added after the
        // client is built. Aborts on drop with the last `Client` clone.
        #[cfg(feature = "gossip")]
        let gossip_refresher = self.gossip.as_ref().and_then(|gossip| {
            gossip
                .options()
                .refresher_interval
                .map(|_| crate::gossip::spawn_refresher(gossip.clone(), pool.clone()))
        });

        let inner = InnerClient {
            pool,
            signer: self.signer,
            #[cfg(feature = "gossip")]
            gossip: self.gossip,
            #[cfg(feature = "gossip")]
            gossip_refresher,
            config: ClientConfig {
                automatic_authentication: self.automatic_authentication,
            },
            subscriptions: Mutex::new(HashMap::new()),
            monitor,
            admit_policy: self.admit_policy,
        };
        Ok(Client {
            inner: Arc::new(inner),
        })
    }
}

// Re-export the pool builder so callers tuning advanced relay-pool
// settings can do it without an extra import.
pub use nula_relay::pool::RelayPoolBuilder as PoolBuilder;

/// Forward every [`PoolNotification::Status`] frame onto the
/// monitor broadcaster. Stops when the pool channel closes.
async fn forward_monitor_notifications(
    mut rx: tokio::sync::broadcast::Receiver<PoolNotification>,
    sender: tokio::sync::broadcast::Sender<MonitorNotification>,
) {
    while let Ok(notification) = rx.recv().await {
        let PoolNotification::Status { url, status } = notification else {
            continue;
        };
        // Drop the SendError silently -- no subscriber is fine.
        drop(sender.send(MonitorNotification::StatusChanged {
            relay_url: url,
            status,
        }));
    }
}
