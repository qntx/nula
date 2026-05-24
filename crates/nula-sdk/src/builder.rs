//! [`ClientBuilder`] — the fluent configurator for [`crate::Client`].
//!
//! Every collaborator the [`Client`] needs (signer, database,
//! transport, gossip, …) is wired here. The builder mirrors the
//! shape of `nostr_sdk::ClientBuilder` from the upstream
//! `rust-nostr` reference but stays minimal: each Layer-4 add-on
//! sits behind its own feature flag, and slots that are only
//! useful in tests (mock transports) live in `nula-net`.

use std::sync::Arc;

use nula_core::signer::NostrSigner;
#[cfg(feature = "gossip")]
use nula_gossip::Gossip;
use nula_relay_pool::{RelayPool, RelayPoolOptions};
use nula_storage::NostrDatabase;

use crate::client::{Client, ClientConfig, InnerClient};
use crate::error::Error;

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
    pub(crate) websocket_transport: Option<Arc<dyn nula_net::WebSocketTransport>>,
    pub(crate) automatic_authentication: bool,
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
    /// up. Use [`nula_storage_memory::MemoryDatabase`] for ephemeral
    /// processes and `nula_storage_lmdb::LmdbDatabase` for
    /// long-running ones.
    #[must_use]
    pub fn database<D>(mut self, database: D) -> Self
    where
        D: NostrDatabase + 'static,
    {
        self.database = Some(Arc::new(database));
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
    /// Defaults to [`nula_net::default::DefaultTransport`] when the
    /// `default-transport` feature is on; mandatory otherwise.
    #[must_use]
    pub fn websocket_transport<T>(mut self, transport: T) -> Self
    where
        T: nula_net::WebSocketTransport + 'static,
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

    /// Build the [`Client`].
    ///
    /// When the `memory-fallback` feature is enabled (default) and
    /// the caller omitted [`Self::database`], the builder substitutes
    /// a fresh [`nula_storage_memory::MemoryDatabase`] so first-touch
    /// users get a working client out of the box. With the feature
    /// disabled, omitting the database surfaces as
    /// [`nula_relay_pool::Error::MissingDatabase`].
    ///
    /// # Errors
    ///
    /// - [`Error::Pool`] if the underlying
    ///   [`nula_relay_pool::RelayPoolBuilder`] refused the
    ///   configuration (missing transport on a build without
    ///   `default-transport`, missing database on a build without
    ///   `memory-fallback`, …).
    pub fn build(self) -> Result<Client, Error> {
        let database: Option<Arc<dyn NostrDatabase>> = self.database.clone().or_else(|| {
            #[cfg(feature = "memory-fallback")]
            {
                Some(Arc::new(nula_storage_memory::MemoryDatabase::new()))
            }
            #[cfg(not(feature = "memory-fallback"))]
            {
                None
            }
        });

        let mut pool_builder = RelayPool::builder().options(self.pool_options);
        if let Some(db) = database {
            pool_builder = pool_builder.database(db);
        }
        if let Some(transport) = self.websocket_transport.clone() {
            pool_builder = pool_builder.transport(transport);
        }
        let pool = pool_builder.build()?;

        let inner = InnerClient {
            pool,
            signer: self.signer,
            #[cfg(feature = "gossip")]
            gossip: self.gossip,
            config: ClientConfig {
                automatic_authentication: self.automatic_authentication,
            },
        };
        Ok(Client {
            inner: Arc::new(inner),
        })
    }
}

// Re-export the pool builder so callers tuning advanced relay-pool
// settings can do it without an extra import.
pub use nula_relay_pool::RelayPoolBuilder as PoolBuilder;
