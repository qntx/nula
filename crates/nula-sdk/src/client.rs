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

use nula_core::signer::NostrSigner;
use nula_core::types::RelayUrl;
#[cfg(feature = "gossip")]
use nula_gossip::Gossip;
use nula_relay::Relay;
use nula_relay_pool::{Output, RelayCapabilities, RelayPool};
use nula_storage::NostrDatabase;

use crate::builder::ClientBuilder;
use crate::error::Error;
use crate::util::IntoRelayUrl;

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
    pub async fn try_connect(&self, per_relay_timeout: std::time::Duration) -> Output<()> {
        self.inner.pool.try_connect(per_relay_timeout).await
    }

    /// Disconnect every relay.
    pub async fn disconnect(&self) -> Output<()> {
        self.inner.pool.disconnect().await
    }
}
