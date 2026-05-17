//! Public [`NostrConnect`] handle and its [`NostrConnectBuilder`].

use std::sync::Arc;
use std::time::Duration;

use nula_core::event::{Tag, UnsignedEvent};
use nula_core::nips::nip46::{KIND as NOSTR_CONNECT_KIND, Method, Permission, Request, Uri};
use nula_core::nips::{nip44, nip46};
use nula_core::{Event, EventBuilder, Keys, Kind, PublicKey, RelayUrl};
use nula_relay_pool::RelayPool;
use tokio::sync::OnceCell;
use tokio::time::timeout;

use crate::auth::{AuthUrlHandler, IntoAuthUrlHandler};
use crate::dispatcher::{self, DispatcherConfig};
use crate::error::Error;
use crate::inner::Inner;
use crate::options::NostrConnectOptions;
use crate::pending::PendingMap;
use crate::pool_handle::PoolMode;

/// NIP-46 (Nostr Connect) remote signer client.
///
/// Cloning is cheap (one `Arc` bump). Dropping the last clone aborts
/// the dispatcher actor and, in [`PoolMode::Embedded`] mode, shuts
/// down the embedded [`RelayPool`].
///
/// See [the crate docs](crate) for the full design and usage notes.
#[derive(Debug, Clone)]
pub struct NostrConnect {
    inner: Arc<Inner>,
}

impl NostrConnect {
    /// Begin configuring a [`NostrConnect`].
    pub fn builder() -> NostrConnectBuilder {
        NostrConnectBuilder::new()
    }

    /// Local client keys (`bunker://` flow uses these to encrypt to
    /// the signer; `nostrconnect://` flow advertises this pubkey to
    /// the signer).
    #[must_use]
    pub fn local_keys(&self) -> &Keys {
        &self.inner.client_keys
    }

    /// Relay URLs taken from the URI at construction time.
    #[must_use]
    pub fn relays(&self) -> &[RelayUrl] {
        &self.inner.relays
    }

    /// `true` for an embedded-pool deployment.
    #[must_use]
    pub fn is_embedded_pool(&self) -> bool {
        self.inner.pool.is_embedded()
    }

    /// Fetch and cache the user's public key (the signer's owner).
    ///
    /// Cached on first success; subsequent calls are O(1).
    ///
    /// # Errors
    ///
    /// Forwards every dispatch failure as [`Error`].
    pub async fn get_public_key(&self) -> Result<PublicKey, Error> {
        if let Some(pk) = self.inner.user_pk.get() {
            return Ok(*pk);
        }
        let pk = self.send_get_public_key().await?;
        // `set` returns `Err` if another caller raced and won;
        // either way the cache holds the right value.
        self.inner.user_pk.set(pk).ok();
        Ok(pk)
    }

    /// Sign an [`UnsignedEvent`] through the remote signer.
    ///
    /// # Errors
    ///
    /// Forwards every dispatch failure as [`Error`].
    pub async fn sign_event(&self, unsigned: UnsignedEvent) -> Result<Event, Error> {
        let req = Request::SignEvent(unsigned);
        match self.dispatch(req).await? {
            nip46::ResponseResult::SignEvent(event) => Ok(*event),
            other => Err(Error::Rejected {
                method: Method::SignEvent,
                message: format!("unexpected response: {}", other.to_wire()),
            }),
        }
    }

    /// NIP-04 (legacy) encrypt to `peer`.
    ///
    /// # Errors
    ///
    /// Forwards every dispatch failure as [`Error`].
    pub async fn nip04_encrypt(&self, peer: &PublicKey, plaintext: &str) -> Result<String, Error> {
        let req = Request::Nip04Encrypt {
            peer: *peer,
            text: plaintext.to_owned(),
        };
        match self.dispatch(req).await? {
            nip46::ResponseResult::Nip04Encrypt(s) => Ok(s),
            other => Err(Error::Rejected {
                method: Method::Nip04Encrypt,
                message: format!("unexpected response: {}", other.to_wire()),
            }),
        }
    }

    /// NIP-04 (legacy) decrypt from `peer`.
    ///
    /// # Errors
    ///
    /// Forwards every dispatch failure as [`Error`].
    pub async fn nip04_decrypt(&self, peer: &PublicKey, ciphertext: &str) -> Result<String, Error> {
        let req = Request::Nip04Decrypt {
            peer: *peer,
            ciphertext: ciphertext.to_owned(),
        };
        match self.dispatch(req).await? {
            nip46::ResponseResult::Nip04Decrypt(s) => Ok(s),
            other => Err(Error::Rejected {
                method: Method::Nip04Decrypt,
                message: format!("unexpected response: {}", other.to_wire()),
            }),
        }
    }

    /// NIP-44 v2 encrypt to `peer`.
    ///
    /// # Errors
    ///
    /// Forwards every dispatch failure as [`Error`].
    pub async fn nip44_encrypt(&self, peer: &PublicKey, plaintext: &str) -> Result<String, Error> {
        let req = Request::Nip44Encrypt {
            peer: *peer,
            text: plaintext.to_owned(),
        };
        match self.dispatch(req).await? {
            nip46::ResponseResult::Nip44Encrypt(s) => Ok(s),
            other => Err(Error::Rejected {
                method: Method::Nip44Encrypt,
                message: format!("unexpected response: {}", other.to_wire()),
            }),
        }
    }

    /// NIP-44 v2 decrypt from `peer`.
    ///
    /// # Errors
    ///
    /// Forwards every dispatch failure as [`Error`].
    pub async fn nip44_decrypt(&self, peer: &PublicKey, ciphertext: &str) -> Result<String, Error> {
        let req = Request::Nip44Decrypt {
            peer: *peer,
            ciphertext: ciphertext.to_owned(),
        };
        match self.dispatch(req).await? {
            nip46::ResponseResult::Nip44Decrypt(s) => Ok(s),
            other => Err(Error::Rejected {
                method: Method::Nip44Decrypt,
                message: format!("unexpected response: {}", other.to_wire()),
            }),
        }
    }

    /// NIP-46 `ping` liveness probe.
    ///
    /// # Errors
    ///
    /// Forwards every dispatch failure as [`Error`].
    pub async fn ping(&self) -> Result<(), Error> {
        match self.dispatch(Request::Ping).await? {
            nip46::ResponseResult::Pong => Ok(()),
            other => Err(Error::Rejected {
                method: Method::Ping,
                message: format!("unexpected response: {}", other.to_wire()),
            }),
        }
    }

    /// Ask the signer for its preferred relay set
    /// (NIP-46 § "Switching relays"). `Ok(None)` means "no change".
    ///
    /// # Errors
    ///
    /// Forwards every dispatch failure as [`Error`].
    pub async fn switch_relays(&self) -> Result<Option<Vec<RelayUrl>>, Error> {
        match self.dispatch(Request::SwitchRelays).await? {
            nip46::ResponseResult::SwitchRelays(payload) => Ok(payload),
            other => Err(Error::Rejected {
                method: Method::SwitchRelays,
                message: format!("unexpected response: {}", other.to_wire()),
            }),
        }
    }

    /// Apply the relay set returned by [`Self::switch_relays`] to
    /// the embedded pool. Errors out for [`PoolMode::External`].
    ///
    /// # Errors
    ///
    /// - [`Error::WrongPoolMode`] when the client was built with an
    ///   external pool.
    /// - [`Error::Pool`] when the pool refuses an `add_relay` call.
    pub async fn adopt_relays(&self, urls: Vec<RelayUrl>) -> Result<(), Error> {
        if !self.inner.pool.is_embedded() {
            return Err(Error::WrongPoolMode);
        }
        self.inner.pool.add_and_connect(&urls).await?;
        Ok(())
    }

    /// Render a fresh `bunker://` URI describing this client's
    /// signer (useful when sharing the established session with a
    /// second device).
    ///
    /// # Errors
    ///
    /// Returns [`Error::DispatcherDown`] when the remote signer
    /// pubkey was never observed (no successful `connect`).
    pub fn bunker_uri(&self) -> Result<Uri, Error> {
        let signer_pk = self
            .inner
            .remote_signer_pk
            .get()
            .copied()
            .ok_or(Error::DispatcherDown(
                "remote signer pubkey not yet observed",
            ))?;
        Ok(Uri::Bunker {
            remote_signer_public_key: signer_pk,
            relays: self.inner.relays.clone(),
            // Secret is one-shot; do not echo it in the new URI.
            secret: None,
        })
    }

    /// Trigger an explicit shutdown: aborts the dispatcher actor
    /// and (in embedded mode) the pool.
    pub async fn shutdown(self) {
        self.inner.dispatcher.abort();
        // Embedded pools are dropped together with `inner` once the
        // last clone is gone; we cannot await that here without
        // racing other clones, so we simply rely on `Drop`. Holding
        // a `shutdown_grace` timeout would only matter if we did
        // active disconnect work, which the pool's own `Drop` does.
        timeout(self.inner.options.shutdown_grace, async {})
            .await
            .ok();
    }

    // ----------------------------------------------------------------
    // Internal: dispatch helpers
    // ----------------------------------------------------------------

    async fn send_get_public_key(&self) -> Result<PublicKey, Error> {
        match self.dispatch(Request::GetPublicKey).await? {
            nip46::ResponseResult::GetPublicKey(pk) => Ok(pk),
            other => Err(Error::Rejected {
                method: Method::GetPublicKey,
                message: format!("unexpected response: {}", other.to_wire()),
            }),
        }
    }

    async fn dispatch(&self, request: Request) -> Result<nip46::ResponseResult, Error> {
        let method = request.method();
        let signer_pk = match self.inner.remote_signer_pk.get() {
            Some(pk) => *pk,
            None => return Err(Error::DispatcherDown("signer pubkey unknown")),
        };

        let id = generate_id();
        let envelope = nip46::Message::request(id.clone(), &request);
        let plain = serde_json::to_string(&envelope).map_err(Error::MalformedEnvelope)?;
        let cipher = nip44::encrypt(self.inner.client_keys.secret_key(), &signer_pk, &plain)?;
        let event = EventBuilder::new(Kind::new(NOSTR_CONNECT_KIND), cipher)
            .tag(Tag::p(signer_pk))
            .sign_with_keys(&self.inner.client_keys)?;

        let receiver = self.inner.pending.insert(&id, method);
        let pool_send = self
            .inner
            .pool
            .send_event_to(self.inner.relays.clone(), event);
        let send_outcome = pool_send.await?;
        if send_outcome.is_total_failure() {
            // Roll back the pending entry: the request never made
            // it, so nobody will ever resolve it.
            self.inner.pending.cancel_all(&|| Error::Rejected {
                method,
                message: format!(
                    "publish failed on every relay: {failed:?}",
                    failed = send_outcome.failed
                ),
            });
            return Err(Error::Rejected {
                method,
                message: format!(
                    "publish failed on every relay: {failed:?}",
                    failed = send_outcome.failed
                ),
            });
        }

        match timeout(self.inner.options.timeout, receiver).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(Error::DispatcherDown("pending channel cancelled")),
            Err(_) => Err(Error::Timeout { method }),
        }
    }
}

/// Builder for [`NostrConnect`].
#[derive(Debug, Default)]
#[must_use]
pub struct NostrConnectBuilder {
    uri: Option<Uri>,
    client_keys: Option<Keys>,
    options: NostrConnectOptions,
    pool: Option<PoolModeBuilder>,
    auth_url_handler: Option<Arc<dyn AuthUrlHandler>>,
    bootstrap_perms: Option<Vec<Permission>>,
}

#[derive(Debug)]
enum PoolModeBuilder {
    External(Arc<RelayPool>),
    Embedded(RelayPool),
}

impl NostrConnectBuilder {
    /// Construct an empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the connection URI (`bunker://` or `nostrconnect://`).
    /// Required.
    pub fn uri(mut self, uri: Uri) -> Self {
        self.uri = Some(uri);
        self
    }

    /// Override the local client keys. Defaults to a freshly
    /// generated keypair.
    pub fn client_keys(mut self, keys: Keys) -> Self {
        self.client_keys = Some(keys);
        self
    }

    /// Override the runtime configuration.
    pub const fn options(mut self, options: NostrConnectOptions) -> Self {
        self.options = options;
        self
    }

    /// Use an externally-owned pool. Mutually exclusive with
    /// [`Self::embedded_pool`].
    pub fn pool(mut self, pool: Arc<RelayPool>) -> Self {
        self.pool = Some(PoolModeBuilder::External(pool));
        self
    }

    /// Use an embedded pool that the client owns. Mutually
    /// exclusive with [`Self::pool`].
    pub fn embedded_pool(mut self, pool: RelayPool) -> Self {
        self.pool = Some(PoolModeBuilder::Embedded(pool));
        self
    }

    /// Plug in an [`AuthUrlHandler`].
    pub fn auth_url_handler<H>(mut self, handler: H) -> Self
    where
        H: IntoAuthUrlHandler,
    {
        self.auth_url_handler = Some(handler.into_auth_url_handler());
        self
    }

    /// Permissions to request inside the bootstrap `connect` call.
    /// The `bunker://` flow is the only one that uses this — the
    /// `nostrconnect://` URI carries permissions inline.
    pub fn perms(mut self, perms: Vec<Permission>) -> Self {
        self.bootstrap_perms = Some(perms);
        self
    }

    /// Drive the bootstrap handshake and return the live client.
    ///
    /// # Errors
    ///
    /// - [`Error::MissingUri`] when [`Self::uri`] was not called.
    /// - [`Error::MissingPool`] when neither [`Self::pool`] nor
    ///   [`Self::embedded_pool`] was called.
    /// - [`Error::Pool`] if the pool refuses to add the URI's relays.
    /// - [`Error::Rejected`] if the bunker rejects the `connect`
    ///   call.
    /// - [`Error::Timeout`] if the bunker takes longer than
    ///   [`NostrConnectOptions::timeout`] to reply.
    /// - [`Error::Spoofed`] if the `nostrconnect://` flow's secret
    ///   was not echoed inside the timeout.
    pub async fn build(self) -> Result<NostrConnect, Error> {
        let uri = self.uri.ok_or(Error::MissingUri)?;
        let pool_mode = self.pool.ok_or(Error::MissingPool)?;
        let client_keys = self
            .client_keys
            .map_or_else(|| Keys::generate().map_err(Error::auth_url), Ok)?;

        // Sanity-check the `nostrconnect://` flow: the URI's
        // advertised pubkey must match the local keypair.
        if let Uri::Client { public_key, .. } = &uri
            && public_key != client_keys.public_key()
        {
            return Err(Error::Rejected {
                method: Method::Connect,
                message: "nostrconnect:// URI public_key does not match client_keys".into(),
            });
        }

        let pool = Arc::new(match pool_mode {
            PoolModeBuilder::External(p) => PoolMode::External(p),
            PoolModeBuilder::Embedded(p) => PoolMode::Embedded(p),
        });
        let relays = uri.relays().to_vec();
        pool.add_and_connect(&relays).await?;

        let pending = Arc::new(PendingMap::new());
        let remote_signer_pk: Arc<OnceCell<PublicKey>> = Arc::new(OnceCell::new());
        let bunker_secret = match &uri {
            Uri::Bunker { secret, .. } => secret.clone(),
            _ => None,
        };
        let nostrconnect_secret = match &uri {
            Uri::Client { secret, .. } => Some(secret.clone()),
            _ => None,
        };
        // Pre-seed the signer pubkey for the bunker:// flow; the
        // nostrconnect:// flow learns it from the connect echo.
        if let Uri::Bunker {
            remote_signer_public_key,
            ..
        } = &uri
        {
            remote_signer_pk.set(*remote_signer_public_key).ok();
        }

        let dispatcher_cfg = DispatcherConfig {
            pool: Arc::clone(&pool),
            client_keys: client_keys.clone(),
            pending: Arc::clone(&pending),
            auth_url_handler: self.auth_url_handler.clone(),
            remote_signer_pk: Arc::clone(&remote_signer_pk),
            nostrconnect_secret: nostrconnect_secret.clone(),
            relays: relays.clone(),
        };
        let dispatcher = dispatcher::spawn(dispatcher_cfg);

        let inner = Arc::new(Inner {
            pool,
            options: self.options,
            client_keys,
            pending,
            dispatcher,
            remote_signer_pk,
            user_pk: OnceCell::new(),
            bunker_secret,
            relays,
        });
        // Drop the dispatcher-owned auth handler / secret bindings;
        // the spawned task already captured them by value.
        drop(self.auth_url_handler);
        drop(nostrconnect_secret);
        let client = NostrConnect { inner };

        // Drive the handshake. `bunker://` clients send `connect`
        // themselves; `nostrconnect://` waits for the signer to dial
        // in and the secret-echo gate handles the rest.
        if matches!(&uri, Uri::Bunker { .. }) {
            client.bunker_handshake(self.bootstrap_perms).await?;
        } else {
            client.client_uri_handshake().await?;
        }

        Ok(client)
    }
}

impl NostrConnect {
    async fn bunker_handshake(
        &self,
        bootstrap_perms: Option<Vec<Permission>>,
    ) -> Result<(), Error> {
        let Some(signer_pk) = self.inner.remote_signer_pk.get().copied() else {
            return Err(Error::DispatcherDown(
                "bunker:// handshake started before remote_signer_pk was seeded",
            ));
        };
        let req = Request::Connect {
            remote_signer_public_key: signer_pk,
            secret: self.inner.bunker_secret.clone(),
            perms: bootstrap_perms,
        };
        // The bunker may reply with `ack` or echo the secret.
        match self.dispatch(req).await? {
            nip46::ResponseResult::Ack | nip46::ResponseResult::ConnectSecret(_) => Ok(()),
            other => Err(Error::Rejected {
                method: Method::Connect,
                message: format!("unexpected connect response: {}", other.to_wire()),
            }),
        }
    }

    async fn client_uri_handshake(&self) -> Result<(), Error> {
        // Wait up to `timeout` for the dispatcher to observe the
        // signer's `connect` reply (which carries the secret echo
        // and pins remote_signer_pk).
        let deadline = tokio::time::sleep(self.inner.options.timeout);
        tokio::pin!(deadline);
        loop {
            if self.inner.remote_signer_pk.get().is_some() {
                return Ok(());
            }
            tokio::select! {
                () = &mut deadline => return Err(Error::Spoofed),
                () = tokio::time::sleep(Duration::from_millis(25)) => {}
            }
        }
    }
}

fn generate_id() -> String {
    let mut bytes = [0u8; 16];
    // The `id` field is opaque to the spec; a 128-bit random suffix
    // is enough for collisions to be practically unreachable. If
    // the OS RNG ever fails we fall back to a process-time-derived
    // id rather than panic — collision risk in that degraded path
    // is dominated by the simultaneous RNG outage.
    if getrandom::fill(&mut bytes).is_err() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0_u128, |d| d.as_nanos());
        bytes[..16].copy_from_slice(&nanos.to_le_bytes());
    }
    let mut out = String::with_capacity(32);
    for byte in bytes {
        out.push(hex_nibble(byte >> 4));
        out.push(hex_nibble(byte & 0x0f));
    }
    out
}

const fn hex_nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + (n - 10)) as char,
        _ => '0',
    }
}
