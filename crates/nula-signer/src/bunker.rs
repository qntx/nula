//! NIP-46 **bunker** (remote signer) side.
//!
//! Where [`crate::NostrConnect`] is the *client* that dials a remote
//! signer, [`NostrConnectRemoteSigner`] is the *server*: it listens on a
//! relay set for `kind:24133` requests addressed to its signer pubkey,
//! NIP-44 decrypts each one, dispatches it against the held
//! [`NostrConnectKeys`], and publishes an encrypted reply.
//!
//! # Key separation
//!
//! [`NostrConnectKeys`] keeps the *signer* key (the transport identity
//! advertised in the `bunker://` URI, used to encrypt the
//! request/response channel) distinct from the *user* key (the identity
//! that actually signs events and performs NIP-04/44 crypto). They may
//! be the same ([`NostrConnectKeys::new`]) or different
//! ([`NostrConnectKeys::with_separate_signer`]).
//!
//! # Authorization
//!
//! Every request other than `connect` is gated through a
//! [`BunkerPolicy`]. The default [`ApproveAll`] runs unattended; supply
//! your own policy to reject `sign_event` for untrusted clients, scope
//! by event kind, etc.
//!
//! # Example
//!
//! ```rust,no_run
//! use std::sync::Arc;
//!
//! use nula_signer::bunker::{NostrConnectKeys, NostrConnectRemoteSigner};
//! use nula_core::Keys;
//! use nula_relay::pool::RelayPool;
//!
//! # async fn doc(db: Arc<dyn nula_storage::NostrDatabase>) -> Result<(), Box<dyn std::error::Error>> {
//! let user = Keys::generate()?;
//! let relay = "wss://relay.example".parse()?;
//! let signer = NostrConnectRemoteSigner::builder()
//!     .keys(NostrConnectKeys::new(user))
//!     .relay(relay)
//!     .embedded_pool(RelayPool::builder().database(db).build()?)
//!     .serve()
//!     .await?;
//!
//! // Share this with a client (e.g. encode as a QR code):
//! let uri = signer.bunker_uri();
//! println!("{uri}");
//! # Ok(()) }
//! ```

use std::sync::Arc;

use futures::StreamExt as _;
use nula_core::event::Tag;
use nula_core::nips::nip44;
use nula_core::nips::nip46::{self, Message, Request, Response, ResponseResult, Uri};
use nula_core::{EventBuilder, Filter, Keys, Kind, PublicKey, RelayUrl};
use nula_relay::SubscribeOptions;
use nula_relay::pool::RelayPool;
use tokio::task::AbortHandle;

use crate::error::Error;
use crate::pool_handle::PoolMode;

/// The two keypairs a bunker uses.
#[derive(Debug, Clone)]
pub struct NostrConnectKeys {
    /// Transport identity: encrypts the `kind:24133` channel and is the
    /// pubkey advertised in the `bunker://` URI.
    pub signer: Keys,
    /// User identity: signs events and performs NIP-04 / NIP-44 crypto.
    pub user: Keys,
}

impl NostrConnectKeys {
    /// Use one keypair for both transport and signing.
    #[must_use]
    pub fn new(user: Keys) -> Self {
        Self {
            signer: user.clone(),
            user,
        }
    }

    /// Use a dedicated transport (`signer`) key distinct from the
    /// signing (`user`) key.
    #[must_use]
    pub const fn with_separate_signer(signer: Keys, user: Keys) -> Self {
        Self { signer, user }
    }
}

/// Authorization hook consulted for every non-`connect` request.
pub trait BunkerPolicy: std::fmt::Debug + Send + Sync {
    /// Return `true` to let the request proceed, `false` to reject it
    /// with an error response.
    fn approve(&self, client: &PublicKey, request: &Request) -> bool;
}

/// A [`BunkerPolicy`] that approves every request. Suitable for an
/// unattended signer dedicated to a single trusted client.
#[derive(Debug, Clone, Copy)]
pub struct ApproveAll;

impl BunkerPolicy for ApproveAll {
    fn approve(&self, _client: &PublicKey, _request: &Request) -> bool {
        true
    }
}

/// A running NIP-46 bunker.
///
/// Cloning is cheap (one `Arc` bump). Dropping the last clone aborts the
/// listener task and, in embedded mode, shuts down the pool.
#[derive(Debug, Clone)]
pub struct NostrConnectRemoteSigner {
    inner: Arc<BunkerInner>,
}

#[derive(Debug)]
struct BunkerInner {
    keys: NostrConnectKeys,
    relays: Vec<RelayUrl>,
    secret: Option<String>,
    pool: Arc<PoolMode>,
    listener: AbortHandle,
}

impl Drop for BunkerInner {
    fn drop(&mut self) {
        self.listener.abort();
    }
}

impl NostrConnectRemoteSigner {
    /// Begin configuring a bunker.
    pub fn builder() -> NostrConnectRemoteSignerBuilder {
        NostrConnectRemoteSignerBuilder::new()
    }

    /// The signer (transport) public key advertised to clients.
    #[must_use]
    pub fn signer_public_key(&self) -> PublicKey {
        *self.inner.keys.signer.public_key()
    }

    /// The user (signing) public key returned by `get_public_key`.
    #[must_use]
    pub fn user_public_key(&self) -> PublicKey {
        *self.inner.keys.user.public_key()
    }

    /// The relays this bunker listens on.
    #[must_use]
    pub fn relays(&self) -> &[RelayUrl] {
        &self.inner.relays
    }

    /// Render the `bunker://` URI clients dial to reach this signer.
    #[must_use]
    pub fn bunker_uri(&self) -> Uri {
        Uri::Bunker {
            remote_signer_public_key: *self.inner.keys.signer.public_key(),
            relays: self.inner.relays.clone(),
            secret: self.inner.secret.clone(),
        }
    }

    /// `true` for an embedded-pool deployment.
    #[must_use]
    pub fn is_embedded_pool(&self) -> bool {
        self.inner.pool.is_embedded()
    }

    /// Abort the listener task. In embedded mode the pool is shut down
    /// when the last clone drops.
    pub fn shutdown(&self) {
        self.inner.listener.abort();
    }
}

/// Builder for [`NostrConnectRemoteSigner`].
#[derive(Debug, Default)]
#[must_use]
pub struct NostrConnectRemoteSignerBuilder {
    keys: Option<NostrConnectKeys>,
    relays: Vec<RelayUrl>,
    secret: Option<String>,
    pool: Option<PoolModeBuilder>,
    policy: Option<Arc<dyn BunkerPolicy>>,
}

#[derive(Debug)]
enum PoolModeBuilder {
    External(Arc<RelayPool>),
    Embedded(RelayPool),
}

impl NostrConnectRemoteSignerBuilder {
    /// Construct an empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the signer/user keypairs. Required.
    pub fn keys(mut self, keys: NostrConnectKeys) -> Self {
        self.keys = Some(keys);
        self
    }

    /// Add a relay to listen on. Call multiple times for several relays.
    pub fn relay(mut self, url: RelayUrl) -> Self {
        self.relays.push(url);
        self
    }

    /// Set the full relay set to listen on (replaces any added so far).
    pub fn relays(mut self, urls: Vec<RelayUrl>) -> Self {
        self.relays = urls;
        self
    }

    /// Set the one-time `connect` secret echoed in the `bunker://` URI.
    /// When set, the bunker rejects `connect` requests that do not carry
    /// the matching secret.
    pub fn secret(mut self, secret: impl Into<String>) -> Self {
        self.secret = Some(secret.into());
        self
    }

    /// Use an externally-owned pool. Mutually exclusive with
    /// [`Self::embedded_pool`].
    pub fn pool(mut self, pool: Arc<RelayPool>) -> Self {
        self.pool = Some(PoolModeBuilder::External(pool));
        self
    }

    /// Use an embedded pool the bunker owns and shuts down on drop.
    /// Mutually exclusive with [`Self::pool`].
    pub fn embedded_pool(mut self, pool: RelayPool) -> Self {
        self.pool = Some(PoolModeBuilder::Embedded(pool));
        self
    }

    /// Install an authorization [`BunkerPolicy`] (default
    /// [`ApproveAll`]).
    pub fn policy<P>(mut self, policy: P) -> Self
    where
        P: BunkerPolicy + 'static,
    {
        self.policy = Some(Arc::new(policy));
        self
    }

    /// Connect the relays, spawn the listener, and return the running
    /// bunker.
    ///
    /// # Errors
    ///
    /// - [`Error::MissingKeys`] when [`Self::keys`] was not called.
    /// - [`Error::MissingRelays`] when no relay was supplied.
    /// - [`Error::MissingPool`] when no pool was supplied.
    /// - [`Error::Pool`] if the pool refuses to add the relays.
    pub async fn serve(self) -> Result<NostrConnectRemoteSigner, Error> {
        let keys = self.keys.ok_or(Error::MissingKeys)?;
        if self.relays.is_empty() {
            return Err(Error::MissingRelays);
        }
        let pool_mode = self.pool.ok_or(Error::MissingPool)?;
        let policy: Arc<dyn BunkerPolicy> = self.policy.unwrap_or_else(|| Arc::new(ApproveAll));

        let pool = Arc::new(match pool_mode {
            PoolModeBuilder::External(p) => PoolMode::External(p),
            PoolModeBuilder::Embedded(p) => PoolMode::Embedded(p),
        });
        pool.add_and_connect(&self.relays).await?;

        let listener = spawn_listener(ListenerConfig {
            pool: Arc::clone(&pool),
            keys: keys.clone(),
            relays: self.relays.clone(),
            secret: self.secret.clone(),
            policy,
        });

        Ok(NostrConnectRemoteSigner {
            inner: Arc::new(BunkerInner {
                keys,
                relays: self.relays,
                secret: self.secret,
                pool,
                listener,
            }),
        })
    }
}

struct ListenerConfig {
    pool: Arc<PoolMode>,
    keys: NostrConnectKeys,
    relays: Vec<RelayUrl>,
    secret: Option<String>,
    policy: Arc<dyn BunkerPolicy>,
}

fn spawn_listener(config: ListenerConfig) -> AbortHandle {
    tokio::spawn(async move {
        run_listener(config).await;
    })
    .abort_handle()
}

async fn run_listener(config: ListenerConfig) {
    let ListenerConfig {
        pool,
        keys,
        relays,
        secret,
        policy,
    } = config;

    let filter = Filter::new()
        .pubkey(*keys.signer.public_key())
        .kind(Kind::new(nip46::KIND))
        .limit(0);

    let Ok(mut stream) = pool
        .stream_events_to(
            relays.clone(),
            vec![filter],
            SubscribeOptions::default(),
            None,
        )
        .await
    else {
        return;
    };

    while let Some((_url, item)) = stream.next().await {
        let Ok(event) = item else { continue };
        if event.kind != Kind::new(nip46::KIND) {
            continue;
        }
        handle_request_event(
            &pool,
            &keys,
            &relays,
            secret.as_deref(),
            policy.as_ref(),
            &event,
        )
        .await;
    }
}

async fn handle_request_event(
    pool: &PoolMode,
    keys: &NostrConnectKeys,
    relays: &[RelayUrl],
    secret: Option<&str>,
    policy: &dyn BunkerPolicy,
    event: &nula_core::Event,
) {
    let Ok(plain) = nip44::decrypt(keys.signer.secret_key(), &event.pubkey, &event.content) else {
        return;
    };
    let Ok(envelope) = serde_json::from_str::<Message>(&plain) else {
        return;
    };
    let request_id = envelope.id().to_owned();
    let Ok(request) = envelope.into_request() else {
        return;
    };
    let response = build_response(keys, secret, policy, &event.pubkey, request);
    publish_response(pool, keys, relays, &event.pubkey, &request_id, response).await;
}

fn build_response(
    keys: &NostrConnectKeys,
    secret: Option<&str>,
    policy: &dyn BunkerPolicy,
    client: &PublicKey,
    request: Request,
) -> Response {
    match request {
        Request::Connect {
            secret: presented, ..
        } => connect_response(secret, presented.as_deref()),
        other => {
            if policy.approve(client, &other) {
                handle_authorized(keys, other)
            } else {
                Response::with_error("request rejected by bunker policy")
            }
        }
    }
}

fn connect_response(expected: Option<&str>, presented: Option<&str>) -> Response {
    match expected {
        // The bunker advertised a secret: require an exact match and
        // echo it back to prove possession of the signer key.
        Some(secret) if presented == Some(secret) => {
            Response::with_result(ResponseResult::ConnectSecret(secret.to_owned()))
        }
        Some(_) => Response::with_error("invalid or missing connect secret"),
        // No secret advertised: a plain ack accepts the session.
        None => Response::with_result(ResponseResult::Ack),
    }
}

fn handle_authorized(keys: &NostrConnectKeys, request: Request) -> Response {
    match request {
        Request::GetPublicKey => {
            Response::with_result(ResponseResult::GetPublicKey(*keys.user.public_key()))
        }
        Request::SignEvent(unsigned) => match unsigned.sign_with_keys(&keys.user) {
            Ok(event) => Response::with_result(ResponseResult::SignEvent(Box::new(event))),
            Err(err) => Response::with_error(format!("sign failed: {err}")),
        },
        Request::Ping => Response::with_result(ResponseResult::Pong),
        Request::SwitchRelays => Response::with_result(ResponseResult::SwitchRelays(None)),
        Request::Nip44Encrypt { peer, text } => {
            match nip44::encrypt(keys.user.secret_key(), &peer, &text) {
                Ok(ciphertext) => Response::with_result(ResponseResult::Nip44Encrypt(ciphertext)),
                Err(err) => Response::with_error(format!("nip44_encrypt failed: {err}")),
            }
        }
        Request::Nip44Decrypt { peer, ciphertext } => {
            match nip44::decrypt(keys.user.secret_key(), &peer, &ciphertext) {
                Ok(plaintext) => Response::with_result(ResponseResult::Nip44Decrypt(plaintext)),
                Err(err) => Response::with_error(format!("nip44_decrypt failed: {err}")),
            }
        }
        #[cfg(feature = "nip04")]
        Request::Nip04Encrypt { peer, text } => {
            match nula_core::nips::nip04::encrypt(keys.user.secret_key(), &peer, &text) {
                Ok(ciphertext) => Response::with_result(ResponseResult::Nip04Encrypt(ciphertext)),
                Err(err) => Response::with_error(format!("nip04_encrypt failed: {err}")),
            }
        }
        #[cfg(feature = "nip04")]
        Request::Nip04Decrypt { peer, ciphertext } => {
            match nula_core::nips::nip04::decrypt(keys.user.secret_key(), &peer, &ciphertext) {
                Ok(plaintext) => Response::with_result(ResponseResult::Nip04Decrypt(plaintext)),
                Err(err) => Response::with_error(format!("nip04_decrypt failed: {err}")),
            }
        }
        #[cfg(not(feature = "nip04"))]
        Request::Nip04Encrypt { .. } | Request::Nip04Decrypt { .. } => {
            Response::with_error("nip04 support is disabled in this build")
        }
        // `connect` is handled before authorization; `Request` is
        // `#[non_exhaustive]`, so future variants degrade gracefully.
        _ => Response::with_error("unsupported method"),
    }
}

async fn publish_response(
    pool: &PoolMode,
    keys: &NostrConnectKeys,
    relays: &[RelayUrl],
    client: &PublicKey,
    request_id: &str,
    response: Response,
) {
    let envelope = Message::response(request_id.to_owned(), response);
    let Ok(plain) = serde_json::to_string(&envelope) else {
        return;
    };
    let Ok(ciphertext) = nip44::encrypt(keys.signer.secret_key(), client, &plain) else {
        return;
    };
    let Ok(event) = EventBuilder::new(Kind::new(nip46::KIND), ciphertext)
        .tag(Tag::p(*client))
        .sign_with_keys(&keys.signer)
    else {
        return;
    };
    pool.send_event_to(relays.to_vec(), event).await.ok();
}
