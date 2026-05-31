//! Public [`NostrWalletConnect`] handle and its builder.

use std::sync::Arc;

use futures::StreamExt as _;
use nula_core::nips::nip47::{
    ConnectionUri, InfoEvent, KIND_INFO, Notification, Request, Response,
};
use nula_core::{EventBuilder, Filter, Keys, PublicKey, RelayUrl};
use nula_relay::SubscribeOptions;
use nula_relay::pool::RelayPool;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::broadcast;
use tokio::time::timeout;

use crate::dispatcher::{self, DispatcherConfig};
use crate::error::Error;
use crate::inner::Inner;
use crate::methods::{
    GetBalanceResponse, GetInfoResponse, ListTransactionsRequest, ListTransactionsResponse,
    LookupInvoiceRequest, MakeInvoiceRequest, PayInvoiceRequest, PayInvoiceResponse,
    PayKeysendRequest, Transaction,
};
use crate::options::NwcOptions;
use crate::pending::PendingMap;
use crate::pool_handle::PoolMode;

/// A NIP-47 Nostr Wallet Connect client.
///
/// Cloning is cheap (one `Arc` bump). Dropping the last clone aborts the
/// dispatcher actor and, in embedded mode, shuts down the pool.
///
/// See [the crate docs](crate) for the full design and usage notes.
#[derive(Debug, Clone)]
pub struct NostrWalletConnect {
    inner: Arc<Inner>,
}

impl NostrWalletConnect {
    /// Begin configuring a client.
    pub fn builder() -> NostrWalletConnectBuilder {
        NostrWalletConnectBuilder::new()
    }

    /// The client public key (derived from the URI `secret`).
    #[must_use]
    pub fn client_public_key(&self) -> PublicKey {
        *self.inner.client_keys.public_key()
    }

    /// The wallet service public key (the URI host).
    #[must_use]
    pub fn wallet_public_key(&self) -> PublicKey {
        self.inner.wallet_pubkey
    }

    /// Relay URLs taken from the URI at construction time.
    #[must_use]
    pub fn relays(&self) -> &[RelayUrl] {
        &self.inner.relays
    }

    /// The optional `lud16` lightning address carried by the URI.
    #[must_use]
    pub fn lud16(&self) -> Option<&str> {
        self.inner.lud16.as_deref()
    }

    /// `true` for an embedded-pool deployment.
    #[must_use]
    pub fn is_embedded_pool(&self) -> bool {
        self.inner.pool.is_embedded()
    }

    /// Subscribe to wallet notifications (`kind:23197` / legacy
    /// `kind:23196`). Each subscriber receives every notification
    /// published after it subscribed.
    #[must_use]
    pub fn subscribe_notifications(&self) -> broadcast::Receiver<Notification> {
        self.inner.notifications.subscribe()
    }


    /// `pay_invoice` — settle a BOLT-11 invoice.
    ///
    /// # Errors
    ///
    /// Forwards transport, encryption, timeout, and wallet-error
    /// conditions as [`Error`].
    pub async fn pay_invoice(
        &self,
        request: PayInvoiceRequest,
    ) -> Result<PayInvoiceResponse, Error> {
        self.call("pay_invoice", request).await
    }

    /// `pay_keysend` — pay a node directly by public key (no invoice).
    ///
    /// # Errors
    ///
    /// See [`Self::pay_invoice`].
    pub async fn pay_keysend(
        &self,
        request: PayKeysendRequest,
    ) -> Result<PayInvoiceResponse, Error> {
        self.call("pay_keysend", request).await
    }

    /// `get_balance` — read the wallet balance (msat).
    ///
    /// # Errors
    ///
    /// See [`Self::pay_invoice`].
    pub async fn get_balance(&self) -> Result<GetBalanceResponse, Error> {
        self.call("get_balance", serde_json::json!({})).await
    }

    /// `get_info` — read node information and supported methods.
    ///
    /// # Errors
    ///
    /// See [`Self::pay_invoice`].
    pub async fn get_info(&self) -> Result<GetInfoResponse, Error> {
        self.call("get_info", serde_json::json!({})).await
    }

    /// `make_invoice` — create a BOLT-11 invoice.
    ///
    /// # Errors
    ///
    /// See [`Self::pay_invoice`].
    pub async fn make_invoice(&self, request: MakeInvoiceRequest) -> Result<Transaction, Error> {
        self.call("make_invoice", request).await
    }

    /// `lookup_invoice` — fetch a transaction by payment hash or invoice.
    ///
    /// # Errors
    ///
    /// See [`Self::pay_invoice`].
    pub async fn lookup_invoice(
        &self,
        request: LookupInvoiceRequest,
    ) -> Result<Transaction, Error> {
        self.call("lookup_invoice", request).await
    }

    /// `list_transactions` — page through the wallet's transactions.
    ///
    /// # Errors
    ///
    /// See [`Self::pay_invoice`].
    pub async fn list_transactions(
        &self,
        request: ListTransactionsRequest,
    ) -> Result<ListTransactionsResponse, Error> {
        self.call("list_transactions", request).await
    }

    /// Send an arbitrary NIP-47 [`Request`] and return the raw
    /// [`Response`]. Use this for methods without a typed wrapper.
    ///
    /// Unlike the typed helpers, a populated `error` envelope is
    /// returned inside the `Response` rather than mapped to
    /// [`Error::Wallet`].
    ///
    /// # Errors
    ///
    /// Forwards transport, encryption, and timeout conditions.
    pub async fn send_request(&self, request: Request) -> Result<Response, Error> {
        self.dispatch(request).await
    }

    /// Fetch the wallet's `kind:13194` capability advert.
    ///
    /// Useful to learn the supported methods, notification types, and
    /// encryption schemes before issuing requests.
    ///
    /// # Errors
    ///
    /// [`Error::Timeout`] if no info event arrives within the
    /// configured timeout, or a forwarded parse error.
    pub async fn get_info_event(&self) -> Result<InfoEvent, Error> {
        let fetch = read_info_event(
            &self.inner.pool,
            self.inner.relays.clone(),
            self.inner.wallet_pubkey,
        );
        match timeout(self.inner.options.timeout, fetch).await {
            Ok(result) => result,
            Err(_elapsed) => Err(Error::Timeout {
                method: "get_info_event".to_owned(),
            }),
        }
    }

    /// Abort the dispatcher actor. In embedded mode the pool is shut
    /// down when the last clone drops.
    pub fn shutdown(&self) {
        self.inner.dispatcher.abort();
    }


    /// Serialize `params`, dispatch the request, and deserialize a
    /// success result into `R`, mapping an `error` envelope to
    /// [`Error::Wallet`].
    async fn call<P, R>(&self, method: &str, params: P) -> Result<R, Error>
    where
        P: Serialize,
        R: DeserializeOwned,
    {
        // Consume `params` into a `Value` before any `await` so the
        // returned future stays `Send` regardless of `P`.
        let params = serde_json::to_value(params).map_err(Error::json)?;
        let request = Request {
            method: method.to_owned(),
            params,
        };
        let response = self.dispatch(request).await?;
        if let Some(error) = response.error {
            return Err(Error::Wallet {
                method: method.to_owned(),
                code: error.code,
                message: error.message,
            });
        }
        let result = response.result.ok_or_else(|| Error::UnexpectedResult {
            method: method.to_owned(),
            message: "wallet returned neither result nor error".to_owned(),
        })?;
        serde_json::from_value(result).map_err(Error::json)
    }

    /// Build, encrypt, publish a request and await the correlated reply.
    async fn dispatch(&self, request: Request) -> Result<Response, Error> {
        let method = request.method.clone();
        let event = EventBuilder::nwc_request(
            self.inner.client_keys.secret_key(),
            &self.inner.wallet_pubkey,
            &request,
            self.inner.options.encryption,
            None,
        )?
        .sign_with_keys(&self.inner.client_keys)?;
        let request_id = event.id;

        let receiver = self.inner.pending.insert(request_id);
        let output = self
            .inner
            .pool
            .send_event_to(self.inner.relays.clone(), event)
            .await?;
        if output.is_total_failure() {
            // The request never went out; drop the orphaned slot.
            self.inner.pending.take(&request_id);
            return Err(Error::PublishFailed(format!("{:?}", output.failed)));
        }

        match timeout(self.inner.options.timeout, receiver).await {
            Ok(Ok(reply)) => reply,
            Ok(Err(_recv)) => Err(Error::DispatcherDown("pending channel cancelled")),
            Err(_elapsed) => {
                self.inner.pending.take(&request_id);
                Err(Error::Timeout { method })
            }
        }
    }
}

/// Builder for [`NostrWalletConnect`].
#[derive(Debug, Default)]
#[must_use]
pub struct NostrWalletConnectBuilder {
    uri: Option<ConnectionUri>,
    options: NwcOptions,
    pool: Option<PoolModeBuilder>,
}

#[derive(Debug)]
enum PoolModeBuilder {
    External(Arc<RelayPool>),
    Embedded(RelayPool),
}

impl NostrWalletConnectBuilder {
    /// Construct an empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the `nostr+walletconnect://` connection URI. Required.
    pub fn uri(mut self, uri: ConnectionUri) -> Self {
        self.uri = Some(uri);
        self
    }

    /// Override the runtime configuration.
    pub const fn options(mut self, options: NwcOptions) -> Self {
        self.options = options;
        self
    }

    /// Use an externally-owned pool. Mutually exclusive with
    /// [`Self::embedded_pool`].
    pub fn pool(mut self, pool: Arc<RelayPool>) -> Self {
        self.pool = Some(PoolModeBuilder::External(pool));
        self
    }

    /// Use an embedded pool the client owns and shuts down on drop.
    /// Mutually exclusive with [`Self::pool`].
    pub fn embedded_pool(mut self, pool: RelayPool) -> Self {
        self.pool = Some(PoolModeBuilder::Embedded(pool));
        self
    }

    /// Connect the relays, spawn the dispatcher, and return the client.
    ///
    /// # Errors
    ///
    /// - [`Error::MissingUri`] when [`Self::uri`] was not called.
    /// - [`Error::MissingPool`] when no pool was supplied.
    /// - [`Error::Pool`] if the pool refuses to add the URI's relays.
    pub async fn build(self) -> Result<NostrWalletConnect, Error> {
        let uri = self.uri.ok_or(Error::MissingUri)?;
        let pool_mode = self.pool.ok_or(Error::MissingPool)?;

        let ConnectionUri {
            wallet_pubkey,
            relays,
            secret,
            lud16,
        } = uri;
        let client_keys = Keys::from_secret_key(secret);

        let pool = Arc::new(match pool_mode {
            PoolModeBuilder::External(p) => PoolMode::External(p),
            PoolModeBuilder::Embedded(p) => PoolMode::Embedded(p),
        });
        pool.add_and_connect(&relays).await?;

        let pending = Arc::new(PendingMap::new());
        let (notifications, _rx) = broadcast::channel(self.options.notification_buffer);

        let dispatcher = dispatcher::spawn(DispatcherConfig {
            pool: Arc::clone(&pool),
            client_secret: client_keys.secret_key().clone(),
            client_pubkey: *client_keys.public_key(),
            wallet_pubkey,
            pending: Arc::clone(&pending),
            notifications: notifications.clone(),
            relays: relays.clone(),
        });

        let inner = Arc::new(Inner {
            pool,
            options: self.options,
            client_keys,
            wallet_pubkey,
            relays,
            lud16,
            pending,
            notifications,
            dispatcher,
        });
        Ok(NostrWalletConnect { inner })
    }
}

/// Read the wallet's `kind:13194` info event from `pool`.
///
/// No timeout of its own; [`NostrWalletConnect::get_info_event`] wraps
/// this in [`tokio::time::timeout`]. Extracted as a free function to keep
/// the public method's nesting shallow.
async fn read_info_event(
    pool: &PoolMode,
    relays: Vec<RelayUrl>,
    wallet: PublicKey,
) -> Result<InfoEvent, Error> {
    let filter = Filter::new().author(wallet).kind(KIND_INFO).limit(1);
    let mut stream = pool
        .stream_events_to(relays, vec![filter], SubscribeOptions::default(), None)
        .await?;
    while let Some((_url, item)) = stream.next().await {
        let Ok(event) = item else { continue };
        if event.pubkey == wallet && event.kind == KIND_INFO {
            return InfoEvent::from_event(&event).map_err(Error::from);
        }
    }
    Err(Error::UnexpectedResult {
        method: "get_info_event".to_owned(),
        message: "info stream ended without a kind:13194 event".to_owned(),
    })
}
