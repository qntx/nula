//! NIP-47 Nostr Wallet Connect (NWC) client.
//!
//! `nula-nwc` drives a remote Lightning **wallet service** from a Nostr
//! **client** over end-to-end-encrypted direct messages, on top of a
//! [`nula_relay::pool::RelayPool`]. It is the client half of NIP-47;
//! the protocol vocabulary (URIs, request/response envelopes, error
//! codes, encryption negotiation) lives in [`nula_core::nips::nip47`]
//! and is re-exported here.
//!
//! # Design
//!
//! - A single **dispatcher actor** subscribes to the wallet's response
//!   (`kind:23195`) and notification (`kind:23197` / `23196`) events,
//!   decrypts each body, and correlates responses to requests through
//!   the response's `e` tag (which references the request event id).
//! - Each request is signed with the URI's `secret` and published to
//!   every relay in the URI; the call awaits the correlated reply with
//!   a per-call timeout.
//! - Notifications are fanned out over a [`tokio::sync::broadcast`]
//!   channel ([`NostrWalletConnect::subscribe_notifications`]).
//! - Typed helpers ([`NostrWalletConnect::pay_invoice`],
//!   [`NostrWalletConnect::get_balance`], …) wrap the common methods;
//!   [`NostrWalletConnect::send_request`] covers everything else.
//!
//! Cloning a [`NostrWalletConnect`] is one `Arc` bump; dropping the last
//! clone aborts the dispatcher and (in embedded mode) the pool.
//!
//! # Feature flags
//!
//! | Feature             | Default | Description                                       |
//! | ------------------- | :-----: | ------------------------------------------------- |
//! | `nip04`             |   ✅    | Allow the legacy NIP-04 transport for old wallets. |
//! | `default-transport` |   ❌    | Ship the embedded pool with a working transport.  |
//!
//! # Quickstart
//!
//! ```rust,no_run
//! use std::sync::Arc;
//!
//! use nula_nwc::{ConnectionUri, NostrWalletConnect, PayInvoiceRequest};
//! use nula_relay::pool::RelayPool;
//!
//! # async fn doc(db: Arc<dyn nula_storage::NostrDatabase>) -> Result<(), Box<dyn std::error::Error>> {
//! let uri = ConnectionUri::parse(
//!     "nostr+walletconnect://b889ff5b1513b641e2a139f661a661364979c5beee91842f8f0ef42ab558e9d4?relay=wss://relay.example&secret=71a8c14c1407c113601079c4302dab36460f0ccd0ad506f1f2dc73b5100e4f3c",
//! )?;
//! let pool = RelayPool::builder().database(db).build()?;
//! let nwc = NostrWalletConnect::builder()
//!     .uri(uri)
//!     .embedded_pool(pool)
//!     .build()
//!     .await?;
//!
//! let balance = nwc.get_balance().await?;
//! println!("balance: {} msat", balance.balance);
//!
//! let paid = nwc.pay_invoice(PayInvoiceRequest::new("lnbc1...")).await?;
//! println!("preimage: {}", paid.preimage);
//! # Ok(()) }
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(html_root_url = "https://docs.rs/nula-nwc")]
#![forbid(unsafe_code)]

// `nula_storage` is a dev-dependency the doctest and integration tests
// use to back a `RelayPool` with an in-memory store. The lib's own unit
// tests do not touch it, so hedge the `unused_crate_dependencies` lint
// on the lib-test build.
#[cfg(test)]
use nula_storage as _;

pub mod error;
pub mod methods;
pub mod options;

mod client;
mod dispatcher;
mod inner;
mod pending;
mod pool_handle;

// Re-export the NIP-47 protocol vocabulary callers interact with.
pub use nula_core::nips::nip47::{
    ConnectionUri, Encryption, ErrorCode, InfoEvent, Notification, NwcError, Request, Response,
    ResponseError,
};

pub use self::client::{NostrWalletConnect, NostrWalletConnectBuilder};
pub use self::error::Error;
pub use self::methods::{
    GetBalanceResponse, GetInfoResponse, ListTransactionsRequest, ListTransactionsResponse,
    LookupInvoiceRequest, MakeInvoiceRequest, PayInvoiceRequest, PayInvoiceResponse, Transaction,
    TransactionType,
};
pub use self::options::NwcOptions;
