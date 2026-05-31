//! Shared state behind every [`crate::NostrWalletConnect`] clone.

use std::sync::Arc;

use nula_core::nips::nip47::Notification;
use nula_core::{Keys, PublicKey, RelayUrl};
use tokio::sync::broadcast;
use tokio::task::AbortHandle;

use crate::options::NwcOptions;
use crate::pending::PendingMap;
use crate::pool_handle::PoolMode;

/// Internal state shared by every clone of a [`crate::NostrWalletConnect`].
#[derive(Debug)]
pub(crate) struct Inner {
    pub(crate) pool: Arc<PoolMode>,
    pub(crate) options: NwcOptions,
    /// Client keypair derived from the URI `secret`; signs every
    /// request and decrypts every reply.
    pub(crate) client_keys: Keys,
    /// Wallet service public key (the URI host).
    pub(crate) wallet_pubkey: PublicKey,
    /// Relay set captured from the URI.
    pub(crate) relays: Vec<RelayUrl>,
    /// Optional `lud16` lightning address carried by the URI.
    pub(crate) lud16: Option<String>,
    pub(crate) pending: Arc<PendingMap>,
    pub(crate) notifications: broadcast::Sender<Notification>,
    pub(crate) dispatcher: AbortHandle,
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Abort the dispatcher when the last clone goes away; the
        // dispatcher's own `cancel_all` hook releases pending requests.
        self.dispatcher.abort();
    }
}
