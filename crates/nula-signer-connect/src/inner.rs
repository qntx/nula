//! Shared mutable state behind every [`crate::NostrConnect`] clone.

use std::sync::Arc;

use nula_core::Keys;
use tokio::sync::OnceCell;
use tokio::task::AbortHandle;

use crate::options::NostrConnectOptions;
use crate::pending::PendingMap;
use crate::pool_handle::PoolMode;

/// Internal state shared by every clone of a [`crate::NostrConnect`].
///
/// `nostrconnect_secret` and `auth_url_handler` are owned by the
/// dispatcher actor (which captured them at spawn time); we
/// intentionally do not duplicate them here.
#[derive(Debug)]
pub(crate) struct Inner {
    pub(crate) pool: Arc<PoolMode>,
    pub(crate) options: NostrConnectOptions,
    pub(crate) client_keys: Keys,
    pub(crate) pending: Arc<PendingMap>,
    pub(crate) dispatcher: AbortHandle,
    pub(crate) remote_signer_pk: Arc<OnceCell<nula_core::PublicKey>>,
    pub(crate) user_pk: OnceCell<nula_core::PublicKey>,
    pub(crate) bunker_secret: Option<String>,
    pub(crate) relays: Vec<nula_core::RelayUrl>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Abort the dispatcher whenever the last clone goes away.
        // Pending RPCs are released by the dispatcher's own
        // `cancel_all` cleanup hook.
        self.dispatcher.abort();
    }
}
