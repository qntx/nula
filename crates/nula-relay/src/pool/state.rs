//! Shared state held by every [`crate::pool::RelayPool`] clone.
//!
//! The pool is a coordinator over two long-lived collaborators: the
//! event store ([`nula_storage::NostrDatabase`]) and the WebSocket
//! transport ([`nula_relay::transport::WebSocketTransport`]). Both are wrapped in
//! `Arc<dyn …>` so they are cheap to share and trivially mockable in
//! tests. Adding a new collaborator (signer, admit policy, …) means
//! adding a field here, which is intentionally a more visible step
//! than threading it through individual call sites.

use std::sync::Arc;

use crate::transport::WebSocketTransport;
use nula_storage::NostrDatabase;

/// Long-lived collaborators shared by every clone of a
/// [`crate::pool::RelayPool`] handle.
///
/// `SharedState` itself is `Clone` and `Send + Sync`; cloning costs
/// two `Arc` bumps. The pool keeps one copy in [`crate::pool::RelayPool`]
/// and hands a clone to each [`nula_relay::Relay`] it constructs.
#[derive(Debug, Clone)]
pub(crate) struct SharedState {
    pub(crate) database: Arc<dyn NostrDatabase>,
    pub(crate) transport: Arc<dyn WebSocketTransport>,
}

impl SharedState {
    pub(crate) const fn new(
        database: Arc<dyn NostrDatabase>,
        transport: Arc<dyn WebSocketTransport>,
    ) -> Self {
        Self {
            database,
            transport,
        }
    }
}
