//! Pending-request map.
//!
//! NIP-47 correlates a wallet response to its request through the
//! response's `e` tag, which references the **request event id**. The
//! caller's send path registers one entry in [`PendingMap`] keyed by
//! that id; the dispatcher actor pulls it back out when the matching
//! `kind:23195` response arrives and delivers it over the
//! [`tokio::sync::oneshot`] channel.

use std::collections::HashMap;
use std::sync::Mutex;

use nula_core::EventId;
use nula_core::nips::nip47::Response;
use tokio::sync::oneshot;

use crate::error::Error;

type Reply = Result<Response, Error>;

/// Concurrent-safe map of in-flight requests keyed by request event id.
#[derive(Debug, Default)]
pub(crate) struct PendingMap {
    inner: Mutex<HashMap<EventId, oneshot::Sender<Reply>>>,
}

impl PendingMap {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Register a request and return the receiver for its eventual
    /// reply (or a teardown error).
    pub(crate) fn insert(&self, id: EventId) -> oneshot::Receiver<Reply> {
        let (sender, receiver) = oneshot::channel();
        if let Ok(mut guard) = self.inner.lock() {
            guard.insert(id, sender);
        }
        receiver
    }

    /// Remove and return the reply slot for `id`, if present.
    pub(crate) fn take(&self, id: &EventId) -> Option<oneshot::Sender<Reply>> {
        self.inner.lock().ok().and_then(|mut g| g.remove(id))
    }

    /// Resolve a single pending request with `reply`.
    pub(crate) fn resolve(&self, id: &EventId, reply: Reply) {
        if let Some(sender) = self.take(id) {
            sender.send(reply).ok();
        }
    }

    /// Fail every pending request (used when the dispatcher tears down,
    /// or when a publish fails on every relay).
    pub(crate) fn cancel_all(&self, error: &(impl Fn() -> Error + Send + Sync)) {
        if let Ok(mut guard) = self.inner.lock() {
            for (_id, sender) in guard.drain() {
                sender.send(Err(error())).ok();
            }
        }
    }
}
