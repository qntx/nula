//! Pending-request map.
//!
//! The dispatcher actor receives one stream of `kind:24133` events
//! and has to fan replies back to the right `await`-ing caller. The
//! caller's send path drops one entry into [`PendingMap`] keyed by
//! the JSON-RPC `id`; the dispatcher pulls it back out, parses the
//! reply against the stored [`Method`], and delivers the result on
//! the [`tokio::sync::oneshot`] channel.

use std::collections::HashMap;
use std::sync::Mutex;

use nula_core::nips::nip46::{Method, ResponseResult};
use tokio::sync::oneshot;

use crate::error::Error;

/// Reply slot for a single in-flight RPC.
#[derive(Debug)]
pub(crate) struct Pending {
    /// Method whose response shape we must decode against.
    pub(crate) method: Method,
    /// One-shot reply channel.
    pub(crate) sender: oneshot::Sender<Result<ResponseResult, Error>>,
}

/// Concurrent-safe map of pending RPCs.
#[derive(Debug, Default)]
pub(crate) struct PendingMap {
    inner: Mutex<HashMap<String, Pending>>,
}

impl PendingMap {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Register a new pending entry. The returned receiver yields
    /// the eventual reply (or [`Error::DispatcherDown`] /
    /// [`Error::Cancelled`] when the dispatcher tears down).
    pub(crate) fn insert(
        &self,
        id: &str,
        method: Method,
    ) -> oneshot::Receiver<Result<ResponseResult, Error>> {
        let (sender, receiver) = oneshot::channel();
        let pending = Pending { method, sender };
        // `insert` returns the previous entry (if any) which we
        // drop — its `sender` is then dropped too, surfacing
        // `Error::Cancelled` to the now-orphaned waiter.
        if let Ok(mut guard) = self.inner.lock()
            && let Some(prev) = guard.insert(id.to_owned(), pending)
        {
            // The id collision is unreachable if the caller seeds id
            // from a strong RNG; surface as `Cancelled` so the
            // earlier waiter does not hang forever.
            prev.sender
                .send(Err(Error::Cancelled("id collision in PendingMap")))
                .ok();
        }
        receiver
    }

    /// Pull out the pending entry matching `id`, if any.
    pub(crate) fn take(&self, id: &str) -> Option<Pending> {
        self.inner.lock().ok().and_then(|mut g| g.remove(id))
    }

    /// Put a previously-taken entry back. Used by the dispatcher
    /// when the bunker emits an `auth_url` response and the real
    /// reply with the same `id` is still expected.
    pub(crate) fn reinsert(&self, id: String, pending: Pending) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.insert(id, pending);
        }
    }

    /// Cancel every pending RPC with `error`. Used when the
    /// dispatcher actor terminates.
    pub(crate) fn cancel_all(&self, error: &(impl Fn() -> Error + Send + Sync)) {
        if let Ok(mut guard) = self.inner.lock() {
            for (_id, pending) in guard.drain() {
                pending.sender.send(Err(error())).ok();
            }
        }
    }
}
