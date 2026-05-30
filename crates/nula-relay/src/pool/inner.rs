//! Internal pool state and per-relay bookkeeping.
//!
//! The public [`crate::pool::RelayPool`] handle is a thin `Arc<Inner>`
//! wrapper. Every collaborator that mutates pool state — `add_relay`,
//! `remove_relay`, `connect`, `subscribe`, the per-relay notification
//! forwarder, the [`Drop`] path — runs through this module so the
//! invariants live in one place.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::{Relay, RelayNotification};
use nula_core::RelayUrl;
use tokio::sync::{RwLock, broadcast};
use tokio::task::{AbortHandle, JoinHandle};

use crate::pool::capabilities::{AtomicRelayCapabilities, RelayCapabilities};
use crate::pool::notification::PoolNotification;
use crate::pool::options::RelayPoolOptions;
use crate::pool::state::SharedState;

/// Per-relay record kept inside the pool.
///
/// Owns the [`Relay`] handle, the live capability set, and the abort
/// handle of the forwarder task that bridges the relay's
/// [`RelayNotification`] stream onto the pool's broadcast channel.
#[derive(Debug)]
pub(crate) struct RelayEntry {
    pub(crate) relay: Relay,
    pub(crate) capabilities: AtomicRelayCapabilities,
    /// Aborts on drop — kept here so [`Inner::Drop`] tears every
    /// forwarder down without waiting for the relay actor to
    /// finish.
    forwarder: AbortHandle,
}

impl RelayEntry {
    pub(crate) const fn new(
        relay: Relay,
        capabilities: RelayCapabilities,
        forwarder: AbortHandle,
    ) -> Self {
        Self {
            relay,
            capabilities: AtomicRelayCapabilities::new(capabilities),
            forwarder,
        }
    }
}

impl Drop for RelayEntry {
    fn drop(&mut self) {
        self.forwarder.abort();
    }
}

/// Heart of the pool. Every public [`crate::pool::RelayPool`] method
/// dispatches into a method on `Inner`.
#[derive(Debug)]
pub(crate) struct Inner {
    pub(crate) state: SharedState,
    pub(crate) relays: RwLock<HashMap<RelayUrl, RelayEntry>>,
    pub(crate) notification_tx: broadcast::Sender<PoolNotification>,
    pub(crate) options: RelayPoolOptions,
    shutdown: AtomicBool,
}

impl Inner {
    pub(crate) fn new(state: SharedState, options: RelayPoolOptions) -> Arc<Self> {
        let (notification_tx, _) = broadcast::channel(options.notification_channel_size.get());
        Arc::new(Self {
            state,
            relays: RwLock::new(HashMap::new()),
            notification_tx,
            options,
            shutdown: AtomicBool::new(false),
        })
    }

    pub(crate) fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Acquire)
    }

    /// Mark the pool as shut down and broadcast
    /// [`PoolNotification::Shutdown`]. Idempotent.
    pub(crate) fn mark_shutdown(&self) {
        // SeqCst pairs with `is_shutdown`'s Acquire so observers
        // either see "still up" or "shut down" without a torn read.
        if !self.shutdown.swap(true, Ordering::SeqCst) {
            // Best-effort: send fails when no receiver subscribed,
            // which is fine — there is nobody to tell.
            self.notification_tx.send(PoolNotification::Shutdown).ok();
        }
    }

    /// Drain every relay entry, disconnecting each [`Relay`] handle
    /// and aborting its forwarder. Safe to call multiple times — the
    /// inner map starts out empty after the first call.
    pub(crate) async fn drain_relays(&self) {
        let mut relays = self.relays.write().await;
        let drained: Vec<(RelayUrl, RelayEntry)> = relays.drain().collect();
        // Drop the lock before any disconnect — `Relay::disconnect`
        // is `async`, holding `relays` across an `await` would
        // serialise teardown.
        drop(relays);

        for (url, entry) in drained {
            // The forwarder is aborted by `RelayEntry::drop`; we
            // disconnect first so the actor sees the shutdown
            // command before the handle is freed.
            entry.relay.disconnect().await.ok();
            self.notification_tx
                .send(PoolNotification::RelayRemoved { url })
                .ok();
        }
    }
}

/// Spawn the per-relay forwarder that bridges
/// [`Relay::notifications`] onto the pool's broadcast channel.
///
/// `notifications` is taken once at registration time; if the relay
/// was constructed elsewhere and someone else already drained it the
/// forwarder is a no-op (it observes `None` and returns).
pub(crate) fn spawn_forwarder(
    url: RelayUrl,
    relay: &Relay,
    notification_tx: broadcast::Sender<PoolNotification>,
) -> AbortHandle {
    let rx = relay.notifications();
    let handle: JoinHandle<()> = tokio::spawn(async move {
        let Some(mut rx) = rx else {
            // Notification stream already taken — nothing to forward.
            return;
        };
        while let Some(item) = rx.recv().await {
            // Translation returns `None` for variants the pool does
            // not surface (today: AUTH challenge — left to the
            // relay-level handler).
            let Some(msg) = translate(url.clone(), item) else {
                continue;
            };
            let is_terminal = matches!(msg, PoolNotification::RelayRemoved { .. });
            notification_tx.send(msg).ok();
            if is_terminal {
                break;
            }
        }
    });
    handle.abort_handle()
}

fn translate(url: RelayUrl, item: RelayNotification) -> Option<PoolNotification> {
    match item {
        RelayNotification::Status(status) => Some(PoolNotification::Status { url, status }),
        RelayNotification::Notice(message) => Some(PoolNotification::Notice { url, message }),
        RelayNotification::Shutdown => Some(PoolNotification::RelayRemoved { url }),
        // AUTH challenges (when the `nip42` feature is on) and any
        // future variants added behind `#[non_exhaustive]` are
        // intentionally not surfaced at the pool level. NIP-42
        // handling is per-relay and lives in the SDK layer; relays
        // needing manual AUTH should be subscribed to directly via
        // `nula_relay::Relay::notifications`.
        _ => None,
    }
}
