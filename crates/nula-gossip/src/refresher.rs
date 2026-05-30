//! Background refresher.
//!
//! Wakes up every [`crate::GossipOptions::refresher_interval`], asks
//! the cache for up to [`crate::GossipOptions::refresher_batch`]
//! outdated keys (NIP-65 first, then NIP-17), and refreshes each one
//! through the configured [`RelayPool`] using the discovery relay
//! set the caller supplied at start-up.

use std::collections::BTreeSet;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use nula_core::RelayUrl;
use nula_relay::pool::RelayPool;
use tokio::task::{AbortHandle, JoinHandle};

use crate::gossip::Gossip;
use crate::options::ListKind;

/// Owning handle around a spawned refresher task. Drop aborts the
/// task. The handle is `Send + Sync` so it can sit inside
/// [`Gossip`]'s clone-cheap `Arc` graph.
#[derive(Debug)]
pub struct RefresherHandle {
    abort: AbortHandle,
}

impl RefresherHandle {
    /// Spawn the refresher loop and return its abort handle.
    ///
    /// The task aborts cleanly on three triggers:
    ///
    /// - `RefresherHandle::drop` — explicit shutdown.
    /// - The pool emits a [`nula_relay::pool::PoolNotification::Shutdown`]
    ///   notification while the task is mid-cycle.
    /// - The configured tick interval is `None`, in which case the
    ///   builder never calls us in the first place.
    ///
    /// # Panics
    ///
    /// Panics if `gossip.options().refresher_interval` is `None`;
    /// callers must check the option before invoking this helper.
    #[must_use]
    #[allow(
        clippy::expect_used,
        reason = "refresher_interval is a builder-time invariant"
    )]
    pub fn spawn(
        gossip: Gossip,
        pool: Arc<RelayPool>,
        discovery: Vec<RelayUrl>,
        per_refresh_timeout: Duration,
    ) -> Self {
        let interval = gossip
            .options()
            .refresher_interval
            .expect("RefresherHandle::spawn requires refresher_interval to be Some");
        let batch =
            NonZeroUsize::new(gossip.options().refresher_batch.max(1)).expect("max(1) is non-zero");
        let join: JoinHandle<()> = tokio::spawn(async move {
            run_loop(
                gossip,
                pool,
                discovery,
                interval,
                batch,
                per_refresh_timeout,
            )
            .await;
        });
        Self {
            abort: join.abort_handle(),
        }
    }

    /// Trigger an explicit shutdown without dropping the handle.
    pub fn shutdown(&self) {
        self.abort.abort();
    }
}

impl Drop for RefresherHandle {
    fn drop(&mut self) {
        self.abort.abort();
    }
}

async fn run_loop(
    gossip: Gossip,
    pool: Arc<RelayPool>,
    discovery: Vec<RelayUrl>,
    interval: Duration,
    batch: NonZeroUsize,
    per_refresh_timeout: Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    // The first tick fires immediately; skip it so a freshly-built
    // refresher does not race with `warm_up`.
    ticker.tick().await;

    while !discovery.is_empty() {
        ticker.tick().await;
        for kind in [ListKind::Nip65, ListKind::Nip17] {
            refresh_one_kind(&gossip, &pool, &discovery, batch, per_refresh_timeout, kind).await;
        }
    }
    // `discovery.is_empty()` falls through to a tight loop with
    // nothing to do; sleep forever so the spawned task does not
    // burn CPU. The handle's `Drop` aborts us.
    futures::future::pending::<()>().await;
}

async fn refresh_one_kind(
    gossip: &Gossip,
    pool: &RelayPool,
    discovery: &[RelayUrl],
    batch: NonZeroUsize,
    per_refresh_timeout: Duration,
    kind: ListKind,
) {
    let outdated: BTreeSet<crate::ttl::OutdatedKey> = gossip.outdated(kind, batch).await;
    if outdated.is_empty() {
        return;
    }
    for key in outdated {
        // Refresh failures are intentionally swallowed: the
        // refresher is best-effort. Production logs surface them via
        // the `tracing` feature.
        let res = gossip
            .refresh(
                pool,
                &key.public_key,
                kind,
                discovery.iter().cloned(),
                per_refresh_timeout,
            )
            .await;
        #[cfg(feature = "tracing")]
        if let Err(err) = res {
            tracing::debug!(
                target: "nula_gossip::refresher",
                ?kind,
                public_key = %key.public_key,
                ?err,
                "refresh attempt failed",
            );
        }
        #[cfg(not(feature = "tracing"))]
        drop(res);
    }
}
