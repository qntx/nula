//! NIP-65 outbox-model automatic routing for [`Client`].
//!
//! When a [`crate::Client`] is built with a [`Gossip`] router, the
//! high-level read/write methods stop fanning out to every relay and
//! instead let the routing graph pick targets:
//!
//! - **Writes** ([`Client::send_event`]) go to the author's outbox
//!   relays unioned with each `#p` recipient's inbox relays (DM relays
//!   for NIP-17 gift wraps). See [`Gossip::break_down_event`].
//! - **Reads** ([`Client::subscribe`] / [`Client::fetch_events`] /
//!   [`Client::stream_events`]) are broken into per-relay sub-filters
//!   via [`Gossip::break_down_filter`]; author filters fan out to
//!   outbox relays, `#p` filters to inbox relays.
//!
//! Relays named by the routing graph that the pool does not yet know
//! are added on demand (tagged [`RelayCapabilities::GOSSIP`]) and
//! connected, so a cold client can reach a peer it has never spoken to
//! purely from that peer's published NIP-65 list.
//!
//! Explicit-relay variants (`*_to`, `*_from`) deliberately bypass all
//! of this: when the caller names the relays, the caller's choice wins.
//!
//! [`Client::send_event`]: crate::Client::send_event
//! [`Client::subscribe`]: crate::Client::subscribe
//! [`Client::fetch_events`]: crate::Client::fetch_events
//! [`Client::stream_events`]: crate::Client::stream_events

use std::num::NonZeroUsize;
use std::time::Duration;

use futures::StreamExt as _;
use futures::stream::select_all;
use nula_core::BoxStream;
use nula_core::event::{Event, EventId};
use nula_core::filter::Filter;
use nula_core::message::SubscriptionId;
use nula_core::types::RelayUrl;
use nula_gossip::{BrokenDownFilters, EventRoute, Gossip, ListKind};
use nula_relay::SubscribeOptions;
use nula_relay::pool::{Output, RelayCapabilities, RelayPool};

use crate::client::{Client, SubscriptionRecord};
use crate::error::Error;

/// Per-list refresh timeout used by the background refresher. Bounds
/// each `(pubkey, list_kind)` fetch so one slow discovery relay cannot
/// wedge a refresher tick.
const REFRESH_TIMEOUT: Duration = Duration::from_secs(10);

impl Client {
    /// Register and connect every relay in `urls` the pool does not
    /// already know, tagging it [`RelayCapabilities::GOSSIP`].
    ///
    /// Best-effort throughout: a relay that fails admission, the
    /// `add_relay` cap, or its connect handshake is skipped without
    /// aborting the batch — the caller's send/subscribe still reaches
    /// every relay that *did* come up. Relays already in the pool are
    /// left untouched (capabilities and connection state preserved).
    pub(crate) async fn ensure_gossip_relays<I>(&self, urls: I)
    where
        I: IntoIterator<Item = RelayUrl>,
    {
        for url in urls {
            if self.inner.pool.relay(&url).await.is_some() {
                continue;
            }
            if self.check_admit_relay(&url).await.is_err() {
                continue;
            }
            if self
                .inner
                .pool
                .add_relay(url.clone(), RelayCapabilities::GOSSIP)
                .await
                .is_err()
            {
                continue;
            }
            if self.check_admit_connection(&url).await.is_err() {
                continue;
            }
            if let Some(relay) = self.inner.pool.relay(&url).await {
                // Bounded by the relay's own `connect_timeout`, so a
                // dead gossip relay times out instead of wedging the
                // calling send/subscribe.
                drop(relay.connect().await);
            }
        }
    }

    /// Gossip-routed backing for [`Client::send_event`].
    ///
    /// Resolves the outbox-model target set via
    /// [`Gossip::break_down_event`], ensures those relays are live,
    /// and publishes to them. A NIP-17 gift wrap whose recipients
    /// advertise no DM relays returns
    /// [`Error::PrivateMessageRelaysNotFound`] rather than leaking the
    /// ciphertext to a broadcast; any other event with no resolvable
    /// route falls back to the pool's WRITE relays.
    pub(crate) async fn gossip_send_event(
        &self,
        gossip: &Gossip,
        event: Event,
    ) -> Result<Output<EventId>, Error> {
        match gossip.break_down_event(&event).await {
            EventRoute::Relays(relays) => {
                self.ensure_gossip_relays(relays.iter().cloned()).await;
                Ok(self.inner.pool.send_event_to(relays, event).await?)
            }
            EventRoute::Orphan {
                private_message: true,
            } => Err(Error::PrivateMessageRelaysNotFound),
            // `Orphan { private_message: false }` and any future
            // (`#[non_exhaustive]`) variant carry no NIP-17
            // constraint, so fall back to a WRITE-relay broadcast.
            _ => Ok(self.inner.pool.send_event(event).await?),
        }
    }

    /// Gossip-routed backing for [`Client::stream_events`] (and, via
    /// it, [`Client::fetch_events`]).
    ///
    /// Breaks `filter` into per-relay sub-filters, opens one EOSE
    /// stream per relay, and merges them into a single stream. When
    /// the filter carries no public-key routing signal (or the graph
    /// has no relays for it) the original filter streams from the
    /// generic READ pool instead.
    pub(crate) async fn gossip_stream_events(
        &self,
        gossip: &Gossip,
        filter: Filter,
        timeout: Option<Duration>,
    ) -> Result<BoxStream<'static, (RelayUrl, Result<Event, nula_relay::Error>)>, Error> {
        let options = SubscribeOptions::default().close_on_eose(true);
        // Orphan / Generic / future non_exhaustive shapes carry no
        // per-relay routing: stream from the generic READ pool with
        // the original filter (Orphan & Generic hand back an equal
        // filter, so reusing `filter` is exact).
        let BrokenDownFilters::PerRelay(map) = gossip.break_down_filter(filter.clone()).await
        else {
            return Ok(self
                .inner
                .pool
                .stream_events(vec![filter], options, timeout)
                .await?);
        };
        self.ensure_gossip_relays(map.keys().cloned()).await;
        let mut streams = Vec::with_capacity(map.len());
        for (url, narrowed) in map {
            if let Ok(stream) = self
                .inner
                .pool
                .stream_events_to(vec![url], vec![narrowed], options, timeout)
                .await
            {
                streams.push(stream);
            }
        }
        if streams.is_empty() {
            // Every resolved relay was unreachable; fall back to the
            // generic READ pool with the original filter.
            return Ok(self
                .inner
                .pool
                .stream_events(vec![filter], options, timeout)
                .await?);
        }
        Ok(select_all(streams).boxed())
    }

    /// Gossip-routed backing for [`Client::subscribe_with_id`].
    ///
    /// Issues the same subscription id to every resolved relay with
    /// its narrowed sub-filter, then records the union in the client's
    /// subscription registry so [`Client::unsubscribe`] can tear it
    /// down. Filters with no routing signal subscribe across the
    /// generic READ pool.
    pub(crate) async fn gossip_subscribe(
        &self,
        gossip: &Gossip,
        id: SubscriptionId,
        filter: Filter,
        options: SubscribeOptions,
    ) -> Result<Output<SubscriptionId>, Error> {
        let BrokenDownFilters::PerRelay(map) = gossip.break_down_filter(filter.clone()).await
        else {
            // Orphan / Generic / future non_exhaustive shapes: a
            // single subscription across the generic READ pool, with
            // the original filter retained.
            let output = self
                .inner
                .pool
                .subscribe(id.clone(), vec![filter.clone()], options)
                .await?;
            let relays: Vec<RelayUrl> = output.success.iter().cloned().collect();
            if !relays.is_empty() {
                let mut subs = self.inner.subscriptions.lock().await;
                subs.insert(
                    id,
                    SubscriptionRecord {
                        relays,
                        filters: vec![filter],
                    },
                );
            }
            return Ok(output);
        };
        self.ensure_gossip_relays(map.keys().cloned()).await;
        let mut merged: Output<SubscriptionId> = Output::new(id.clone());
        let mut relays: Vec<RelayUrl> = Vec::with_capacity(map.len());
        let mut filters: Vec<Filter> = Vec::with_capacity(map.len());
        for (url, narrowed) in map {
            let Ok(out) = self
                .inner
                .pool
                .subscribe_to(
                    vec![url.clone()],
                    id.clone(),
                    vec![narrowed.clone()],
                    options,
                )
                .await
            else {
                continue;
            };
            merged.success.extend(out.success);
            merged.failed.extend(out.failed);
            relays.push(url);
            filters.push(narrowed);
        }
        if !merged.success.is_empty() {
            let mut subs = self.inner.subscriptions.lock().await;
            subs.insert(id, SubscriptionRecord { relays, filters });
        }
        Ok(merged)
    }
}

/// Owning handle for the background gossip refresher task.
///
/// Dropping it aborts the loop, so it lives inside
/// [`crate::client::InnerClient`] and dies with the last [`Client`]
/// clone — no explicit teardown required.
#[derive(Debug)]
pub(crate) struct GossipRefresher {
    abort: tokio::task::AbortHandle,
}

impl Drop for GossipRefresher {
    fn drop(&mut self) {
        self.abort.abort();
    }
}

/// Spawn the background refresher: every
/// [`refresher_interval`](nula_gossip::GossipOptions::refresher_interval)
/// it pulls up to `refresher_batch` outdated `(pubkey, list)` pairs
/// and re-fetches them from the pool's current DISCOVERY/READ relays.
///
/// Unlike [`nula_gossip::RefresherHandle`] — which freezes its
/// discovery set at spawn — this reads the discovery relays from the
/// live pool on every tick, so it tracks relays added (including by
/// [`Client::ensure_gossip_relays`]) after the client was built.
pub(crate) fn spawn_refresher(gossip: Gossip, pool: RelayPool) -> GossipRefresher {
    let join = tokio::spawn(async move {
        let Some(interval) = gossip.options().refresher_interval else {
            return;
        };
        let batch =
            NonZeroUsize::new(gossip.options().refresher_batch).unwrap_or(NonZeroUsize::MIN);
        let mut ticker = tokio::time::interval(interval);
        // The first tick fires immediately; skip it so the refresher
        // does not race a freshly-built client's warm-up.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            if pool.is_shutdown() {
                break;
            }
            let discovery: Vec<RelayUrl> = pool
                .relays_with_any_capability(RelayCapabilities::DISCOVERY | RelayCapabilities::READ)
                .await
                .into_iter()
                .collect();
            if discovery.is_empty() {
                continue;
            }
            refresh_tick(&gossip, &pool, &discovery, batch).await;
        }
    });
    GossipRefresher {
        abort: join.abort_handle(),
    }
}

/// Re-fetch every outdated `(pubkey, list)` pair from `discovery`.
///
/// Extracted from [`spawn_refresher`]'s loop body so the surrounding
/// `loop` does not push the double iteration past clippy's nesting
/// budget. Best-effort: per-key refresh failures are surfaced via the
/// gossip layer's own `tracing` spans and otherwise dropped.
async fn refresh_tick(
    gossip: &Gossip,
    pool: &RelayPool,
    discovery: &[RelayUrl],
    batch: NonZeroUsize,
) {
    for kind in [ListKind::Nip65, ListKind::Nip17] {
        for key in gossip.outdated(kind, batch).await {
            drop(
                gossip
                    .refresh(
                        pool,
                        &key.public_key,
                        kind,
                        discovery.iter().cloned(),
                        REFRESH_TIMEOUT,
                    )
                    .await,
            );
        }
    }
}
