//! Cross-relay event stream with LRU-bounded `EventId` dedup.
//!
//! The stream returned by [`crate::pool::RelayPool::stream_events`] /
//! [`crate::pool::RelayPool::stream_events_to`] is produced by a single
//! driver task that owns the per-relay [`SubscriptionHandle`]s,
//! forwards their events into a bounded mpsc channel, and skips
//! duplicates seen by `EventId` within the LRU window.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use crate::{SubscriptionHandle, SubscriptionItem};
use futures::StreamExt;
use futures::stream::SelectAll;
use lru::LruCache;
use nula_core::boxed::BoxStream;
use nula_core::{Event, EventId, RelayUrl, SubscriptionId};
use nula_storage::NostrDatabase;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_stream::wrappers::ReceiverStream;

/// Outbound channel capacity for [`crate::pool::RelayPool::stream_events`].
///
/// The dedup-driver awaits each `tx.send`, so a slow consumer
/// back-pressures every relay's `SubscriptionHandle` evenly. A
/// kilobuffer is large enough to absorb mid-stream bursts (a single
/// relay can deliver thousands of EVENT frames in a tight loop on
/// EOSE backfill) yet small enough to keep the worst-case memory
/// footprint predictable.
const OUTBOUND_CAPACITY: usize = 1024;

/// Spawn the driver task and return the consumer-side stream.
pub(crate) fn run(
    handles: Vec<(RelayUrl, SubscriptionId, SubscriptionHandle)>,
    dedup_capacity: NonZeroUsize,
    auto_save_db: Option<Arc<dyn NostrDatabase>>,
    timeout: Option<Duration>,
) -> BoxStream<'static, (RelayUrl, Result<Event, crate::Error>)> {
    let (tx, rx) = mpsc::channel::<(RelayUrl, Result<Event, crate::Error>)>(OUTBOUND_CAPACITY);

    tokio::spawn(driver(handles, tx, dedup_capacity, auto_save_db, timeout));

    Box::pin(ReceiverStream::new(rx))
}

async fn driver(
    handles: Vec<(RelayUrl, SubscriptionId, SubscriptionHandle)>,
    tx: mpsc::Sender<(RelayUrl, Result<Event, crate::Error>)>,
    dedup_capacity: NonZeroUsize,
    auto_save_db: Option<Arc<dyn NostrDatabase>>,
    timeout: Option<Duration>,
) {
    let mut seen: LruCache<EventId, ()> = LruCache::new(dedup_capacity);
    let mut workers: SelectAll<BoxStream<'static, (RelayUrl, SubscriptionId, SubscriptionItem)>> =
        SelectAll::new();
    for (url, sub_id, handle) in handles {
        let stream = handle
            .map(move |item| (url.clone(), sub_id.clone(), item))
            .boxed();
        workers.push(stream);
    }

    let deadline = timeout.map(|d| Instant::now() + d);

    loop {
        tokio::select! {
            // Receiver dropped — driver has nothing left to do.
            () = tx.closed() => break,

            // Deadline elapsed — close the stream gracefully.
            () = async {
                match deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    // No deadline configured: never resolve.
                    None => std::future::pending::<()>().await,
                }
            } => break,

            // Incoming subscription frame.
            next = workers.next() => {
                let Some((url, sub_id, item)) = next else {
                    // Every per-relay stream has terminated.
                    break;
                };
                if !forward(&tx, &mut seen, auto_save_db.as_deref(), url, sub_id, item).await {
                    // Receiver hung up mid-flight.
                    break;
                }
            }
        }
    }
}

/// Returns `false` when the outbound channel has been closed and the
/// driver should exit.
async fn forward(
    tx: &mpsc::Sender<(RelayUrl, Result<Event, crate::Error>)>,
    seen: &mut LruCache<EventId, ()>,
    auto_save_db: Option<&dyn NostrDatabase>,
    url: RelayUrl,
    subscription_id: SubscriptionId,
    item: SubscriptionItem,
) -> bool {
    match item {
        SubscriptionItem::Event(event) => {
            if seen.put(event.id, ()).is_some() {
                // Already seen on a different relay; drop silently.
                return true;
            }
            if let Some(db) = auto_save_db {
                // Best-effort persist; failures are intentionally
                // swallowed so the consumer still observes the event.
                db.save_event(&event).await.ok();
            }
            tx.send((url, Ok(event))).await.is_ok()
        }
        SubscriptionItem::Closed { message } => tx
            .send((
                url,
                Err(crate::Error::SubscriptionClosed {
                    subscription_id,
                    message,
                }),
            ))
            .await
            .is_ok(),
        // `SubscriptionItem::EndOfStoredEvents` plus any future
        // `#[non_exhaustive]` variants are silently consumed; if a
        // new variant ever needs the pool's attention we expand
        // this arm explicitly.
        _ => true,
    }
}
