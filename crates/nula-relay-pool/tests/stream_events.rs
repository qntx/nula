//! Cross-relay event stream with LRU dedup.

#![allow(
    unused_crate_dependencies,
    reason = "dev-dependencies serve sibling test files"
)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::tests_outside_test_module,
    reason = "this is an integration test file, not production code"
)]

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use nula_relay_pool::{RelayCapabilities, RelayPool, RelayPoolOptions};
use nula_storage::NostrDatabase;
use nula_storage::memory::MemoryDatabase;

mod helpers;
use helpers::{make_relay, make_text_note};

#[tokio::test]
async fn stream_events_dedups_across_relays() {
    let db: Arc<dyn NostrDatabase> = Arc::new(MemoryDatabase::new());
    let pool = RelayPool::builder()
        .database(Arc::clone(&db))
        .options(RelayPoolOptions::default().auto_save_events(false))
        .build()
        .expect("database supplied to builder");
    let r1 = make_relay().await;
    let r2 = make_relay().await;

    // The same event lives on both relays — the pool should yield it
    // exactly once.
    let event = make_text_note("dedup-me", "dedup");
    r1.database().save_event(&event).await.expect("seed r1");
    r2.database().save_event(&event).await.expect("seed r2");

    pool.add_relay(r1.url().clone(), RelayCapabilities::READ)
        .await
        .expect("add r1");
    pool.add_relay(r2.url().clone(), RelayCapabilities::READ)
        .await
        .expect("add r2");
    let _ = pool.try_connect(Duration::from_secs(2)).await;

    let mut stream = pool
        .stream_events(
            vec![nula_core::Filter::new().id(event.id)],
            nula_relay::SubscribeOptions::default().close_on_eose(true),
            Some(Duration::from_secs(2)),
        )
        .await
        .expect("stream");

    let count = tokio::time::timeout(
        Duration::from_secs(3),
        count_matching(&mut stream, event.id),
    )
    .await
    .unwrap_or(0);
    assert_eq!(
        count, 1,
        "dedup must fire across 2 relays carrying the same event"
    );
}

/// Drain a `stream_events` cursor and count the events whose id
/// matches `target`. Pulled into a helper so the test bodies stay
/// flat (clippy `excessive_nesting`).
async fn count_matching(
    stream: &mut nula_net::BoxStream<
        'static,
        (
            nula_core::RelayUrl,
            Result<nula_core::Event, nula_relay::Error>,
        ),
    >,
    target: nula_core::EventId,
) -> usize {
    let mut count = 0_usize;
    while let Some((_url, item)) = stream.next().await {
        if let Ok(observed) = item
            && observed.id == target
        {
            count += 1;
        }
    }
    count
}

#[tokio::test]
async fn stream_events_auto_save_persists_to_pool_database() {
    let db: Arc<dyn NostrDatabase> = Arc::new(MemoryDatabase::new());
    let pool = RelayPool::builder()
        .database(Arc::clone(&db))
        .options(RelayPoolOptions::default().auto_save_events(true))
        .build()
        .expect("database supplied to builder");
    let relay = make_relay().await;

    let event = make_text_note("persist", "auto-save");
    let id = event.id;
    relay.database().save_event(&event).await.expect("seed");

    pool.add_relay(relay.url().clone(), RelayCapabilities::READ)
        .await
        .expect("add");
    let _ = pool.try_connect(Duration::from_secs(2)).await;

    let mut stream = pool
        .stream_events(
            vec![nula_core::Filter::new().id(id)],
            nula_relay::SubscribeOptions::default().close_on_eose(true),
            Some(Duration::from_secs(2)),
        )
        .await
        .expect("stream");
    tokio::time::timeout(Duration::from_secs(3), async {
        while stream.next().await.is_some() {}
    })
    .await
    .ok();

    let stored = db.event_by_id(&id).await.expect("db lookup");
    assert!(stored.is_some(), "auto_save_events must persist");
}
