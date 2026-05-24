//! End-to-end integration tests for `nula_sdk::Client`.
//!
//! Every test spins up an in-process `MockRelay` from
//! `nula-relay-builder`, drives the SDK against it, and asserts on
//! the observable side effects (Output success sets, fetched event
//! ids, etc.). The mock relay binds to `127.0.0.1:0` so the test
//! suite stays parallel-safe.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::tests_outside_test_module,
    reason = "this is an integration test binary, not production code"
)]

// `nula_sdk` transitively pulls every Layer 1-4 crate into the
// integration binary's dependency closure even when we only name a
// subset here. Pin the rest so the workspace
// `unused_crate_dependencies` lint stays quiet without forcing each
// test to import a Layer it does not use.
use std::time::Duration;

use futures as _;
use nula_core::{EventBuilder, Filter, Keys, Kind, Tag, Timestamp};
use nula_gossip as _;
use nula_net as _;
use nula_relay::SubscribeOptions;
use nula_relay_builder::MockRelayBuilder;
use nula_relay_pool as _;
use nula_sdk::Client;
#[cfg(feature = "nip46")]
use nula_signer_connect as _;
use nula_storage as _;
use nula_storage_memory as _;
use nula_sync as _;
use thiserror as _;
use tokio_stream as _;
#[cfg(feature = "tracing")]
use tracing as _;

fn deterministic_keys() -> Keys {
    Keys::parse("0000000000000000000000000000000000000000000000000000000000000005")
        .expect("hardcoded hex secret key")
}

fn text_note(content: &str, alt: &str) -> EventBuilder {
    EventBuilder::text_note(content)
        .tag(Tag::new(["alt", alt]).expect("valid tag"))
        .created_at(Timestamp::now().expect("system clock available"))
}

#[tokio::test]
async fn add_relay_accepts_str() {
    let client = Client::new();
    let inserted = client
        .add_relay("wss://relay.example.com")
        .await
        .expect("parses and inserts");
    assert!(inserted, "first add_relay should report a fresh insertion");

    let duplicate = client
        .add_relay("wss://relay.example.com")
        .await
        .expect("duplicate parses");
    assert!(!duplicate, "second add_relay should report no-op");
}

#[tokio::test]
async fn sign_event_builder_requires_signer() {
    let client = Client::new();
    let err = client
        .sign_event_builder(text_note("orphan", "no-signer"))
        .await
        .expect_err("no signer was configured");
    assert!(
        matches!(err, nula_sdk::Error::SignerNotConfigured),
        "got {err:?}"
    );
}

#[tokio::test]
async fn round_trip_publish_and_fetch() {
    let relay = MockRelayBuilder::new()
        .run()
        .await
        .expect("mock relay binds");

    let client = Client::builder()
        .signer(deterministic_keys())
        .build()
        .expect("default features build");
    client.add_relay(relay.url()).await.expect("add mock relay");
    client.connect().await;

    let output = client
        .send_event_builder(text_note("hello sdk", "round-trip"))
        .await
        .expect("send succeeds");
    assert!(
        output.success.contains(relay.url()),
        "mock relay should ack the publish; failed={:?}",
        output.failed
    );

    let filter = Filter::new()
        .kind(Kind::TEXT_NOTE)
        .author(*deterministic_keys().public_key())
        .limit(10);
    let events = client
        .fetch_events(filter, Some(Duration::from_secs(5)))
        .await
        .expect("fetch succeeds");
    assert_eq!(events.len(), 1, "exactly one event published");
    assert_eq!(events.first().expect("non-empty").content, "hello sdk");

    client.shutdown().await;
    relay.shutdown();
}

#[tokio::test]
async fn subscribe_and_unsubscribe_round_trip() {
    let relay = MockRelayBuilder::new()
        .run()
        .await
        .expect("mock relay binds");

    let client = Client::builder()
        .signer(deterministic_keys())
        .build()
        .expect("default features build");
    client.add_relay(relay.url()).await.expect("add mock relay");
    client.connect().await;

    let filter = Filter::new().kind(Kind::TEXT_NOTE).limit(0);
    let output = client
        .subscribe(filter, SubscribeOptions::default())
        .await
        .expect("subscribe succeeds");
    assert!(
        output.success.contains(relay.url()),
        "subscription should land; failed={:?}",
        output.failed
    );

    let unsub = client.unsubscribe(&output.value).await;
    // `unsubscribe` is a snapshot of the relay topology; it never
    // fails because the per-relay handles already auto-close.
    assert!(unsub.failed.is_empty(), "unsubscribe has no failures");

    client.shutdown().await;
    relay.shutdown();
}

#[tokio::test]
async fn send_event_to_unparseable_url_fails_with_relay_url_error() {
    let client = Client::builder()
        .signer(deterministic_keys())
        .build()
        .expect("default features build");

    let event = text_note("test", "bad-url")
        .sign_with_keys(&deterministic_keys())
        .expect("sign succeeds");

    let err = client
        .send_event_to(["not a url"], event)
        .await
        .expect_err("url is malformed");
    assert!(
        matches!(err, nula_sdk::Error::RelayUrl(_)),
        "expected RelayUrl error, got {err:?}"
    );
}

#[cfg(feature = "sync")]
#[tokio::test]
async fn sync_to_relay_classifies_have_and_need() {
    use std::sync::Arc;

    use nula_storage_memory::MemoryDatabase;

    let keys = deterministic_keys();

    // Build the events. `shared_event` ends up on both replicas;
    // `local_only` is on the client; `relay_only` is on the relay.
    let shared_event = text_note("shared", "shared-content")
        .sign_with_keys(&keys)
        .expect("sign shared");
    let local_only = text_note("local-only", "local-only-content")
        .sign_with_keys(&keys)
        .expect("sign local-only");
    let relay_only = text_note("relay-only", "relay-only-content")
        .sign_with_keys(&keys)
        .expect("sign relay-only");

    // Stand up a fresh in-process relay backed by a memory database
    // so we can pre-seed events the client does not have.
    let relay_storage: Arc<dyn nula_storage::NostrDatabase> = Arc::new(MemoryDatabase::new());
    relay_storage
        .save_event(&shared_event)
        .await
        .expect("relay seed shared");
    relay_storage
        .save_event(&relay_only)
        .await
        .expect("relay seed relay-only");
    let relay = MockRelayBuilder::new()
        .storage(Arc::clone(&relay_storage))
        .run()
        .await
        .expect("mock relay binds");

    // Pre-seed the client's database before passing it to the
    // builder so the sync session sees `shared_event` + `local_only`.
    let client_db: Arc<dyn nula_storage::NostrDatabase> = Arc::new(MemoryDatabase::new());
    client_db
        .save_event(&shared_event)
        .await
        .expect("client seed shared");
    client_db
        .save_event(&local_only)
        .await
        .expect("client seed local-only");

    let client = Client::builder()
        .signer(keys.clone())
        .database_arc(Arc::clone(&client_db))
        .build()
        .expect("client builds");
    client.add_relay(relay.url()).await.expect("add relay");
    client.connect().await;

    let filter = Filter::new()
        .kind(Kind::TEXT_NOTE)
        .author(*keys.public_key());

    // Dry-run with SyncDirection::Both classifies the local /
    // remote diff without performing any actual upload or
    // download.
    let opts = nula_sdk::SyncOptions::new()
        .direction(nula_sdk::SyncDirection::Both)
        .timeout(Some(Duration::from_secs(5)))
        .dry_run(true);
    let outcome = client
        .sync_to_relay(relay.url(), filter, opts)
        .await
        .expect("sync converges");

    assert!(
        outcome.local.contains(&local_only.id),
        "client-only event must be classified as `local`; got local={:?} remote={:?}",
        outcome.local,
        outcome.remote,
    );
    assert!(
        outcome.remote.contains(&relay_only.id),
        "relay-only event must be classified as `remote`; got local={:?} remote={:?}",
        outcome.local,
        outcome.remote,
    );
    assert!(
        !outcome.local.contains(&shared_event.id),
        "shared event must not appear in `local`",
    );
    assert!(
        !outcome.remote.contains(&shared_event.id),
        "shared event must not appear in `remote`",
    );
    assert!(
        outcome.is_empty_exchange(),
        "dry_run must not exchange any events",
    );

    client.shutdown().await;
    relay.shutdown();
}

#[cfg(feature = "sync")]
#[tokio::test]
async fn sync_to_unknown_relay_fails_with_typed_error() {
    let client = Client::builder()
        .signer(deterministic_keys())
        .build()
        .expect("default features build");

    let unknown = nula_core::RelayUrl::parse("wss://relay.unknown.example").expect("parses");
    let err = client
        .sync_to_relay(
            &unknown,
            Filter::new(),
            nula_sdk::SyncOptions::new().timeout(Some(Duration::from_millis(50))),
        )
        .await
        .expect_err("relay never registered");
    assert!(
        matches!(err, nula_sdk::Error::UnknownRelay { .. }),
        "got {err:?}"
    );
}

#[cfg(feature = "sync")]
#[tokio::test]
async fn sync_direction_both_uploads_and_downloads_events() {
    use std::sync::Arc;

    use nula_storage_memory::MemoryDatabase;

    let keys = deterministic_keys();

    let local_only = text_note("L1", "local-uploaded")
        .sign_with_keys(&keys)
        .expect("sign local-only");
    let relay_only = text_note("R1", "relay-downloaded")
        .sign_with_keys(&keys)
        .expect("sign relay-only");

    let relay_storage: Arc<dyn nula_storage::NostrDatabase> = Arc::new(MemoryDatabase::new());
    relay_storage
        .save_event(&relay_only)
        .await
        .expect("seed relay");
    let relay = MockRelayBuilder::new()
        .storage(Arc::clone(&relay_storage))
        .run()
        .await
        .expect("mock relay binds");

    let client_db: Arc<dyn nula_storage::NostrDatabase> = Arc::new(MemoryDatabase::new());
    client_db
        .save_event(&local_only)
        .await
        .expect("seed client");

    let client = Client::builder()
        .signer(keys.clone())
        .database_arc(Arc::clone(&client_db))
        .build()
        .expect("client builds");
    client.add_relay(relay.url()).await.expect("add relay");
    client.connect().await;

    let filter = Filter::new().kind(Kind::TEXT_NOTE).author(*keys.public_key());
    let opts = nula_sdk::SyncOptions::new()
        .direction(nula_sdk::SyncDirection::Both)
        .timeout(Some(Duration::from_secs(10)));
    let summary = client
        .sync_to_relay(relay.url(), filter, opts)
        .await
        .expect("bidirectional sync converges");

    assert!(summary.sent.contains(&local_only.id), "local_only must be uploaded");
    assert!(
        summary.received.contains(&relay_only.id),
        "relay_only must be downloaded",
    );
    assert!(summary.send_failures.is_empty(), "got failures: {:?}", summary.send_failures);

    // The client database now holds both events.
    let after = client_db
        .event_by_id(&relay_only.id)
        .await
        .expect("db query ok");
    assert!(after.is_some(), "download phase persisted relay_only into the client db");

    // The relay database now holds both events too.
    let on_relay = relay_storage
        .event_by_id(&local_only.id)
        .await
        .expect("relay db query ok");
    assert!(on_relay.is_some(), "upload phase persisted local_only into the relay");

    client.shutdown().await;
    relay.shutdown();
}

#[cfg(feature = "sync")]
#[tokio::test]
async fn sync_progress_watch_channel_reports_totals() {
    use std::sync::Arc;

    use nula_storage_memory::MemoryDatabase;
    use tokio::sync::watch;

    let keys = deterministic_keys();
    let relay_only = text_note("watch-target", "watch")
        .sign_with_keys(&keys)
        .expect("sign");

    let relay_storage: Arc<dyn nula_storage::NostrDatabase> = Arc::new(MemoryDatabase::new());
    relay_storage
        .save_event(&relay_only)
        .await
        .expect("seed relay");
    let relay = MockRelayBuilder::new()
        .storage(Arc::clone(&relay_storage))
        .run()
        .await
        .expect("mock relay binds");

    let client = Client::builder()
        .signer(keys.clone())
        .build()
        .expect("client builds");
    client.add_relay(relay.url()).await.expect("add relay");
    client.connect().await;

    let (tx, rx) = watch::channel(nula_sdk::SyncProgress::default());
    let filter = Filter::new().kind(Kind::TEXT_NOTE).author(*keys.public_key());
    let opts = nula_sdk::SyncOptions::new()
        .direction(nula_sdk::SyncDirection::Down)
        .timeout(Some(Duration::from_secs(5)))
        .with_progress(tx);
    let summary = client
        .sync_to_relay(relay.url(), filter, opts)
        .await
        .expect("sync converges");

    assert_eq!(summary.received.len(), 1);
    let final_progress = *rx.borrow();
    assert!(
        final_progress.total >= 1,
        "progress total must reflect at least one classified event, got {final_progress:?}",
    );
    assert!(
        final_progress.current >= 1,
        "progress current must reflect the downloaded event, got {final_progress:?}",
    );

    client.shutdown().await;
    relay.shutdown();
}

#[cfg(feature = "sync")]
#[tokio::test]
async fn sync_direction_up_skips_download_phase() {
    use std::sync::Arc;

    use nula_storage_memory::MemoryDatabase;

    let keys = deterministic_keys();
    let relay_only = text_note("R-only", "relay-not-downloaded")
        .sign_with_keys(&keys)
        .expect("sign");

    let relay_storage: Arc<dyn nula_storage::NostrDatabase> = Arc::new(MemoryDatabase::new());
    relay_storage
        .save_event(&relay_only)
        .await
        .expect("seed relay");
    let relay = MockRelayBuilder::new()
        .storage(Arc::clone(&relay_storage))
        .run()
        .await
        .expect("mock relay binds");

    let client_db: Arc<dyn nula_storage::NostrDatabase> = Arc::new(MemoryDatabase::new());
    let client = Client::builder()
        .signer(keys.clone())
        .database_arc(Arc::clone(&client_db))
        .build()
        .expect("client builds");
    client.add_relay(relay.url()).await.expect("add relay");
    client.connect().await;

    let filter = Filter::new().kind(Kind::TEXT_NOTE).author(*keys.public_key());
    let opts = nula_sdk::SyncOptions::new()
        .direction(nula_sdk::SyncDirection::Up)
        .timeout(Some(Duration::from_secs(5)));
    let summary = client
        .sync_to_relay(relay.url(), filter, opts)
        .await
        .expect("sync converges");

    // Up direction must not classify any need ids and must not
    // download anything.
    assert!(summary.remote.is_empty(), "Up must not classify remote-only");
    assert!(summary.received.is_empty(), "Up must not download events");
    let after = client_db
        .event_by_id(&relay_only.id)
        .await
        .expect("db query ok");
    assert!(after.is_none(), "Up direction must not persist relay-only events locally");

    client.shutdown().await;
    relay.shutdown();
}
