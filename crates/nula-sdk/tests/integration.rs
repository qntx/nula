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
use nula_sdk::{Client, MonitorNotification};
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

#[tokio::test]
async fn subscribe_registers_in_subscriptions_map() {
    let relay = MockRelayBuilder::new()
        .run()
        .await
        .expect("mock relay binds");

    let client = Client::builder()
        .signer(deterministic_keys())
        .build()
        .expect("default features build");
    client.add_relay(relay.url()).await.expect("add relay");
    client.connect().await;

    let filter = Filter::new().kind(Kind::TEXT_NOTE).limit(0);
    let output = client
        .subscribe(filter, SubscribeOptions::default())
        .await
        .expect("subscribe");

    let active = client.subscriptions().await;
    assert!(
        active.contains_key(&output.value),
        "subscribe must register the id; active={:?}",
        active.keys().collect::<Vec<_>>(),
    );

    // unsubscribe_all clears the registry.
    let _ = client.unsubscribe_all().await;
    assert!(
        client.subscriptions().await.is_empty(),
        "unsubscribe_all must drain the registry",
    );

    client.shutdown().await;
    relay.shutdown();
}

#[tokio::test]
async fn monitor_observes_relay_status_transitions() {
    let relay = MockRelayBuilder::new()
        .run()
        .await
        .expect("mock relay binds");

    let client = Client::builder()
        .signer(deterministic_keys())
        .monitor()
        .build()
        .expect("monitor builds");

    let monitor = client.monitor().expect("monitor opt-in returns Some");
    let rx = monitor.subscribe();

    client.add_relay(relay.url()).await.expect("add relay");
    client.connect().await;

    let saw_connected = tokio::time::timeout(Duration::from_secs(5), wait_for_connected(rx))
        .await
        .unwrap_or(false);
    assert!(saw_connected, "monitor must observe a Connected transition");

    client.shutdown().await;
    relay.shutdown();
}

#[tokio::test]
async fn wait_for_connection_returns_true_after_connect() {
    let relay = MockRelayBuilder::new()
        .run()
        .await
        .expect("mock relay binds");

    let client = Client::builder()
        .signer(deterministic_keys())
        .build()
        .expect("default features build");
    client.add_relay(relay.url()).await.expect("add relay");
    client.connect().await;

    let connected = client.wait_for_connection(Duration::from_secs(5)).await;
    assert!(connected, "wait_for_connection must succeed within 5s");

    client.shutdown().await;
    relay.shutdown();
}

#[tokio::test]
async fn wait_for_connection_times_out_when_no_relays_registered() {
    let client = Client::builder()
        .signer(deterministic_keys())
        .build()
        .expect("default features build");

    // No relays ever registered -- the call must time out.
    let connected = client
        .wait_for_connection(Duration::from_millis(100))
        .await;
    assert!(
        !connected,
        "wait_for_connection must return false with zero relays",
    );
}

#[tokio::test]
async fn add_capability_helpers_route_to_the_right_bit() {
    let client = Client::builder()
        .signer(deterministic_keys())
        .build()
        .expect("default features build");

    let inserted_discovery = client
        .add_discovery_relay("wss://discovery.example/")
        .await
        .expect("add discovery");
    let inserted_read = client
        .add_read_relay("wss://read.example/")
        .await
        .expect("add read");
    let inserted_write = client
        .add_write_relay("wss://write.example/")
        .await
        .expect("add write");
    let inserted_gossip = client
        .add_gossip_relay("wss://gossip.example/")
        .await
        .expect("add gossip");

    assert!(inserted_discovery, "discovery relay must be a fresh insert");
    assert!(inserted_read, "read relay must be a fresh insert");
    assert!(inserted_write, "write relay must be a fresh insert");
    assert!(inserted_gossip, "gossip relay must be a fresh insert");

    let relays = client.relays().await;
    assert_eq!(relays.len(), 4, "all four relays must be registered");
}

#[tokio::test]
async fn connect_relay_and_disconnect_relay_target_a_single_endpoint() {
    let relay = MockRelayBuilder::new()
        .run()
        .await
        .expect("mock relay binds");

    let client = Client::builder()
        .signer(deterministic_keys())
        .build()
        .expect("default features build");
    client.add_relay(relay.url()).await.expect("add relay");

    client
        .connect_relay(relay.url())
        .await
        .expect("connect_relay succeeds");
    client
        .disconnect_relay(relay.url())
        .await
        .expect("disconnect_relay succeeds");

    let unknown = nula_core::RelayUrl::parse("wss://unknown.example/").expect("url");
    let err = client
        .connect_relay(&unknown)
        .await
        .expect_err("unknown relay must fail typed");
    assert!(matches!(err, nula_sdk::Error::UnknownRelay { .. }));

    client.shutdown().await;
    relay.shutdown();
}

#[tokio::test]
async fn try_connect_relay_times_out_with_connect_timeout_error() {
    // RFC 5737 TEST-NET-1: guaranteed non-routable, so the TCP
    // connect hangs and the per-attempt timeout fires (rather than
    // a fast connection-refused, which would map to Error::Relay).
    let url = nula_core::RelayUrl::parse("ws://192.0.2.1:9/").expect("url");

    let client = Client::builder()
        .signer(deterministic_keys())
        .build()
        .expect("default features build");
    client.add_relay(url.clone()).await.expect("add relay");

    let err = client
        .try_connect_relay(&url, Duration::from_millis(150))
        .await
        .expect_err("unreachable relay must time out");
    assert!(
        matches!(&err, nula_sdk::Error::ConnectTimeout { url: u } if *u == url),
        "expected ConnectTimeout, got {err:?}",
    );

    // Intentionally drop instead of `shutdown().await`: shutdown
    // drains driver tasks, and the unreachable relay's in-flight TCP
    // connect would block the drain for the OS connect timeout
    // (~30s). The runtime drop at test end aborts the task.
    drop(client);
}

#[tokio::test]
async fn nip17_round_trip_alice_to_bob_via_mock_relay() {
    use std::sync::Arc;

    use nula_core::nips::nip17::Recipient;
    use nula_storage_memory::MemoryDatabase;

    // Shared backing relay so both clients see the same event stream.
    let relay_storage: Arc<dyn nula_storage::NostrDatabase> = Arc::new(MemoryDatabase::new());
    let relay = MockRelayBuilder::new()
        .storage(Arc::clone(&relay_storage))
        .run()
        .await
        .expect("mock relay binds");

    let alice_keys = Keys::generate().expect("alice keys");
    let bob_keys = Keys::generate().expect("bob keys");

    let alice = Client::builder()
        .signer(alice_keys.clone())
        .build()
        .expect("alice builds");
    alice
        .add_relay(relay.url())
        .await
        .expect("alice add relay");
    alice.connect().await;

    let bob = Client::builder()
        .signer(bob_keys.clone())
        .build()
        .expect("bob builds");
    bob.add_relay(relay.url()).await.expect("bob add relay");
    bob.connect().await;

    let bob_recipient = Recipient {
        public_key: *bob_keys.public_key(),
        relay_hint: None,
    };
    let plaintext = "alice -> bob: hello via gift wrap";
    let output = alice
        .send_private_msg(&alice_keys, &[bob_recipient], plaintext, None)
        .await
        .expect("send_private_msg");
    // Two wraps go out: one for Bob and one self-wrap for Alice.
    assert_eq!(
        output.value.len(),
        2,
        "expected 2 wraps (recipient + self), got {}",
        output.value.len(),
    );

    let received = bob
        .receive_private_msgs(&bob_keys, None, Some(Duration::from_secs(5)))
        .await
        .expect("bob fetches dms");
    assert_eq!(
        received.len(),
        1,
        "Bob must see exactly one wrap, got {}",
        received.len(),
    );
    let msg = received.first().expect("len already asserted");
    assert_eq!(msg.rumor.content, plaintext);
    assert_eq!(
        msg.rumor.pubkey,
        *alice_keys.public_key(),
        "rumor.pubkey must equal Alice (deniable but truthful when honest)",
    );

    // Alice's self-wrap is also visible when she queries.
    let alice_inbox = alice
        .receive_private_msgs(&alice_keys, None, Some(Duration::from_secs(5)))
        .await
        .expect("alice fetches own copy");
    assert_eq!(
        alice_inbox.len(),
        1,
        "Alice's self-wrap must be readable; got {}",
        alice_inbox.len(),
    );
    let alice_self = alice_inbox.first().expect("len already asserted");
    assert_eq!(alice_self.rumor.content, plaintext);

    alice.shutdown().await;
    bob.shutdown().await;
    relay.shutdown();
}

#[tokio::test]
async fn nip17_send_private_msg_rejects_empty_recipients() {
    let alice_keys = Keys::generate().expect("alice keys");
    let alice = Client::builder()
        .signer(alice_keys.clone())
        .build()
        .expect("alice builds");

    let err = alice
        .send_private_msg(&alice_keys, &[], "noop", None)
        .await
        .expect_err("empty recipients must be rejected");
    assert!(
        matches!(
            err,
            nula_sdk::Error::Nip17(nula_core::nips::nip17::Nip17Error::NoRecipients)
        ),
        "got {err:?}",
    );
}

#[tokio::test]
async fn nip65_set_and_get_relay_list_round_trip() {
    use nula_core::nips::nip65::{RelayList, RelayMarker};

    let relay = MockRelayBuilder::new()
        .run()
        .await
        .expect("mock relay binds");

    let keys = deterministic_keys();
    let client = Client::builder()
        .signer(keys.clone())
        .build()
        .expect("client builds");
    client.add_relay(relay.url()).await.expect("add relay");
    client.connect().await;

    let mut list = RelayList::new();
    list.insert(
        nula_core::RelayUrl::parse("wss://r1.example/").expect("url"),
        RelayMarker::Read,
    );
    list.insert(
        nula_core::RelayUrl::parse("wss://w1.example/").expect("url"),
        RelayMarker::Write,
    );
    list.insert(
        nula_core::RelayUrl::parse("wss://both.example/").expect("url"),
        RelayMarker::ReadWrite,
    );

    let output = client
        .set_relay_list(&list)
        .await
        .expect("set_relay_list publishes kind 10002");
    assert!(
        !output.success.is_empty(),
        "at least one relay must accept the kind-10002 event",
    );

    let fetched = client
        .get_relay_list(keys.public_key(), Some(Duration::from_secs(5)))
        .await
        .expect("get_relay_list succeeds")
        .expect("kind 10002 was published");
    assert_eq!(
        fetched, list,
        "round-trip relay list must match (insertion-order via BTreeMap key)",
    );

    client.shutdown().await;
    relay.shutdown();
}

#[tokio::test]
async fn nip65_get_relay_list_returns_none_when_unpublished() {
    let relay = MockRelayBuilder::new()
        .run()
        .await
        .expect("mock relay binds");
    let keys = deterministic_keys();
    let client = Client::builder()
        .signer(keys.clone())
        .build()
        .expect("client builds");
    client.add_relay(relay.url()).await.expect("add relay");
    client.connect().await;

    let none = client
        .get_relay_list(keys.public_key(), Some(Duration::from_millis(200)))
        .await
        .expect("get_relay_list succeeds with no event");
    assert!(none.is_none(), "no kind-10002 was ever published");

    client.shutdown().await;
    relay.shutdown();
}

#[cfg(feature = "gossip")]
#[tokio::test]
async fn nip65_refresh_relay_metadata_drives_gossip_routing() {
    use std::sync::Arc;

    use nula_core::nips::nip65::{RelayList, RelayMarker};
    use nula_storage_memory::MemoryDatabase;

    // Shared backing relay so the publishing client and the
    // refreshing client both see the same kind-10002 event stream.
    let relay_storage: Arc<dyn nula_storage::NostrDatabase> = Arc::new(MemoryDatabase::new());
    let relay = MockRelayBuilder::new()
        .storage(Arc::clone(&relay_storage))
        .run()
        .await
        .expect("mock relay binds");

    // Publisher: Alice publishes her NIP-65 list so the relay
    // archive reflects an outbox advertisement.
    let alice_keys = Keys::generate().expect("alice keys");
    let alice = Client::builder()
        .signer(alice_keys.clone())
        .build()
        .expect("alice builds");
    alice.add_relay(relay.url()).await.expect("add relay");
    alice.connect().await;
    let mut alice_list = RelayList::new();
    let outbox = nula_core::RelayUrl::parse("wss://outbox.example/").expect("url");
    let inbox = nula_core::RelayUrl::parse("wss://inbox.example/").expect("url");
    alice_list.insert(outbox.clone(), RelayMarker::Write);
    alice_list.insert(inbox.clone(), RelayMarker::Read);
    alice
        .set_relay_list(&alice_list)
        .await
        .expect("alice publishes kind-10002");

    // Subscriber: Bob runs a fresh client with gossip enabled and
    // wants to discover Alice's relays via refresh_relay_metadata.
    let gossip_db: Arc<dyn nula_storage::NostrDatabase> = Arc::new(MemoryDatabase::new());
    let gossip = nula_gossip::Gossip::builder()
        .database(Arc::clone(&gossip_db))
        .build()
        .expect("gossip builds");
    let bob = Client::builder()
        .signer(Keys::generate().expect("bob keys"))
        .database_arc(Arc::clone(&gossip_db))
        .gossip(gossip)
        .build()
        .expect("bob builds with gossip");
    bob.add_relay(relay.url()).await.expect("add relay");
    bob.connect().await;

    let ingested = bob
        .refresh_relay_metadata([*alice_keys.public_key()], Some(Duration::from_secs(5)))
        .await
        .expect("refresh succeeds");
    assert_eq!(
        ingested, 1,
        "exactly the kind-10002 should be ingested (no kind-10050 was published); got {ingested}",
    );

    let outbox_relays = bob
        .gossip()
        .expect("gossip wired")
        .outbox_relays(alice_keys.public_key())
        .await;
    assert!(
        outbox_relays.contains(&outbox),
        "Alice's outbox relay must be visible after refresh; got {outbox_relays:?}",
    );

    alice.shutdown().await;
    bob.shutdown().await;
    relay.shutdown();
}

#[tokio::test]
async fn nip17_set_and_get_dm_relays_round_trip() {
    let relay = MockRelayBuilder::new()
        .run()
        .await
        .expect("mock relay binds");

    let keys = deterministic_keys();
    let client = Client::builder()
        .signer(keys.clone())
        .build()
        .expect("client builds");
    client.add_relay(relay.url()).await.expect("add relay");
    client.connect().await;

    let advertised = vec![
        nula_core::RelayUrl::parse("wss://dm-relay-1.example/").expect("url1"),
        nula_core::RelayUrl::parse("wss://dm-relay-2.example/").expect("url2"),
    ];
    client
        .set_dm_relays(&advertised)
        .await
        .expect("set_dm_relays publishes kind 10050");

    let fetched = client
        .get_dm_relays(keys.public_key(), Some(Duration::from_secs(5)))
        .await
        .expect("get_dm_relays succeeds")
        .expect("kind 10050 was published");
    assert_eq!(fetched, advertised, "DM-relays round-trip must preserve order");

    client.shutdown().await;
    relay.shutdown();
}

/// Drain a monitor receiver until a `StatusChanged { status: Connected }` arrives.
/// Returns `false` if the channel closes first.
async fn wait_for_connected(
    mut rx: tokio::sync::broadcast::Receiver<MonitorNotification>,
) -> bool {
    loop {
        match rx.recv().await {
            Ok(MonitorNotification::StatusChanged { status, .. }) if status.is_connected() => {
                return true;
            }
            Ok(_) => {}
            Err(_) => return false,
        }
    }
}

/// Stub admission policy used by the Phase 7.3.7 tests.
///
/// Every gate is independently configurable: any url containing
/// the matching substring is rejected with the configured reason,
/// every other input is admitted.
#[derive(Debug, Default)]
struct StubPolicy {
    reject_relay_substring: Option<String>,
    reject_connection_substring: Option<String>,
    reject_events_after_kind: Option<Kind>,
}

impl nula_sdk::AdmitPolicy for StubPolicy {
    fn admit_relay<'a>(
        &'a self,
        relay_url: &'a nula_core::RelayUrl,
    ) -> nula_net::BoxFuture<'a, Result<nula_sdk::AdmitStatus, nula_sdk::PolicyError>> {
        Box::pin(async move {
            let Some(needle) = self.reject_relay_substring.as_deref() else {
                return Ok(nula_sdk::AdmitStatus::Success);
            };
            if relay_url.as_str().contains(needle) {
                Ok(nula_sdk::AdmitStatus::rejected(format!(
                    "relay url matches `{needle}`"
                )))
            } else {
                Ok(nula_sdk::AdmitStatus::Success)
            }
        })
    }

    fn admit_connection<'a>(
        &'a self,
        relay_url: &'a nula_core::RelayUrl,
    ) -> nula_net::BoxFuture<'a, Result<nula_sdk::AdmitStatus, nula_sdk::PolicyError>> {
        Box::pin(async move {
            let Some(needle) = self.reject_connection_substring.as_deref() else {
                return Ok(nula_sdk::AdmitStatus::Success);
            };
            if relay_url.as_str().contains(needle) {
                Ok(nula_sdk::AdmitStatus::rejected("connection blocked"))
            } else {
                Ok(nula_sdk::AdmitStatus::Success)
            }
        })
    }

    fn admit_event<'a>(
        &'a self,
        _relay_url: &'a nula_core::RelayUrl,
        _subscription_id: &'a nula_core::message::SubscriptionId,
        event: &'a nula_core::Event,
    ) -> nula_net::BoxFuture<'a, Result<nula_sdk::AdmitStatus, nula_sdk::PolicyError>> {
        Box::pin(async move {
            let Some(min_kind) = self.reject_events_after_kind else {
                return Ok(nula_sdk::AdmitStatus::Success);
            };
            if event.kind.as_u16() >= min_kind.as_u16() {
                Ok(nula_sdk::AdmitStatus::rejected("kind blocked"))
            } else {
                Ok(nula_sdk::AdmitStatus::Success)
            }
        })
    }
}

#[tokio::test]
async fn admit_policy_rejects_relay_at_add_time() {
    use std::sync::Arc;
    let policy: Arc<dyn nula_sdk::AdmitPolicy> = Arc::new(StubPolicy {
        reject_relay_substring: Some("forbidden".to_owned()),
        ..StubPolicy::default()
    });

    let client = Client::builder()
        .signer(deterministic_keys())
        .admit_policy(policy)
        .build()
        .expect("policy builder ok");

    let err = client
        .add_relay("wss://forbidden.example/")
        .await
        .expect_err("add_relay must surface PolicyRejected");
    assert!(matches!(
        err,
        nula_sdk::Error::PolicyRejected { stage: "relay", .. }
    ));

    // Allowed relay still goes through.
    client
        .add_relay("wss://allowed.example/")
        .await
        .expect("non-matching url admitted");
}

#[tokio::test]
async fn admit_policy_rejects_connection_after_add() {
    use std::sync::Arc;

    let relay = MockRelayBuilder::new()
        .run()
        .await
        .expect("mock relay binds");

    let policy: Arc<dyn nula_sdk::AdmitPolicy> = Arc::new(StubPolicy {
        reject_connection_substring: Some("127.0.0.1".to_owned()),
        ..StubPolicy::default()
    });

    let client = Client::builder()
        .signer(deterministic_keys())
        .admit_policy(policy)
        .build()
        .expect("policy builder ok");
    // add_relay is admitted because admit_relay defaults to Success
    // for this stub (only admit_connection is configured to reject
    // 127.0.0.1).
    client.add_relay(relay.url()).await.expect("add ok");

    let err = client
        .connect_relay(relay.url())
        .await
        .expect_err("connect_relay must surface PolicyRejected");
    assert!(matches!(
        err,
        nula_sdk::Error::PolicyRejected {
            stage: "connection",
            ..
        }
    ));

    relay.shutdown();
}

#[cfg(feature = "sync")]
#[tokio::test]
async fn admit_policy_rejects_events_during_sync_download() {
    use std::sync::Arc;

    use nula_storage_memory::MemoryDatabase;

    let keys = deterministic_keys();
    let blocked_kind = Kind::TEXT_NOTE;
    let blocked_event = text_note("blocked", "blocked-by-policy")
        .sign_with_keys(&keys)
        .expect("sign blocked");

    let relay_storage: Arc<dyn nula_storage::NostrDatabase> = Arc::new(MemoryDatabase::new());
    relay_storage
        .save_event(&blocked_event)
        .await
        .expect("seed relay");

    let relay = MockRelayBuilder::new()
        .storage(Arc::clone(&relay_storage))
        .run()
        .await
        .expect("mock relay binds");

    let client_db: Arc<dyn nula_storage::NostrDatabase> = Arc::new(MemoryDatabase::new());
    let policy: Arc<dyn nula_sdk::AdmitPolicy> = Arc::new(StubPolicy {
        reject_events_after_kind: Some(blocked_kind),
        ..StubPolicy::default()
    });

    let client = Client::builder()
        .signer(keys.clone())
        .database_arc(Arc::clone(&client_db))
        .admit_policy(policy)
        .build()
        .expect("policy builder ok");
    client.add_relay(relay.url()).await.expect("add relay");
    client.connect().await;

    let filter = Filter::new().kind(blocked_kind).author(*keys.public_key());
    let opts = nula_sdk::SyncOptions::new()
        .direction(nula_sdk::SyncDirection::Down)
        .timeout(Some(Duration::from_secs(5)));
    let summary = client
        .sync_to_relay(relay.url(), filter, opts)
        .await
        .expect("sync ok");

    assert!(
        summary.received.is_empty(),
        "rejected events must not be persisted; got received={:?}",
        summary.received,
    );
    assert!(
        summary.rejected_by_policy.contains_key(&blocked_event.id),
        "rejected_by_policy must record the blocked event id; got {:?}",
        summary.rejected_by_policy,
    );
    let stored = client_db
        .event_by_id(&blocked_event.id)
        .await
        .expect("db lookup");
    assert!(
        stored.is_none(),
        "policy-rejected event must not land in the local database",
    );

    client.shutdown().await;
    relay.shutdown();
}
