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
