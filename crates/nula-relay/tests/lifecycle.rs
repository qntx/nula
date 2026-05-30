//! Lifecycle tests: connect, disconnect, drop-induced shutdown.

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

use nula_core::RelayUrl;
use nula_relay::transport::mock::MockTransport;
use nula_relay::{Relay, RelayStatus};
use tokio::time::timeout;

const STEP_TIMEOUT: Duration = Duration::from_secs(5);

fn url() -> RelayUrl {
    RelayUrl::parse("wss://relay.test.example").expect("valid relay URL")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_round_trip_via_mock_transport() {
    let transport = Arc::new(MockTransport::new());
    let endpoint = url();
    let mut subscriber = transport.subscribe(&endpoint);

    let relay = Relay::builder(endpoint.clone())
        .transport(Arc::clone(&transport))
        .build()
        .expect("transport supplied to builder");

    assert_eq!(relay.status(), RelayStatus::Initialized);

    // Trigger the handshake; the mock subscriber must observe a
    // connect attempt.
    let connect = tokio::spawn({
        let relay = relay.clone();
        async move { relay.connect().await }
    });

    let _handle = timeout(STEP_TIMEOUT, subscriber.recv())
        .await
        .expect("subscriber received connect handle within deadline")
        .expect("subscriber channel still open");

    timeout(STEP_TIMEOUT, connect)
        .await
        .expect("connect resolves within deadline")
        .expect("task joined")
        .expect("connect succeeds");

    assert_eq!(relay.status(), RelayStatus::Connected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disconnect_returns_to_disconnected_state() {
    let transport = Arc::new(MockTransport::new());
    let endpoint = url();
    let mut subscriber = transport.subscribe(&endpoint);

    let relay = Relay::builder(endpoint.clone())
        .transport(Arc::clone(&transport))
        .build()
        .expect("transport supplied to builder");

    let connect = tokio::spawn({
        let relay = relay.clone();
        async move { relay.connect().await }
    });
    let _handle = subscriber.recv().await.expect("handle");
    connect
        .await
        .expect("task joined")
        .expect("connect succeeds");

    assert_eq!(relay.status(), RelayStatus::Connected);
    relay.disconnect().await.expect("disconnect");
    assert_eq!(relay.status(), RelayStatus::Disconnected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_last_handle_terminates_actor() {
    let transport = Arc::new(MockTransport::new());
    let endpoint = url();

    {
        let _relay = Relay::builder(endpoint.clone())
            .transport(Arc::clone(&transport))
            .build()
            .expect("transport supplied to builder");
        // _relay drops at end of block → actor should
        // observe Shutdown command and exit.
    }

    // Give the actor a tick to process the Shutdown command.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // The mock subscriber map still holds a sender; a fresh relay
    // can be constructed against the same URL without leaks.
    let _another = Relay::builder(endpoint)
        .transport(transport)
        .build()
        .expect("transport supplied to builder");
}
