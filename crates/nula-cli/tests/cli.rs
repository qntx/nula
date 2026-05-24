//! End-to-end tests for the `nula` binary.
//!
//! Uses `assert_cmd` to spawn the compiled binary and inspect
//! stdout / stderr / exit codes. Every test runs against a
//! one-shot in-process `MockRelay` started by the `nula relay run`
//! subcommand or by spawning `MockRelayBuilder` directly when the
//! tests need a server-side handle (publish / fetch round-trip).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::tests_outside_test_module,
    reason = "this is an integration test binary"
)]

// Pin transitive crates the integration binary inherits from the
// CLI's dev/runtime closure to keep the workspace
// `unused_crate_dependencies` lint quiet.
use anyhow as _;
use assert_cmd::Command;
use clap as _;
use nula_core as _;
use nula_relay_builder as _;
use nula_sdk as _;
use predicates as _;
use serde_json as _;
use tokio as _;
use tracing as _;
use tracing_subscriber as _;

/// Build a Command that invokes the compiled `nula` binary.
fn nula() -> Command {
    Command::cargo_bin("nula").expect("binary `nula` builds")
}

#[test]
fn keys_generate_produces_valid_json() {
    let out = nula().args(["keys", "generate"]).assert().success();
    let stdout = std::str::from_utf8(&out.get_output().stdout).expect("utf8");
    let value: serde_json::Value = serde_json::from_str(stdout).expect("valid JSON");
    assert_eq!(value["kind"], "keypair");
    let nsec = value["secret_key"]["bech32"].as_str().unwrap();
    let npub = value["public_key"]["bech32"].as_str().unwrap();
    assert!(nsec.starts_with("nsec1"));
    assert!(npub.starts_with("npub1"));
    assert_eq!(value["secret_key"]["hex"].as_str().unwrap().len(), 64);
    assert_eq!(value["public_key"]["hex"].as_str().unwrap().len(), 64);
}

#[test]
fn keys_parse_round_trips_a_generated_key() {
    let generated = nula().args(["keys", "generate"]).assert().success();
    let gen_stdout = std::str::from_utf8(&generated.get_output().stdout).expect("utf8");
    let value: serde_json::Value = serde_json::from_str(gen_stdout).expect("valid JSON");
    let nsec = value["secret_key"]["bech32"].as_str().unwrap().to_owned();

    let parsed = nula().args(["keys", "parse", &nsec]).assert().success();
    let parsed_stdout = std::str::from_utf8(&parsed.get_output().stdout).expect("utf8");
    let parsed_value: serde_json::Value = serde_json::from_str(parsed_stdout).expect("valid JSON");
    assert_eq!(parsed_value["kind"], "keypair");
    assert_eq!(parsed_value["secret_key"]["bech32"], nsec);
}

#[test]
fn keys_parse_accepts_npub_only_input() {
    let generated = nula().args(["keys", "generate"]).assert().success();
    let gen_stdout = std::str::from_utf8(&generated.get_output().stdout).expect("utf8");
    let value: serde_json::Value = serde_json::from_str(gen_stdout).expect("valid JSON");
    let npub = value["public_key"]["bech32"].as_str().unwrap().to_owned();

    let parsed = nula().args(["keys", "parse", &npub]).assert().success();
    let parsed_stdout = std::str::from_utf8(&parsed.get_output().stdout).expect("utf8");
    let parsed_value: serde_json::Value = serde_json::from_str(parsed_stdout).expect("valid JSON");
    assert_eq!(parsed_value["kind"], "public_key");
    assert_eq!(parsed_value["public_key"]["bech32"], npub);
}

#[test]
fn keys_parse_rejects_garbage() {
    nula()
        .args(["keys", "parse", "not a key"])
        .assert()
        .failure();
}

#[test]
fn event_publish_requires_relay_flag() {
    nula()
        .args(["event", "publish", "--content", "hi", "--secret", "garbage"])
        .assert()
        .failure();
}

#[test]
fn event_fetch_requires_relay_flag() {
    nula().args(["event", "fetch"]).assert().failure();
}

#[test]
fn publish_then_fetch_round_trip() {
    use nula_relay_builder::MockRelayBuilder;

    // Multi-thread runtime: MockRelay spawns a background accept
    // loop that must keep running while the subprocess CLI calls
    // out to its WebSocket port. A `current_thread` runtime would
    // park the worker the moment `block_on` returns.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("build runtime");
    let relay = runtime.block_on(async {
        MockRelayBuilder::new()
            .run()
            .await
            .expect("mock relay binds")
    });
    let relay_url = relay.url().as_str().to_owned();

    // Generate a fresh keypair to sign with.
    let generated = nula().args(["keys", "generate"]).assert().success();
    let key_value: serde_json::Value =
        serde_json::from_slice(&generated.get_output().stdout).expect("valid JSON");
    let nsec = key_value["secret_key"]["bech32"]
        .as_str()
        .expect("nsec present")
        .to_owned();
    let npub = key_value["public_key"]["bech32"]
        .as_str()
        .expect("npub present")
        .to_owned();

    // Publish.
    let publish = nula()
        .args([
            "event",
            "publish",
            "--relay",
            &relay_url,
            "--content",
            "hello from cli",
            "--secret",
            &nsec,
        ])
        .assert()
        .success();
    let pub_value: serde_json::Value =
        serde_json::from_slice(&publish.get_output().stdout).expect("valid JSON");
    assert_eq!(pub_value["kind"], "event_published");
    let success = pub_value["success"].as_array().expect("array");
    assert_eq!(success.len(), 1);
    assert_eq!(success[0], serde_json::Value::String(relay_url.clone()));

    // Fetch.
    let fetch = nula()
        .args([
            "event", "fetch", "--relay", &relay_url, "--author", &npub, "--kind", "1",
        ])
        .assert()
        .success();
    let fetch_value: serde_json::Value =
        serde_json::from_slice(&fetch.get_output().stdout).expect("valid JSON");
    assert_eq!(fetch_value["kind"], "events_fetched");
    assert_eq!(fetch_value["count"], 1);
    assert_eq!(
        fetch_value["events"][0]["content"],
        serde_json::Value::String("hello from cli".to_owned())
    );

    relay.shutdown();
    drop(runtime);
}
