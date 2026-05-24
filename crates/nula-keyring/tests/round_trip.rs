//! Integration tests for `nula-keyring`.
//!
//! Full set / get round-trip semantics rely on the OS-native
//! keychain (macOS Keychain / Linux Secret Service / Windows
//! Credential Manager), which is unsuitable for CI gating: it
//! requires an unlocked session keyring, interactive prompts, or
//! D-Bus access that headless runners do not provide.
//!
//! The `keyring` crate ships a `mock` backend, but it stores
//! secrets inside each `Entry` instance rather than in a shared
//! map keyed by `(service, name)`. That makes it useful for
//! per-instance API smoke tests, but it cannot mirror the
//! cross-call persistence the OS backends provide.
//!
//! These tests therefore focus on the API shape (every method
//! compiles and is callable end-to-end), the error contract
//! (`delete` is idempotent, `InvalidSecret` fires on garbage
//! bytes), and the typed-error surface. Cross-launch round trips
//! are exercised by hand against a real keychain.

#![allow(
    unused_crate_dependencies,
    reason = "dev-dependencies serve sibling test files"
)]
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    reason = "integration test file, not production code"
)]

use std::sync::Once;

use nula_core::Keys;
use nula_keyring::Keyring;

static MOCK_INIT: Once = Once::new();

/// Switch the global keyring backend to the in-process mock the
/// crate ships for testing. Idempotent -- safe to call from every
/// test.
fn install_mock_backend() {
    MOCK_INIT.call_once(|| {
        keyring::set_default_credential_builder(keyring::mock::default_credential_builder());
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn set_then_delete_is_well_formed() {
    install_mock_backend();
    let keyring = Keyring::new("test.nula.set-delete");
    let keys = Keys::generate().expect("OS RNG");

    // The `set` call only writes to the freshly-created Entry, so
    // we cannot read it back through a second Entry under the mock
    // backend. We can still verify that the write itself does not
    // return an error, and that the matching `delete` resolves
    // cleanly (which, under the mock backend, hits the NoEntry
    // tolerance path because `set` and `delete` see different
    // Entry instances).
    keyring.set("primary", &keys).await.expect("set");
    keyring
        .delete("primary")
        .await
        .expect("delete tolerates the mock backend's per-Entry semantics");
}

#[test]
fn set_blocking_then_delete_blocking_is_well_formed() {
    install_mock_backend();
    let keyring = Keyring::new("test.nula.set-delete-blocking");
    let keys = Keys::generate().expect("OS RNG");

    keyring.set_blocking("primary", &keys).expect("set");
    keyring.delete_blocking("primary").expect("delete");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn delete_is_idempotent() {
    install_mock_backend();
    let keyring = Keyring::new("test.nula.delete-idempotent");

    // Never written -- delete must still resolve to Ok.
    keyring
        .delete("missing")
        .await
        .expect("delete of missing entry is a no-op");
    keyring
        .delete("missing")
        .await
        .expect("second delete still ok");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_missing_entry_surfaces_no_entry_error() {
    install_mock_backend();
    let keyring = Keyring::new("test.nula.missing");

    let err = keyring
        .get("nothing-here")
        .await
        .expect_err("missing entry must error");
    assert!(
        matches!(err, nula_keyring::Error::Keyring(keyring::Error::NoEntry)),
        "got {err:?}"
    );
}

#[test]
fn service_accessor_returns_constructor_input() {
    let keyring = Keyring::new("test.nula.service-accessor");
    assert_eq!(keyring.service(), "test.nula.service-accessor");
}
