//! HTTP integration tests for [`BlossomClient`] against a `wiremock`
//! mock Blossom server.

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

use nula_blossom::{BlossomClient, sha256_hex};
use nula_core::{Keys, NostrSigner, Url};
use wiremock::matchers::{header_exists, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn client() -> BlossomClient {
    let signer: Arc<dyn NostrSigner> = Arc::new(Keys::generate().expect("generate keys"));
    BlossomClient::new(signer)
}

fn server_url(server: &MockServer) -> Url {
    Url::parse(server.uri()).expect("mock server url")
}

#[tokio::test]
async fn upload_returns_descriptor_and_sends_authorization() {
    let server = MockServer::start().await;
    let url = server_url(&server);
    let data = b"hello blossom".to_vec();
    let sha = sha256_hex(&data);

    let body = serde_json::json!({
        "url": format!("{}/{sha}.bin", server.uri()),
        "sha256": sha,
        "size": data.len(),
        "type": "text/plain",
        "uploaded": 1_700_000_000_u64,
    });

    Mock::given(method("PUT"))
        .and(path("/upload"))
        .and(header_exists("authorization"))
        .respond_with(ResponseTemplate::new(201).set_body_json(body))
        .mount(&server)
        .await;

    let descriptor = client()
        .upload(&url, data, Some("text/plain"))
        .await
        .expect("upload");
    assert_eq!(descriptor.sha256, sha);
    assert_eq!(descriptor.size, 13);
    assert_eq!(descriptor.mime_type.as_deref(), Some("text/plain"));
}

#[tokio::test]
async fn download_verifies_integrity() {
    let server = MockServer::start().await;
    let url = server_url(&server);
    let data = b"verify me".to_vec();
    let sha = sha256_hex(&data);

    Mock::given(method("GET"))
        .and(path(format!("/{sha}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(data.clone()))
        .mount(&server)
        .await;

    let got = client().download(&url, &sha).await.expect("download");
    assert_eq!(got, data);
}

#[tokio::test]
async fn download_rejects_tampered_blob() {
    let server = MockServer::start().await;
    let url = server_url(&server);
    let requested = sha256_hex(b"original content");

    // The server returns bytes that do NOT hash to the requested digest.
    Mock::given(method("GET"))
        .and(path(format!("/{requested}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"tampered content".to_vec()))
        .mount(&server)
        .await;

    let err = client()
        .download(&url, &requested)
        .await
        .expect_err("integrity check must fail");
    assert!(
        matches!(err, nula_blossom::Error::HashMismatch { .. }),
        "got {err:?}"
    );
}

#[tokio::test]
async fn has_maps_404_to_false() {
    let server = MockServer::start().await;
    let url = server_url(&server);
    let sha = sha256_hex(b"absent blob");

    Mock::given(method("HEAD"))
        .and(path(format!("/{sha}")))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    assert!(!client().has(&url, &sha).await.expect("has"));
}

#[tokio::test]
async fn server_error_surfaces_x_reason() {
    let server = MockServer::start().await;
    let url = server_url(&server);

    Mock::given(method("PUT"))
        .and(path("/upload"))
        .respond_with(ResponseTemplate::new(413).insert_header("X-Reason", "blob too large"))
        .mount(&server)
        .await;

    let err = client()
        .upload(&url, b"x".to_vec(), None)
        .await
        .expect_err("server rejects upload");
    match err {
        nula_blossom::Error::Server { status, message } => {
            assert_eq!(status, 413);
            assert_eq!(message, "blob too large");
        }
        other => panic!("expected Error::Server, got {other:?}"),
    }
}
