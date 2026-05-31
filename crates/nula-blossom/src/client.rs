//! The [`BlossomClient`] HTTP client.

use std::sync::Arc;

use nula_core::nips::nipb7::BlossomServerList;
use nula_core::signer::NostrSigner;
use nula_core::{PublicKey, Url};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use sha2::{Digest, Sha256};

use crate::auth::{self, BlossomVerb};
use crate::descriptor::BlobDescriptor;
use crate::error::Error;

/// Default lifetime (seconds) stamped onto authorization events.
const DEFAULT_AUTH_TTL_SECS: u64 = 60;

/// Custom header carrying the client-computed sha256 (BUD-02).
const X_SHA_256: &str = "X-SHA-256";

/// A Blossom blob-transport client.
///
/// Wraps a [`reqwest::Client`] and a [`NostrSigner`]; the signer authors
/// the `kind: 24242` authorization events the authenticated endpoints
/// require. Cloning is cheap.
#[derive(Debug, Clone)]
pub struct BlossomClient {
    http: reqwest::Client,
    signer: Arc<dyn NostrSigner>,
    auth_ttl_secs: u64,
}

impl BlossomClient {
    /// Build a client with a default [`reqwest::Client`].
    #[must_use]
    pub fn new(signer: Arc<dyn NostrSigner>) -> Self {
        Self::with_http_client(reqwest::Client::new(), signer)
    }

    /// Build a client over a caller-supplied [`reqwest::Client`] (to
    /// share a connection pool, set proxies/timeouts, etc.).
    #[must_use]
    pub fn with_http_client(http: reqwest::Client, signer: Arc<dyn NostrSigner>) -> Self {
        Self {
            http,
            signer,
            auth_ttl_secs: DEFAULT_AUTH_TTL_SECS,
        }
    }

    /// Override the authorization-event lifetime (seconds).
    #[must_use]
    pub const fn auth_ttl_secs(mut self, secs: u64) -> Self {
        self.auth_ttl_secs = secs;
        self
    }

    /// Upload `data` to `server` (`PUT /upload`).
    ///
    /// Computes the sha256 client-side, signs an `upload` authorization
    /// event pinning that digest, and returns the server's
    /// [`BlobDescriptor`].
    ///
    /// # Errors
    ///
    /// See [`Error`].
    pub async fn upload(
        &self,
        server: &Url,
        data: Vec<u8>,
        mime_type: Option<&str>,
    ) -> Result<BlobDescriptor, Error> {
        let sha256 = sha256_hex(&data);
        let authorization = auth::authorization_header(
            self.signer.as_ref(),
            BlossomVerb::Upload,
            std::slice::from_ref(&sha256),
            "Upload blob",
            self.auth_ttl_secs,
        )
        .await?;

        let mut request = self
            .http
            .put(endpoint(server, "upload"))
            .header(AUTHORIZATION, authorization)
            .header(X_SHA_256, &sha256)
            .body(data);
        if let Some(mime) = mime_type {
            request = request.header(CONTENT_TYPE, mime);
        }

        let response = request.send().await?;
        decode_json(response).await
    }

    /// Download the blob `sha256` from `server` (`GET /<sha256>`) and
    /// verify its integrity against the requested digest.
    ///
    /// # Errors
    ///
    /// [`Error::HashMismatch`] if the downloaded bytes do not hash to
    /// `sha256`; otherwise see [`Error`].
    pub async fn download(&self, server: &Url, sha256: &str) -> Result<Vec<u8>, Error> {
        let response = self.http.get(blob_url(server, sha256)).send().await?;
        if !response.status().is_success() {
            return Err(server_error(response).await);
        }
        let bytes = response.bytes().await?.to_vec();
        let actual = sha256_hex(&bytes);
        let expected = sha256.to_ascii_lowercase();
        if actual == expected {
            Ok(bytes)
        } else {
            Err(Error::HashMismatch { expected, actual })
        }
    }

    /// Check whether `server` has the blob `sha256` (`HEAD /<sha256>`).
    ///
    /// # Errors
    ///
    /// See [`Error`]. A `404` / `410` maps to `Ok(false)`, not an error.
    pub async fn has(&self, server: &Url, sha256: &str) -> Result<bool, Error> {
        let response = self.http.head(blob_url(server, sha256)).send().await?;
        match response.status().as_u16() {
            200 | 206 => Ok(true),
            404 | 410 => Ok(false),
            _ => Err(server_error(response).await),
        }
    }

    /// Delete the blob `sha256` from `server` (`DELETE /<sha256>`).
    ///
    /// # Errors
    ///
    /// See [`Error`].
    pub async fn delete(&self, server: &Url, sha256: &str) -> Result<(), Error> {
        let authorization = auth::authorization_header(
            self.signer.as_ref(),
            BlossomVerb::Delete,
            std::slice::from_ref(&sha256.to_owned()),
            "Delete blob",
            self.auth_ttl_secs,
        )
        .await?;
        let response = self
            .http
            .delete(blob_url(server, sha256))
            .header(AUTHORIZATION, authorization)
            .send()
            .await?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(server_error(response).await)
        }
    }

    /// List the blobs `pubkey` has stored on `server` (`GET
    /// /list/<pubkey>`).
    ///
    /// # Errors
    ///
    /// See [`Error`].
    pub async fn list(
        &self,
        server: &Url,
        pubkey: &PublicKey,
    ) -> Result<Vec<BlobDescriptor>, Error> {
        let authorization = auth::authorization_header(
            self.signer.as_ref(),
            BlossomVerb::List,
            &[],
            "List blobs",
            self.auth_ttl_secs,
        )
        .await?;
        let url = format!("{}/list/{}", trim_server(server), pubkey.to_hex());
        let response = self
            .http
            .get(url)
            .header(AUTHORIZATION, authorization)
            .send()
            .await?;
        decode_json(response).await
    }

    /// Upload `data` to every server in a NIP-B7 [`BlossomServerList`],
    /// returning a per-server result. This is the discovery-side
    /// (NIP-B7) and transport-side (BUD-02) halves stitched together.
    ///
    /// # Errors
    ///
    /// [`Error::NoServers`] when the list is empty. Individual upload
    /// failures are returned per server rather than aborting the batch.
    pub async fn upload_to_all(
        &self,
        servers: &BlossomServerList,
        data: Vec<u8>,
        mime_type: Option<&str>,
    ) -> Result<Vec<(Url, Result<BlobDescriptor, Error>)>, Error> {
        if servers.servers.is_empty() {
            return Err(Error::NoServers);
        }
        let mut results = Vec::with_capacity(servers.servers.len());
        for server in &servers.servers {
            let outcome = self.upload(server, data.clone(), mime_type).await;
            results.push((server.clone(), outcome));
        }
        Ok(results)
    }

    /// Download `sha256` from the first server in a NIP-B7 list that has
    /// it, trying each in order (the user's preferred-then-mirror order).
    ///
    /// # Errors
    ///
    /// [`Error::NoServers`] when the list is empty; otherwise the last
    /// per-server error encountered.
    pub async fn download_any(
        &self,
        servers: &BlossomServerList,
        sha256: &str,
    ) -> Result<Vec<u8>, Error> {
        let mut last_error: Option<Error> = None;
        for server in &servers.servers {
            match self.download(server, sha256).await {
                Ok(bytes) => return Ok(bytes),
                Err(err) => last_error = Some(err),
            }
        }
        Err(last_error.unwrap_or(Error::NoServers))
    }
}

/// Compute the lowercase-hex sha256 digest of `data` — the address a
/// blob is stored and retrieved under in Blossom.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    faster_hex::hex_string(Sha256::digest(data).as_slice())
}

fn trim_server(server: &Url) -> &str {
    server.as_str().trim_end_matches('/')
}

fn endpoint(server: &Url, path: &str) -> String {
    format!("{}/{path}", trim_server(server))
}

fn blob_url(server: &Url, sha256: &str) -> String {
    format!("{}/{sha256}", trim_server(server))
}

async fn decode_json<T>(response: reqwest::Response) -> Result<T, Error>
where
    T: serde::de::DeserializeOwned,
{
    if !response.status().is_success() {
        return Err(server_error(response).await);
    }
    let text = response.text().await?;
    serde_json::from_str(&text).map_err(Error::json)
}

async fn server_error(response: reqwest::Response) -> Error {
    let status = response.status().as_u16();
    let reason = response
        .headers()
        .get("X-Reason")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let message = match reason {
        Some(reason) => reason,
        None => response.text().await.unwrap_or_default(),
    };
    Error::Server { status, message }
}
