//! Error surface for [`crate::BlossomClient`].

use nula_core::event::EventBuilderError;
use nula_core::signer::SignerError;
use nula_core::types::{TimestampError, UrlError};
use thiserror::Error;

/// Errors raised by [`crate::BlossomClient`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The underlying HTTP request failed (connection, TLS, timeout, …).
    #[error(transparent)]
    Http(#[from] reqwest::Error),

    /// Signing the NIP-24242 authorization event failed.
    #[error("authorization signer error: {0}")]
    Signer(#[from] SignerError),

    /// Building the authorization event failed.
    #[error(transparent)]
    Event(#[from] EventBuilderError),

    /// A server or blob URL was malformed.
    #[error(transparent)]
    Url(#[from] UrlError),

    /// The system clock could not be read while stamping the auth event.
    #[error(transparent)]
    Clock(#[from] TimestampError),

    /// A JSON body failed to (de)serialize. Boxed to keep the enum small.
    #[error("blossom JSON (de)serialization failed: {0}")]
    Json(#[source] Box<serde_json::Error>),

    /// The server responded with a non-success HTTP status. `message`
    /// carries the `X-Reason` header (or the response body) when present.
    #[error("blossom server error (HTTP {status}): {message}")]
    Server {
        /// HTTP status code.
        status: u16,
        /// Human-readable diagnostic (`X-Reason` header or body).
        message: String,
    },

    /// A downloaded blob did not hash to the requested digest.
    #[error("blob integrity check failed: expected sha256 {expected}, computed {actual}")]
    HashMismatch {
        /// The sha256 the caller requested.
        expected: String,
        /// The sha256 actually computed over the downloaded bytes.
        actual: String,
    },

    /// [`crate::BlossomClient::download_any`] /
    /// [`crate::BlossomClient::upload_to_all`] was given an empty server
    /// list.
    #[error("no Blossom servers were provided")]
    NoServers,
}

impl Error {
    pub(crate) fn json(err: serde_json::Error) -> Self {
        Self::Json(Box::new(err))
    }
}
