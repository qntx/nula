//! Blossom blob-transport client.
//!
//! [Blossom] is a family of HTTP standards ("BUDs") for content-addressed
//! file storage: every blob lives at `<server>/<sha256>` and authenticated
//! actions are authorized with a signed `kind: 24242` Nostr event. This
//! crate is the *transport* half — upload, download, existence checks,
//! delete, and list — complementing the *discovery* half
//! ([`nula_core::nips::nipb7`], the `kind: 10063` server list).
//!
//! Together they close the loop: discover a user's servers with NIP-B7,
//! then move bytes with this client. [`BlossomClient::upload_to_all`] and
//! [`BlossomClient::download_any`] take a
//! [`BlossomServerList`](nula_core::nips::nipb7::BlossomServerList)
//! directly.
//!
//! # Authorization
//!
//! Authenticated endpoints require an `Authorization: Nostr <base64>`
//! header wrapping a signed [`KIND_AUTH`] event. Any
//! [`NostrSigner`](nula_core::NostrSigner) authors it — a local
//! [`Keys`](nula_core::Keys) or a remote `nula-signer` bunker — so the
//! signing key never has to live in the HTTP layer.
//!
//! # Integrity
//!
//! [`BlossomClient::download`] verifies the downloaded bytes hash to the
//! requested digest and returns [`Error::HashMismatch`] otherwise, so a
//! misbehaving or compromised mirror cannot serve substituted content.
//!
//! [Blossom]: https://github.com/hzrd149/blossom
//!
//! # Quickstart
//!
//! ```rust,no_run
//! use std::sync::Arc;
//!
//! use nula_blossom::BlossomClient;
//! use nula_core::{Keys, NostrSigner, Url};
//!
//! # async fn doc() -> Result<(), Box<dyn std::error::Error>> {
//! let signer: Arc<dyn NostrSigner> = Arc::new(Keys::generate()?);
//! let client = BlossomClient::new(signer);
//! let server = Url::parse("https://cdn.example.com")?;
//!
//! let descriptor = client
//!     .upload(&server, b"hello blossom".to_vec(), Some("text/plain"))
//!     .await?;
//! let bytes = client.download(&server, &descriptor.sha256).await?;
//! assert_eq!(bytes, b"hello blossom");
//! # Ok(()) }
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(html_root_url = "https://docs.rs/nula-blossom")]
#![forbid(unsafe_code)]

// `wiremock` is a dev-dependency exercised only by the HTTP integration
// tests; hedge the `unused_crate_dependencies` lint on the lib-test build
// (whose unit tests never touch it).
#[cfg(test)]
use wiremock as _;

pub mod auth;
pub mod descriptor;
pub mod error;

mod client;

pub use self::auth::{BlossomVerb, KIND_AUTH};
pub use self::client::{BlossomClient, sha256_hex};
pub use self::descriptor::BlobDescriptor;
pub use self::error::Error;
