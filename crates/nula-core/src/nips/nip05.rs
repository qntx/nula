//! [NIP-05] DNS-based internet identifiers for Nostr keys.
//!
//! NIP-05 maps an email-like identifier `<local>@<domain>` to a Nostr
//! public key by resolving
//! `https://<domain>/.well-known/nostr.json?name=<local>` and looking
//! the pubkey up under the document's `names` mapping. The optional
//! `relays` field then yields per-pubkey relay hints.
//!
//! # Architecture
//!
//! Network IO is intentionally split from the spec logic:
//!
//! 1. [`Nip05Address::parse`] enforces the local-part charset
//!    (`a-z0-9-_.`), lowercases the domain, and recognises the
//!    `_@<domain>` "root" form that clients render as just `<domain>`.
//! 2. [`Nip05Document::parse`] deserialises the well-known JSON.
//! 3. [`verify_document`] composes (1) and (2) into a single
//!    side-effect-free verifier that operates on a JSON string the
//!    caller already obtained somehow.
//! 4. [`Nip05Fetcher`] is the **only** trait that touches network IO.
//!    It returns a boxed future so the trait stays
//!    [dyn-compatible](https://doc.rust-lang.org/reference/items/traits.html#dyn-compatible-traits)
//!    and so future NAPI / FFI bindings can pin the boxed future
//!    across the FFI boundary without conditional compilation.
//! 5. [`lookup_pubkey`] / [`lookup_with_relays`] / [`verify_identifier`]
//!    are the user-facing async helpers that wire (4) into (1)–(3).
//!
//! The default reqwest-backed fetcher ([`ReqwestNip05Fetcher`]) is
//! gated behind the `nip05` Cargo feature. Implementers who want to
//! plug in a different HTTP client (`hyper`, `surf`, an in-process
//! cache, …) only need to implement [`Nip05Fetcher`].
//!
//! # Security
//!
//! NIP-05 §"Security Constraints" states the well-known endpoint
//! MUST NOT return HTTP redirects and fetchers MUST ignore any.
//! [`ReqwestNip05Fetcher`] hard-disables redirects via
//! [`reqwest::redirect::Policy::none`], so a server that points
//! to a third-party host cannot launder a different pubkey under the
//! original identifier.
//!
//! [NIP-05]: https://github.com/nostr-protocol/nips/blob/master/05.md

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::key::PublicKey;
use crate::types::RelayUrl;

/// Conventional `local-part` for the "root" identifier (`_@<domain>`),
/// rendered as just `<domain>` by clients per NIP-05 §"Showing just
/// the domain as an identifier".
pub const ROOT_LOCAL_PART: &str = "_";

/// Path component appended to the domain to produce the well-known URL.
pub const WELL_KNOWN_PATH: &str = "/.well-known/nostr.json";

/// Errors common to NIP-05 parsing and verification.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Nip05Error {
    /// The address did not contain exactly one `@` separator.
    #[error("NIP-05 address must contain exactly one `@`")]
    MalformedAddress,
    /// The `local-part` contained a character outside `a-z0-9-_.`.
    #[error("NIP-05 local-part must only use `a-z0-9-_.`; got `{0}`")]
    InvalidLocalPart(String),
    /// The domain part was empty.
    #[error("NIP-05 domain must not be empty")]
    EmptyDomain,
    /// The well-known JSON document failed to parse.
    #[error("NIP-05 well-known JSON failed to parse: {0}")]
    DocumentParse(#[from] serde_json::Error),
    /// The document did not contain a mapping for the local-part.
    #[error("NIP-05 well-known document does not list `{0}` under `names`")]
    NameNotListed(String),
}

/// Errors that can surface from a [`Nip05Fetcher`] implementation.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Nip05FetchError {
    /// The HTTP request failed (network, TLS, DNS, …).
    #[error("NIP-05 well-known fetch failed: {0}")]
    Transport(String),
    /// The server returned a non-2xx status code.
    #[error("NIP-05 well-known fetch returned status {0}")]
    Status(u16),
    /// The server attempted an HTTP redirect, which NIP-05 forbids.
    #[error("NIP-05 well-known fetch was redirected, which the spec forbids")]
    Redirected,
}

/// Errors raised by the high-level helpers ([`lookup_pubkey`] etc.).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Nip05LookupError {
    /// The address itself was invalid.
    #[error(transparent)]
    Address(Nip05Error),
    /// The fetcher could not retrieve the well-known document.
    #[error(transparent)]
    Fetch(#[from] Nip05FetchError),
    /// The fetched document failed to parse or did not list the name.
    #[error(transparent)]
    Document(Nip05Error),
}

/// A NIP-05 internet identifier.
///
/// Both halves are stored in their canonical wire-form
/// (lowercase). Use [`Self::parse`] to construct, [`Self::display`]
/// to render the user-facing form (which suppresses the leading
/// `_@` for the root identifier).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Nip05Address {
    /// The `local-part` after lowercasing.
    pub local: String,
    /// The `<domain>` after lowercasing.
    pub domain: String,
}

impl Nip05Address {
    /// Parse `<local>@<domain>` per NIP-05.
    ///
    /// # Errors
    ///
    /// - [`Nip05Error::MalformedAddress`] if the input lacks exactly
    ///   one `@`.
    /// - [`Nip05Error::InvalidLocalPart`] if the local part contains
    ///   any character outside `a-z0-9-_.` (after case-folding).
    /// - [`Nip05Error::EmptyDomain`] if the domain is empty.
    pub fn parse(input: &str) -> Result<Self, Nip05Error> {
        let (local, domain) = input.split_once('@').ok_or(Nip05Error::MalformedAddress)?;
        if local.contains('@') || domain.contains('@') {
            return Err(Nip05Error::MalformedAddress);
        }
        if domain.is_empty() {
            return Err(Nip05Error::EmptyDomain);
        }
        let local_lower = local.to_ascii_lowercase();
        if !is_valid_local_part(&local_lower) {
            return Err(Nip05Error::InvalidLocalPart(local.to_owned()));
        }
        Ok(Self {
            local: local_lower,
            domain: domain.to_ascii_lowercase(),
        })
    }

    /// Return the `https://<domain>/.well-known/nostr.json?name=<local>`
    /// URL the client must `GET`.
    #[must_use]
    pub fn well_known_url(&self) -> String {
        format!(
            "https://{domain}{path}?name={local}",
            domain = self.domain,
            path = WELL_KNOWN_PATH,
            local = self.local,
        )
    }

    /// `true` when `local == "_"`. Such addresses are rendered as
    /// just the domain in user-facing UIs.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.local == ROOT_LOCAL_PART
    }

    /// Render the address for display: `_@d.com` becomes `d.com`,
    /// every other form is `<local>@<domain>`.
    #[must_use]
    pub fn display(&self) -> String {
        if self.is_root() {
            self.domain.clone()
        } else {
            format!("{}@{}", self.local, self.domain)
        }
    }
}

fn is_valid_local_part(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.'))
}

/// The JSON document served at the well-known endpoint.
///
/// Both maps are deserialised verbatim; further validation against
/// the queried local-part lives in [`verify_document`] /
/// [`Self::pubkey_for`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Nip05Document {
    /// `local-part -> pubkey` mapping. The pubkey is BIP-340 hex.
    #[serde(default)]
    pub names: HashMap<String, PublicKey>,
    /// `pubkey -> [relay urls]` mapping for relay hints.
    #[serde(default)]
    pub relays: HashMap<PublicKey, Vec<RelayUrl>>,
}

impl Nip05Document {
    /// Parse a JSON document.
    ///
    /// # Errors
    ///
    /// Returns [`Nip05Error::DocumentParse`] when the bytes are not
    /// valid JSON or the schema does not match.
    pub fn parse(json: &str) -> Result<Self, Nip05Error> {
        Ok(serde_json::from_str(json)?)
    }

    /// Look up the pubkey for `local`. NIP-05 does not specify
    /// case-sensitivity on the lookup but in practice servers serve
    /// the same lowercase form the client sent in `?name=`; we
    /// therefore look up by the exact local-part the caller already
    /// canonicalised through [`Nip05Address::parse`].
    #[must_use]
    pub fn pubkey_for(&self, local: &str) -> Option<&PublicKey> {
        self.names.get(local)
    }

    /// Borrow the relay-hint list for `pubkey`. Returns `&[]` when
    /// no hints are present.
    #[must_use]
    pub fn relays_for(&self, pubkey: &PublicKey) -> &[RelayUrl] {
        self.relays
            .get(pubkey)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }
}

/// Verify a NIP-05 document against an `(address, expected_pubkey)`
/// pair without doing any IO.
///
/// This is the side-effect-free entry point most callers should
/// reach for first: it lets unit tests pin behaviour against
/// fixture JSON, and lets advanced integrations swap in their own
/// fetch layer.
///
/// # Errors
///
/// - [`Nip05Error::DocumentParse`] for malformed JSON.
/// - [`Nip05Error::NameNotListed`] when the document does not map
///   the queried local-part.
pub fn verify_document(
    address: &Nip05Address,
    document_json: &str,
    expected_pubkey: &PublicKey,
) -> Result<bool, Nip05Error> {
    let doc = Nip05Document::parse(document_json)?;
    let listed = doc
        .pubkey_for(&address.local)
        .ok_or_else(|| Nip05Error::NameNotListed(address.local.clone()))?;
    Ok(listed == expected_pubkey)
}

/// Boxed `Future` returned by [`Nip05Fetcher::fetch`].
pub type FetchFuture<'a, T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'a>>;

/// IO trait for retrieving a NIP-05 well-known document.
///
/// Implementations MUST:
///
/// - issue an HTTPS `GET` for the supplied `url`,
/// - **refuse to follow** any HTTP 3xx redirects (NIP-05 §"Security
///   Constraints"),
/// - return [`Nip05FetchError::Status`] for non-2xx responses,
/// - return the response body verbatim as a UTF-8 [`String`].
///
/// The trait is [`Send`] + [`Sync`] so callers can share a single
/// fetcher across futures and threads.
pub trait Nip05Fetcher: Send + Sync {
    /// Fetch the JSON document at `url`.
    fn fetch<'a>(&'a self, url: &'a str) -> FetchFuture<'a, String, Nip05FetchError>;
}

/// Look up the public key associated with `address`.
///
/// # Errors
///
/// Wraps the underlying error in the appropriate [`Nip05LookupError`]
/// variant.
pub async fn lookup_pubkey<F>(
    fetcher: &F,
    address: &Nip05Address,
) -> Result<PublicKey, Nip05LookupError>
where
    F: Nip05Fetcher + ?Sized,
{
    let body = fetcher.fetch(&address.well_known_url()).await?;
    let doc = Nip05Document::parse(&body).map_err(Nip05LookupError::Document)?;
    let pk = doc.pubkey_for(&address.local).copied().ok_or_else(|| {
        Nip05LookupError::Document(Nip05Error::NameNotListed(address.local.clone()))
    })?;
    Ok(pk)
}

/// Look up `(pubkey, relay_hints)` for `address` in one fetch.
///
/// # Errors
///
/// See [`lookup_pubkey`].
pub async fn lookup_with_relays<F>(
    fetcher: &F,
    address: &Nip05Address,
) -> Result<(PublicKey, Vec<RelayUrl>), Nip05LookupError>
where
    F: Nip05Fetcher + ?Sized,
{
    let body = fetcher.fetch(&address.well_known_url()).await?;
    let doc = Nip05Document::parse(&body).map_err(Nip05LookupError::Document)?;
    let pk = doc.pubkey_for(&address.local).copied().ok_or_else(|| {
        Nip05LookupError::Document(Nip05Error::NameNotListed(address.local.clone()))
    })?;
    let relays = doc.relays_for(&pk).to_vec();
    Ok((pk, relays))
}

/// Verify that `address` resolves to `expected_pubkey`.
///
/// Returns `Ok(true)` when the document lists `expected_pubkey`,
/// `Ok(false)` when the document lists a *different* pubkey for the
/// same name, and an error when the lookup itself failed.
///
/// # Errors
///
/// See [`lookup_pubkey`].
pub async fn verify_identifier<F>(
    fetcher: &F,
    address: &Nip05Address,
    expected_pubkey: &PublicKey,
) -> Result<bool, Nip05LookupError>
where
    F: Nip05Fetcher + ?Sized,
{
    let body = fetcher.fetch(&address.well_known_url()).await?;
    verify_document(address, &body, expected_pubkey).map_err(Nip05LookupError::Document)
}

#[cfg(feature = "nip05")]
#[cfg_attr(docsrs, doc(cfg(feature = "nip05")))]
pub use reqwest_impl::ReqwestNip05Fetcher;

#[cfg(feature = "nip05")]
mod reqwest_impl {
    use super::{FetchFuture, Nip05FetchError, Nip05Fetcher};

    /// `reqwest`-backed [`Nip05Fetcher`] with redirects disabled per
    /// NIP-05 §"Security Constraints".
    ///
    /// The internal client uses `reqwest::redirect::Policy::none()`
    /// so a server that emits an HTTP 3xx is treated as a fetch
    /// failure ([`Nip05FetchError::Redirected`]) rather than
    /// transparently re-routing under a different identity.
    #[derive(Debug, Clone)]
    pub struct ReqwestNip05Fetcher {
        client: reqwest::Client,
    }

    impl ReqwestNip05Fetcher {
        /// Build a new fetcher with a fresh internal client.
        ///
        /// # Errors
        ///
        /// Propagates the underlying [`reqwest::Error`] when the
        /// client cannot be initialised (typically a TLS backend
        /// initialisation failure).
        pub fn new() -> Result<Self, reqwest::Error> {
            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?;
            Ok(Self { client })
        }

        /// Wrap an existing `reqwest::Client`.
        ///
        /// **Caller responsibility**: the supplied client MUST be
        /// configured with `redirect::Policy::none()`. NIP-05's
        /// security constraints rely on every fetch refusing
        /// redirects; passing in a client with a default redirect
        /// policy silently weakens that.
        #[must_use]
        pub const fn from_client(client: reqwest::Client) -> Self {
            Self { client }
        }
    }

    async fn do_fetch(client: &reqwest::Client, url: &str) -> Result<String, Nip05FetchError> {
        let response = client
            .get(url)
            .send()
            .await
            .map_err(|e| Nip05FetchError::Transport(e.to_string()))?;
        let status = response.status();
        if status.is_redirection() {
            return Err(Nip05FetchError::Redirected);
        }
        if !status.is_success() {
            return Err(Nip05FetchError::Status(status.as_u16()));
        }
        response
            .text()
            .await
            .map_err(|e| Nip05FetchError::Transport(e.to_string()))
    }

    impl Nip05Fetcher for ReqwestNip05Fetcher {
        fn fetch<'a>(&'a self, url: &'a str) -> FetchFuture<'a, String, Nip05FetchError> {
            Box::pin(do_fetch(&self.client, url))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_PUBKEY_HEX: &str =
        "b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9";
    const FIXTURE_DOC: &str = r#"{
        "names": {
            "bob": "b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9"
        },
        "relays": {
            "b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9": [
                "wss://relay.example.com",
                "wss://relay2.example.com"
            ]
        }
    }"#;

    fn fixture_pubkey() -> PublicKey {
        PublicKey::parse(FIXTURE_PUBKEY_HEX).unwrap()
    }

    #[test]
    fn parse_address_lowercases_and_validates_local_part() {
        let a = Nip05Address::parse("Bob@Example.COM").unwrap();
        assert_eq!(a.local, "bob");
        assert_eq!(a.domain, "example.com");
        assert!(!a.is_root());
        assert_eq!(a.display(), "bob@example.com");
    }

    #[test]
    fn parse_address_recognises_root_identifier() {
        let a = Nip05Address::parse("_@bob.com").unwrap();
        assert!(a.is_root());
        // Display strips the leading `_@` for root identifiers.
        assert_eq!(a.display(), "bob.com");
    }

    #[test]
    fn parse_address_rejects_invalid_local_part() {
        let cases = [
            ("bob+spam@x.com", "bob+spam"),
            ("bob spam@x.com", "bob spam"),
            ("bob/spam@x.com", "bob/spam"),
            ("bob:spam@x.com", "bob:spam"),
        ];
        for (input, raw_local) in cases {
            let err = Nip05Address::parse(input).unwrap_err();
            assert!(
                matches!(err, Nip05Error::InvalidLocalPart(s) if s == raw_local),
                "expected InvalidLocalPart for {input:?}, got something else"
            );
        }
    }

    #[test]
    fn parse_address_rejects_missing_or_doubled_separator() {
        assert!(matches!(
            Nip05Address::parse("noseparator").unwrap_err(),
            Nip05Error::MalformedAddress,
        ));
        assert!(matches!(
            Nip05Address::parse("a@b@c").unwrap_err(),
            Nip05Error::MalformedAddress,
        ));
        assert!(matches!(
            Nip05Address::parse("nodomain@").unwrap_err(),
            Nip05Error::EmptyDomain,
        ));
    }

    #[test]
    fn well_known_url_uses_https_and_lowercase_query() {
        let a = Nip05Address::parse("BOB@Example.COM").unwrap();
        assert_eq!(
            a.well_known_url(),
            "https://example.com/.well-known/nostr.json?name=bob"
        );
    }

    #[test]
    fn document_parse_round_trips_names_and_relays() {
        let doc = Nip05Document::parse(FIXTURE_DOC).unwrap();
        assert_eq!(doc.pubkey_for("bob"), Some(&fixture_pubkey()));
        let relays = doc.relays_for(&fixture_pubkey());
        assert_eq!(relays.len(), 2);
        assert_eq!(relays[0].as_str(), "wss://relay.example.com/");
    }

    #[test]
    fn document_parse_handles_minimal_fixture_without_relays() {
        let json = r#"{"names":{"bob":"b0635d6a9851d3aed0cd6c495b282167acf761729078d975fc341b22650b07b9"}}"#;
        let doc = Nip05Document::parse(json).unwrap();
        assert!(doc.relays.is_empty());
        assert_eq!(doc.pubkey_for("bob"), Some(&fixture_pubkey()));
    }

    #[test]
    fn verify_document_returns_true_for_match_and_false_for_mismatch() {
        let address = Nip05Address::parse("bob@example.com").unwrap();
        assert!(verify_document(&address, FIXTURE_DOC, &fixture_pubkey()).unwrap());

        // Different pubkey -> false (not an error: the document is
        // well-formed, the identifier just doesn't match the user we
        // have).
        let other =
            PublicKey::parse("0000000000000000000000000000000000000000000000000000000000000003")
                .unwrap();
        // Construct a synthetic Keys to derive a public key.
        let some_other_pubkey =
            *crate::Keys::parse("0000000000000000000000000000000000000000000000000000000000000005")
                .unwrap()
                .public_key();
        assert!(!verify_document(&address, FIXTURE_DOC, &other).unwrap());
        assert!(!verify_document(&address, FIXTURE_DOC, &some_other_pubkey).unwrap());
    }

    #[test]
    fn verify_document_errors_when_name_is_absent() {
        let address = Nip05Address::parse("alice@example.com").unwrap();
        let err = verify_document(&address, FIXTURE_DOC, &fixture_pubkey()).unwrap_err();
        assert!(matches!(err, Nip05Error::NameNotListed(s) if s == "alice"));
    }

    /// In-memory mock fetcher used to drive the async helpers without
    /// pulling in tokio as a dev-dep.
    struct MockFetcher {
        body: String,
    }

    impl Nip05Fetcher for MockFetcher {
        fn fetch<'a>(&'a self, _url: &'a str) -> FetchFuture<'a, String, Nip05FetchError> {
            let body = self.body.clone();
            Box::pin(async move { Ok(body) })
        }
    }

    fn block_on<F: Future>(fut: F) -> F::Output {
        // A tiny in-test executor: poll the future until it's done,
        // using the standard library's no-op waker. Sufficient for a
        // fetcher that finishes synchronously.
        use std::task::{Context, Poll, Waker};
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut fut = Box::pin(fut);
        loop {
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    #[test]
    fn high_level_helpers_work_against_a_mock_fetcher() {
        let fetcher = MockFetcher {
            body: FIXTURE_DOC.to_owned(),
        };
        let address = Nip05Address::parse("bob@example.com").unwrap();

        let pk = block_on(lookup_pubkey(&fetcher, &address)).unwrap();
        assert_eq!(pk, fixture_pubkey());

        let (pk2, relays) = block_on(lookup_with_relays(&fetcher, &address)).unwrap();
        assert_eq!(pk2, fixture_pubkey());
        assert_eq!(relays.len(), 2);

        let ok = block_on(verify_identifier(&fetcher, &address, &fixture_pubkey())).unwrap();
        assert!(ok);
    }
}
