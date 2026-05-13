//! [NIP-11] Relay Information Document.
//!
//! NIP-11 lets a relay describe itself by serving a JSON document over HTTPS
//! when the client sends `Accept: application/nostr+json`. Clients use the
//! document to discover supported NIPs, fee schedules, contact points, etc.
//!
//! Every field is optional and forward-compatible: the relay can drop or add
//! fields between releases without breaking older clients. The crate keeps
//! every documented field as a strongly typed [`Option`] / [`Vec`] and
//! tolerates unknown fields silently (`#[serde(default)]` plus the absence
//! of `deny_unknown_fields`).
//!
//! # Architecture
//!
//! The module is split into two layers, mirroring the NIP-05 design:
//!
//! - **Core** ([`RelayInformation`], [`Nip11Fetcher`], [`Nip11FetchError`]):
//!   side-effect-free data types plus an IO-bound trait. Always compiled,
//!   trivially mockable in tests.
//! - **Default fetcher** ([`ReqwestNip11Fetcher`]): a `reqwest`-backed
//!   implementation behind the `nip11-fetch` Cargo feature. Sends the
//!   spec-mandated `Accept: application/nostr+json` header.
//!
//! [NIP-11]: https://github.com/nostr-protocol/nips/blob/master/11.md

pub mod fees;
pub mod limitation;
pub mod retention;

use std::future::Future;
use std::pin::Pin;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use self::fees::{RelayFee, RelayFees};
pub use self::limitation::RelayLimitation;
pub use self::retention::{KindRange, RelayRetention};
use crate::key::PublicKey;
use crate::types::Url;

/// The complete NIP-11 document.
///
/// All fields are optional. `Default` returns an empty document — useful as
/// the starting point of a builder.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RelayInformation {
    /// Operator-chosen name for the relay.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Human-readable description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Operator's public key (typically used for moderation messages).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<PublicKey>,
    /// Relay's own public key (NIP-11 §Self).
    ///
    /// Distinct from [`Self::pubkey`]: NIP-11 allows a relay to maintain a
    /// machine identity independent from its administrator's pubkey, which
    /// it uses to publish events on its own behalf.
    #[serde(rename = "self", skip_serializing_if = "Option::is_none")]
    pub self_pubkey: Option<PublicKey>,
    /// Free-form contact string (email, Nostr profile, …).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact: Option<String>,
    /// NIP numbers the relay claims to support.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub supported_nips: Vec<u16>,
    /// URL of the relay's source code or product page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software: Option<Url>,
    /// Software version string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Link to the relay's terms-of-service document (NIP-11 §Terms of
    /// Service). Free text; typically a URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_of_service: Option<Url>,
    /// Visual representation of the relay (NIP-11 §Banner).
    ///
    /// Distinct from [`Self::icon`]: a banner is the wide visual used in
    /// relay descriptions and onboarding screens, while the icon is the
    /// compact representation used in relay-list rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<Url>,
    /// Optional icon URL (PNG/SVG).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<Url>,
    /// Server-side limitations on client behaviour.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limitation: Option<RelayLimitation>,
    /// Two-letter ISO country codes the relay primarily serves.
    ///
    /// Not part of NIP-11's normative spec; defined under §"Community
    /// Preferences" and emitted by relays such as `nostr.wine`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub relay_countries: Vec<String>,
    /// IETF BCP-47 language tags the operator suggests for the relay.
    ///
    /// Not part of NIP-11's normative spec; defined under §"Community
    /// Preferences" and used by community indexes to filter discovery.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub language_tags: Vec<String>,
    /// Free-form classification tags (`"spanish"`, `"music"`, …).
    ///
    /// Not part of NIP-11's normative spec; defined under §"Community
    /// Preferences" alongside `relay_countries` and `language_tags`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Posting policy URL (terms of use).
    ///
    /// Distinct from [`Self::terms_of_service`]: this is the *content*
    /// policy (what users may post). Defined alongside the community
    /// preferences block.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub posting_policy: Option<Url>,
    /// Web page where users can pay fees.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payments_url: Option<Url>,
    /// Fee schedule.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fees: Option<RelayFees>,
    /// Per-class retention rules.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub retention: Vec<RelayRetention>,
}

impl RelayInformation {
    /// Construct an empty document.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the relay advertises support for the given NIP number.
    #[must_use]
    pub fn supports_nip(&self, nip: u16) -> bool {
        self.supported_nips.contains(&nip)
    }
}

/// MIME type required by NIP-11 §"Discovering Relay Information": the
/// HTTP request MUST carry `Accept: application/nostr+json`, and a
/// compliant relay responds with the same `Content-Type`.
pub const NIP11_MEDIA_TYPE: &str = "application/nostr+json";

/// Errors raised by a [`Nip11Fetcher`] implementation.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Nip11FetchError {
    /// HTTP transport failure (network, TLS, DNS, …).
    ///
    /// We collapse the underlying error to a `String` so the trait stays
    /// free of any HTTP-client dependency on the core path; concrete
    /// fetchers stringify their backend error when bubbling it up.
    #[error("NIP-11 relay-info fetch failed: {0}")]
    Transport(String),
    /// Non-2xx response.
    #[error("NIP-11 relay-info fetch returned HTTP {0}")]
    Status(u16),
    /// Response body was not valid JSON or did not match the
    /// [`RelayInformation`] schema.
    #[error("NIP-11 relay-info JSON decode failed: {0}")]
    Decode(#[from] serde_json::Error),
}

/// Boxed `Future` returned by [`Nip11Fetcher::fetch`].
///
/// Using a heap-allocated future keeps the trait object-safe so callers
/// can hold an `Arc<dyn Nip11Fetcher>` across async tasks.
pub type FetchFuture<'a, T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'a>>;

/// IO trait for retrieving a NIP-11 relay-info document.
///
/// Implementations MUST:
///
/// - issue an HTTPS `GET` for the supplied relay URL,
/// - send `Accept: application/nostr+json` per NIP-11
///   §"Discovering Relay Information",
/// - return [`Nip11FetchError::Status`] for non-2xx responses,
/// - parse the response body as a [`RelayInformation`] JSON document
///   and surface decode failures as [`Nip11FetchError::Decode`].
///
/// The trait is [`Send`] + [`Sync`] so a single fetcher can be shared
/// across futures and threads.
pub trait Nip11Fetcher: Send + Sync {
    /// Fetch the relay-info document advertised by `url`.
    fn fetch<'a>(&'a self, url: &'a Url) -> FetchFuture<'a, RelayInformation, Nip11FetchError>;
}

#[cfg(feature = "nip11-fetch")]
#[cfg_attr(docsrs, doc(cfg(feature = "nip11-fetch")))]
pub use reqwest_impl::ReqwestNip11Fetcher;

#[cfg(feature = "nip11-fetch")]
mod reqwest_impl {
    use super::{
        FetchFuture, NIP11_MEDIA_TYPE, Nip11FetchError, Nip11Fetcher, RelayInformation, Url,
    };

    /// `reqwest`-backed [`Nip11Fetcher`].
    ///
    /// The internal client refuses to follow HTTP redirects: the relay
    /// URL is the relay's identifier in this protocol, so a 3xx
    /// pointing at a different host would silently change identity.
    /// Override via [`Self::from_client`] when you need a custom
    /// redirect policy and accept the security implications.
    #[derive(Debug, Clone)]
    pub struct ReqwestNip11Fetcher {
        client: reqwest::Client,
    }

    impl ReqwestNip11Fetcher {
        /// Build a new fetcher with a fresh internal client.
        ///
        /// # Errors
        ///
        /// Propagates the underlying [`reqwest::Error`] when the client
        /// cannot be initialised (typically a TLS backend init failure).
        pub fn new() -> Result<Self, reqwest::Error> {
            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?;
            Ok(Self { client })
        }

        /// Wrap an existing `reqwest::Client`.
        ///
        /// **Caller responsibility**: the supplied client should be
        /// configured with `redirect::Policy::none()` to keep the
        /// relay URL well-defined; pre-existing clients with permissive
        /// redirect policies silently weaken that guarantee.
        #[must_use]
        pub const fn from_client(client: reqwest::Client) -> Self {
            Self { client }
        }
    }

    async fn do_fetch(
        client: &reqwest::Client,
        url: &Url,
    ) -> Result<RelayInformation, Nip11FetchError> {
        let response = client
            .get(url.as_str())
            .header(reqwest::header::ACCEPT, NIP11_MEDIA_TYPE)
            .send()
            .await
            .map_err(|e| Nip11FetchError::Transport(e.to_string()))?;
        let status = response.status();
        if !status.is_success() {
            return Err(Nip11FetchError::Status(status.as_u16()));
        }
        let body = response
            .text()
            .await
            .map_err(|e| Nip11FetchError::Transport(e.to_string()))?;
        serde_json::from_str::<RelayInformation>(&body).map_err(Nip11FetchError::Decode)
    }

    impl Nip11Fetcher for ReqwestNip11Fetcher {
        fn fetch<'a>(&'a self, url: &'a Url) -> FetchFuture<'a, RelayInformation, Nip11FetchError> {
            Box::pin(do_fetch(&self.client, url))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;

    fn fixture_pubkey() -> PublicKey {
        let keys = Keys::parse("0000000000000000000000000000000000000000000000000000000000000003")
            .unwrap();
        *keys.public_key()
    }

    #[test]
    fn empty_serializes_to_empty_object() {
        let json = serde_json::to_string(&RelayInformation::default()).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn round_trip_full_document() {
        let info = RelayInformation {
            name: Some("Nula Relay".to_owned()),
            description: Some("A reliable Nostr relay.".to_owned()),
            pubkey: Some(fixture_pubkey()),
            self_pubkey: Some(fixture_pubkey()),
            contact: Some("ops@nula.example".to_owned()),
            supported_nips: vec![1, 9, 11, 19, 42],
            software: Some(Url::parse("https://github.com/qntx/nula").unwrap()),
            version: Some("0.1.0".to_owned()),
            terms_of_service: Some(Url::parse("https://nula.example/tos").unwrap()),
            banner: Some(Url::parse("https://nula.example/banner.png").unwrap()),
            icon: Some(Url::parse("https://nula.example/icon.png").unwrap()),
            limitation: Some(RelayLimitation {
                max_message_length: Some(16_384),
                max_subscriptions: Some(20),
                auth_required: Some(true),
                ..RelayLimitation::default()
            }),
            relay_countries: vec!["US".into(), "JP".into()],
            language_tags: vec!["en".into(), "ja".into()],
            tags: vec!["general".into()],
            posting_policy: Some(Url::parse("https://nula.example/policy").unwrap()),
            payments_url: Some(Url::parse("https://nula.example/billing").unwrap()),
            fees: Some(RelayFees {
                admission: vec![RelayFee {
                    amount: 1000,
                    unit: "msats".into(),
                    period: None,
                    kinds: None,
                }],
                ..RelayFees::default()
            }),
            retention: vec![RelayRetention {
                kinds: vec![KindRange::Single(crate::Kind::from(0_u16))],
                time: Some(3600),
                count: None,
            }],
        };
        let json = serde_json::to_string(&info).unwrap();
        // Wire-form sanity check: spec field names are emitted verbatim.
        assert!(json.contains(r#""banner":"https://nula.example/banner.png""#));
        assert!(json.contains(r#""self":""#));
        let parsed: RelayInformation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, info);
    }

    #[test]
    fn self_field_round_trips_independently_from_pubkey() {
        // NIP-11 §Self: the relay machine pubkey may be set without the
        // administrator pubkey and vice versa.
        let info = RelayInformation {
            self_pubkey: Some(fixture_pubkey()),
            ..RelayInformation::default()
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains(r#""self":""#));
        assert!(!json.contains(r#""pubkey""#));
        let parsed: RelayInformation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, info);
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let json = r#"{
            "name": "Future",
            "future_field": 42,
            "supported_nips": [1, 99]
        }"#;
        let info: RelayInformation = serde_json::from_str(json).unwrap();
        assert_eq!(info.name.as_deref(), Some("Future"));
        assert!(info.supports_nip(99));
        assert!(!info.supports_nip(7));
    }

    /// In-memory [`Nip11Fetcher`] that returns a canned body — used by
    /// downstream crates wiring relay-info into pool / gossip logic
    /// without spinning up an HTTP server. Mirrors the `MockFetcher`
    /// fixture in `nip05`.
    #[derive(Debug, Clone)]
    struct MockNip11Fetcher {
        body: String,
    }

    impl Nip11Fetcher for MockNip11Fetcher {
        fn fetch<'a>(
            &'a self,
            _url: &'a Url,
        ) -> FetchFuture<'a, RelayInformation, Nip11FetchError> {
            let body = self.body.clone();
            Box::pin(async move {
                serde_json::from_str::<RelayInformation>(&body).map_err(Nip11FetchError::Decode)
            })
        }
    }

    /// Minimal blocking runtime for synchronous test futures. The
    /// fetcher futures here are pure compute (no IO wakers), so a
    /// busy-poll over [`Waker::noop`] is correct and avoids pulling in
    /// `futures-executor` or `tokio` as a dev-dep.
    fn block_on<F: Future>(future: F) -> F::Output {
        use std::task::{Context, Poll, Waker};
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut future = Box::pin(future);
        loop {
            if let Poll::Ready(v) = future.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    #[test]
    fn mock_fetcher_round_trips_relay_information() {
        let fetcher = MockNip11Fetcher {
            body: r#"{
                "name": "Mock Relay",
                "supported_nips": [1, 11, 42],
                "limitation": {"max_message_length": 8192, "auth_required": false}
            }"#
            .to_owned(),
        };
        let url = Url::parse("https://relay.example/").unwrap();
        let info = block_on(fetcher.fetch(&url)).unwrap();
        assert_eq!(info.name.as_deref(), Some("Mock Relay"));
        assert!(info.supports_nip(11));
        assert_eq!(
            info.limitation.as_ref().and_then(|l| l.max_message_length),
            Some(8192),
        );
    }

    #[test]
    fn mock_fetcher_surfaces_decode_error_on_invalid_json() {
        let fetcher = MockNip11Fetcher {
            body: "not json".to_owned(),
        };
        let url = Url::parse("https://relay.example/").unwrap();
        let err = block_on(fetcher.fetch(&url)).unwrap_err();
        assert!(matches!(err, Nip11FetchError::Decode(_)));
    }
}
