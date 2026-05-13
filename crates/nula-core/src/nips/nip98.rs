//! [NIP-98] HTTP Auth.
//!
//! `kind: 27235` is an *ephemeral* event used as an
//! `Authorization: Nostr <base64>` token for HTTP requests served
//! by Nostr-aware backends. The body is empty (`.content == ""`)
//! and the request shape lives entirely in two MUST-tags:
//!
//! - `["u", "<absolute URL>"]` — the exact request target,
//!   including query string;
//! - `["method", "<HTTP method>"]` — the verb of the request being
//!   authorised.
//!
//! When the request carries a body, NIP-98 §"Nostr event" tells
//! clients to add `["payload", "<sha256-hex>"]` and servers MAY
//! cross-check it before accepting the request.
//!
//! # Why a typed module
//!
//! Upstream `rust-nostr` ships only a thin `EventBuilder::http_auth`
//! that takes a [`Url`] and a method string. We model the whole
//! flow:
//!
//! - [`HttpMethod`] — strongly-typed enum with `Other(String)` for
//!   forward compatibility;
//! - [`HttpAuthRequest`] — typed bundle that round-trips through
//!   [`HttpAuthRequest::to_tags`] / [`HttpAuthRequest::from_event`];
//! - [`HttpAuthRequest::validate`] — the four-step server-side
//!   validation NIP-98 §"validate" mandates (kind, timestamp
//!   skew, exact URL match, exact method match) plus the optional
//!   `payload` body-hash cross-check;
//! - [`authorization_header`] / [`parse_authorization_header`] —
//!   the `Nostr <base64>` HTTP `Authorization` header
//!   encoder/decoder that the spec describes but no upstream
//!   crate ships.
//!
//! [NIP-98]: https://github.com/nostr-protocol/nips/blob/master/98.md

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::event::{Event, EventBuilder, EventError, Kind, Tag, TagKind, Tags};
use crate::types::{Timestamp, Url, UrlError};
use crate::util::JsonUtil;
use crate::util::hex::{self, HexError};

/// `kind: 27235` — NIP-98 HTTP authorization event.
pub const KIND_HTTP_AUTH: Kind = Kind::new(27_235);

/// `u` tag wire head.
pub const URL_TAG: &str = "u";
/// `method` tag wire head.
pub const METHOD_TAG: &str = "method";
/// `payload` tag wire head.
pub const PAYLOAD_TAG: &str = "payload";

/// Default acceptance window for [`HttpAuthRequest::validate`] —
/// **60 seconds** per NIP-98 §"validate" suggestion.
pub const DEFAULT_TIMESTAMP_SKEW_SECS: u64 = 60;

/// HTTP request method, with [`Self::Other`] preserving any verb the
/// IANA registry adds in the future (or any per-app extension).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HttpMethod {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
    /// `PUT`.
    Put,
    /// `PATCH`.
    Patch,
    /// `DELETE`.
    Delete,
    /// `HEAD`.
    Head,
    /// `OPTIONS`.
    Options,
    /// `CONNECT`.
    Connect,
    /// `TRACE`.
    Trace,
    /// Forward-compatible passthrough. `Other(String)` always
    /// stores the **uppercase** verb so two equal verbs compare
    /// equal regardless of the wire casing.
    Other(String),
}

impl HttpMethod {
    /// Render to wire form. RFC 9110 §9 uses uppercase verbs;
    /// callers that must follow another convention can post-process
    /// the returned string.
    #[must_use]
    pub const fn as_str(&self) -> &str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
            Self::Connect => "CONNECT",
            Self::Trace => "TRACE",
            Self::Other(s) => s.as_str(),
        }
    }

    /// Parse a wire token. Always succeeds: unknown verbs become
    /// `Other(uppercased)` for forward compatibility.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        let upper = s.trim().to_ascii_uppercase();
        match upper.as_str() {
            "GET" => Self::Get,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "PATCH" => Self::Patch,
            "DELETE" => Self::Delete,
            "HEAD" => Self::Head,
            "OPTIONS" => Self::Options,
            "CONNECT" => Self::Connect,
            "TRACE" => Self::Trace,
            _ => Self::Other(upper),
        }
    }
}

impl core::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Typed bundle for a `kind: 27235` HTTP-auth event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpAuthRequest {
    /// Absolute request URL (the `u` tag).
    pub url: Url,
    /// HTTP method (the `method` tag).
    pub method: HttpMethod,
    /// Optional SHA-256 over the request body (the `payload` tag).
    /// `None` matches a body-less request.
    pub payload_hash: Option<[u8; 32]>,
}

impl HttpAuthRequest {
    /// Construct a body-less request bundle.
    #[must_use]
    pub const fn new(url: Url, method: HttpMethod) -> Self {
        Self {
            url,
            method,
            payload_hash: None,
        }
    }

    /// Attach a SHA-256 hash of the request body.
    #[must_use]
    pub const fn payload_hash(mut self, hash: [u8; 32]) -> Self {
        self.payload_hash = Some(hash);
        self
    }

    /// Convenience: hash `body` with SHA-256 and attach the digest.
    ///
    /// Use this when the caller already has the body bytes in hand.
    #[must_use]
    pub fn payload(self, body: &[u8]) -> Self {
        self.payload_hash(sha256_hash(body))
    }

    /// Render to the tag list of a `kind: 27235` event.
    #[must_use]
    pub fn to_tags(&self) -> Vec<Tag> {
        let mut tags: Vec<Tag> = Vec::with_capacity(3);
        tags.push(custom_tag(URL_TAG, [self.url.as_str().to_owned()]));
        tags.push(custom_tag(METHOD_TAG, [self.method.as_str().to_owned()]));
        if let Some(hash) = self.payload_hash {
            tags.push(custom_tag(PAYLOAD_TAG, [hex::encode(hash)]));
        }
        tags
    }

    /// Parse a `kind: 27235` event back into a typed bundle.
    ///
    /// # Errors
    ///
    /// - [`HttpAuthError::WrongKind`] for any other kind.
    /// - [`HttpAuthError::MissingUrl`] / `MissingMethod` when a
    ///   required tag is absent.
    /// - [`HttpAuthError::InvalidUrl`] / `InvalidPayloadHash` when
    ///   a tag value is malformed.
    pub fn from_event(event: &Event) -> Result<Self, HttpAuthError> {
        if event.kind != KIND_HTTP_AUTH {
            return Err(HttpAuthError::WrongKind(event.kind));
        }
        Self::from_tags(&event.tags)
    }

    /// Parse from a tag list (without enforcing the wrapping kind).
    ///
    /// # Errors
    ///
    /// See [`Self::from_event`].
    pub fn from_tags(tags: &Tags) -> Result<Self, HttpAuthError> {
        let url_str = custom_value(tags, URL_TAG).ok_or(HttpAuthError::MissingUrl)?;
        let url = Url::parse(url_str).map_err(HttpAuthError::InvalidUrl)?;
        let method_str = custom_value(tags, METHOD_TAG).ok_or(HttpAuthError::MissingMethod)?;
        let method = HttpMethod::parse(method_str);

        let payload_hash = if let Some(hex_str) = custom_value(tags, PAYLOAD_TAG) {
            Some(parse_sha256_hex(hex_str)?)
        } else {
            None
        };
        Ok(Self {
            url,
            method,
            payload_hash,
        })
    }

    /// Server-side validation per NIP-98 §"Servers MUST perform the
    /// following checks":
    ///
    /// 1. Event kind is `27235` (already enforced when the bundle
    ///    came from [`Self::from_event`]).
    /// 2. `created_at` is within `±skew` of `now`. Default skew is
    ///    [`DEFAULT_TIMESTAMP_SKEW_SECS`].
    /// 3. The bundle's [`Self::url`] equals `request_url`
    ///    byte-for-byte.
    /// 4. The bundle's [`Self::method`] equals `request_method`.
    ///
    /// When `body` is `Some`, the SHA-256 over those bytes must
    /// equal the bundle's [`Self::payload_hash`].
    ///
    /// A `body == None` + `payload_hash == Some(_)` mismatch fails
    /// validation; a `body == Some` + `payload_hash == None` is
    /// *allowed* (spec uses "SHOULD include", not "MUST"), but
    /// most servers will want to reject it themselves with a
    /// higher-level rule.
    ///
    /// # Errors
    ///
    /// One of the variants of [`HttpAuthError`] tagged with
    /// `Validation*`.
    pub fn validate(
        &self,
        signed_at: Timestamp,
        now: Timestamp,
        skew_secs: u64,
        request_url: &Url,
        request_method: &HttpMethod,
        body: Option<&[u8]>,
    ) -> Result<(), HttpAuthError> {
        let signed = signed_at.as_secs();
        let current = now.as_secs();
        let delta = signed.abs_diff(current);
        if delta > skew_secs {
            return Err(HttpAuthError::ValidationTimestampSkew {
                delta_secs: delta,
                allowed_secs: skew_secs,
            });
        }
        if self.url != *request_url {
            return Err(HttpAuthError::ValidationUrlMismatch {
                expected: request_url.as_str().to_owned(),
                got: self.url.as_str().to_owned(),
            });
        }
        if self.method != *request_method {
            return Err(HttpAuthError::ValidationMethodMismatch {
                expected: request_method.to_string(),
                got: self.method.to_string(),
            });
        }
        if let Some(body_bytes) = body
            && let Some(expected_hash) = self.payload_hash
        {
            let actual_hash = sha256_hash(body_bytes);
            if actual_hash != expected_hash {
                return Err(HttpAuthError::ValidationPayloadMismatch);
            }
        }
        Ok(())
    }
}

fn parse_sha256_hex(input: &str) -> Result<[u8; 32], HttpAuthError> {
    if input.len() != 64 {
        return Err(HttpAuthError::InvalidPayloadHashLength(input.len()));
    }
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(input, &mut bytes).map_err(HttpAuthError::InvalidPayloadHash)?;
    Ok(bytes)
}

fn sha256_hash(body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(body);
    hasher.finalize().into()
}

fn custom_tag<I, S>(name: &str, args: I) -> Tag
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    Tag::with(&TagKind::from_wire(name), args)
}

fn custom_value<'a>(tags: &'a Tags, name: &str) -> Option<&'a str> {
    tags.iter()
        .find(|tag| tag.name() == name)
        .and_then(|tag| tag.get(1))
}

/// Errors raised while building, parsing, or validating an HTTP-auth
/// event.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HttpAuthError {
    /// The wrapping event was not `kind: 27235`.
    #[error("expected kind 27235 (HTTP auth), got kind {}", .0.as_u16())]
    WrongKind(Kind),
    /// `u` tag was absent.
    #[error("NIP-98 event must carry a `u` tag")]
    MissingUrl,
    /// `method` tag was absent.
    #[error("NIP-98 event must carry a `method` tag")]
    MissingMethod,
    /// `u` tag value did not parse.
    #[error("invalid URL: {0}")]
    InvalidUrl(#[source] UrlError),
    /// `payload` hex was the wrong length.
    #[error("`payload` hash must be 64 hex chars, got {0}")]
    InvalidPayloadHashLength(usize),
    /// `payload` hex did not decode.
    #[error("invalid `payload` hash: {0}")]
    InvalidPayloadHash(#[source] HexError),
    /// `Authorization` header did not start with `Nostr `.
    #[error("`Authorization` header must use the `Nostr` scheme")]
    HeaderWrongScheme,
    /// `Authorization` header body was not parseable base64.
    #[error("`Authorization` body is not valid base64: {0}")]
    HeaderInvalidBase64(#[source] base64::DecodeError),
    /// `Authorization` body decoded to non-UTF-8.
    #[error("`Authorization` body is not UTF-8: {0}")]
    HeaderInvalidUtf8(#[source] core::str::Utf8Error),
    /// `Authorization` body did not deserialise as a Nostr event.
    #[error("`Authorization` body is not a valid Nostr event: {0}")]
    HeaderInvalidEvent(#[source] EventError),
    /// `Authorization` body JSON was malformed.
    #[error("`Authorization` body is not valid JSON: {0}")]
    HeaderInvalidJson(#[source] serde_json::Error),
    /// `created_at` skew exceeded `skew_secs`.
    #[error("`created_at` is {delta_secs}s away from `now`; max allowed is {allowed_secs}s")]
    ValidationTimestampSkew {
        /// Observed `|signed_at - now|` in seconds.
        delta_secs: u64,
        /// Configured limit in seconds.
        allowed_secs: u64,
    },
    /// `u` tag did not match the request URL.
    #[error("`u` mismatch: expected `{expected}`, got `{got}`")]
    ValidationUrlMismatch {
        /// URL the server saw on the wire.
        expected: String,
        /// URL the bundle attests to.
        got: String,
    },
    /// `method` tag did not match the request method.
    #[error("`method` mismatch: expected `{expected}`, got `{got}`")]
    ValidationMethodMismatch {
        /// HTTP method the server saw.
        expected: String,
        /// HTTP method the bundle attests to.
        got: String,
    },
    /// SHA-256 of the request body did not match `payload`.
    #[error("`payload` SHA-256 does not match the request body")]
    ValidationPayloadMismatch,
}

impl EventBuilder {
    /// Author a NIP-98 HTTP-auth event from a typed bundle.
    #[must_use]
    pub fn http_auth(request: &HttpAuthRequest) -> Self {
        let mut builder = Self::new(KIND_HTTP_AUTH, "");
        for tag in request.to_tags() {
            builder = builder.tag(tag);
        }
        builder
    }
}

/// HTTP authentication scheme prefix.
pub const AUTH_SCHEME_PREFIX: &str = "Nostr ";

/// Encode `event` (a signed `kind: 27235` event) as the body of an
/// `Authorization: Nostr <base64>` HTTP header.
///
/// # Errors
///
/// Forwarded from [`JsonUtil::try_to_json`] (effectively unreachable
/// for spec-conforming inputs but propagated for completeness).
pub fn authorization_header(event: &Event) -> Result<String, HttpAuthError> {
    let json = event
        .try_to_json()
        .map_err(HttpAuthError::HeaderInvalidJson)?;
    Ok(format!("{AUTH_SCHEME_PREFIX}{}", BASE64.encode(json)))
}

/// Decode an `Authorization: Nostr <base64>` header into the
/// underlying [`Event`].
///
/// The caller is responsible for re-running [`Event::verify`] and
/// [`HttpAuthRequest::validate`].
///
/// # Errors
///
/// - [`HttpAuthError::HeaderWrongScheme`] when the header does not
///   start with `Nostr ` (case-sensitive per NIP-98 §"Request
///   Flow").
/// - [`HttpAuthError::HeaderInvalidBase64`] when the body is not
///   valid base64.
/// - [`HttpAuthError::HeaderInvalidUtf8`] when the decoded bytes
///   are not UTF-8.
/// - [`HttpAuthError::HeaderInvalidJson`] when the JSON does not
///   deserialise.
pub fn parse_authorization_header(header: &str) -> Result<Event, HttpAuthError> {
    let body = header
        .strip_prefix(AUTH_SCHEME_PREFIX)
        .ok_or(HttpAuthError::HeaderWrongScheme)?;
    let bytes = BASE64
        .decode(body.trim())
        .map_err(HttpAuthError::HeaderInvalidBase64)?;
    let json = core::str::from_utf8(&bytes).map_err(HttpAuthError::HeaderInvalidUtf8)?;
    let event = Event::from_json(json).map_err(HttpAuthError::HeaderInvalidJson)?;
    Ok(event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;

    fn keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    fn fixture_url() -> Url {
        Url::parse("https://api.example.com/api/v1/n5sp/list").unwrap()
    }

    #[test]
    fn round_trip_through_event_for_get_request() {
        let req = HttpAuthRequest::new(fixture_url(), HttpMethod::Get);
        let event = EventBuilder::http_auth(&req)
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, KIND_HTTP_AUTH);
        assert_eq!(event.content, "");
        let parsed = HttpAuthRequest::from_event(&event).unwrap();
        assert_eq!(parsed, req);
    }

    #[test]
    fn round_trip_includes_payload_hash_for_post() {
        let body = b"{\"hello\":\"world\"}";
        let req = HttpAuthRequest::new(fixture_url(), HttpMethod::Post).payload(body);
        let event = EventBuilder::http_auth(&req)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = HttpAuthRequest::from_event(&event).unwrap();
        assert_eq!(parsed, req);
        let expected = sha256_hash(body);
        assert_eq!(parsed.payload_hash, Some(expected));
    }

    #[test]
    fn missing_url_is_rejected_when_parsing() {
        let event = EventBuilder::new(KIND_HTTP_AUTH, "")
            .tag(custom_tag(METHOD_TAG, ["GET"]))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            HttpAuthRequest::from_event(&event),
            Err(HttpAuthError::MissingUrl)
        ));
    }

    #[test]
    fn missing_method_is_rejected_when_parsing() {
        let event = EventBuilder::new(KIND_HTTP_AUTH, "")
            .tag(custom_tag(URL_TAG, [fixture_url().as_str()]))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            HttpAuthRequest::from_event(&event),
            Err(HttpAuthError::MissingMethod)
        ));
    }

    #[test]
    fn unknown_method_round_trips_as_other() {
        let m = HttpMethod::parse("MOVE");
        assert_eq!(m, HttpMethod::Other("MOVE".to_owned()));
        assert_eq!(m.as_str(), "MOVE");
    }

    #[test]
    fn lowercase_method_is_normalised() {
        let m = HttpMethod::parse("get");
        assert_eq!(m, HttpMethod::Get);
    }

    #[test]
    fn validate_passes_for_correct_request() {
        let req = HttpAuthRequest::new(fixture_url(), HttpMethod::Get);
        let signed_at = Timestamp::from_secs(1_700_000_000);
        let now = Timestamp::from_secs(1_700_000_010); // 10s later, within window
        req.validate(
            signed_at,
            now,
            DEFAULT_TIMESTAMP_SKEW_SECS,
            &fixture_url(),
            &HttpMethod::Get,
            None,
        )
        .unwrap();
    }

    #[test]
    fn validate_rejects_timestamp_skew() {
        let req = HttpAuthRequest::new(fixture_url(), HttpMethod::Get);
        let err = req
            .validate(
                Timestamp::from_secs(1_700_000_000),
                Timestamp::from_secs(1_700_000_120), // 2 minutes later, > 60s
                DEFAULT_TIMESTAMP_SKEW_SECS,
                &fixture_url(),
                &HttpMethod::Get,
                None,
            )
            .unwrap_err();
        assert!(matches!(err, HttpAuthError::ValidationTimestampSkew { .. }));
    }

    #[test]
    fn validate_rejects_url_mismatch() {
        let req = HttpAuthRequest::new(fixture_url(), HttpMethod::Get);
        let err = req
            .validate(
                Timestamp::from_secs(0),
                Timestamp::from_secs(0),
                DEFAULT_TIMESTAMP_SKEW_SECS,
                &Url::parse("https://other.example/foo").unwrap(),
                &HttpMethod::Get,
                None,
            )
            .unwrap_err();
        assert!(matches!(err, HttpAuthError::ValidationUrlMismatch { .. }));
    }

    #[test]
    fn validate_rejects_method_mismatch() {
        let req = HttpAuthRequest::new(fixture_url(), HttpMethod::Get);
        let err = req
            .validate(
                Timestamp::from_secs(0),
                Timestamp::from_secs(0),
                DEFAULT_TIMESTAMP_SKEW_SECS,
                &fixture_url(),
                &HttpMethod::Post,
                None,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            HttpAuthError::ValidationMethodMismatch { .. }
        ));
    }

    #[test]
    fn validate_rejects_payload_mismatch() {
        let req = HttpAuthRequest::new(fixture_url(), HttpMethod::Post).payload(b"original");
        let err = req
            .validate(
                Timestamp::from_secs(0),
                Timestamp::from_secs(0),
                DEFAULT_TIMESTAMP_SKEW_SECS,
                &fixture_url(),
                &HttpMethod::Post,
                Some(b"tampered"),
            )
            .unwrap_err();
        assert!(matches!(err, HttpAuthError::ValidationPayloadMismatch));
    }

    #[test]
    fn authorization_header_round_trips() {
        let req = HttpAuthRequest::new(fixture_url(), HttpMethod::Get);
        let event = EventBuilder::http_auth(&req)
            .sign_with_keys(&keys())
            .unwrap();
        let header = authorization_header(&event).unwrap();
        assert!(header.starts_with("Nostr "));
        let parsed = parse_authorization_header(&header).unwrap();
        assert_eq!(parsed.id, event.id);
    }

    #[test]
    fn parse_authorization_rejects_wrong_scheme() {
        let err = parse_authorization_header("Bearer xxx").unwrap_err();
        assert!(matches!(err, HttpAuthError::HeaderWrongScheme));
    }

    #[test]
    fn parse_authorization_rejects_bad_base64() {
        let err = parse_authorization_header("Nostr !!!!!").unwrap_err();
        assert!(matches!(err, HttpAuthError::HeaderInvalidBase64(_)));
    }

    #[test]
    fn malformed_payload_hash_surfaces_typed_error() {
        let event = EventBuilder::new(KIND_HTTP_AUTH, "")
            .tag(custom_tag(URL_TAG, [fixture_url().as_str()]))
            .tag(custom_tag(METHOD_TAG, ["POST"]))
            .tag(custom_tag(PAYLOAD_TAG, ["not-hex"]))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            HttpAuthRequest::from_event(&event),
            Err(HttpAuthError::InvalidPayloadHashLength(_))
        ));
    }

    #[test]
    fn wrong_kind_is_rejected_when_parsing() {
        let event = EventBuilder::text_note("nope")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            HttpAuthRequest::from_event(&event),
            Err(HttpAuthError::WrongKind(_))
        ));
    }
}
