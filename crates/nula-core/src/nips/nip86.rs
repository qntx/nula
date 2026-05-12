//! [NIP-86] Relay Management API.
//!
//! JSON-RPC-like protocol over HTTP for relay administration. The wire
//! envelope is:
//!
//! ```jsonc
//! { "method": "<method-name>", "params": ["<array>", "<of>", "<parameters>"] }
//! ```
//!
//! and responses are:
//!
//! ```jsonc
//! { "result": <arbitrary>, "error": "<optional error message>" }
//! ```
//!
//! This module exposes the typed [`Method`] enum (every method named
//! by the spec, plus a forward-compatible [`Method::Custom`]),
//! [`Request`] / [`Response`] structs that round-trip through the
//! wire JSON, and [`PubkeyEntry`] / [`EventEntry`] / [`IpEntry`]
//! result rows.
//!
//! Authorization MUST be provided via a NIP-98 HTTP-auth event with
//! the `payload` and `u` tags filled in; this module only models the
//! payload shape and leaves the HTTP transport to the caller.
//!
//! [NIP-86]: https://github.com/nostr-protocol/nips/blob/master/86.md

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::event::Kind;
use crate::key::{PublicKey, PublicKeyError};
use crate::types::{Url, UrlError};

/// HTTP `Content-Type` the spec requires.
pub const CONTENT_TYPE: &str = "application/nostr+json+rpc";

/// Wire envelope for a NIP-86 request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Request {
    /// Method token.
    pub method: String,
    /// Parameter array (mixed-type per spec).
    #[serde(default)]
    pub params: Vec<serde_json::Value>,
}

/// Wire envelope for a NIP-86 response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Response {
    /// Result payload (`null` on error).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// Optional error message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Response {
    /// True when [`Self::error`] is set.
    #[must_use]
    pub const fn is_error(&self) -> bool {
        self.error.is_some()
    }

    /// Construct a successful response.
    #[must_use]
    pub const fn ok(result: serde_json::Value) -> Self {
        Self {
            result: Some(result),
            error: None,
        }
    }

    /// Construct an error response.
    #[must_use]
    pub fn err(message: impl Into<String>) -> Self {
        Self {
            result: None,
            error: Some(message.into()),
        }
    }
}

/// Spec-listed methods plus a forward-compatible passthrough.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Method {
    /// `supportedmethods` — server enumerates supported tokens.
    SupportedMethods,
    /// `banpubkey` — ban a pubkey.
    BanPubkey,
    /// `unbanpubkey` — undo a ban.
    UnbanPubkey,
    /// `listbannedpubkeys`.
    ListBannedPubkeys,
    /// `allowpubkey` — allowlist a pubkey.
    AllowPubkey,
    /// `unallowpubkey` — undo an allow.
    UnallowPubkey,
    /// `listallowedpubkeys`.
    ListAllowedPubkeys,
    /// `listeventsneedingmoderation`.
    ListEventsNeedingModeration,
    /// `allowevent`.
    AllowEvent,
    /// `banevent`.
    BanEvent,
    /// `listbannedevents`.
    ListBannedEvents,
    /// `changerelayname`.
    ChangeRelayName,
    /// `changerelaydescription`.
    ChangeRelayDescription,
    /// `changerelayicon`.
    ChangeRelayIcon,
    /// `allowkind` — accept a `kind` integer.
    AllowKind,
    /// `disallowkind`.
    DisallowKind,
    /// `listallowedkinds`.
    ListAllowedKinds,
    /// `blockip`.
    BlockIp,
    /// `unblockip`.
    UnblockIp,
    /// `listblockedips`.
    ListBlockedIps,
    /// Forward-compatible passthrough for non-spec tokens.
    Custom(String),
}

impl Method {
    /// Wire token.
    #[must_use]
    #[expect(
        clippy::missing_const_for_fn,
        reason = "`Self::Custom` borrows from a heap `String`"
    )]
    pub fn as_str(&self) -> &str {
        match self {
            Self::SupportedMethods => "supportedmethods",
            Self::BanPubkey => "banpubkey",
            Self::UnbanPubkey => "unbanpubkey",
            Self::ListBannedPubkeys => "listbannedpubkeys",
            Self::AllowPubkey => "allowpubkey",
            Self::UnallowPubkey => "unallowpubkey",
            Self::ListAllowedPubkeys => "listallowedpubkeys",
            Self::ListEventsNeedingModeration => "listeventsneedingmoderation",
            Self::AllowEvent => "allowevent",
            Self::BanEvent => "banevent",
            Self::ListBannedEvents => "listbannedevents",
            Self::ChangeRelayName => "changerelayname",
            Self::ChangeRelayDescription => "changerelaydescription",
            Self::ChangeRelayIcon => "changerelayicon",
            Self::AllowKind => "allowkind",
            Self::DisallowKind => "disallowkind",
            Self::ListAllowedKinds => "listallowedkinds",
            Self::BlockIp => "blockip",
            Self::UnblockIp => "unblockip",
            Self::ListBlockedIps => "listblockedips",
            Self::Custom(s) => s.as_str(),
        }
    }

    /// Parse a wire token. Always succeeds.
    #[must_use]
    pub fn parse(token: &str) -> Self {
        match token {
            "supportedmethods" => Self::SupportedMethods,
            "banpubkey" => Self::BanPubkey,
            "unbanpubkey" => Self::UnbanPubkey,
            "listbannedpubkeys" => Self::ListBannedPubkeys,
            "allowpubkey" => Self::AllowPubkey,
            "unallowpubkey" => Self::UnallowPubkey,
            "listallowedpubkeys" => Self::ListAllowedPubkeys,
            "listeventsneedingmoderation" => Self::ListEventsNeedingModeration,
            "allowevent" => Self::AllowEvent,
            "banevent" => Self::BanEvent,
            "listbannedevents" => Self::ListBannedEvents,
            "changerelayname" => Self::ChangeRelayName,
            "changerelaydescription" => Self::ChangeRelayDescription,
            "changerelayicon" => Self::ChangeRelayIcon,
            "allowkind" => Self::AllowKind,
            "disallowkind" => Self::DisallowKind,
            "listallowedkinds" => Self::ListAllowedKinds,
            "blockip" => Self::BlockIp,
            "unblockip" => Self::UnblockIp,
            "listblockedips" => Self::ListBlockedIps,
            _ => Self::Custom(token.to_owned()),
        }
    }
}

/// `{"pubkey": "...", "reason": "..."}` row used by ban/allow lists.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PubkeyEntry {
    /// 32-byte hex pubkey.
    pub pubkey: String,
    /// Optional moderation reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `{"id": "...", "reason": "..."}` row used by event ban / moderation
/// queue lists.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventEntry {
    /// 32-byte hex event id.
    pub id: String,
    /// Optional moderation reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `{"ip": "...", "reason": "..."}` row used by IP block lists.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IpEntry {
    /// IP address (string form).
    pub ip: String,
    /// Optional moderation reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Errors raised while building NIP-86 requests / parsing responses.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ManagementError {
    /// Wrapped JSON serialisation error.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Wrapped pubkey parser error.
    #[error(transparent)]
    InvalidPublicKey(#[from] PublicKeyError),
    /// Wrapped URL parser error.
    #[error(transparent)]
    InvalidUrl(#[from] UrlError),
}

/// Build a request that takes a `(pubkey, optional reason)` pair.
#[must_use]
pub fn pubkey_request(method: &Method, pubkey: &PublicKey, reason: Option<&str>) -> Request {
    let mut params = vec![serde_json::Value::String(pubkey.to_hex())];
    if let Some(r) = reason {
        params.push(serde_json::Value::String(r.to_owned()));
    }
    Request {
        method: method.as_str().to_owned(),
        params,
    }
}

/// Build a request that takes an `(event-id-hex, optional reason)`
/// pair.
#[must_use]
pub fn event_request(method: &Method, event_id_hex: &str, reason: Option<&str>) -> Request {
    let mut params = vec![serde_json::Value::String(event_id_hex.to_owned())];
    if let Some(r) = reason {
        params.push(serde_json::Value::String(r.to_owned()));
    }
    Request {
        method: method.as_str().to_owned(),
        params,
    }
}

/// Build a request that takes a single `kind` integer (used by
/// `allowkind` / `disallowkind`).
#[must_use]
pub fn kind_request(method: &Method, kind: Kind) -> Request {
    Request {
        method: method.as_str().to_owned(),
        params: vec![serde_json::Value::Number(kind.as_u16().into())],
    }
}

/// Build a request that takes a single `(ip, optional reason)` pair.
#[must_use]
pub fn ip_request(method: &Method, ip: &str, reason: Option<&str>) -> Request {
    let mut params = vec![serde_json::Value::String(ip.to_owned())];
    if let Some(r) = reason {
        params.push(serde_json::Value::String(r.to_owned()));
    }
    Request {
        method: method.as_str().to_owned(),
        params,
    }
}

/// Build a request that takes a single string (used by
/// `changerelayname` / `description` / `icon`).
#[must_use]
pub fn string_request(method: &Method, value: impl Into<String>) -> Request {
    Request {
        method: method.as_str().to_owned(),
        params: vec![serde_json::Value::String(value.into())],
    }
}

/// Build a request that takes a single URL.
#[must_use]
pub fn url_request(method: &Method, url: &Url) -> Request {
    string_request(method, url.as_str())
}

/// Build a parameterless request (used by all `list*` methods).
#[must_use]
pub fn empty_request(method: &Method) -> Request {
    Request {
        method: method.as_str().to_owned(),
        params: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;

    fn keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    #[test]
    fn ban_pubkey_request_roundtrip() {
        let req = pubkey_request(&Method::BanPubkey, keys().public_key(), Some("spam"));
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("banpubkey"));
        assert!(json.contains("spam"));
        let parsed: Request = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.method, "banpubkey");
        assert_eq!(parsed.params.len(), 2);
    }

    #[test]
    fn response_serialisation() {
        let resp = Response::ok(serde_json::json!(true));
        let json = serde_json::to_string(&resp).unwrap();
        assert_eq!(json, r#"{"result":true}"#);
        let err = Response::err("forbidden");
        let json2 = serde_json::to_string(&err).unwrap();
        assert!(json2.contains("forbidden"));
    }

    #[test]
    fn method_round_trip_custom() {
        assert_eq!(
            Method::parse("nostr.relay.custom"),
            Method::Custom("nostr.relay.custom".to_owned())
        );
    }

    #[test]
    fn pubkey_entry_roundtrip() {
        let entry = PubkeyEntry {
            pubkey: keys().public_key().to_hex(),
            reason: Some("abuse".into()),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: PubkeyEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, entry);
    }

    #[test]
    fn empty_request_has_no_params() {
        let req = empty_request(&Method::SupportedMethods);
        assert!(req.params.is_empty());
    }
}
