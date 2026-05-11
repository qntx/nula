//! [NIP-47] Nostr Wallet Connect (NWC).
//!
//! NWC stitches a Nostr **client** to a remote Lightning **wallet
//! service** through end-to-end-encrypted direct messages over a
//! relay. Five event kinds carry the protocol:
//!
//! | Kind   | Direction              | Purpose                                     |
//! |--------|------------------------|---------------------------------------------|
//! | 13194  | wallet → relay (replaceable) | Capability advert ([`InfoEvent`])        |
//! | 23194  | client → wallet         | Request envelope ([`Request`])              |
//! | 23195  | wallet → client         | Response envelope ([`Response`])            |
//! | 23197  | wallet → client         | NIP-44 notification ([`Notification`])      |
//! | 23196  | wallet → client         | Legacy NIP-04 notification (deprecated)     |
//!
//! The client gets a connection URI shaped
//! `nostr+walletconnect://<wallet_pubkey>?relay=…&secret=…&lud16=…`
//! ([`ConnectionUri`]) — one URI per (client, wallet) pair, with the
//! `secret` acting as the client-side signing key for that
//! conversation. Body content is encrypted with NIP-44 v2 by
//! default and falls back to NIP-04 only for legacy peers
//! ([`Encryption`]).
//!
//! # What this module ships
//!
//! - [`ConnectionUri`] — a strict URI parser/encoder backed by the
//!   `url` crate's query-string utility. The wallet pubkey, relay
//!   list, secret, and optional `lud16` round-trip cleanly.
//! - [`InfoEvent`] — typed reader / builder for the `kind: 13194`
//!   capability advert (`content` is the space-separated method
//!   list, `notifications` and `encryption` tags carry the
//!   capability sets).
//! - [`Encryption::negotiate`] — the §"Encryption" handshake:
//!   absent tag → NIP-04, prefer NIP-44 v2 when both sides support
//!   it.
//! - [`Request`] / [`Response`] / [`Notification`] — JSON-RPCish
//!   payload structs (`method` / `result_type` /
//!   `notification_type`, `params`, `result`, `error`) with
//!   `serde_json::Value` payloads so every method spec'd today
//!   (and any added tomorrow) round-trips without a per-method
//!   patch.
//! - [`ErrorCode`] — every spec'd error code as a typed variant
//!   plus `Other(String)` for forward compatibility.
//! - [`EventBuilder::nwc_*`] / [`decrypt_request`] /
//!   [`decrypt_response`] / [`decrypt_notification`] — the
//!   end-to-end happy path: build a signed encrypted event, parse
//!   one back, all behind the `nip44` feature gate so the build
//!   stays fast for callers who don't need NWC at all.
//!
//! What the module **does not** do (yet): per-method typed
//! payloads (`PayInvoice`, `MakeInvoice`, …). Those are pure
//! `serde_json` structs and can be layered on top without touching
//! the envelope code.
//!
//! [NIP-47]: https://github.com/nostr-protocol/nips/blob/master/47.md

use core::fmt;
use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::form_urlencoded;

use crate::event::{Alphabet, Event, EventBuilder, Kind, SingleLetterTag, Tag, TagKind};
use crate::key::{PublicKey, PublicKeyError, SecretKey, SecretKeyError};
use crate::types::{RelayUrl, RelayUrlError, Timestamp};

#[cfg(feature = "nip04")]
use crate::nips::nip04;
#[cfg(feature = "nip44")]
use crate::nips::nip44;

/// `kind: 13194` — info event.
pub const KIND_INFO: Kind = Kind::WALLET_CONNECT_INFO;
/// `kind: 23194` — request.
pub const KIND_REQUEST: Kind = Kind::WALLET_CONNECT_REQUEST;
/// `kind: 23195` — response.
pub const KIND_RESPONSE: Kind = Kind::WALLET_CONNECT_RESPONSE;
/// `kind: 23197` — NIP-44 notification.
pub const KIND_NOTIFICATION: Kind = Kind::WALLET_CONNECT_NOTIFICATION;
/// `kind: 23196` — legacy NIP-04 notification.
pub const KIND_NOTIFICATION_LEGACY: Kind = Kind::WALLET_CONNECT_NOTIFICATION_LEGACY;

/// URI scheme prefix used by `ConnectionUri`.
pub const URI_SCHEME: &str = "nostr+walletconnect://";
/// `encryption` tag head.
pub const ENCRYPTION_TAG: &str = "encryption";
/// `notifications` tag head.
pub const NOTIFICATIONS_TAG: &str = "notifications";

/// NIP-47 §"Encryption" — wire token of an encryption scheme.
pub mod encryption_tokens {
    /// `nip44_v2`.
    pub const NIP44_V2: &str = "nip44_v2";
    /// `nip04`.
    pub const NIP04: &str = "nip04";
}

/// Encryption scheme negotiated for a given conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Encryption {
    /// NIP-44 v2 — required by spec.
    Nip44V2,
    /// NIP-04 — deprecated; only used when the wallet's `info`
    /// event omits the `encryption` tag entirely or explicitly
    /// advertises `nip04`.
    Nip04,
}

impl Encryption {
    /// Wire token used in the `encryption` tag.
    #[must_use]
    pub const fn as_token(self) -> &'static str {
        match self {
            Self::Nip44V2 => encryption_tokens::NIP44_V2,
            Self::Nip04 => encryption_tokens::NIP04,
        }
    }

    /// Parse a wire token.
    ///
    /// # Errors
    ///
    /// [`NwcError::UnknownEncryption`] for any other value.
    pub fn parse(token: &str) -> Result<Self, NwcError> {
        match token {
            encryption_tokens::NIP44_V2 => Ok(Self::Nip44V2),
            encryption_tokens::NIP04 => Ok(Self::Nip04),
            other => Err(NwcError::UnknownEncryption(other.to_owned())),
        }
    }

    /// NIP-47 §"Encryption" negotiation:
    ///
    /// - If `wallet_supported` is empty (i.e. the wallet's info
    ///   event omitted the `encryption` tag), fall back to NIP-04.
    /// - Otherwise, prefer NIP-44 v2 when both sides accept it,
    ///   else use NIP-04 if both accept it, else return
    ///   [`NwcError::EncryptionNotNegotiable`].
    ///
    /// # Errors
    ///
    /// See above.
    pub fn negotiate(
        wallet_supported: &[Self],
        client_supported: &[Self],
    ) -> Result<Self, NwcError> {
        if wallet_supported.is_empty() {
            return Ok(Self::Nip04);
        }
        let wallet: HashSet<Self> = wallet_supported.iter().copied().collect();
        let client: HashSet<Self> = client_supported.iter().copied().collect();
        if wallet.contains(&Self::Nip44V2) && client.contains(&Self::Nip44V2) {
            Ok(Self::Nip44V2)
        } else if wallet.contains(&Self::Nip04) && client.contains(&Self::Nip04) {
            Ok(Self::Nip04)
        } else {
            Err(NwcError::EncryptionNotNegotiable)
        }
    }
}

impl fmt::Display for Encryption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_token())
    }
}

/// Parsed `nostr+walletconnect://…` URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionUri {
    /// Wallet service public key (host part of the URI).
    pub wallet_pubkey: PublicKey,
    /// One or more `relay` query parameters.
    pub relays: Vec<RelayUrl>,
    /// `secret` query parameter — the *client*'s 32-byte signing
    /// key for this conversation.
    pub secret: SecretKey,
    /// Optional `lud16` lightning address.
    pub lud16: Option<String>,
}

impl ConnectionUri {
    /// Parse a `nostr+walletconnect://…` URI.
    ///
    /// # Errors
    ///
    /// - [`NwcError::UriBadScheme`] if the prefix is wrong.
    /// - [`NwcError::UriMissingPubkey`] when the host portion is
    ///   absent.
    /// - [`NwcError::UriMissingRelay`] when no `relay` parameter
    ///   was supplied (spec marks it as required).
    /// - [`NwcError::UriMissingSecret`] when no `secret` parameter
    ///   was supplied.
    /// - Forwarded parse errors for individual fields.
    pub fn parse(input: &str) -> Result<Self, NwcError> {
        let rest = input
            .strip_prefix(URI_SCHEME)
            .ok_or(NwcError::UriBadScheme)?;
        let (host, query) = match rest.split_once('?') {
            Some((host, query)) => (host, query),
            None => (rest, ""),
        };
        if host.is_empty() {
            return Err(NwcError::UriMissingPubkey);
        }
        let wallet_pubkey = PublicKey::parse(host).map_err(NwcError::InvalidPublicKey)?;

        let mut relays: Vec<RelayUrl> = Vec::new();
        let mut secret: Option<SecretKey> = None;
        let mut lud16: Option<String> = None;
        for (key, value) in form_urlencoded::parse(query.as_bytes()) {
            match key.as_ref() {
                "relay" => {
                    let url = RelayUrl::parse(value.as_ref()).map_err(NwcError::InvalidRelayUrl)?;
                    relays.push(url);
                }
                "secret" => {
                    secret =
                        Some(SecretKey::parse(value.as_ref()).map_err(NwcError::InvalidSecretKey)?);
                }
                "lud16" => {
                    lud16 = Some(value.into_owned());
                }
                _ => { /* ignore unknown parameters */ }
            }
        }
        if relays.is_empty() {
            return Err(NwcError::UriMissingRelay);
        }
        let secret = secret.ok_or(NwcError::UriMissingSecret)?;
        Ok(Self {
            wallet_pubkey,
            relays,
            secret,
            lud16,
        })
    }

    /// Render back to the wire `nostr+walletconnect://…` form.
    #[must_use]
    pub fn to_uri(&self) -> String {
        let mut serializer = form_urlencoded::Serializer::new(String::new());
        for relay in &self.relays {
            serializer.append_pair("relay", relay.as_str());
        }
        serializer.append_pair("secret", &self.secret.to_hex());
        if let Some(lud16) = &self.lud16 {
            serializer.append_pair("lud16", lud16);
        }
        let query = serializer.finish();
        format!("{URI_SCHEME}{}?{query}", self.wallet_pubkey.to_hex())
    }
}

/// Typed bundle for a `kind: 13194` info event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InfoEvent {
    /// Methods advertised in `content` (space-separated).
    pub methods: Vec<String>,
    /// `notifications` tag — supported notification types.
    pub notifications: Vec<String>,
    /// `encryption` tag — supported encryption schemes. Empty
    /// when the tag was absent (which spec §"Encryption" reads as
    /// "NIP-04 only").
    pub encryption_schemes: Vec<Encryption>,
}

impl InfoEvent {
    /// Construct an info bundle.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            methods: Vec::new(),
            notifications: Vec::new(),
            encryption_schemes: Vec::new(),
        }
    }

    /// Append a supported method.
    #[must_use]
    pub fn method(mut self, method: impl Into<String>) -> Self {
        self.methods.push(method.into());
        self
    }

    /// Append a supported notification type.
    #[must_use]
    pub fn notification(mut self, notification: impl Into<String>) -> Self {
        self.notifications.push(notification.into());
        self
    }

    /// Append a supported encryption scheme.
    #[must_use]
    pub fn encryption(mut self, scheme: Encryption) -> Self {
        self.encryption_schemes.push(scheme);
        self
    }

    /// Build the wire `content` string (space-separated methods).
    #[must_use]
    pub fn content(&self) -> String {
        self.methods.join(" ")
    }

    /// Build the wire tag list.
    #[must_use]
    pub fn to_tags(&self) -> Vec<Tag> {
        let mut tags: Vec<Tag> = Vec::with_capacity(2);
        if !self.encryption_schemes.is_empty() {
            let mut values: Vec<String> = Vec::with_capacity(self.encryption_schemes.len() + 1);
            for scheme in &self.encryption_schemes {
                values.push(scheme.as_token().to_owned());
            }
            tags.push(custom_tag(ENCRYPTION_TAG, [values.join(" ")]));
        }
        if !self.notifications.is_empty() {
            tags.push(custom_tag(
                NOTIFICATIONS_TAG,
                [self.notifications.join(" ")],
            ));
        }
        tags
    }

    /// Parse an info event back into a typed bundle.
    ///
    /// Spec §"Encryption": *"Absence of this tag implies that the
    /// wallet only supports nip04."* — the parser keeps the empty
    /// vector in [`Self::encryption_schemes`] and lets
    /// [`Encryption::negotiate`] apply that rule.
    ///
    /// # Errors
    ///
    /// - [`NwcError::WrongKind`] for unrelated kinds.
    /// - Forwarded parse errors for malformed encryption tokens.
    pub fn from_event(event: &Event) -> Result<Self, NwcError> {
        if event.kind != KIND_INFO {
            return Err(NwcError::WrongKind(event.kind));
        }
        let methods = event
            .content
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        let mut notifications: Vec<String> = Vec::new();
        let mut encryption_schemes: Vec<Encryption> = Vec::new();
        for tag in &event.tags {
            match tag.name() {
                NOTIFICATIONS_TAG => parse_notifications_tag(tag, &mut notifications),
                ENCRYPTION_TAG => parse_encryption_tag(tag, &mut encryption_schemes)?,
                _ => {}
            }
        }
        Ok(Self {
            methods,
            notifications,
            encryption_schemes,
        })
    }
}

impl Default for InfoEvent {
    fn default() -> Self {
        Self::new()
    }
}

/// JSON-RPC request payload (`content` of a `kind: 23194` event
/// after decryption).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    /// Method name (e.g. `pay_invoice`).
    pub method: String,
    /// Method-specific parameters.
    pub params: serde_json::Value,
}

/// JSON-RPC response payload (`content` of a `kind: 23195` event
/// after decryption).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    /// Echoes the method name from the original request.
    pub result_type: String,
    /// `null` on success, populated on error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ResponseError>,
    /// `null` on error, populated on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
}

/// Error envelope inside a [`Response`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseError {
    /// Spec'd error code.
    pub code: ErrorCode,
    /// Human-readable error message.
    pub message: String,
}

/// JSON-RPC notification payload (`content` of a `kind: 23197`
/// event after decryption).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notification {
    /// Notification type (e.g. `payment_received`).
    pub notification_type: String,
    /// Notification-specific data.
    pub notification: serde_json::Value,
}

/// Typed wallet error code (NIP-47 §"Error codes").
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    /// `RATE_LIMITED`.
    RateLimited,
    /// `NOT_IMPLEMENTED`.
    NotImplemented,
    /// `INSUFFICIENT_BALANCE`.
    InsufficientBalance,
    /// `QUOTA_EXCEEDED`.
    QuotaExceeded,
    /// `RESTRICTED`.
    Restricted,
    /// `UNAUTHORIZED`.
    Unauthorized,
    /// `INTERNAL`.
    Internal,
    /// `UNSUPPORTED_ENCRYPTION`.
    UnsupportedEncryption,
    /// `PAYMENT_FAILED` — defined under `pay_invoice` /
    /// `pay_keysend`.
    PaymentFailed,
    /// `NOT_FOUND` — defined under `lookup_invoice`.
    NotFound,
    /// `OTHER` — spec-listed catch-all.
    Other,
    /// Forward-compatible passthrough for unknown codes.
    Custom(String),
}

impl ErrorCode {
    /// Wire token.
    ///
    /// Returns the spec-defined uppercase code or, for [`Self::Custom`],
    /// the borrowed inner string. The latter forbids a `const fn`.
    #[must_use]
    #[expect(
        clippy::missing_const_for_fn,
        reason = "`Self::Custom` borrows from a heap `String`"
    )]
    pub fn as_str(&self) -> &str {
        match self {
            Self::RateLimited => "RATE_LIMITED",
            Self::NotImplemented => "NOT_IMPLEMENTED",
            Self::InsufficientBalance => "INSUFFICIENT_BALANCE",
            Self::QuotaExceeded => "QUOTA_EXCEEDED",
            Self::Restricted => "RESTRICTED",
            Self::Unauthorized => "UNAUTHORIZED",
            Self::Internal => "INTERNAL",
            Self::UnsupportedEncryption => "UNSUPPORTED_ENCRYPTION",
            Self::PaymentFailed => "PAYMENT_FAILED",
            Self::NotFound => "NOT_FOUND",
            Self::Other => "OTHER",
            Self::Custom(s) => s.as_str(),
        }
    }

    /// Parse a wire token.
    #[must_use]
    pub fn parse(token: &str) -> Self {
        match token {
            "RATE_LIMITED" => Self::RateLimited,
            "NOT_IMPLEMENTED" => Self::NotImplemented,
            "INSUFFICIENT_BALANCE" => Self::InsufficientBalance,
            "QUOTA_EXCEEDED" => Self::QuotaExceeded,
            "RESTRICTED" => Self::Restricted,
            "UNAUTHORIZED" => Self::Unauthorized,
            "INTERNAL" => Self::Internal,
            "UNSUPPORTED_ENCRYPTION" => Self::UnsupportedEncryption,
            "PAYMENT_FAILED" => Self::PaymentFailed,
            "NOT_FOUND" => Self::NotFound,
            "OTHER" => Self::Other,
            other => Self::Custom(other.to_owned()),
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for ErrorCode {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ErrorCode {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ok(Self::parse(&s))
    }
}

fn parse_notifications_tag(tag: &Tag, out: &mut Vec<String>) {
    if let Some(v) = tag.get(1) {
        *out = v.split_whitespace().map(str::to_owned).collect();
    }
}

fn parse_encryption_tag(tag: &Tag, out: &mut Vec<Encryption>) -> Result<(), NwcError> {
    let Some(v) = tag.get(1) else { return Ok(()) };
    for token in v.split_whitespace() {
        out.push(Encryption::parse(token)?);
    }
    Ok(())
}

fn custom_tag<I, S>(name: &str, args: I) -> Tag
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    Tag::with(&TagKind::from_wire(name), args)
}

fn p_tag(pubkey: PublicKey) -> Tag {
    let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::P));
    Tag::with(&head, [pubkey.to_hex()])
}

fn e_tag(id: crate::event::EventId) -> Tag {
    let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::E));
    Tag::with(&head, [id.to_hex()])
}

/// Errors raised by the NIP-47 helpers.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NwcError {
    /// The wrapping event was not the expected kind.
    #[error("unexpected kind {}", .0.as_u16())]
    WrongKind(Kind),
    /// URI scheme prefix did not match.
    #[error("URI must start with `{URI_SCHEME}`")]
    UriBadScheme,
    /// URI host was empty.
    #[error("URI is missing the wallet pubkey host")]
    UriMissingPubkey,
    /// No `relay` query parameter was provided.
    #[error("URI is missing the `relay` query parameter")]
    UriMissingRelay,
    /// No `secret` query parameter was provided.
    #[error("URI is missing the `secret` query parameter")]
    UriMissingSecret,
    /// Pubkey hex did not parse.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(#[source] PublicKeyError),
    /// Secret key hex did not parse.
    #[error("invalid secret key: {0}")]
    InvalidSecretKey(#[source] SecretKeyError),
    /// Relay URL did not parse.
    #[error("invalid relay URL: {0}")]
    InvalidRelayUrl(#[source] RelayUrlError),
    /// Encryption tag carried an unrecognised scheme.
    #[error("unknown encryption scheme: {0}")]
    UnknownEncryption(String),
    /// Wallet and client could not agree on an encryption scheme.
    #[error("client and wallet do not share a supported encryption scheme")]
    EncryptionNotNegotiable,
    /// JSON encode/decode failed.
    #[error("invalid JSON-RPC payload: {0}")]
    InvalidJson(#[source] serde_json::Error),
    /// `p` tag column missing.
    #[error("event missing required `p` tag")]
    MissingPTag,
    /// `e` tag column missing on a response.
    #[error("response event missing required `e` tag")]
    MissingETag,
    /// NIP-44 encrypt/decrypt failed.
    #[cfg(feature = "nip44")]
    #[cfg_attr(docsrs, doc(cfg(feature = "nip44")))]
    #[error("NIP-44 failure: {0}")]
    Nip44(#[source] nip44::Nip44Error),
    /// NIP-04 encrypt/decrypt failed.
    #[cfg(feature = "nip04")]
    #[cfg_attr(docsrs, doc(cfg(feature = "nip04")))]
    #[error("NIP-04 failure: {0}")]
    Nip04(#[source] nip04::Nip04Error),
    /// Caller asked for NIP-04 but the `nip04` feature is off.
    #[cfg(not(feature = "nip04"))]
    #[error("NIP-04 fallback required but the `nip04` feature is disabled")]
    Nip04Unavailable,
}

#[cfg(feature = "nip44")]
fn encrypt_with(
    encryption: Encryption,
    secret: &SecretKey,
    peer: &PublicKey,
    plaintext: &str,
) -> Result<String, NwcError> {
    match encryption {
        Encryption::Nip44V2 => nip44::encrypt(secret, peer, plaintext).map_err(NwcError::Nip44),
        #[cfg(feature = "nip04")]
        Encryption::Nip04 => nip04::encrypt(secret, peer, plaintext).map_err(NwcError::Nip04),
        #[cfg(not(feature = "nip04"))]
        Encryption::Nip04 => Err(NwcError::Nip04Unavailable),
    }
}

#[cfg(feature = "nip44")]
fn decrypt_with(
    encryption: Encryption,
    secret: &SecretKey,
    peer: &PublicKey,
    payload: &str,
) -> Result<String, NwcError> {
    match encryption {
        Encryption::Nip44V2 => nip44::decrypt(secret, peer, payload).map_err(NwcError::Nip44),
        #[cfg(feature = "nip04")]
        Encryption::Nip04 => nip04::decrypt(secret, peer, payload).map_err(NwcError::Nip04),
        #[cfg(not(feature = "nip04"))]
        Encryption::Nip04 => Err(NwcError::Nip04Unavailable),
    }
}

/// Inspect an event's `encryption` tag to learn which scheme the
/// peer used. Absence of the tag implies NIP-04 per spec.
///
/// # Errors
///
/// Returns [`NwcError::UnsupportedEncryption`] if the tag value is
/// not one of the schemes defined in §2.
pub fn encryption_for_event(event: &Event) -> Result<Encryption, NwcError> {
    for tag in &event.tags {
        if tag.name() == ENCRYPTION_TAG
            && let Some(token) = tag.get(1)
        {
            return Encryption::parse(token);
        }
    }
    Ok(Encryption::Nip04)
}

#[cfg(feature = "nip44")]
#[cfg_attr(docsrs, doc(cfg(feature = "nip44")))]
impl EventBuilder {
    /// Author a NIP-47 info event from a typed bundle. The author
    /// SHOULD be the wallet service's pubkey.
    #[must_use]
    pub fn nwc_info(info: &InfoEvent) -> Self {
        let mut builder = Self::new(KIND_INFO, info.content());
        for tag in info.to_tags() {
            builder = builder.tag(tag);
        }
        builder
    }

    /// Build a NIP-47 request event with encrypted body.
    ///
    /// `client_secret` is the URI's `secret`; `wallet_public` is
    /// the URI's host. `expiration` populates a NIP-40 expiration
    /// tag when set — spec §"Request and Response Events" treats
    /// the timestamp as a hard cut-off the wallet service may use
    /// to drop late requests.
    ///
    /// # Errors
    ///
    /// - [`NwcError::InvalidJson`] when `request` cannot be
    ///   serialised.
    /// - [`NwcError::Nip44`] / [`NwcError::Nip04`] from the
    ///   underlying encryption primitives.
    pub fn nwc_request(
        client_secret: &SecretKey,
        wallet_public: &PublicKey,
        request: &Request,
        encryption: Encryption,
        expiration: Option<Timestamp>,
    ) -> Result<Self, NwcError> {
        let plaintext = serde_json::to_string(request).map_err(NwcError::InvalidJson)?;
        let ciphertext = encrypt_with(encryption, client_secret, wallet_public, &plaintext)?;
        let mut builder = Self::new(KIND_REQUEST, ciphertext)
            .tag(p_tag(*wallet_public))
            .tag(custom_tag(ENCRYPTION_TAG, [encryption.as_token()]));
        if let Some(ts) = expiration {
            builder = builder.expiration(ts);
        }
        Ok(builder)
    }

    /// Build a NIP-47 response event with encrypted body.
    ///
    /// # Errors
    ///
    /// See [`Self::nwc_request`].
    pub fn nwc_response(
        wallet_secret: &SecretKey,
        client_public: &PublicKey,
        request_event_id: crate::event::EventId,
        response: &Response,
        encryption: Encryption,
    ) -> Result<Self, NwcError> {
        let plaintext = serde_json::to_string(response).map_err(NwcError::InvalidJson)?;
        let ciphertext = encrypt_with(encryption, wallet_secret, client_public, &plaintext)?;
        Ok(Self::new(KIND_RESPONSE, ciphertext)
            .tag(p_tag(*client_public))
            .tag(e_tag(request_event_id))
            .tag(custom_tag(ENCRYPTION_TAG, [encryption.as_token()])))
    }

    /// Build a NIP-47 notification event with encrypted body.
    ///
    /// `kind` should be [`KIND_NOTIFICATION`] for NIP-44 or
    /// [`KIND_NOTIFICATION_LEGACY`] for NIP-04.
    ///
    /// # Errors
    ///
    /// See [`Self::nwc_request`].
    pub fn nwc_notification(
        wallet_secret: &SecretKey,
        client_public: &PublicKey,
        notification: &Notification,
        encryption: Encryption,
    ) -> Result<Self, NwcError> {
        let kind = match encryption {
            Encryption::Nip44V2 => KIND_NOTIFICATION,
            Encryption::Nip04 => KIND_NOTIFICATION_LEGACY,
        };
        let plaintext = serde_json::to_string(notification).map_err(NwcError::InvalidJson)?;
        let ciphertext = encrypt_with(encryption, wallet_secret, client_public, &plaintext)?;
        Ok(Self::new(kind, ciphertext)
            .tag(p_tag(*client_public))
            .tag(custom_tag(ENCRYPTION_TAG, [encryption.as_token()])))
    }
}

/// Decrypt and parse a `kind: 23194` request event.
///
/// `wallet_secret` is the wallet service's secret key;
/// `client_public` MUST come from the *event signature* (not from
/// any tag) and is typically `event.pubkey`.
///
/// # Errors
///
/// - [`NwcError::WrongKind`] for unrelated kinds.
/// - Forwarded errors from the encryption primitives and
///   `serde_json`.
#[cfg(feature = "nip44")]
#[cfg_attr(docsrs, doc(cfg(feature = "nip44")))]
pub fn decrypt_request(event: &Event, wallet_secret: &SecretKey) -> Result<Request, NwcError> {
    if event.kind != KIND_REQUEST {
        return Err(NwcError::WrongKind(event.kind));
    }
    let encryption = encryption_for_event(event)?;
    let plaintext = decrypt_with(encryption, wallet_secret, &event.pubkey, &event.content)?;
    serde_json::from_str(&plaintext).map_err(NwcError::InvalidJson)
}

/// Decrypt and parse a `kind: 23195` response event.
///
/// # Errors
///
/// See [`decrypt_request`].
#[cfg(feature = "nip44")]
#[cfg_attr(docsrs, doc(cfg(feature = "nip44")))]
pub fn decrypt_response(event: &Event, client_secret: &SecretKey) -> Result<Response, NwcError> {
    if event.kind != KIND_RESPONSE {
        return Err(NwcError::WrongKind(event.kind));
    }
    let encryption = encryption_for_event(event)?;
    let plaintext = decrypt_with(encryption, client_secret, &event.pubkey, &event.content)?;
    serde_json::from_str(&plaintext).map_err(NwcError::InvalidJson)
}

/// Decrypt and parse a notification event (`kind: 23197` or
/// `kind: 23196`).
///
/// # Errors
///
/// See [`decrypt_request`].
#[cfg(feature = "nip44")]
#[cfg_attr(docsrs, doc(cfg(feature = "nip44")))]
pub fn decrypt_notification(
    event: &Event,
    client_secret: &SecretKey,
) -> Result<Notification, NwcError> {
    if event.kind != KIND_NOTIFICATION && event.kind != KIND_NOTIFICATION_LEGACY {
        return Err(NwcError::WrongKind(event.kind));
    }
    let encryption = encryption_for_event(event)?;
    let plaintext = decrypt_with(encryption, client_secret, &event.pubkey, &event.content)?;
    serde_json::from_str(&plaintext).map_err(NwcError::InvalidJson)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;

    fn wallet() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    fn client() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000005").unwrap()
    }

    #[test]
    fn connection_uri_round_trips_with_lud16() {
        let uri = ConnectionUri {
            wallet_pubkey: *wallet().public_key(),
            relays: vec![
                RelayUrl::parse("wss://relay.one/").unwrap(),
                RelayUrl::parse("wss://relay.two/").unwrap(),
            ],
            secret: client().secret_key().clone(),
            lud16: Some("alice@example.com".to_owned()),
        };
        let wire = uri.to_uri();
        let parsed = ConnectionUri::parse(&wire).unwrap();
        assert_eq!(parsed, uri);
    }

    #[test]
    fn connection_uri_rejects_bad_scheme() {
        let err = ConnectionUri::parse("https://example.com/").unwrap_err();
        assert!(matches!(err, NwcError::UriBadScheme));
    }

    #[test]
    fn connection_uri_requires_relay_and_secret() {
        let pk = wallet().public_key().to_hex();
        let no_relay = format!(
            "nostr+walletconnect://{pk}?secret={}",
            client().secret_key().to_hex()
        );
        assert!(matches!(
            ConnectionUri::parse(&no_relay),
            Err(NwcError::UriMissingRelay)
        ));
        let no_secret = format!("nostr+walletconnect://{pk}?relay=wss%3A%2F%2Frelay/");
        assert!(matches!(
            ConnectionUri::parse(&no_secret),
            Err(NwcError::UriMissingSecret)
        ));
    }

    #[test]
    fn info_event_round_trips() {
        let info = InfoEvent::new()
            .method("pay_invoice")
            .method("get_balance")
            .notification("payment_received")
            .encryption(Encryption::Nip44V2)
            .encryption(Encryption::Nip04);
        let event = EventBuilder::nwc_info(&info)
            .sign_with_keys(&wallet())
            .unwrap();
        assert_eq!(event.kind, KIND_INFO);
        let parsed = InfoEvent::from_event(&event).unwrap();
        assert_eq!(parsed.methods, vec!["pay_invoice", "get_balance"]);
        assert_eq!(parsed.notifications, vec!["payment_received"]);
        assert_eq!(
            parsed.encryption_schemes,
            vec![Encryption::Nip44V2, Encryption::Nip04]
        );
    }

    #[test]
    fn info_event_without_encryption_tag_is_nip04_only() {
        let event = EventBuilder::new(KIND_INFO, "pay_invoice")
            .sign_with_keys(&wallet())
            .unwrap();
        let info = InfoEvent::from_event(&event).unwrap();
        assert!(info.encryption_schemes.is_empty());
        let scheme = Encryption::negotiate(
            &info.encryption_schemes,
            &[Encryption::Nip44V2, Encryption::Nip04],
        )
        .unwrap();
        assert_eq!(scheme, Encryption::Nip04);
    }

    #[test]
    fn encryption_negotiation_prefers_nip44_v2() {
        let scheme = Encryption::negotiate(
            &[Encryption::Nip44V2, Encryption::Nip04],
            &[Encryption::Nip44V2, Encryption::Nip04],
        )
        .unwrap();
        assert_eq!(scheme, Encryption::Nip44V2);
    }

    #[test]
    fn encryption_negotiation_falls_back_to_nip04_when_only_overlap() {
        let scheme = Encryption::negotiate(
            &[Encryption::Nip04],
            &[Encryption::Nip44V2, Encryption::Nip04],
        )
        .unwrap();
        assert_eq!(scheme, Encryption::Nip04);
    }

    #[test]
    fn encryption_negotiation_fails_when_no_overlap() {
        let err = Encryption::negotiate(&[Encryption::Nip04], &[Encryption::Nip44V2]).unwrap_err();
        assert!(matches!(err, NwcError::EncryptionNotNegotiable));
    }

    #[test]
    fn error_code_round_trips_through_serde() {
        let code = ErrorCode::PaymentFailed;
        let json = serde_json::to_string(&code).unwrap();
        assert_eq!(json, "\"PAYMENT_FAILED\"");
        let parsed: ErrorCode = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, code);
    }

    #[test]
    fn error_code_unknown_passes_through_as_custom() {
        let code: ErrorCode = serde_json::from_str("\"FUTURE_CODE\"").unwrap();
        assert_eq!(code, ErrorCode::Custom("FUTURE_CODE".to_owned()));
    }

    #[cfg(feature = "nip44")]
    #[test]
    fn request_response_round_trip_through_nip44() {
        let request = Request {
            method: "pay_invoice".to_owned(),
            params: serde_json::json!({ "invoice": "lnbc1..." }),
        };
        let req_event = EventBuilder::nwc_request(
            client().secret_key(),
            wallet().public_key(),
            &request,
            Encryption::Nip44V2,
            None,
        )
        .unwrap()
        .sign_with_keys(&client())
        .unwrap();

        let parsed = decrypt_request(&req_event, wallet().secret_key()).unwrap();
        assert_eq!(parsed, request);

        let response = Response {
            result_type: "pay_invoice".to_owned(),
            error: None,
            result: Some(serde_json::json!({ "preimage": "deadbeef" })),
        };
        let resp_event = EventBuilder::nwc_response(
            wallet().secret_key(),
            client().public_key(),
            req_event.id,
            &response,
            Encryption::Nip44V2,
        )
        .unwrap()
        .sign_with_keys(&wallet())
        .unwrap();

        let parsed_resp = decrypt_response(&resp_event, client().secret_key()).unwrap();
        assert_eq!(parsed_resp, response);
    }

    #[cfg(all(feature = "nip44", feature = "nip04"))]
    #[test]
    fn legacy_notification_uses_nip04_kind_and_works_end_to_end() {
        let notification = Notification {
            notification_type: "payment_received".to_owned(),
            notification: serde_json::json!({ "payment_hash": "abc" }),
        };
        let event = EventBuilder::nwc_notification(
            wallet().secret_key(),
            client().public_key(),
            &notification,
            Encryption::Nip04,
        )
        .unwrap()
        .sign_with_keys(&wallet())
        .unwrap();
        assert_eq!(event.kind, KIND_NOTIFICATION_LEGACY);

        let parsed = decrypt_notification(&event, client().secret_key()).unwrap();
        assert_eq!(parsed, notification);
    }

    #[cfg(feature = "nip44")]
    #[test]
    fn request_with_expiration_attaches_nip40_tag() {
        let request = Request {
            method: "get_balance".to_owned(),
            params: serde_json::json!({}),
        };
        let event = EventBuilder::nwc_request(
            client().secret_key(),
            wallet().public_key(),
            &request,
            Encryption::Nip44V2,
            Some(Timestamp::from_secs(2_000_000_000)),
        )
        .unwrap()
        .sign_with_keys(&client())
        .unwrap();
        let has_expiration = event.tags.iter().any(|t| t.name() == "expiration");
        assert!(has_expiration);
    }
}
