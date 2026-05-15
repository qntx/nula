//! [NIP-46] Nostr Connect — protocol primitives.
//!
//! NIP-46 specifies an asynchronous JSON-RPC interface between a
//! *client* (an app that owns no signing keys) and a *remote signer*
//! (a bunker or browser extension that does). Messages travel over
//! Nostr itself: each request/response is a kind-`24133` event whose
//! `content` is the JSON-RPC body, encrypted with [NIP-44] v2 to the
//! peer's public key.
//!
//! `nula-core` ships the **protocol primitives** — message types,
//! method enum, URI parser. The actual transport (relay subscription,
//! request bookkeeping, timeout policy, retry logic) belongs to a
//! higher crate that owns a relay client; the surface here is enough
//! to encode/decode every wire payload and to negotiate the initial
//! handshake.
//!
//! # Method matrix
//!
//! | Method            | Request payload                            | Response payload                            |
//! |-------------------|--------------------------------------------|---------------------------------------------|
//! | `connect`         | `[remote_pubkey, secret?, perms?]`         | `"ack"` or echoed secret                    |
//! | `get_public_key`  | `[]`                                       | user's pubkey (hex)                         |
//! | `sign_event`      | `[unsigned_json]`                          | signed event JSON                           |
//! | `nip04_encrypt`   | `[peer_pubkey, plaintext]`                 | base64 ciphertext                           |
//! | `nip04_decrypt`   | `[peer_pubkey, ciphertext]`                | plaintext                                   |
//! | `nip44_encrypt`   | `[peer_pubkey, plaintext]`                 | base64 ciphertext                           |
//! | `nip44_decrypt`   | `[peer_pubkey, ciphertext]`                | plaintext                                   |
//! | `ping`            | `[]`                                       | `"pong"`                                    |
//! | `switch_relays`   | `[]`                                       | JSON array of relay URLs, or `null`         |
//!
//! Any method may instead return `"auth_url"` (signaling that the user
//! must complete an out-of-band auth step) or `"error"` with the
//! `error` field populated.
//!
//! # Permissions (NIP-46 § "Requested permissions")
//!
//! The third positional slot of `connect` carries a comma-separated
//! list of `method[:params]` tokens, e.g. `nip44_encrypt,sign_event:4`.
//! Each token is modelled as a [`Permission`]; the typed enum keeps the
//! two well-defined shapes (blanket method, `sign_event` restricted to
//! a kind) and falls back to [`Permission::Other`] for vendor or
//! future-spec extensions.
//!
//! # Connection URIs
//!
//! Two kinds:
//!
//! - **`bunker://<remote_pubkey>?relay=...&secret=...`** — signer
//!   advertises its address; client dials in.
//! - **`nostrconnect://<client_pubkey>?relay=...&metadata=...&secret=...`** —
//!   client advertises itself; signer dials in. NIP-46 mandates that
//!   the `secret` field is present and that the signer echoes it back
//!   inside the `connect` response (anti-spoofing).
//!
//! [NIP-46]: https://github.com/nostr-protocol/nips/blob/master/46.md
//! [NIP-44]: https://github.com/nostr-protocol/nips/blob/master/44.md

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use url::Url;

use crate::event::{Event, EventError, Kind, UnsignedEvent, UnsignedEventError};
use crate::key::{PublicKey, PublicKeyError};
use crate::types::{RelayUrl, RelayUrlError};
use crate::util::JsonUtil;

/// URI scheme for client-initiated connections (`nostrconnect://…`).
pub const URI_SCHEME_CLIENT: &str = "nostrconnect";
/// URI scheme for signer-initiated connections (`bunker://…`).
pub const URI_SCHEME_BUNKER: &str = "bunker";

/// Kind of a NIP-46 wire event.
///
/// Re-exposed as a constant for callers building filters or routing
/// dispatchers without importing the magic number.
pub const KIND: u16 = 24_133;

/// Errors raised by the NIP-46 helpers.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Nip46Error {
    /// A hex-encoded pubkey in the request/URI was invalid.
    #[error(transparent)]
    PublicKey(#[from] PublicKeyError),
    /// A relay URL inside a connection URI was invalid.
    #[error(transparent)]
    RelayUrl(#[from] RelayUrlError),
    /// `serde_json` rejected the wire payload.
    #[error("invalid JSON payload: {0}")]
    Json(#[from] serde_json::Error),
    /// An unsigned event JSON in `sign_event` request failed to parse.
    #[error(transparent)]
    UnsignedEvent(#[from] UnsignedEventError),
    /// A signed event JSON in a `sign_event` response failed to parse.
    #[error(transparent)]
    Event(#[from] EventError),
    /// A request had the wrong number of params for its method.
    #[error("method `{method}` expects {expected} param(s), got {actual}")]
    InvalidParamLength {
        /// Method that was being parsed.
        method: Method,
        /// Number of params the method requires.
        expected: usize,
        /// Number of params the message actually carried.
        actual: usize,
    },
    /// The wire `method` field is not one of the nine defined methods.
    #[error("unsupported NIP-46 method: {0}")]
    UnsupportedMethod(String),
    /// The `switch_relays` response carried JSON that was neither
    /// `null` nor an array of relay URL strings.
    #[error("invalid switch_relays response payload")]
    InvalidSwitchRelaysPayload,
    /// Tried to convert a [`Message::Response`] to a [`Request`] (or
    /// vice-versa).
    #[error("{0}")]
    WrongMessageKind(&'static str),
    /// The connection URI's scheme was neither `bunker` nor
    /// `nostrconnect`.
    #[error("unknown URI scheme `{0}` (expected `bunker` or `nostrconnect`)")]
    UnknownUriScheme(String),
    /// The connection URI was missing a required component.
    #[error("malformed connection URI: {0}")]
    MalformedUri(&'static str),
    /// The base URL parser rejected the URI.
    #[error(transparent)]
    Url(#[from] url::ParseError),
    /// The result returned by the signer didn't match the request's
    /// method (e.g. asked to `sign_event`, got a `pong` back).
    #[error("unexpected response for method `{method}` (expected {expected}, got `{received}`)")]
    UnexpectedResponse {
        /// The method whose response was being decoded.
        method: Method,
        /// Short label of the expected response shape.
        expected: &'static str,
        /// What the wire actually carried.
        received: String,
    },
}

/// Bare request method (the string in the wire `method` field).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Method {
    /// Negotiate or echo the connection (anti-spoofing).
    Connect,
    /// Return the user's BIP-340 public key.
    GetPublicKey,
    /// Sign an [`UnsignedEvent`] on the user's behalf.
    SignEvent,
    /// NIP-04 (legacy) encrypt.
    Nip04Encrypt,
    /// NIP-04 (legacy) decrypt.
    Nip04Decrypt,
    /// NIP-44 v2 encrypt.
    Nip44Encrypt,
    /// NIP-44 v2 decrypt.
    Nip44Decrypt,
    /// Liveness probe.
    Ping,
    /// Ask the remote signer for its preferred relay set
    /// (NIP-46 § "Switching relays").
    SwitchRelays,
}

impl Method {
    /// Wire identifier (lowercase, `snake_case`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::GetPublicKey => "get_public_key",
            Self::SignEvent => "sign_event",
            Self::Nip04Encrypt => "nip04_encrypt",
            Self::Nip04Decrypt => "nip04_decrypt",
            Self::Nip44Encrypt => "nip44_encrypt",
            Self::Nip44Decrypt => "nip44_decrypt",
            Self::Ping => "ping",
            Self::SwitchRelays => "switch_relays",
        }
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Method {
    type Err = Nip46Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "connect" => Self::Connect,
            "get_public_key" => Self::GetPublicKey,
            "sign_event" => Self::SignEvent,
            "nip04_encrypt" => Self::Nip04Encrypt,
            "nip04_decrypt" => Self::Nip04Decrypt,
            "nip44_encrypt" => Self::Nip44Encrypt,
            "nip44_decrypt" => Self::Nip44Decrypt,
            "ping" => Self::Ping,
            "switch_relays" => Self::SwitchRelays,
            other => return Err(Nip46Error::UnsupportedMethod(other.to_owned())),
        })
    }
}

/// A single permission entry inside the `connect` request's third
/// positional slot.
///
/// Wire format: `method[:params]`, comma-separated when packed into the
/// surrounding string. Spec line 112 reserves "parameters for other
/// methods are to be defined later", so anything that does not match a
/// known shape falls into [`Self::Other`] verbatim — round-tripping is
/// always lossless.
///
/// # Examples
///
/// ```
/// use nula_core::Kind;
/// use nula_core::nips::nip46::{Method, Permission};
///
/// assert_eq!(
///     "nip44_encrypt".parse::<Permission>().unwrap(),
///     Permission::Method(Method::Nip44Encrypt),
/// );
/// assert_eq!(
///     "sign_event:1".parse::<Permission>().unwrap(),
///     Permission::SignEventKind(Kind::TEXT_NOTE),
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Permission {
    /// Blanket permission to call a known method with no further
    /// parameter constraints (`<method>` form).
    Method(Method),
    /// Permission to call `sign_event` restricted to one event kind
    /// (`sign_event:<kind>` form).
    SignEventKind(Kind),
    /// Forward-compat: a vendor extension or a shape the spec has not
    /// standardised yet. Stored verbatim so encoding is lossless.
    Other(String),
}

impl Permission {
    /// Encode a single permission as its wire token (`method[:params]`).
    #[must_use]
    pub fn to_wire(&self) -> String {
        match self {
            Self::Method(method) => method.to_string(),
            Self::SignEventKind(kind) => {
                format!("{}:{}", Method::SignEvent.as_str(), kind.as_u16())
            }
            Self::Other(raw) => raw.clone(),
        }
    }

    /// Encode a list of permissions as a single comma-separated wire
    /// string (suitable for the `connect` request's third positional
    /// slot or the `nostrconnect://?perms=` query parameter).
    #[must_use]
    pub fn join(perms: &[Self]) -> String {
        let mut out = String::new();
        for (i, perm) in perms.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&perm.to_wire());
        }
        out
    }

    /// Decode a comma-separated wire string into a vector of
    /// permissions. Empty input yields an empty vector; whitespace
    /// around each token is trimmed.
    #[must_use]
    pub fn split(wire: &str) -> Vec<Self> {
        if wire.is_empty() {
            return Vec::new();
        }
        wire.split(',')
            .map(str::trim)
            .filter(|tok| !tok.is_empty())
            .map(|tok| tok.parse().unwrap_or_else(|_| Self::Other(tok.to_owned())))
            .collect()
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_wire())
    }
}

impl FromStr for Permission {
    type Err = Nip46Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // `method[:params]` — split on the first colon.
        if let Some((head, tail)) = s.split_once(':') {
            if head == Method::SignEvent.as_str()
                && let Ok(raw) = tail.parse::<u16>()
            {
                return Ok(Self::SignEventKind(Kind::new(raw)));
            }
            // Known method with an unknown parameter shape, or a
            // vendor namespace — preserve verbatim.
            return Ok(Self::Other(s.to_owned()));
        }
        // No colon: bare method name. Unknown vocabulary falls
        // through to the spec-mandated `Other` passthrough.
        Ok(s.parse::<Method>()
            .map_or_else(|_| Self::Other(s.to_owned()), Self::Method))
    }
}

impl Serialize for Method {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Method {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = <&str>::deserialize(deserializer)?;
        Self::from_str(raw).map_err(serde::de::Error::custom)
    }
}

/// Typed request payload.
///
/// Each variant carries exactly the data its method needs; converting
/// to and from the wire `Vec<String>` happens inside this module.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Request {
    /// `connect` — present the remote signer's public key (and an
    /// optional one-time secret) to negotiate the session.
    ///
    /// `perms` carries the optional third positional argument from
    /// NIP-46 § "Requested permissions"; `None` means the caller did
    /// not negotiate any (the slot is omitted on the wire),
    /// `Some(vec![])` means an explicitly empty set is being sent.
    Connect {
        /// Remote signer's pubkey.
        remote_signer_public_key: PublicKey,
        /// Optional anti-spoofing secret (carried in `bunker://`
        /// URIs and required in `nostrconnect://` URIs).
        secret: Option<String>,
        /// Optional requested permissions.
        perms: Option<Vec<Permission>>,
    },
    /// `get_public_key` — return the user's pubkey.
    GetPublicKey,
    /// `sign_event` — sign the given unsigned event.
    SignEvent(UnsignedEvent),
    /// `nip04_encrypt` — encrypt `text` for `peer`.
    Nip04Encrypt {
        /// Peer's pubkey.
        peer: PublicKey,
        /// UTF-8 plaintext.
        text: String,
    },
    /// `nip04_decrypt` — decrypt `ciphertext` from `peer`.
    Nip04Decrypt {
        /// Peer's pubkey.
        peer: PublicKey,
        /// Wire-format ciphertext.
        ciphertext: String,
    },
    /// `nip44_encrypt` — encrypt `text` for `peer` with NIP-44 v2.
    Nip44Encrypt {
        /// Peer's pubkey.
        peer: PublicKey,
        /// UTF-8 plaintext.
        text: String,
    },
    /// `nip44_decrypt` — decrypt `ciphertext` from `peer` with NIP-44 v2.
    Nip44Decrypt {
        /// Peer's pubkey.
        peer: PublicKey,
        /// Wire-format ciphertext.
        ciphertext: String,
    },
    /// `ping` — liveness probe.
    Ping,
    /// `switch_relays` — ask the signer for its preferred relay set.
    SwitchRelays,
}

impl Request {
    /// The method this request implements.
    #[must_use]
    pub const fn method(&self) -> Method {
        match self {
            Self::Connect { .. } => Method::Connect,
            Self::GetPublicKey => Method::GetPublicKey,
            Self::SignEvent(_) => Method::SignEvent,
            Self::Nip04Encrypt { .. } => Method::Nip04Encrypt,
            Self::Nip04Decrypt { .. } => Method::Nip04Decrypt,
            Self::Nip44Encrypt { .. } => Method::Nip44Encrypt,
            Self::Nip44Decrypt { .. } => Method::Nip44Decrypt,
            Self::Ping => Method::Ping,
            Self::SwitchRelays => Method::SwitchRelays,
        }
    }

    /// Wire-format params (the `params` JSON array).
    ///
    /// `connect` follows the spec's positional layout
    /// `[pubkey, secret?, perms?]`. Because the slots are positional,
    /// emitting `perms` requires emitting a `secret` slot first; an
    /// absent secret is encoded as the empty string so the perms slot
    /// stays at index 2.
    #[must_use]
    pub fn params(&self) -> Vec<String> {
        match self {
            Self::Connect {
                remote_signer_public_key,
                secret,
                perms,
            } => {
                let mut out = Vec::with_capacity(
                    1 + usize::from(secret.is_some()) + usize::from(perms.is_some()),
                );
                out.push(remote_signer_public_key.to_hex());
                if perms.is_some() {
                    // perms occupies position 2, so a placeholder for
                    // an absent secret keeps the layout positional.
                    out.push(secret.clone().unwrap_or_default());
                } else if let Some(s) = secret {
                    out.push(s.clone());
                }
                if let Some(perms) = perms {
                    out.push(Permission::join(perms));
                }
                out
            }
            Self::GetPublicKey | Self::Ping | Self::SwitchRelays => Vec::new(),
            Self::SignEvent(unsigned) => vec![unsigned.try_to_json().unwrap_or_default()],
            Self::Nip04Encrypt { peer, text } | Self::Nip44Encrypt { peer, text } => {
                vec![peer.to_hex(), text.clone()]
            }
            Self::Nip04Decrypt { peer, ciphertext } | Self::Nip44Decrypt { peer, ciphertext } => {
                vec![peer.to_hex(), ciphertext.clone()]
            }
        }
    }

    /// Parse a `(method, params)` pair into a typed request.
    ///
    /// Implemented as a single match over `(method, params.as_slice())`
    /// so the slice patterns simultaneously bind, validate the arity,
    /// and avoid `params[i]` indexing (which clippy flags as
    /// potentially panicking).
    ///
    /// # Errors
    ///
    /// See [`Nip46Error`] for the failure surface; in particular,
    /// [`Nip46Error::InvalidParamLength`] when a method receives the
    /// wrong number of params.
    pub fn from_wire(method: Method, params: &[String]) -> Result<Self, Nip46Error> {
        match (method, params) {
            // Happy paths — slice patterns simultaneously bind, validate
            // arity, and avoid `params[i]` indexing that clippy flags
            // as potentially panicking.
            (Method::Connect, [pk_hex]) => Ok(Self::Connect {
                remote_signer_public_key: PublicKey::parse(pk_hex)?,
                secret: None,
                perms: None,
            }),
            (Method::Connect, [pk_hex, secret]) => Ok(Self::Connect {
                remote_signer_public_key: PublicKey::parse(pk_hex)?,
                secret: Some(secret.clone()),
                perms: None,
            }),
            (Method::Connect, [pk_hex, secret, perms]) => Ok(Self::Connect {
                remote_signer_public_key: PublicKey::parse(pk_hex)?,
                // An empty secret slot is a placeholder for "no secret
                // but perms present" — collapse it back to `None` so
                // round-trips preserve the original semantic shape.
                secret: if secret.is_empty() {
                    None
                } else {
                    Some(secret.clone())
                },
                perms: Some(Permission::split(perms)),
            }),
            (Method::GetPublicKey, []) => Ok(Self::GetPublicKey),
            (Method::SignEvent, [json]) => Ok(Self::SignEvent(UnsignedEvent::from_json(json)?)),
            (Method::Nip04Encrypt, [pk_hex, text]) => Ok(Self::Nip04Encrypt {
                peer: PublicKey::parse(pk_hex)?,
                text: text.clone(),
            }),
            (Method::Nip44Encrypt, [pk_hex, text]) => Ok(Self::Nip44Encrypt {
                peer: PublicKey::parse(pk_hex)?,
                text: text.clone(),
            }),
            (Method::Nip04Decrypt, [pk_hex, ciphertext]) => Ok(Self::Nip04Decrypt {
                peer: PublicKey::parse(pk_hex)?,
                ciphertext: ciphertext.clone(),
            }),
            (Method::Nip44Decrypt, [pk_hex, ciphertext]) => Ok(Self::Nip44Decrypt {
                peer: PublicKey::parse(pk_hex)?,
                ciphertext: ciphertext.clone(),
            }),
            (Method::Ping, []) => Ok(Self::Ping),
            (Method::SwitchRelays, []) => Ok(Self::SwitchRelays),
            // Arity-mismatch fallbacks, grouped by required param count
            // (clippy::match_same_arms refuses two arms that produce
            // structurally identical bodies).
            (Method::GetPublicKey | Method::Ping | Method::SwitchRelays, _) => {
                Err(invalid_param_length(method, 0, params.len()))
            }
            // `connect` accepts 1, 2, or 3 positional args; the
            // catch-all here only fires for 0 or 4+. We report the
            // canonical 1-arg form for both `sign_event` and
            // `connect` to keep the diagnostic surface stable.
            (Method::SignEvent | Method::Connect, _) => {
                Err(invalid_param_length(method, 1, params.len()))
            }
            (
                Method::Nip04Encrypt
                | Method::Nip04Decrypt
                | Method::Nip44Encrypt
                | Method::Nip44Decrypt,
                _,
            ) => Err(invalid_param_length(method, 2, params.len())),
        }
    }
}

const fn invalid_param_length(method: Method, expected: usize, actual: usize) -> Nip46Error {
    Nip46Error::InvalidParamLength {
        method,
        expected,
        actual,
    }
}

/// Typed response payload.
///
/// `result == None && error == Some(_)` is signaled by [`Response`].
/// `ResponseResult` only models the `success` / `auth_url` / `error`
/// tagged variants the spec defines for the `result` slot.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResponseResult {
    /// `connect` accepted via the `bunker://` flow.
    Ack,
    /// `connect` accepted via the `nostrconnect://` flow; the signer
    /// echoes the secret from the URI back to prove possession of the
    /// matching key.
    ConnectSecret(String),
    /// User's pubkey.
    GetPublicKey(PublicKey),
    /// Signed event.
    SignEvent(Box<Event>),
    /// NIP-04 ciphertext.
    Nip04Encrypt(String),
    /// NIP-04 plaintext.
    Nip04Decrypt(String),
    /// NIP-44 ciphertext.
    Nip44Encrypt(String),
    /// NIP-44 plaintext.
    Nip44Decrypt(String),
    /// Liveness probe response.
    Pong,
    /// `switch_relays` reply: either the signer's updated relay set,
    /// or `None` meaning "no change" (spec line 108 `... OR null`).
    SwitchRelays(Option<Vec<RelayUrl>>),
    /// The signer needs the user to complete an out-of-band step
    /// (typically open a URL); the URL travels in the `error` slot per
    /// spec.
    AuthUrl,
    /// An error string is present in `error`.
    Error,
}

impl ResponseResult {
    /// Decode a wire `result` string (already JSON-decoded out of the
    /// outer envelope) given the originating `method`.
    ///
    /// # Errors
    ///
    /// Returns [`Nip46Error::Json`] / [`Nip46Error::PublicKey`] /
    /// [`Nip46Error::Event`] when the body is malformed for the
    /// requested method, and [`Nip46Error::UnexpectedResponse`] for
    /// `ping` if the literal payload isn't `"pong"`.
    pub fn from_wire(method: Method, result: &str) -> Result<Self, Nip46Error> {
        // The two universal sentinels first; both can be returned by
        // any method.
        match result {
            "auth_url" => return Ok(Self::AuthUrl),
            "error" => return Ok(Self::Error),
            _ => {}
        }
        match method {
            Method::Connect => {
                if result == "ack" {
                    Ok(Self::Ack)
                } else {
                    Ok(Self::ConnectSecret(result.to_owned()))
                }
            }
            Method::GetPublicKey => Ok(Self::GetPublicKey(PublicKey::parse(result)?)),
            Method::SignEvent => Ok(Self::SignEvent(Box::new(Event::from_json(result)?))),
            Method::Nip04Encrypt => Ok(Self::Nip04Encrypt(result.to_owned())),
            Method::Nip04Decrypt => Ok(Self::Nip04Decrypt(result.to_owned())),
            Method::Nip44Encrypt => Ok(Self::Nip44Encrypt(result.to_owned())),
            Method::Nip44Decrypt => Ok(Self::Nip44Decrypt(result.to_owned())),
            Method::Ping => {
                if result == "pong" {
                    Ok(Self::Pong)
                } else {
                    Err(Nip46Error::UnexpectedResponse {
                        method,
                        expected: "pong",
                        received: result.to_owned(),
                    })
                }
            }
            Method::SwitchRelays => {
                let trimmed = result.trim();
                if trimmed == "null" {
                    return Ok(Self::SwitchRelays(None));
                }
                let raw: Vec<String> = serde_json::from_str(trimmed)
                    .map_err(|_| Nip46Error::InvalidSwitchRelaysPayload)?;
                let mut relays = Vec::with_capacity(raw.len());
                for url in raw {
                    relays.push(RelayUrl::parse(&url)?);
                }
                Ok(Self::SwitchRelays(Some(relays)))
            }
        }
    }

    /// Wire encoding of the result (string placed in the JSON `result`
    /// field).
    ///
    /// `SignEvent` produces a JSON-encoded event, `SwitchRelays`
    /// produces a JSON-encoded array (or the literal `null`), every
    /// other variant is a single token.
    #[must_use]
    pub fn to_wire(&self) -> String {
        match self {
            Self::Ack => "ack".to_owned(),
            Self::ConnectSecret(s)
            | Self::Nip04Encrypt(s)
            | Self::Nip04Decrypt(s)
            | Self::Nip44Encrypt(s)
            | Self::Nip44Decrypt(s) => s.clone(),
            Self::GetPublicKey(pk) => pk.to_hex(),
            Self::SignEvent(ev) => ev.try_to_json().unwrap_or_default(),
            Self::Pong => "pong".to_owned(),
            Self::SwitchRelays(None) => "null".to_owned(),
            Self::SwitchRelays(Some(relays)) => {
                let urls: Vec<&str> = relays.iter().map(RelayUrl::as_str).collect();
                serde_json::to_string(&urls).unwrap_or_else(|_| "null".to_owned())
            }
            Self::AuthUrl => "auth_url".to_owned(),
            Self::Error => "error".to_owned(),
        }
    }

    /// `true` if this is the `auth_url` sentinel.
    #[must_use]
    pub const fn is_auth_url(&self) -> bool {
        matches!(self, Self::AuthUrl)
    }

    /// `true` if this is the `error` sentinel.
    #[must_use]
    pub const fn is_error(&self) -> bool {
        matches!(self, Self::Error)
    }
}

/// Decoded response (result + optional error).
///
/// At most one of `result` / `error` is meaningful at a time; the
/// other is `None`. The wire format always carries both fields, with
/// `null` for the slot that doesn't apply.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Response {
    /// Decoded `result` slot.
    pub result: Option<ResponseResult>,
    /// Optional human-readable error message (carries the auth URL
    /// when `result == Some(AuthUrl)`).
    pub error: Option<String>,
}

impl Response {
    /// Build a successful response.
    #[must_use]
    pub const fn with_result(result: ResponseResult) -> Self {
        Self {
            result: Some(result),
            error: None,
        }
    }

    /// Build an error response.
    #[must_use]
    pub fn with_error(error: impl Into<String>) -> Self {
        Self {
            result: None,
            error: Some(error.into()),
        }
    }

    /// Decode a wire `(result?, error?)` pair given the originating method.
    ///
    /// # Errors
    ///
    /// Forwards every failure from [`ResponseResult::from_wire`].
    pub fn from_wire(
        method: Method,
        result: Option<&str>,
        error: Option<String>,
    ) -> Result<Self, Nip46Error> {
        let decoded = match result {
            Some(s) => Some(ResponseResult::from_wire(method, s)?),
            None => None,
        };
        Ok(Self {
            result: decoded,
            error,
        })
    }
}

/// Wire envelope: a request *or* a response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum Message {
    /// Request frame.
    Request {
        /// Caller-chosen identifier; the response carries the same
        /// `id` so the requester can match them up.
        id: String,
        /// Method to invoke.
        method: Method,
        /// Wire-format params (each element pre-stringified).
        params: Vec<String>,
    },
    /// Response frame.
    Response {
        /// Matches the `id` of the originating [`Self::Request`].
        id: String,
        /// Result slot — always present in the JSON, possibly
        /// `null`.
        result: Option<String>,
        /// Error slot — always present in the JSON, possibly
        /// `null`.
        error: Option<String>,
    },
}

impl Message {
    /// Build a request envelope from a typed [`Request`] and an
    /// arbitrary id (typically a random `u32` or a UUID).
    #[must_use]
    pub fn request(id: impl Into<String>, request: &Request) -> Self {
        Self::Request {
            id: id.into(),
            method: request.method(),
            params: request.params(),
        }
    }

    /// Build a response envelope from a typed [`Response`] and the
    /// originating request id.
    #[must_use]
    pub fn response(id: impl Into<String>, response: Response) -> Self {
        Self::Response {
            id: id.into(),
            result: response.result.as_ref().map(ResponseResult::to_wire),
            error: response.error,
        }
    }

    /// Borrow the envelope id (matches across request/response).
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::Request { id, .. } | Self::Response { id, .. } => id,
        }
    }

    /// Decode a [`Self::Request`] envelope into a typed [`Request`].
    ///
    /// # Errors
    ///
    /// Returns [`Nip46Error::WrongMessageKind`] when the envelope is
    /// actually a response, and forwards every parse error from
    /// [`Request::from_wire`].
    pub fn into_request(self) -> Result<Request, Nip46Error> {
        match self {
            Self::Request { method, params, .. } => Request::from_wire(method, &params),
            Self::Response { .. } => Err(Nip46Error::WrongMessageKind(
                "expected Request, got Response",
            )),
        }
    }

    /// Decode a [`Self::Response`] envelope into a typed [`Response`].
    ///
    /// # Errors
    ///
    /// Returns [`Nip46Error::WrongMessageKind`] when the envelope is
    /// actually a request, and forwards every parse error from
    /// [`Response::from_wire`].
    pub fn into_response(self, method: Method) -> Result<Response, Nip46Error> {
        match self {
            Self::Response { result, error, .. } => {
                Response::from_wire(method, result.as_deref(), error)
            }
            Self::Request { .. } => Err(Nip46Error::WrongMessageKind(
                "expected Response, got Request",
            )),
        }
    }
}

// `JsonUtil` is auto-implemented for every `Serialize + DeserializeOwned`
// type via the blanket `impl<T> JsonUtil for T` in `crate::util::json`,
// so `Message::try_to_json` and `Message::from_json` work without an
// explicit impl block.

/// Connection metadata advertised by a `nostrconnect://` URI.
///
/// The signer renders these fields when prompting the user to approve
/// the connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Metadata {
    /// Human-readable app name.
    pub name: String,
    /// Optional homepage URL.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub url: Option<String>,
    /// Optional one-line description.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub description: Option<String>,
    /// Optional list of icon URLs (for the signer's UI).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub icons: Option<Vec<String>>,
}

impl Metadata {
    /// Construct minimal metadata with just an app name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            url: None,
            description: None,
            icons: None,
        }
    }
}

// `JsonUtil` for `Metadata` comes from the blanket impl (see comment
// on `Message`).

/// Connection URI: `bunker://` or `nostrconnect://`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Uri {
    /// `bunker://<remote_signer_pubkey>?relay=…&relay=…&secret=…`
    ///
    /// The signer publishes this URI; the client dials the listed
    /// relays and addresses the signer's pubkey directly.
    Bunker {
        /// Remote signer's pubkey (the one the client encrypts to).
        remote_signer_public_key: PublicKey,
        /// Relays the signer is listening on (in preference order).
        relays: Vec<RelayUrl>,
        /// Optional one-time secret the client must echo to prove the
        /// URI was used by the intended party.
        secret: Option<String>,
    },
    /// `nostrconnect://<client_pubkey>?relay=…&metadata=…&secret=…&perms=…`
    ///
    /// The client publishes this URI (typically as a QR code); the
    /// signer dials the listed relays and addresses the client's
    /// pubkey. NIP-46 makes the `secret` field **mandatory** in this
    /// flow — the signer must echo it back inside the `connect`
    /// response so the client can rule out an MITM.
    Client {
        /// App's session pubkey.
        public_key: PublicKey,
        /// Relays both sides will rendezvous on.
        relays: Vec<RelayUrl>,
        /// App identity metadata.
        metadata: Metadata,
        /// Anti-spoofing secret (mandatory).
        secret: String,
        /// Optional requested permissions (NIP-46 § "Requested
        /// permissions"); empty when omitted from the URI.
        perms: Vec<Permission>,
    },
}

impl Uri {
    /// Parse a `bunker://` or `nostrconnect://` URI.
    ///
    /// # Errors
    ///
    /// See [`Nip46Error`].
    pub fn parse(uri: &str) -> Result<Self, Nip46Error> {
        let parsed = Url::parse(uri)?;
        let host = parsed
            .host_str()
            .ok_or(Nip46Error::MalformedUri("missing pubkey host"))?;
        let public_key = PublicKey::parse(host)?;

        let mut relays: Vec<RelayUrl> = Vec::new();
        let mut secret: Option<String> = None;
        let mut metadata: Option<Metadata> = None;
        let mut perms: Vec<Permission> = Vec::new();
        for (key, value) in parsed.query_pairs() {
            match key.as_ref() {
                "relay" => relays.push(RelayUrl::parse(value.as_ref())?),
                "secret" => secret = Some(value.into_owned()),
                "metadata" => metadata = Some(Metadata::from_json(value.as_ref())?),
                "perms" => perms = Permission::split(value.as_ref()),
                // Forward-compat: silently drop unknown query
                // parameters (vendor-specific keys we have no model for).
                _ => {}
            }
        }

        match parsed.scheme() {
            URI_SCHEME_BUNKER => Ok(Self::Bunker {
                remote_signer_public_key: public_key,
                relays,
                secret,
            }),
            URI_SCHEME_CLIENT => {
                let secret = secret.ok_or(Nip46Error::MalformedUri(
                    "`nostrconnect://` URIs require the `secret` query parameter",
                ))?;
                let metadata = metadata.ok_or(Nip46Error::MalformedUri(
                    "`nostrconnect://` URIs require the `metadata` query parameter",
                ))?;
                Ok(Self::Client {
                    public_key,
                    relays,
                    metadata,
                    secret,
                    perms,
                })
            }
            other => Err(Nip46Error::UnknownUriScheme(other.to_owned())),
        }
    }

    /// `true` if this is a `bunker://` URI.
    #[must_use]
    pub const fn is_bunker(&self) -> bool {
        matches!(self, Self::Bunker { .. })
    }

    /// Borrow the relay set the URI advertises.
    #[must_use]
    pub fn relays(&self) -> &[RelayUrl] {
        match self {
            Self::Bunker { relays, .. } | Self::Client { relays, .. } => relays,
        }
    }

    /// Borrow the secret slot (always `Some` for `Client`, optional
    /// for `Bunker`).
    #[must_use]
    pub fn secret(&self) -> Option<&str> {
        match self {
            Self::Bunker { secret, .. } => secret.as_deref(),
            Self::Client { secret, .. } => Some(secret),
        }
    }
}

impl FromStr for Uri {
    type Err = Nip46Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for Uri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bunker {
                remote_signer_public_key,
                relays,
                secret,
            } => {
                write!(f, "{URI_SCHEME_BUNKER}://{remote_signer_public_key}")?;
                write_query(f, relays, secret.as_deref(), None, &[])
            }
            Self::Client {
                public_key,
                relays,
                metadata,
                secret,
                perms,
            } => {
                write!(f, "{URI_SCHEME_CLIENT}://{public_key}")?;
                let metadata_json = metadata.try_to_json().unwrap_or_default();
                write_query(f, relays, Some(secret), Some(&metadata_json), perms)
            }
        }
    }
}

fn write_query(
    out: &mut fmt::Formatter<'_>,
    relays: &[RelayUrl],
    secret: Option<&str>,
    metadata_json: Option<&str>,
    perms: &[Permission],
) -> fmt::Result {
    let mut first = true;
    let mut emit = |sink: &mut fmt::Formatter<'_>, key: &str, value: &str| -> fmt::Result {
        sink.write_str(if first { "?" } else { "&" })?;
        first = false;
        write!(sink, "{key}={}", url_encode(value))
    };
    for relay in relays {
        emit(out, "relay", relay.as_str())?;
    }
    if let Some(meta) = metadata_json {
        emit(out, "metadata", meta)?;
    }
    if let Some(s) = secret {
        emit(out, "secret", s)?;
    }
    if !perms.is_empty() {
        emit(out, "perms", &Permission::join(perms))?;
    }
    Ok(())
}

/// Minimal percent-encoding for query-string values. Encodes the
/// reserved `:?#[]@!$&'()*+,;=` plus `%` and whitespace; everything
/// else passes through unchanged. This is a tighter set than the full
/// RFC-3986 spec but is sufficient for the values we ever produce
/// (relay URLs, base64, JSON).
fn url_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        let preserve =
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~' | b'/' | b':');
        if preserve {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(hex_nibble(byte >> 4));
            out.push(hex_nibble(byte & 0x0f));
        }
    }
    out
}

const fn hex_nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'A' + (n - 10)) as char,
        _ => '0',
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;

    fn fixture_pk() -> PublicKey {
        // Deterministic fixture; the exact value doesn't matter for
        // the round-trip / parse tests below.
        *Keys::parse("0000000000000000000000000000000000000000000000000000000000000003")
            .unwrap()
            .public_key()
    }

    #[test]
    fn method_round_trips_through_str() {
        for method in [
            Method::Connect,
            Method::GetPublicKey,
            Method::SignEvent,
            Method::Nip04Encrypt,
            Method::Nip04Decrypt,
            Method::Nip44Encrypt,
            Method::Nip44Decrypt,
            Method::Ping,
            Method::SwitchRelays,
        ] {
            let s = method.as_str();
            let parsed: Method = s.parse().unwrap();
            assert_eq!(parsed, method);
        }
    }

    #[test]
    fn unknown_method_is_rejected() {
        let err: Nip46Error = "open_my_drone".parse::<Method>().unwrap_err();
        assert!(matches!(err, Nip46Error::UnsupportedMethod(s) if s == "open_my_drone"));
    }

    #[test]
    fn request_round_trip_through_wire_params() {
        let pk = fixture_pk();
        let cases: Vec<Request> = vec![
            Request::Connect {
                remote_signer_public_key: pk,
                secret: Some("hunter2".to_owned()),
                perms: None,
            },
            Request::Connect {
                remote_signer_public_key: pk,
                secret: None,
                perms: None,
            },
            Request::Connect {
                remote_signer_public_key: pk,
                secret: Some("hunter2".to_owned()),
                perms: Some(vec![
                    Permission::Method(Method::Nip44Encrypt),
                    Permission::SignEventKind(Kind::TEXT_NOTE),
                ]),
            },
            Request::Connect {
                remote_signer_public_key: pk,
                secret: None,
                perms: Some(vec![Permission::Method(Method::GetPublicKey)]),
            },
            Request::Connect {
                remote_signer_public_key: pk,
                secret: None,
                perms: Some(Vec::new()),
            },
            Request::GetPublicKey,
            Request::Nip04Encrypt {
                peer: pk,
                text: "hi".to_owned(),
            },
            Request::Nip04Decrypt {
                peer: pk,
                ciphertext: "AAAA?iv=AAAA".to_owned(),
            },
            Request::Nip44Encrypt {
                peer: pk,
                text: "hello".to_owned(),
            },
            Request::Nip44Decrypt {
                peer: pk,
                ciphertext: "AgAB...".to_owned(),
            },
            Request::Ping,
            Request::SwitchRelays,
        ];

        for req in cases {
            let method = req.method();
            let params = req.params();
            let recovered = Request::from_wire(method, &params).unwrap();
            assert_eq!(recovered, req);
        }
    }

    #[test]
    fn request_param_count_validation() {
        let pk = fixture_pk();
        let bad = Request::from_wire(Method::Nip04Encrypt, &[pk.to_hex()]).unwrap_err();
        assert!(matches!(
            bad,
            Nip46Error::InvalidParamLength {
                method: Method::Nip04Encrypt,
                expected: 2,
                actual: 1,
            }
        ));
    }

    #[test]
    fn response_decode_handles_universal_sentinels() {
        let auth = ResponseResult::from_wire(Method::SignEvent, "auth_url").unwrap();
        assert!(auth.is_auth_url());
        let err = ResponseResult::from_wire(Method::Connect, "error").unwrap();
        assert!(err.is_error());
    }

    #[test]
    fn response_decode_for_each_method() {
        let pk = fixture_pk();
        // GetPublicKey
        match ResponseResult::from_wire(Method::GetPublicKey, &pk.to_hex()).unwrap() {
            ResponseResult::GetPublicKey(decoded) => assert_eq!(decoded, pk),
            other => panic!("unexpected variant: {other:?}"),
        }
        // Connect with literal "ack"
        let ack = ResponseResult::from_wire(Method::Connect, "ack").unwrap();
        assert!(matches!(ack, ResponseResult::Ack));
        // Connect with custom secret
        let secret = ResponseResult::from_wire(Method::Connect, "abcdef0123").unwrap();
        assert!(matches!(secret, ResponseResult::ConnectSecret(s) if s == "abcdef0123"));
        // Ping happy path
        let pong = ResponseResult::from_wire(Method::Ping, "pong").unwrap();
        assert!(matches!(pong, ResponseResult::Pong));
        // Ping unhappy path
        let err = ResponseResult::from_wire(Method::Ping, "ping").unwrap_err();
        assert!(matches!(err, Nip46Error::UnexpectedResponse { .. }));
    }

    #[test]
    fn message_request_round_trips_through_json() {
        let pk = fixture_pk();
        let request = Request::Nip44Encrypt {
            peer: pk,
            text: "hello".to_owned(),
        };
        let msg = Message::request("req-1", &request);
        let json = msg.try_to_json().unwrap();
        let recovered = Message::from_json(&json).unwrap();
        assert_eq!(recovered.id(), "req-1");
        let recovered_req = recovered.into_request().unwrap();
        assert_eq!(recovered_req, request);
    }

    #[test]
    fn message_response_round_trips_through_json() {
        let response = Response::with_result(ResponseResult::Pong);
        let msg = Message::response("ping-42", response);
        let json = msg.try_to_json().unwrap();
        let recovered = Message::from_json(&json).unwrap();
        assert_eq!(recovered.id(), "ping-42");
        let recovered_resp = recovered.into_response(Method::Ping).unwrap();
        assert!(matches!(recovered_resp.result, Some(ResponseResult::Pong)));
        assert!(recovered_resp.error.is_none());
    }

    #[test]
    fn into_request_rejects_response_envelopes() {
        let msg = Message::Response {
            id: "x".into(),
            result: Some("ack".into()),
            error: None,
        };
        let err = msg.into_request().unwrap_err();
        assert!(matches!(err, Nip46Error::WrongMessageKind(_)));
    }

    #[test]
    fn bunker_uri_round_trip() {
        let pk = fixture_pk();
        let original = format!(
            "bunker://{}?relay=wss%3A%2F%2Frelay.example%2F&secret=hunter2",
            pk.to_hex(),
        );
        let parsed = Uri::parse(&original).unwrap();
        match &parsed {
            Uri::Bunker {
                remote_signer_public_key,
                relays,
                secret,
            } => {
                assert_eq!(*remote_signer_public_key, pk);
                assert_eq!(relays.len(), 1);
                assert_eq!(relays[0].as_str(), "wss://relay.example/");
                assert_eq!(secret.as_deref(), Some("hunter2"));
            }
            other => panic!("unexpected variant: {other:?}"),
        }
        // Reformatted output is parseable again — we don't compare the
        // strings byte-for-byte because the percent-encoding may
        // differ (URLs are unique per character set, not per byte
        // representation).
        let rendered = parsed.to_string();
        let reparsed = Uri::parse(&rendered).unwrap();
        assert_eq!(reparsed, parsed);
    }

    #[test]
    fn nostrconnect_uri_requires_secret() {
        let pk = fixture_pk();
        let bad = format!(
            "nostrconnect://{}?relay=wss%3A%2F%2Frelay.example%2F&metadata=%7B%22name%22%3A%22demo%22%7D",
            pk.to_hex(),
        );
        let err = Uri::parse(&bad).unwrap_err();
        assert!(matches!(err, Nip46Error::MalformedUri(_)));
    }

    #[test]
    fn nostrconnect_uri_round_trip() {
        let pk = fixture_pk();
        let metadata = Metadata::new("demo");
        let original = Uri::Client {
            public_key: pk,
            relays: vec![RelayUrl::parse("wss://relay.example/").unwrap()],
            metadata: metadata.clone(),
            secret: "anti-mitm".into(),
            perms: Vec::new(),
        };
        let rendered = original.to_string();
        let reparsed = Uri::parse(&rendered).unwrap();
        assert_eq!(reparsed, original);
        assert_eq!(reparsed.secret(), Some("anti-mitm"));
        match reparsed {
            Uri::Client {
                metadata: parsed_meta,
                ..
            } => assert_eq!(parsed_meta, metadata),
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn unknown_scheme_is_rejected() {
        let pk = fixture_pk();
        let err = Uri::parse(&format!("nip46://{}", pk.to_hex())).unwrap_err();
        assert!(matches!(err, Nip46Error::UnknownUriScheme(s) if s == "nip46"));
    }

    #[test]
    fn permission_token_round_trips() {
        // Bare method.
        let bare: Permission = "get_public_key".parse().unwrap();
        assert_eq!(bare, Permission::Method(Method::GetPublicKey));
        assert_eq!(bare.to_wire(), "get_public_key");
        // sign_event:<kind>
        let kinded: Permission = "sign_event:4".parse().unwrap();
        assert_eq!(kinded, Permission::SignEventKind(Kind::new(4)));
        assert_eq!(kinded.to_wire(), "sign_event:4");
        // Vendor / future-spec passthrough preserves the verbatim wire.
        let vendor: Permission = "weird_vendor:opt=1".parse().unwrap();
        assert_eq!(vendor, Permission::Other("weird_vendor:opt=1".to_owned()));
        assert_eq!(vendor.to_wire(), "weird_vendor:opt=1");
        // sign_event with a non-numeric tail falls into Other rather than
        // a parse error — spec leaves param shapes extensible.
        let extensible: Permission = "sign_event:any".parse().unwrap();
        assert_eq!(extensible, Permission::Other("sign_event:any".to_owned()));
    }

    #[test]
    fn permission_list_round_trips_via_join_split() {
        // Mirrors the spec example string at NIP-46 line 112.
        let perms = vec![
            Permission::Method(Method::Nip44Encrypt),
            Permission::SignEventKind(Kind::new(4)),
        ];
        let joined = Permission::join(&perms);
        assert_eq!(joined, "nip44_encrypt,sign_event:4");
        let parsed = Permission::split(&joined);
        assert_eq!(parsed, perms);
        // Empty string \u2192 empty vec; whitespace tolerated.
        assert!(Permission::split("").is_empty());
        assert_eq!(
            Permission::split(" ping , sign_event:1 "),
            vec![
                Permission::Method(Method::Ping),
                Permission::SignEventKind(Kind::TEXT_NOTE),
            ],
        );
    }

    #[test]
    fn connect_request_with_perms_emits_positional_layout() {
        let pk = fixture_pk();
        // perms-only: position 1 (secret) is a placeholder empty string
        // so position 2 (perms) keeps its index.
        let req = Request::Connect {
            remote_signer_public_key: pk,
            secret: None,
            perms: Some(vec![Permission::Method(Method::GetPublicKey)]),
        };
        let params = req.params();
        assert_eq!(params.len(), 3);
        assert_eq!(params[0], pk.to_hex());
        assert_eq!(params[1], "");
        assert_eq!(params[2], "get_public_key");
        let recovered = Request::from_wire(Method::Connect, &params).unwrap();
        assert_eq!(recovered, req);
    }

    #[test]
    fn switch_relays_response_round_trips_through_wire() {
        // null branch: spec line 108 explicit `OR null`.
        let null_value = ResponseResult::SwitchRelays(None);
        assert_eq!(null_value.to_wire(), "null");
        let null_recovered = ResponseResult::from_wire(Method::SwitchRelays, "null").unwrap();
        assert_eq!(null_recovered, null_value);

        // empty-array branch.
        let empty_value = ResponseResult::SwitchRelays(Some(Vec::new()));
        let empty_wire = empty_value.to_wire();
        assert_eq!(empty_wire, "[]");
        let empty_recovered = ResponseResult::from_wire(Method::SwitchRelays, &empty_wire).unwrap();
        assert_eq!(empty_recovered, empty_value);

        // non-empty array branch.
        let relays = vec![
            RelayUrl::parse("wss://relay.one/").unwrap(),
            RelayUrl::parse("wss://relay.two/").unwrap(),
        ];
        let populated = ResponseResult::SwitchRelays(Some(relays));
        let populated_wire = populated.to_wire();
        let populated_recovered =
            ResponseResult::from_wire(Method::SwitchRelays, &populated_wire).unwrap();
        assert_eq!(populated_recovered, populated);

        // malformed JSON \u2192 dedicated error variant.
        let err =
            ResponseResult::from_wire(Method::SwitchRelays, "not-json").expect_err("must reject");
        assert!(matches!(err, Nip46Error::InvalidSwitchRelaysPayload));
    }

    #[test]
    fn switch_relays_request_envelope_round_trips_through_json() {
        let msg = Message::request("sw-1", &Request::SwitchRelays);
        let json = msg.try_to_json().unwrap();
        let recovered = Message::from_json(&json).unwrap();
        assert_eq!(recovered.id(), "sw-1");
        let req = recovered.into_request().unwrap();
        assert_eq!(req, Request::SwitchRelays);
    }

    #[test]
    fn nostrconnect_uri_carries_perms_round_trip() {
        let pk = fixture_pk();
        let metadata = Metadata::new("demo");
        let original = Uri::Client {
            public_key: pk,
            relays: vec![RelayUrl::parse("wss://relay.example/").unwrap()],
            metadata,
            secret: "anti-mitm".into(),
            perms: vec![
                Permission::Method(Method::Nip44Encrypt),
                Permission::Method(Method::Nip44Decrypt),
                Permission::SignEventKind(Kind::new(13)),
                Permission::SignEventKind(Kind::new(14)),
                Permission::SignEventKind(Kind::new(1059)),
            ],
        };
        let rendered = original.to_string();
        assert!(rendered.contains("perms="));
        let reparsed = Uri::parse(&rendered).unwrap();
        assert_eq!(reparsed, original);
    }
}
