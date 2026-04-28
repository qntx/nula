// Copyright (c) 2026 QNTX <https://qntx.fun>
// Distributed under the MIT or Apache-2.0 license.

//! WebSocket relay URL.
//!
//! Per [NIP-01], a relay is identified by a `ws://` or `wss://` URL. This
//! module gives that constraint a strongly-typed home — [`RelayUrl`] — so
//! callers cannot accidentally hand a relay an `https://` URL or vice versa.
//! Construction also normalises the URL so two relays that differ only by
//! casing or fragment compare equal.
//!
//! The normalisation rules applied at parse time are:
//!
//! - the scheme is lowercased (and validated to be `ws` or `wss`),
//! - the host is lowercased,
//! - any fragment is stripped,
//! - the default port for the scheme (`80` for `ws`, `443` for `wss`) is
//!   removed, and
//! - the path's trailing slash, when it is the only content of the path, is
//!   left untouched (NIP-29 relay groups encode information in the path, so we
//!   never trim it).
//!
//! [NIP-01]: https://github.com/nostr-protocol/nips/blob/master/01.md

use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// Errors returned by [`RelayUrl`] constructors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RelayUrlError {
    /// The input could not be parsed as a URL at all.
    #[error("invalid relay URL: {0}")]
    Parse(#[from] url::ParseError),
    /// The scheme is not `ws` or `wss`.
    #[error("invalid relay scheme `{0}`: expected `ws` or `wss`")]
    InvalidScheme(String),
    /// The URL has no host (e.g. `ws:///path`).
    #[error("relay URL has no host: {0}")]
    MissingHost(String),
    /// The URL was syntactically valid but the [`url`] crate refused the
    /// `set_port(None)` call when stripping the default port. In practice
    /// unreachable for `ws`/`wss` schemes, but kept as an explicit
    /// failure mode rather than a `String` fallback.
    #[error("relay URL cannot have its port modified")]
    PortNotModifiable,
}

/// WebSocket relay URL.
///
/// Always uses scheme `ws` or `wss`. Constructors normalize the value, so
/// `RelayUrl::parse("WSS://Relay.Damus.io/").unwrap()` is equal to
/// `RelayUrl::parse("wss://relay.damus.io/").unwrap()`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RelayUrl {
    inner: url::Url,
}

impl RelayUrl {
    /// Parse a string as a [`RelayUrl`], applying the documented normalisation.
    ///
    /// # Errors
    ///
    /// Returns [`RelayUrlError::Parse`] if the input is not a valid URL,
    /// [`RelayUrlError::InvalidScheme`] if the scheme is not `ws`/`wss`, or
    /// [`RelayUrlError::MissingHost`] if no host is present.
    pub fn parse<S>(input: S) -> Result<Self, RelayUrlError>
    where
        S: AsRef<str>,
    {
        let input = input.as_ref();
        let mut inner = url::Url::parse(input)?;

        // Fold scheme validation and default-port lookup into a single match
        // so the validated invariant ("scheme is ws or wss") cannot drift
        // away from the lookup table. This eliminates the previous
        // `unreachable!()` fallback, which was a `panic!` in production code.
        let default_port = match inner.scheme() {
            "ws" => 80,
            "wss" => 443,
            other => return Err(RelayUrlError::InvalidScheme(other.to_owned())),
        };

        if inner.host_str().is_none() {
            return Err(RelayUrlError::MissingHost(input.to_owned()));
        }

        inner.set_fragment(None);
        if inner.port() == Some(default_port) {
            inner
                .set_port(None)
                .map_err(|()| RelayUrlError::PortNotModifiable)?;
        }

        Ok(Self { inner })
    }

    /// Borrow the underlying [`url::Url`].
    #[must_use]
    pub const fn as_url(&self) -> &url::Url {
        &self.inner
    }

    /// Return the URL as a borrowed string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.inner.as_str()
    }

    /// Return the scheme — always `"ws"` or `"wss"`.
    #[must_use]
    pub fn scheme(&self) -> &str {
        self.inner.scheme()
    }

    /// Return the host — always present after construction.
    #[must_use]
    pub fn host(&self) -> &str {
        // Validated at construction: `host_str().is_some()`.
        self.inner.host_str().unwrap_or("")
    }

    /// Whether this is a `wss://` URL.
    #[must_use]
    pub fn is_secure(&self) -> bool {
        self.inner.scheme() == "wss"
    }

    /// Whether the host ends with `.onion`.
    #[must_use]
    #[allow(
        clippy::case_sensitive_file_extension_comparisons,
        reason = "hostnames are ASCII-lowercased at construction time"
    )]
    pub fn is_onion(&self) -> bool {
        self.host().ends_with(".onion")
    }
}

impl fmt::Display for RelayUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

impl FromStr for RelayUrl {
    type Err = RelayUrlError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl AsRef<str> for RelayUrl {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Serialize for RelayUrl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RelayUrl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = <&str>::deserialize(deserializer)?;
        Self::parse(raw).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_wss() {
        let url = RelayUrl::parse("wss://relay.damus.io").unwrap();
        assert!(url.is_secure());
        assert_eq!(url.host(), "relay.damus.io");
    }

    #[test]
    fn parse_ws() {
        let url = RelayUrl::parse("ws://localhost:7777/").unwrap();
        assert!(!url.is_secure());
        assert_eq!(url.host(), "localhost");
    }

    #[test]
    fn lowercases_scheme_and_host() {
        let upper = RelayUrl::parse("WSS://Relay.Damus.IO/").unwrap();
        let lower = RelayUrl::parse("wss://relay.damus.io/").unwrap();
        assert_eq!(upper, lower);
    }

    #[test]
    fn strips_fragment() {
        let with = RelayUrl::parse("wss://relay.example.com/#frag").unwrap();
        let without = RelayUrl::parse("wss://relay.example.com/").unwrap();
        assert_eq!(with, without);
    }

    #[test]
    fn strips_default_port() {
        let with = RelayUrl::parse("wss://relay.example.com:443/").unwrap();
        let without = RelayUrl::parse("wss://relay.example.com/").unwrap();
        assert_eq!(with, without);

        let ws_with = RelayUrl::parse("ws://relay.example.com:80/").unwrap();
        let ws_without = RelayUrl::parse("ws://relay.example.com/").unwrap();
        assert_eq!(ws_with, ws_without);
    }

    #[test]
    fn keeps_non_default_port() {
        let url = RelayUrl::parse("wss://relay.example.com:8080/").unwrap();
        assert_eq!(url.as_str(), "wss://relay.example.com:8080/");
    }

    #[test]
    fn keeps_path() {
        let url = RelayUrl::parse("wss://groups.fiatjaf.com/relay29/").unwrap();
        assert_eq!(url.as_str(), "wss://groups.fiatjaf.com/relay29/");
    }

    #[test]
    fn rejects_https() {
        let err = RelayUrl::parse("https://relay.damus.io").unwrap_err();
        assert!(matches!(err, RelayUrlError::InvalidScheme(_)));
    }

    #[test]
    fn rejects_invalid_url() {
        let err = RelayUrl::parse("not a url").unwrap_err();
        assert!(matches!(err, RelayUrlError::Parse(_)));
    }

    #[test]
    fn detects_onion() {
        let url =
            RelayUrl::parse("ws://jgqaglhautb4k6e6i2g34jakxiemqp6z4wynlirltuukgkft2xuglmqd.onion")
                .unwrap();
        assert!(url.is_onion());
    }

    #[test]
    fn serde_round_trip() {
        let url = RelayUrl::parse("wss://relay.damus.io").unwrap();
        let json = serde_json::to_string(&url).unwrap();
        let parsed: RelayUrl = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, url);
    }
}
