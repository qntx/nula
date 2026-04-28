//! Generic absolute URL.
//!
//! A thin wrapper around [`url::Url`] that adds:
//!
//! - a stable `serde` representation (always a JSON string),
//! - a custom error type that does not leak the upstream API into our public
//!   surface, and
//! - the `?T` constructor pattern (`Url::parse` returns our own error).
//!
//! Higher-level types ([`super::RelayUrl`], NIP-19 `nevent` URIs, NIP-21
//! `nostr:` URIs) build on this primitive.

use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// Errors returned by [`Url`] constructors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum UrlError {
    /// The input could not be parsed as an absolute URL.
    #[error("invalid URL: {0}")]
    Parse(#[from] url::ParseError),
    /// The URL was relative; absolute URLs are required.
    #[error("URL must be absolute: {0}")]
    Relative(String),
}

/// Absolute URL.
///
/// Comparison and hashing are case-sensitive on every component except the
/// `scheme` and `host`, both normalized by [`url::Url`] itself.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Url {
    inner: url::Url,
}

impl Url {
    /// Parse a string as an absolute URL.
    ///
    /// # Errors
    ///
    /// Returns [`UrlError::Parse`] if the input is not a valid URL, or
    /// [`UrlError::Relative`] if it parses successfully but is relative.
    pub fn parse<S>(input: S) -> Result<Self, UrlError>
    where
        S: AsRef<str>,
    {
        let input = input.as_ref();
        let inner = url::Url::parse(input)?;
        if inner.cannot_be_a_base() {
            return Err(UrlError::Relative(input.to_owned()));
        }
        Ok(Self { inner })
    }

    /// Borrow the underlying [`url::Url`].
    #[must_use]
    pub const fn as_url(&self) -> &url::Url {
        &self.inner
    }

    /// Consume self and return the underlying [`url::Url`].
    #[must_use]
    pub fn into_url(self) -> url::Url {
        self.inner
    }

    /// Return the URL as a borrowed string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.inner.as_str()
    }

    /// Return the scheme (e.g. `"https"`, `"ws"`, `"wss"`).
    #[must_use]
    pub fn scheme(&self) -> &str {
        self.inner.scheme()
    }
}

impl fmt::Display for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

impl FromStr for Url {
    type Err = UrlError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl AsRef<str> for Url {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl From<url::Url> for Url {
    fn from(value: url::Url) -> Self {
        Self { inner: value }
    }
}

impl Serialize for Url {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Url {
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
    fn parse_https() {
        let url = Url::parse("https://example.com/path?q=1").unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.as_str(), "https://example.com/path?q=1");
    }

    #[test]
    fn parse_invalid() {
        let err = Url::parse("not a url").unwrap_err();
        assert!(matches!(err, UrlError::Parse(_)));
    }

    #[test]
    fn parse_relative() {
        let err = Url::parse("data:,Hello").unwrap_err();
        assert!(matches!(err, UrlError::Relative(_)));
    }

    #[test]
    fn from_str() {
        let url: Url = "https://example.com".parse().unwrap();
        assert_eq!(url.scheme(), "https");
    }

    #[test]
    fn serde_round_trip() {
        let url = Url::parse("https://example.com/p").unwrap();
        let json = serde_json::to_string(&url).unwrap();
        assert_eq!(json, r#""https://example.com/p""#);
        let parsed: Url = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, url);
    }

    #[test]
    fn display_matches_as_str() {
        let url = Url::parse("https://example.com/").unwrap();
        assert_eq!(url.to_string(), url.as_str());
    }
}
