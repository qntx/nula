//! Small ergonomic helpers shared by the public [`crate::Client`]
//! surface.

use nula_core::types::{RelayUrl, RelayUrlError};

/// Anything that can become a [`RelayUrl`] without an explicit
/// `RelayUrl::parse` call.
///
/// Implemented for [`RelayUrl`], `&str`, `String`, and `&String`,
/// which covers every practical caller without forcing a trait
/// import.
pub trait IntoRelayUrl {
    /// Convert into a [`RelayUrl`].
    ///
    /// # Errors
    ///
    /// Forwards [`RelayUrlError`] from the underlying parser.
    fn into_relay_url(self) -> Result<RelayUrl, RelayUrlError>;
}

impl IntoRelayUrl for RelayUrl {
    fn into_relay_url(self) -> Result<RelayUrl, RelayUrlError> {
        Ok(self)
    }
}

impl IntoRelayUrl for &RelayUrl {
    fn into_relay_url(self) -> Result<RelayUrl, RelayUrlError> {
        Ok(self.clone())
    }
}

impl IntoRelayUrl for &str {
    fn into_relay_url(self) -> Result<RelayUrl, RelayUrlError> {
        RelayUrl::parse(self)
    }
}

impl IntoRelayUrl for String {
    fn into_relay_url(self) -> Result<RelayUrl, RelayUrlError> {
        RelayUrl::parse(&self)
    }
}

impl IntoRelayUrl for &String {
    fn into_relay_url(self) -> Result<RelayUrl, RelayUrlError> {
        RelayUrl::parse(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn str_round_trips() {
        let url = "wss://relay.example.com".into_relay_url().unwrap();
        assert_eq!(url.host(), "relay.example.com");
    }

    #[test]
    fn relay_url_passthrough() {
        let original = RelayUrl::parse("wss://relay.example.com").unwrap();
        let cloned = original.clone().into_relay_url().unwrap();
        assert_eq!(cloned, original);
    }

    #[test]
    fn invalid_str_errors() {
        let err = "not a url".into_relay_url().unwrap_err();
        assert!(matches!(err, RelayUrlError::Parse(_)));
    }
}
