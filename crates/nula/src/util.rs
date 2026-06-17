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

/// Collect an iterator of [`IntoRelayUrl`] inputs into a `Vec<RelayUrl>`.
///
/// Used internally by the multi-target `Client::send_event_to`,
/// `Client::subscribe_to`, and friends to accept heterogenous
/// iterators of `&str` / `String` / `RelayUrl` without forcing
/// callers to do the conversion themselves.
///
/// # Errors
///
/// Returns the first [`RelayUrlError`] encountered while parsing
/// any element of `iter`.
pub fn collect_relay_urls<I, U>(iter: I) -> Result<Vec<RelayUrl>, RelayUrlError>
where
    I: IntoIterator<Item = U>,
    U: IntoRelayUrl,
{
    iter.into_iter().map(IntoRelayUrl::into_relay_url).collect()
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

    #[test]
    fn collect_relay_urls_mixed_inputs() {
        let urls = collect_relay_urls([
            "wss://relay.one.com",
            "wss://relay.two.com",
            "wss://relay.three.com",
        ])
        .unwrap();
        assert_eq!(urls.len(), 3);
        assert_eq!(urls.first().map(RelayUrl::host), Some("relay.one.com"));
        assert_eq!(urls.get(2).map(RelayUrl::host), Some("relay.three.com"));
    }

    #[test]
    fn collect_relay_urls_surfaces_first_error() {
        let err = collect_relay_urls(["wss://relay.ok.com", "not a url"]).unwrap_err();
        assert!(matches!(err, RelayUrlError::Parse(_)));
    }
}
