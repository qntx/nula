//! JSON serialization helper trait.
//!
//! [`JsonUtil`] is implemented automatically for every `serde::Serialize +
//! serde::DeserializeOwned` type and gives Nostr value objects (events,
//! filters, messages, …) a uniform `to_json` / `from_json` API. It is the
//! ergonomic equivalent of `serde_json::to_string` / `serde_json::from_str`
//! that callers reach for in 99% of cases.

use serde::Serialize;
use serde::de::DeserializeOwned;

/// Convenience JSON serialization API for Nostr value types.
///
/// Auto-implemented for any `T: Serialize + DeserializeOwned` so callers can
/// just `use nula_core::JsonUtil` and call `event.to_json()`.
pub trait JsonUtil: Sized + Serialize + DeserializeOwned {
    /// Serialize to a compact JSON [`String`].
    ///
    /// # Errors
    ///
    /// Propagates [`serde_json::Error`] when serialization fails. With the
    /// default `Serialize` implementations of the `nula-core` types this is
    /// effectively unreachable, but is kept for forward compatibility with
    /// custom types and `#[serde(skip_serializing_if = ...)]` predicates that
    /// could fail.
    fn try_to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Serialize to a pretty-printed JSON [`String`].
    ///
    /// # Errors
    ///
    /// See [`Self::try_to_json`].
    fn try_to_pretty_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize from JSON.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`serde_json::Error`] when the input is not
    /// valid JSON or does not match the expected schema.
    fn from_json<S>(json: S) -> Result<Self, serde_json::Error>
    where
        S: AsRef<str>,
    {
        serde_json::from_str(json.as_ref())
    }
}

impl<T> JsonUtil for T where T: Sized + Serialize + DeserializeOwned {}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Sample {
        a: u32,
        b: String,
    }

    #[test]
    fn round_trip() {
        let value = Sample {
            a: 1,
            b: "hi".to_owned(),
        };
        let json = value.try_to_json().unwrap();
        assert_eq!(json, r#"{"a":1,"b":"hi"}"#);
        let parsed = Sample::from_json(&json).unwrap();
        assert_eq!(parsed, value);
    }

    #[test]
    fn pretty() {
        let value = Sample {
            a: 1,
            b: "hi".to_owned(),
        };
        let json = value.try_to_pretty_json().unwrap();
        assert!(json.contains('\n'));
    }
}
