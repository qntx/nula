// Copyright (c) 2026 QNTX <https://qntx.fun>
// Distributed under the MIT or Apache-2.0 license.

//! Opaque subscription identifier.
//!
//! Per NIP-01, a subscription id is a non-empty string of up to 64
//! characters. The protocol does not restrict the character set further, but
//! interoperable clients use lowercase hex random strings to avoid surprising
//! relays that index the value as a database key.

use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::util::rng::{self, RngError};

/// Maximum length permitted by NIP-01.
pub const MAX_LENGTH: usize = 64;

/// Errors raised when constructing a [`SubscriptionId`].
#[derive(Debug, Clone, Copy, Error)]
pub enum SubscriptionIdError {
    /// The input was empty.
    #[error("subscription id must not be empty")]
    Empty,
    /// The input exceeded [`MAX_LENGTH`].
    #[error("subscription id too long: {0} characters (max {MAX_LENGTH})")]
    TooLong(usize),
    /// Random generation failed because the OS RNG was unavailable.
    #[error("failed to generate subscription id: {0}")]
    Rng(#[from] RngError),
}

/// Opaque subscription identifier.
///
/// `Display` and `serde` write the value as a plain JSON string.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubscriptionId(String);

impl SubscriptionId {
    /// Construct a subscription id from a string.
    ///
    /// # Errors
    ///
    /// Returns [`SubscriptionIdError::Empty`] for an empty input or
    /// [`SubscriptionIdError::TooLong`] when longer than [`MAX_LENGTH`].
    pub fn new<S>(value: S) -> Result<Self, SubscriptionIdError>
    where
        S: Into<String>,
    {
        let value = value.into();
        Self::validate(&value)?;
        Ok(Self(value))
    }

    /// Generate a random 32-character lowercase hex subscription id.
    ///
    /// # Errors
    ///
    /// Returns [`SubscriptionIdError::Rng`] if the OS RNG fails.
    pub fn generate() -> Result<Self, SubscriptionIdError> {
        let id = rng::random_hex_string::<16>()?;
        Ok(Self(id))
    }

    /// Borrow the value as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Decompose into the underlying [`String`].
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }

    const fn validate(value: &str) -> Result<(), SubscriptionIdError> {
        if value.is_empty() {
            return Err(SubscriptionIdError::Empty);
        }
        if value.len() > MAX_LENGTH {
            return Err(SubscriptionIdError::TooLong(value.len()));
        }
        Ok(())
    }
}

impl fmt::Display for SubscriptionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for SubscriptionId {
    type Err = SubscriptionIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.to_owned())
    }
}

impl AsRef<str> for SubscriptionId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Serialize for SubscriptionId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SubscriptionId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_round_trip() {
        let id = SubscriptionId::new("abcdef").unwrap();
        assert_eq!(id.as_str(), "abcdef");
    }

    #[test]
    fn empty_is_rejected() {
        let err = SubscriptionId::new("").unwrap_err();
        assert!(matches!(err, SubscriptionIdError::Empty));
    }

    #[test]
    fn too_long_is_rejected() {
        let value = "a".repeat(MAX_LENGTH + 1);
        let err = SubscriptionId::new(value).unwrap_err();
        assert!(matches!(err, SubscriptionIdError::TooLong(_)));
    }

    #[test]
    fn generate_unique() {
        let lhs = SubscriptionId::generate().unwrap();
        let rhs = SubscriptionId::generate().unwrap();
        assert_ne!(lhs, rhs);
        assert_eq!(lhs.as_str().len(), 32);
    }

    #[test]
    fn serde_round_trip() {
        let id = SubscriptionId::new("query-1").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, r#""query-1""#);
        let parsed: SubscriptionId = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn from_str_works() {
        let id: SubscriptionId = "x".parse().unwrap();
        assert_eq!(id.as_str(), "x");
    }
}
