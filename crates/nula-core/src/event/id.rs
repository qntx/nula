// Copyright (c) 2026 QNTX <https://qntx.fun>
// Distributed under the MIT or Apache-2.0 license.

//! 32-byte event identifier.
//!
//! Per [NIP-01], an event's `id` is the SHA-256 hash of its canonical
//! serialization:
//!
//! ```json
//! [0, pubkey, created_at, kind, tags, content]
//! ```
//!
//! - the JSON has *no* whitespace,
//! - `pubkey` is lowercase 64-char hex,
//! - `tags` is an array of arrays of strings, and
//! - control characters in `content` are escaped per the NIP-01 rules.
//!
//! [`EventId::compute_from_canonical`] consumes a serializer that produces this
//! exact bytestream. [`crate::event::Event`] composes it for users so they
//! never have to deal with the canonical form directly.
//!
//! [NIP-01]: https://github.com/nostr-protocol/nips/blob/master/01.md

use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::util::hex::{self, HexError};

/// Length of an [`EventId`] in bytes.
pub const EVENT_ID_SIZE: usize = 32;

/// Errors raised when constructing an [`EventId`].
#[derive(Debug, Clone, Copy, Error)]
pub enum EventIdError {
    /// The hex representation could not be decoded.
    #[error("invalid hex encoding: {0}")]
    Hex(#[from] HexError),
    /// The byte slice was not exactly [`EVENT_ID_SIZE`] long.
    #[error("invalid length: expected {EVENT_ID_SIZE} bytes, got {0}")]
    InvalidLength(usize),
}

/// 32-byte event identifier (SHA-256 of the canonical event serialization).
///
/// `Display` and `serde` use lowercase 64-char hex.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventId([u8; EVENT_ID_SIZE]);

impl EventId {
    /// Construct from a fixed-size byte array.
    #[must_use]
    pub const fn from_byte_array(bytes: [u8; EVENT_ID_SIZE]) -> Self {
        Self(bytes)
    }

    /// Construct from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`EventIdError::InvalidLength`] when the slice is not 32 bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, EventIdError> {
        let array: [u8; EVENT_ID_SIZE] = bytes
            .try_into()
            .map_err(|_| EventIdError::InvalidLength(bytes.len()))?;
        Ok(Self(array))
    }

    /// Parse from a 64-char lowercase hex string.
    ///
    /// # Errors
    ///
    /// See [`EventIdError`].
    pub fn parse<S>(input: S) -> Result<Self, EventIdError>
    where
        S: AsRef<str>,
    {
        let bytes = hex::decode(input.as_ref())?;
        Self::from_slice(&bytes)
    }

    /// Compute an [`EventId`] from the canonical event serialization bytes.
    ///
    /// The caller must produce the exact byte sequence described by NIP-01.
    /// This function does not validate the structure; it only hashes.
    #[must_use]
    pub fn compute_from_canonical(canonical: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(canonical);
        let digest = hasher.finalize();
        let mut bytes = [0_u8; EVENT_ID_SIZE];
        bytes.copy_from_slice(&digest);
        Self(bytes)
    }

    /// Return the 32-byte representation.
    #[must_use]
    pub const fn to_byte_array(self) -> [u8; EVENT_ID_SIZE] {
        self.0
    }

    /// Borrow the 32-byte representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; EVENT_ID_SIZE] {
        &self.0
    }

    /// Return a 64-char lowercase hex representation.
    #[must_use]
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("EventId").field(&self.to_hex()).finish()
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex::fmt_lower(self.0, f)
    }
}

impl fmt::LowerHex for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex::fmt_lower(self.0, f)
    }
}

impl FromStr for EventId {
    type Err = EventIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl AsRef<[u8]> for EventId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for EventId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for EventId {
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
    use hex_literal::hex;

    use super::*;

    /// SHA-256 of the empty input — a known constant.
    const SHA256_EMPTY: [u8; 32] =
        hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    #[test]
    fn from_byte_array_round_trip() {
        let id = EventId::from_byte_array(SHA256_EMPTY);
        assert_eq!(id.to_byte_array(), SHA256_EMPTY);
    }

    #[test]
    fn from_slice_wrong_length() {
        let err = EventId::from_slice(&[0_u8; 16]).unwrap_err();
        assert!(matches!(err, EventIdError::InvalidLength(16)));
    }

    #[test]
    fn parse_round_trip() {
        let lower = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let id = EventId::parse(lower).unwrap();
        assert_eq!(id.to_hex(), lower);
    }

    #[test]
    fn parse_rejects_bad_hex() {
        let err = EventId::parse("zzzz").unwrap_err();
        assert!(matches!(err, EventIdError::Hex(_)));
    }

    #[test]
    fn compute_matches_known_sha256() {
        let id = EventId::compute_from_canonical(b"");
        assert_eq!(id.to_byte_array(), SHA256_EMPTY);
    }

    #[test]
    fn compute_distinct_for_distinct_inputs() {
        let lhs = EventId::compute_from_canonical(b"alice");
        let rhs = EventId::compute_from_canonical(b"bob");
        assert_ne!(lhs, rhs);
    }

    #[test]
    fn display_lowercase() {
        let id = EventId::from_byte_array(SHA256_EMPTY);
        let s = format!("{id}");
        assert_eq!(s.len(), 64);
        assert!(
            s.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn debug_includes_hex() {
        let id = EventId::from_byte_array(SHA256_EMPTY);
        let dbg = format!("{id:?}");
        assert!(dbg.contains(&id.to_hex()));
    }

    #[test]
    fn ordering_is_lexicographic() {
        let lhs = EventId::from_byte_array([0_u8; 32]);
        let rhs = EventId::from_byte_array([1_u8; 32]);
        assert!(lhs < rhs);
    }

    #[test]
    fn serde_round_trip() {
        let id = EventId::from_byte_array(SHA256_EMPTY);
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(
            json,
            r#""e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855""#
        );
        let parsed: EventId = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, id);
    }
}
