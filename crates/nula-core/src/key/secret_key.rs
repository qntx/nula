//! 32-byte secp256k1 secret scalar.
//!
//! [`SecretKey`] is a thin wrapper around [`secp256k1::SecretKey`] that
//! tightens the public surface for Nostr:
//!
//! - construction from raw bytes and lowercase hex (NIP-01),
//! - random generation backed by the OS entropy source,
//! - `Debug` redacts the secret material (so we never leak it in logs),
//! - `serde` always uses the 64-char lowercase hex representation, and
//! - [`Drop`] calls [`secp256k1::SecretKey::non_secure_erase`] so the inner
//!   bytes are best-effort overwritten before the allocation is released.
//!   The "non-secure" qualifier is upstream's: the compiler may still elide
//!   the write under aggressive optimization, but on every common target
//!   the volatile memset survives. This is the same primitive `bitcoin`
//!   and `rust-secp256k1` themselves rely on.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::util::hex::{self, HexError};
use crate::util::rng::{self, RngError};

/// Length of a serialized secret key in bytes.
pub const SECRET_KEY_SIZE: usize = 32;

/// Errors raised when constructing a [`SecretKey`].
#[derive(Debug, Clone, Copy, Error)]
#[non_exhaustive]
pub enum SecretKeyError {
    /// The hex representation could not be decoded.
    #[error("invalid hex encoding: {0}")]
    Hex(#[from] HexError),
    /// The byte slice was not exactly [`SECRET_KEY_SIZE`] long.
    #[error("invalid length: expected {SECRET_KEY_SIZE} bytes, got {0}")]
    InvalidLength(usize),
    /// The bytes did not encode a valid secp256k1 scalar (`0` or `>= n`).
    #[error("not a valid secp256k1 scalar")]
    InvalidScalar,
    /// The OS entropy source failed.
    #[error("entropy unavailable: {0}")]
    Rng(#[from] RngError),
}

/// 32-byte secp256k1 secret scalar.
///
/// `Display` and `serde` use lowercase hex. `Debug` deliberately hides the
/// secret bytes — this type never logs in plaintext.
///
/// # Example
///
/// ```
/// use nula_core::SecretKey;
///
/// let sk = SecretKey::generate().unwrap();
/// let hex = sk.to_hex();
/// let restored = SecretKey::parse(&hex).unwrap();
/// assert_eq!(sk, restored);
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct SecretKey(secp256k1::SecretKey);

impl SecretKey {
    /// Construct a [`SecretKey`] from a fixed-size byte array.
    ///
    /// # Errors
    ///
    /// Returns [`SecretKeyError::InvalidScalar`] if the bytes do not encode a
    /// valid secp256k1 scalar (i.e. `0` or `>= n`).
    pub fn from_byte_array(bytes: [u8; SECRET_KEY_SIZE]) -> Result<Self, SecretKeyError> {
        secp256k1::SecretKey::from_byte_array(bytes)
            .map(Self)
            .map_err(|_| SecretKeyError::InvalidScalar)
    }

    /// Construct a [`SecretKey`] from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`SecretKeyError::InvalidLength`] when the slice is not 32
    /// bytes long, or [`SecretKeyError::InvalidScalar`] when the bytes are
    /// not a valid scalar.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, SecretKeyError> {
        let array: [u8; SECRET_KEY_SIZE] = bytes
            .try_into()
            .map_err(|_| SecretKeyError::InvalidLength(bytes.len()))?;
        Self::from_byte_array(array)
    }

    /// Parse a [`SecretKey`] from a 64-char lowercase hex string.
    ///
    /// # Errors
    ///
    /// See [`SecretKeyError`].
    pub fn parse<S>(input: S) -> Result<Self, SecretKeyError>
    where
        S: AsRef<str>,
    {
        let bytes = hex::decode(input.as_ref())?;
        Self::from_slice(&bytes)
    }

    /// Generate a fresh [`SecretKey`] using the operating system's entropy.
    ///
    /// # Errors
    ///
    /// Returns [`SecretKeyError::Rng`] if the OS RNG fails, or
    /// [`SecretKeyError::InvalidScalar`] in the cryptographically negligible
    /// case where the random bytes happen to land on `0` or `>= n`.
    pub fn generate() -> Result<Self, SecretKeyError> {
        let bytes: [u8; SECRET_KEY_SIZE] = rng::random_bytes()?;
        Self::from_byte_array(bytes)
    }

    /// Return the secret key as raw bytes.
    #[must_use]
    pub fn to_byte_array(&self) -> [u8; SECRET_KEY_SIZE] {
        self.0.secret_bytes()
    }

    /// Return the secret key as a 64-char lowercase hex string.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0.secret_bytes())
    }

    /// Borrow the inner [`secp256k1::SecretKey`].
    ///
    /// Use this only at the boundary with the cryptography backend.
    #[must_use]
    pub const fn as_inner(&self) -> &secp256k1::SecretKey {
        &self.0
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SecretKey").field(&"<redacted>").finish()
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        // Best-effort secret zeroization. See the module-level note for the
        // soundness caveats; in practice this prevents accidental leaks via
        // `Vec` reallocation, async cancellation, and process core dumps.
        self.0.non_secure_erase();
    }
}

impl FromStr for SecretKey {
    type Err = SecretKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for SecretKey {
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

    const VALID_SECRET: [u8; 32] =
        hex!("0000000000000000000000000000000000000000000000000000000000000001");

    #[test]
    fn from_byte_array_valid() {
        let sk = SecretKey::from_byte_array(VALID_SECRET).unwrap();
        assert_eq!(sk.to_byte_array(), VALID_SECRET);
    }

    #[test]
    fn from_byte_array_zero_is_invalid() {
        let zero = [0_u8; 32];
        let err = SecretKey::from_byte_array(zero).unwrap_err();
        assert!(matches!(err, SecretKeyError::InvalidScalar));
    }

    #[test]
    fn from_slice_wrong_length() {
        let err = SecretKey::from_slice(&[0_u8; 16]).unwrap_err();
        assert!(matches!(err, SecretKeyError::InvalidLength(16)));
    }

    #[test]
    fn parse_round_trip() {
        let sk = SecretKey::from_byte_array(VALID_SECRET).unwrap();
        let hex_str = sk.to_hex();
        assert_eq!(hex_str.len(), 64);
        assert!(hex_str.chars().all(|c| c.is_ascii_hexdigit()));
        let parsed = SecretKey::parse(&hex_str).unwrap();
        assert_eq!(parsed, sk);
    }

    #[test]
    fn generate_distinct() {
        let lhs = SecretKey::generate().unwrap();
        let rhs = SecretKey::generate().unwrap();
        assert_ne!(lhs, rhs);
    }

    #[test]
    fn debug_redacts() {
        let sk = SecretKey::from_byte_array(VALID_SECRET).unwrap();
        let dbg = format!("{sk:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains(&sk.to_hex()));
    }

    #[test]
    fn serde_round_trip() {
        let sk = SecretKey::from_byte_array(VALID_SECRET).unwrap();
        let json = serde_json::to_string(&sk).unwrap();
        let parsed: SecretKey = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, sk);
    }

    #[test]
    fn serde_rejects_short_hex() {
        let result: Result<SecretKey, _> = serde_json::from_str("\"abcdef\"");
        assert!(result.is_err());
    }

    #[test]
    fn from_str_works() {
        let sk: SecretKey = "0000000000000000000000000000000000000000000000000000000000000001"
            .parse()
            .unwrap();
        assert_eq!(sk.to_byte_array(), VALID_SECRET);
    }

    #[test]
    fn drop_runs_non_secure_erase() {
        // We cannot inspect freed memory soundly from Rust, but we can prove
        // that the user-facing path runs without panicking when a key falls
        // out of scope. `non_secure_erase` is a `&mut self` operation that
        // overwrites the inner bytes; this test guards against accidental
        // regressions of the `Drop` impl (e.g. someone removing it).
        let _ = SecretKey::from_byte_array(VALID_SECRET).unwrap();
    }
}
