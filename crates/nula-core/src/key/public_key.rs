//! 32-byte BIP-340 x-only public key.
//!
//! NIP-01 carries public keys as a 32-byte x-only encoding (the `pubkey` field
//! and every `p` tag). [`PublicKey`] wraps [`secp256k1::XOnlyPublicKey`] with
//! Nostr-friendly construction, hex/serde representations, and clear errors.

use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::util::hex::{self, HexError};

/// Length of a serialized public key in bytes.
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Errors raised when constructing a [`PublicKey`].
#[derive(Debug, Clone, Copy, Error)]
#[non_exhaustive]
pub enum PublicKeyError {
    /// The hex representation could not be decoded.
    #[error("invalid hex encoding: {0}")]
    Hex(#[from] HexError),
    /// The byte slice was not exactly [`PUBLIC_KEY_SIZE`] long.
    #[error("invalid length: expected {PUBLIC_KEY_SIZE} bytes, got {0}")]
    InvalidLength(usize),
    /// The bytes did not encode a valid x-only point on secp256k1.
    #[error("not a valid x-only public key")]
    InvalidPoint,
}

/// 32-byte BIP-340 x-only public key.
///
/// `Display` and `serde` use lowercase 64-char hex.
///
/// # Example
///
/// ```
/// use nula_core::PublicKey;
///
/// let pk = PublicKey::parse(
///     "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
/// )
/// .unwrap();
/// assert_eq!(pk.to_hex().len(), 64);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey(secp256k1::XOnlyPublicKey);

impl PublicKey {
    /// Construct from a fixed-size byte array.
    ///
    /// # Errors
    ///
    /// Returns [`PublicKeyError::InvalidPoint`] when the bytes do not encode
    /// a valid x-coordinate.
    pub fn from_byte_array(bytes: [u8; PUBLIC_KEY_SIZE]) -> Result<Self, PublicKeyError> {
        secp256k1::XOnlyPublicKey::from_byte_array(bytes)
            .map(Self)
            .map_err(|_| PublicKeyError::InvalidPoint)
    }

    /// Construct from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`PublicKeyError::InvalidLength`] when the slice is not 32
    /// bytes long, or [`PublicKeyError::InvalidPoint`] otherwise.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, PublicKeyError> {
        let array: [u8; PUBLIC_KEY_SIZE] = bytes
            .try_into()
            .map_err(|_| PublicKeyError::InvalidLength(bytes.len()))?;
        Self::from_byte_array(array)
    }

    /// Parse from a 64-char lowercase hex string.
    ///
    /// # Errors
    ///
    /// See [`PublicKeyError`].
    pub fn parse<S>(input: S) -> Result<Self, PublicKeyError>
    where
        S: AsRef<str>,
    {
        let bytes = hex::decode(input.as_ref())?;
        Self::from_slice(&bytes)
    }

    /// Return the public key as raw bytes.
    #[must_use]
    pub fn to_byte_array(self) -> [u8; PUBLIC_KEY_SIZE] {
        self.0.serialize()
    }

    /// Return the public key as a 64-char lowercase hex string.
    #[must_use]
    pub fn to_hex(self) -> String {
        hex::encode(self.0.serialize())
    }

    /// Borrow the inner [`secp256k1::XOnlyPublicKey`].
    ///
    /// Use this only at the boundary with the cryptography backend.
    #[must_use]
    pub const fn as_inner(&self) -> &secp256k1::XOnlyPublicKey {
        &self.0
    }

    /// Verify a BIP-340 Schnorr signature against this public key.
    ///
    /// `message` is the 32-byte digest the signer signed (typically the
    /// canonical NIP-01 event id). The function uses the global
    /// `secp256k1` context and is therefore allocation-free.
    ///
    /// Returns `true` when the signature is valid for this public key
    /// over `message`, `false` on every other path (invalid signature,
    /// wrong key, malformed point at construction time is impossible
    /// because [`PublicKey`] only holds curve-valid points).
    #[must_use]
    pub fn verify_schnorr(&self, message: &[u8; 32], sig: &secp256k1::schnorr::Signature) -> bool {
        secp256k1::SECP256K1
            .verify_schnorr(sig, message, &self.0)
            .is_ok()
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PublicKey").field(&self.to_hex()).finish()
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex::fmt_lower(self.0.serialize(), f)
    }
}

impl fmt::LowerHex for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex::fmt_lower(self.0.serialize(), f)
    }
}

impl FromStr for PublicKey {
    type Err = PublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl From<secp256k1::XOnlyPublicKey> for PublicKey {
    fn from(value: secp256k1::XOnlyPublicKey) -> Self {
        Self(value)
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
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

    /// Generator point `G`'s x-coordinate (BIP-340 § Test Vectors).
    const G_X: [u8; 32] = hex!("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");

    #[test]
    fn parse_lowercase_hex() {
        let lower = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let pk = PublicKey::parse(lower).unwrap();
        assert_eq!(pk.to_hex(), lower);
    }

    #[test]
    fn from_byte_array_round_trip() {
        let pk = PublicKey::from_byte_array(G_X).unwrap();
        assert_eq!(pk.to_byte_array(), G_X);
    }

    #[test]
    fn from_slice_wrong_length() {
        let err = PublicKey::from_slice(&[0_u8; 16]).unwrap_err();
        assert!(matches!(err, PublicKeyError::InvalidLength(16)));
    }

    #[test]
    fn invalid_point_rejected() {
        // The point is rejected because the curve does not contain it.
        let bytes = hex!("0100000000000000000000000000000000000000000000000000000000000000");
        let err = PublicKey::from_byte_array(bytes).unwrap_err();
        assert!(matches!(err, PublicKeyError::InvalidPoint));
    }

    #[test]
    fn display_lowercase() {
        let pk = PublicKey::from_byte_array(G_X).unwrap();
        let s = format!("{pk}");
        assert_eq!(s.len(), 64);
        assert!(
            s.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn debug_includes_hex() {
        let pk = PublicKey::from_byte_array(G_X).unwrap();
        let dbg = format!("{pk:?}");
        assert!(dbg.contains(&pk.to_hex()));
    }

    #[test]
    fn serde_round_trip() {
        let pk = PublicKey::from_byte_array(G_X).unwrap();
        let json = serde_json::to_string(&pk).unwrap();
        let parsed: PublicKey = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, pk);
    }

    #[test]
    fn ordering_is_lexicographic() {
        let lhs = PublicKey::from_byte_array(hex!(
            "0000000000000000000000000000000000000000000000000000000000000002"
        ))
        .unwrap();
        let rhs = PublicKey::from_byte_array(hex!(
            "0000000000000000000000000000000000000000000000000000000000000003"
        ))
        .unwrap();
        assert!(lhs < rhs);
    }

    #[test]
    fn verify_schnorr_round_trip() {
        use crate::Keys;
        let keys = Keys::parse("0000000000000000000000000000000000000000000000000000000000000003")
            .unwrap();
        let message = hex!("0202020202020202020202020202020202020202020202020202020202020202");
        let sig = keys.sign_schnorr(&message);
        // Correct key + correct message: success.
        assert!(keys.public_key().verify_schnorr(&message, &sig));
        // Tamper with the message: must reject.
        let mut bad = message;
        bad[0] ^= 0xff;
        assert!(!keys.public_key().verify_schnorr(&bad, &sig));
    }
}
