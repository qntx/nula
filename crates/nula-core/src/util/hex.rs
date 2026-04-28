// Copyright (c) 2026 QNTX <https://qntx.fun>
// Distributed under the MIT or Apache-2.0 license.

//! Hex encoding and decoding helpers.
//!
//! Thin wrappers over [`faster_hex`] that present a small, allocation-aware
//! API and a single error type. Lowercase encoding is used everywhere: the
//! Nostr wire format expects lowercase hex (NIP-01) and consistency makes
//! pubkeys/event IDs trivially comparable.

use core::fmt;

use thiserror::Error;

/// Error raised while encoding or decoding hex.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum HexError {
    /// The hex string contained a non-ASCII or non-hex character.
    #[error("invalid hex character")]
    InvalidChar,
    /// The hex string length is invalid (odd, or doesn't fit the target buffer).
    #[error("invalid hex length: {0}")]
    InvalidLength(usize),
    /// The decoded length did not match the caller-supplied buffer.
    #[error("hex length mismatch: expected {expected} bytes, got {actual}")]
    LengthMismatch {
        /// Bytes expected by the caller.
        expected: usize,
        /// Bytes provided by the caller.
        actual: usize,
    },
    /// Upstream `faster_hex` reported an internal capacity overflow. Kept
    /// as a distinct variant so callers can tell it apart from the
    /// (much more common) `InvalidLength` failure on user input.
    #[error("hex decoder reported an internal overflow")]
    Overflow,
}

impl From<faster_hex::Error> for HexError {
    fn from(err: faster_hex::Error) -> Self {
        match err {
            faster_hex::Error::InvalidChar => Self::InvalidChar,
            faster_hex::Error::InvalidLength(len) => Self::InvalidLength(len),
            faster_hex::Error::Overflow => Self::Overflow,
        }
    }
}

/// Encode `bytes` as a lowercase hex [`String`].
#[must_use]
pub fn encode<T>(bytes: T) -> String
where
    T: AsRef<[u8]>,
{
    faster_hex::hex_string(bytes.as_ref())
}

/// Encode `bytes` into a caller-provided buffer.
///
/// `out` must be exactly `2 * bytes.len()` long.
///
/// # Errors
///
/// Returns [`HexError::LengthMismatch`] if `out` is sized incorrectly.
pub fn encode_to_slice<T>(bytes: T, out: &mut [u8]) -> Result<(), HexError>
where
    T: AsRef<[u8]>,
{
    let bytes = bytes.as_ref();
    let expected = bytes.len() * 2;
    if out.len() != expected {
        return Err(HexError::LengthMismatch {
            expected,
            actual: out.len(),
        });
    }
    faster_hex::hex_encode(bytes, out).map_err(HexError::from)?;
    Ok(())
}

/// Decode a hex string into an owned [`Vec<u8>`].
///
/// # Errors
///
/// Returns an error if the input contains non-hex characters or has odd
/// length.
pub fn decode<T>(input: T) -> Result<Vec<u8>, HexError>
where
    T: AsRef<[u8]>,
{
    let input = input.as_ref();
    if input.len() % 2 != 0 {
        return Err(HexError::InvalidLength(input.len()));
    }

    let mut out = vec![0_u8; input.len() / 2];
    faster_hex::hex_decode(input, &mut out).map_err(HexError::from)?;
    Ok(out)
}

/// Decode a hex string into the caller-provided buffer.
///
/// `input.len()` must equal `2 * out.len()`.
///
/// # Errors
///
/// Returns [`HexError::LengthMismatch`] if the lengths do not match, or
/// [`HexError::InvalidChar`] / [`HexError::InvalidLength`] if `input` is
/// malformed.
pub fn decode_to_slice<T>(input: T, out: &mut [u8]) -> Result<(), HexError>
where
    T: AsRef<[u8]>,
{
    let input = input.as_ref();
    let expected = out.len() * 2;
    if input.len() != expected {
        return Err(HexError::LengthMismatch {
            expected,
            actual: input.len(),
        });
    }

    faster_hex::hex_decode(input, out).map_err(HexError::from)?;
    Ok(())
}

/// Render `bytes` as lowercase hex into the provided [`fmt::Formatter`].
///
/// Used by `Display` / `LowerHex` impls of fixed-size types (event IDs,
/// pubkeys, …) to avoid intermediate allocations.
///
/// # Errors
///
/// Propagates errors from the formatter.
pub fn fmt_lower<T>(bytes: T, f: &mut fmt::Formatter<'_>) -> fmt::Result
where
    T: AsRef<[u8]>,
{
    for byte in bytes.as_ref() {
        write!(f, "{byte:02x}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    #[test]
    fn encode_roundtrip() {
        let bytes = hex!("deadbeef");
        let encoded = encode(bytes);
        assert_eq!(encoded, "deadbeef");
        assert_eq!(decode(&encoded).unwrap(), bytes);
    }

    #[test]
    fn encode_to_slice_exact() {
        let bytes = hex!("00112233");
        let mut buf = [0_u8; 8];
        encode_to_slice(bytes, &mut buf).unwrap();
        assert_eq!(&buf, b"00112233");
    }

    #[test]
    fn encode_to_slice_wrong_length() {
        let bytes = hex!("ab");
        let mut buf = [0_u8; 4];
        let err = encode_to_slice(bytes, &mut buf).unwrap_err();
        assert!(matches!(
            err,
            HexError::LengthMismatch {
                expected: 2,
                actual: 4
            }
        ));
    }

    #[test]
    fn decode_to_slice_exact() {
        let mut buf = [0_u8; 4];
        decode_to_slice("deadbeef", &mut buf).unwrap();
        assert_eq!(buf, hex!("deadbeef"));
    }

    #[test]
    fn decode_odd_length() {
        let err = decode("abc").unwrap_err();
        assert!(matches!(err, HexError::InvalidLength(3)));
    }

    #[test]
    fn decode_invalid_char() {
        let err = decode("zz").unwrap_err();
        assert_eq!(err, HexError::InvalidChar);
    }

    #[test]
    fn decode_to_slice_length_mismatch() {
        let mut buf = [0_u8; 2];
        let err = decode_to_slice("aabbcc", &mut buf).unwrap_err();
        assert!(matches!(
            err,
            HexError::LengthMismatch {
                expected: 4,
                actual: 6
            }
        ));
    }

    #[test]
    fn fmt_lower_matches_encode() {
        struct Wrap([u8; 4]);
        impl fmt::Display for Wrap {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt_lower(self.0, f)
            }
        }
        assert_eq!(Wrap(hex!("0a1b2c3d")).to_string(), "0a1b2c3d");
    }
}
