// Copyright (c) 2026 QNTX <https://qntx.fun>
// Distributed under the MIT or Apache-2.0 license.

//! NIP-19 TLV (type-length-value) encoder and decoder.
//!
//! Every NIP-19 entity that carries more than a single 32-byte payload (
//! `nprofile`, `nevent`, `naddr`) packs its fields into TLV records:
//!
//! ```text
//! +------+--------+-----------------+
//! | type | length | value (length B)|
//! +------+--------+-----------------+
//!  1 byte 1 byte   variable
//! ```
//!
//! NIP-19 reuses a small set of well-known type tags:
//!
//! | tag | meaning                                   |
//! |-----|-------------------------------------------|
//! | `0` | the entity-specific *special* payload     |
//! | `1` | a relay URL string                        |
//! | `2` | an author public key (32 bytes)           |
//! | `3` | an event kind encoded as `u32` big-endian |

use thiserror::Error;

/// TLV tag for the entity-specific payload (pubkey, event id, identifier).
pub const SPECIAL: u8 = 0;
/// TLV tag for a relay URL.
pub const RELAY: u8 = 1;
/// TLV tag for an author public key.
pub const AUTHOR: u8 = 2;
/// TLV tag for an event kind (`u32` big-endian).
pub const KIND: u8 = 3;

/// Errors raised while encoding or decoding a TLV stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum TlvError {
    /// A value supplied to [`encode`] exceeded the 255-byte cap.
    #[error("TLV value is too long for a 1-byte length field: {len} bytes (max 255)")]
    ValueTooLong {
        /// Length that overflowed.
        len: usize,
    },
    /// The buffer ended before a length byte could be read.
    #[error("TLV record truncated at offset {offset}: missing length byte")]
    TruncatedHeader {
        /// Byte index where the truncation was detected.
        offset: usize,
    },
    /// The buffer ended before the declared value bytes.
    #[error(
        "TLV record truncated at offset {offset}: expected {expected} value bytes, only {available} remain"
    )]
    TruncatedValue {
        /// Offset at which the value should start.
        offset: usize,
        /// Number of bytes the length byte advertised.
        expected: usize,
        /// Number of bytes actually available in the input.
        available: usize,
    },
}

/// A decoded TLV record borrowing into the input buffer.
#[derive(Debug, Clone, Copy)]
pub struct Record<'a> {
    /// 1-byte tag.
    pub tag: u8,
    /// Variable-length value.
    pub value: &'a [u8],
}

/// Encode an iterator of `(tag, value)` pairs into a freshly allocated
/// buffer.
///
/// # Errors
///
/// Returns [`TlvError::ValueTooLong`] if any value is longer than 255
/// bytes; that is the maximum representable in the 1-byte length field.
pub fn encode<'a, I>(records: I) -> Result<Vec<u8>, TlvError>
where
    I: IntoIterator<Item = (u8, &'a [u8])>,
{
    let records = records.into_iter();
    let (lower, _) = records.size_hint();
    let mut out = Vec::with_capacity(lower * 2);
    for (tag, value) in records {
        let len =
            u8::try_from(value.len()).map_err(|_| TlvError::ValueTooLong { len: value.len() })?;
        out.push(tag);
        out.push(len);
        out.extend_from_slice(value);
    }
    Ok(out)
}

/// Iterate over the TLV records in `bytes`.
///
/// The iterator yields a [`TlvError`] if the buffer is malformed; the iter
/// fuses on first error.
#[must_use]
pub const fn iter(bytes: &[u8]) -> RecordIter<'_> {
    RecordIter {
        bytes,
        cursor: 0,
        finished: false,
    }
}

/// Iterator returned by [`iter`].
#[derive(Debug)]
pub struct RecordIter<'a> {
    bytes: &'a [u8],
    cursor: usize,
    finished: bool,
}

impl<'a> Iterator for RecordIter<'a> {
    type Item = Result<Record<'a>, TlvError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        let offset = self.cursor;
        let remaining = self.bytes.get(offset..)?;
        let (&tag, after_tag) = remaining.split_first()?;
        let Some((&len_byte, value_buf)) = after_tag.split_first() else {
            self.finished = true;
            return Some(Err(TlvError::TruncatedHeader { offset }));
        };
        let len = len_byte as usize;
        if value_buf.len() < len {
            self.finished = true;
            return Some(Err(TlvError::TruncatedValue {
                offset: offset + 2,
                expected: len,
                available: value_buf.len(),
            }));
        }
        let (value, _) = value_buf.split_at(len);
        self.cursor = offset + 2 + len;
        Some(Ok(Record { tag, value }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_single_record() {
        let payload = [0xab; 32];
        let encoded = encode([(SPECIAL, payload.as_slice())]).unwrap();
        let records: Result<Vec<_>, _> = iter(&encoded).collect();
        let records = records.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].tag, SPECIAL);
        assert_eq!(records[0].value, payload);
    }

    #[test]
    fn round_trip_multiple_records() {
        let pubkey = [0x01; 32];
        let relay: &[u8] = b"wss://relay.example";
        let kind = [0x00, 0x00, 0x00, 0x01];
        let encoded = encode([
            (SPECIAL, pubkey.as_slice()),
            (RELAY, relay),
            (KIND, kind.as_slice()),
        ])
        .unwrap();
        let records: Vec<_> = iter(&encoded).map(Result::unwrap).collect();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].value, pubkey);
        assert_eq!(records[1].value, relay);
        assert_eq!(records[2].value, kind);
    }

    #[test]
    fn encode_rejects_oversized_value() {
        let big = vec![0u8; 300];
        let err = encode([(SPECIAL, big.as_slice())]).unwrap_err();
        assert!(matches!(err, TlvError::ValueTooLong { len: 300 }));
    }

    #[test]
    fn truncated_header_is_rejected() {
        let bytes = [SPECIAL]; // missing length byte
        let err = iter(&bytes).next().unwrap().unwrap_err();
        assert!(matches!(err, TlvError::TruncatedHeader { offset: 0 }));
    }

    #[test]
    fn truncated_value_is_rejected() {
        let bytes = [SPECIAL, 0x05, 0x00, 0x00];
        let err = iter(&bytes).next().unwrap().unwrap_err();
        assert!(matches!(
            err,
            TlvError::TruncatedValue {
                expected: 5,
                available: 2,
                ..
            }
        ));
    }

    #[test]
    fn empty_input_produces_no_records() {
        assert!(iter(&[]).next().is_none());
    }
}
