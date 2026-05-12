//! [NIP-77] Negentropy Syncing.
//!
//! NIP-77 wraps the binary [Negentropy](https://github.com/hoytech/negentropy)
//! reconciliation protocol in three Nostr-style WebSocket messages:
//!
//! - `["NEG-OPEN", <subscription_id>, <filter>, <hex-payload>]`
//! - `["NEG-MSG", <subscription_id>, <hex-payload>]`
//! - `["NEG-CLOSE", <subscription_id>]`
//! - `["NEG-ERR", <subscription_id>, <reason>]`
//!
//! This module provides a typed envelope ([`NegMessage`]) plus the
//! Negentropy v1 binary primitives ([`NegProtocolVersion`],
//! [`NegItem`], [`NegBound`], [`NegRange`], [`NegRangeMode`],
//! [`NegPayload`]) and a low-level encoder/decoder
//! ([`encode_payload`] / [`decode_payload`]).
//!
//! The full reconciliation algorithm (which delivers the IDs each
//! side has / needs) lives downstream in the relay implementation;
//! this module only models the wire bytes.
//!
//! [NIP-77]: https://github.com/nostr-protocol/nips/blob/master/77.md

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::filter::Filter;
use crate::message::SubscriptionId;
use crate::util::hex;

const FINGERPRINT_BYTES: usize = 16;
const ID_BYTES: usize = 32;
const INFINITY_TIMESTAMP: u64 = u64::MAX;
const RESERVED_TIMESTAMP_INFINITY_OFFSET: u64 = 0;

/// Protocol version byte. `1` ⇒ `0x61`, `2` ⇒ `0x62`, ….
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NegProtocolVersion(pub u8);

impl NegProtocolVersion {
    /// Current protocol version (1).
    pub const V1: Self = Self(0x61);

    /// Construct a protocol version from a byte. Returns `None` if
    /// the byte does not look like a valid version (i.e., not in
    /// `0x60..=0x6f`).
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        if byte >= 0x60 && byte < 0x70 {
            Some(Self(byte))
        } else {
            None
        }
    }

    /// Underlying byte.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self.0
    }

    /// Numeric version index (`0x61 ⇒ 1`).
    #[must_use]
    pub const fn version(self) -> u8 {
        self.0.wrapping_sub(0x60)
    }
}

/// A `(timestamp, id)` record participating in reconciliation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NegItem {
    /// 64-bit unsigned timestamp. `u64::MAX` is the reserved
    /// "infinity" sentinel and MUST NOT be used for real records.
    pub timestamp: u64,
    /// 32-byte event id.
    pub id: [u8; ID_BYTES],
}

impl NegItem {
    /// Construct an item.
    #[must_use]
    pub const fn new(timestamp: u64, id: [u8; ID_BYTES]) -> Self {
        Self { timestamp, id }
    }

    /// Special "infinity" upper bound used as a sentinel.
    #[must_use]
    pub const fn infinity() -> Self {
        Self {
            timestamp: INFINITY_TIMESTAMP,
            id: [0u8; ID_BYTES],
        }
    }
}

/// Half-open range bound `[upperTimestamp, idPrefix)` per spec
/// §"Bound".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegBound {
    /// Upper-bound timestamp (special-cased: `0` ⇒ infinity in the
    /// encoded form).
    pub timestamp: u64,
    /// Optional id-prefix bytes (0–32). Trailing bytes are implicitly
    /// 0 when shorter than 32.
    pub id_prefix: Vec<u8>,
}

impl NegBound {
    /// Construct an infinity bound (used as the implicit final
    /// `Skip` boundary).
    #[must_use]
    pub const fn infinity() -> Self {
        Self {
            timestamp: INFINITY_TIMESTAMP,
            id_prefix: Vec::new(),
        }
    }
}

/// Mode of a [`NegRange`] payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NegRangeMode {
    /// `0` — sender does not wish to process this range further.
    Skip,
    /// `1` — sender carries a 16-byte fingerprint of all IDs within
    /// the range.
    Fingerprint([u8; FINGERPRINT_BYTES]),
    /// `2` — sender carries the full id list within the range.
    IdList(Vec<[u8; ID_BYTES]>),
}

/// A reconciliation range (upper-bound + payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegRange {
    /// Inclusive lower bound is implicit (the previous range's upper
    /// bound, or zero for the first range).
    pub upper_bound: NegBound,
    /// Mode-tagged payload.
    pub mode: NegRangeMode,
}

/// Decoded [Negentropy v1 message](https://github.com/hoytech/negentropy/blob/master/docs/protocol.md).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegPayload {
    /// Protocol version byte.
    pub version: NegProtocolVersion,
    /// Range list in ascending order.
    pub ranges: Vec<NegRange>,
}

/// Payload bundle for [`NegMessage::Open`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegOpen {
    /// Subscription id.
    pub subscription_id: SubscriptionId,
    /// Filter matching events to reconcile.
    pub filter: Filter,
    /// Initial Negentropy payload.
    pub payload: NegPayload,
}

/// Wire-level NIP-77 envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NegMessage {
    /// `["NEG-OPEN", <id>, <filter>, <hex-payload>]`.
    Open(Box<NegOpen>),
    /// `["NEG-MSG", <id>, <hex-payload>]`.
    Msg {
        /// Subscription id.
        subscription_id: SubscriptionId,
        /// Negentropy payload.
        payload: NegPayload,
    },
    /// `["NEG-CLOSE", <id>]`.
    Close {
        /// Subscription id.
        subscription_id: SubscriptionId,
    },
    /// `["NEG-ERR", <id>, <reason>]`.
    Err {
        /// Subscription id.
        subscription_id: SubscriptionId,
        /// Error reason (`<machine-prefix>: <human-message>` per
        /// NIP-01 conventions).
        reason: String,
    },
}

/// Errors raised by Negentropy encoders / decoders.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NegentropyError {
    /// Buffer ended before a varint terminator was reached.
    #[error("unexpected end of input while decoding varint")]
    UnexpectedEof,
    /// Varint exceeds 10 bytes (would overflow `u64`).
    #[error("varint exceeds 10 bytes")]
    VarintOverflow,
    /// Buffer ended while still waiting for `length` bytes of payload.
    #[error("buffer ended {expected} bytes before payload completed")]
    PayloadTruncated {
        /// Bytes still expected.
        expected: usize,
    },
    /// Unknown range mode tag.
    #[error("unknown range mode {0}")]
    UnknownRangeMode(u64),
    /// Unsupported protocol version.
    #[error("unsupported Negentropy protocol version 0x{0:02x}")]
    UnsupportedVersion(u8),
    /// Hex decode failure.
    #[error("hex decode failure: {0}")]
    Hex(String),
}

fn write_varint(value: u64, out: &mut Vec<u8>) {
    let mut value = value;
    let mut tmp: Vec<u8> = Vec::with_capacity(10);
    loop {
        let byte = u8::try_from(value & 0x7f).unwrap_or(0);
        tmp.push(byte);
        value >>= 7;
        if value == 0 {
            break;
        }
    }
    // Most-significant-digit-first; flip the high bit on every byte
    // except the last per spec.
    for (i, byte) in tmp.iter().rev().enumerate() {
        let with_continuation = if i + 1 < tmp.len() {
            *byte | 0x80
        } else {
            *byte
        };
        out.push(with_continuation);
    }
}

fn read_varint(buf: &[u8], cursor: &mut usize) -> Result<u64, NegentropyError> {
    let mut value: u64 = 0;
    for _ in 0..10 {
        let byte = *buf.get(*cursor).ok_or(NegentropyError::UnexpectedEof)?;
        *cursor += 1;
        value = value
            .checked_shl(7)
            .ok_or(NegentropyError::VarintOverflow)?
            | u64::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(NegentropyError::VarintOverflow)
}

fn encode_bound(bound: &NegBound, prev_timestamp: &mut u64, out: &mut Vec<u8>) {
    let encoded_ts = if bound.timestamp == INFINITY_TIMESTAMP {
        RESERVED_TIMESTAMP_INFINITY_OFFSET
    } else {
        // Offsets reset at the beginning of every message; the caller
        // tracks the running value.
        bound
            .timestamp
            .saturating_sub(*prev_timestamp)
            .saturating_add(1)
    };
    write_varint(encoded_ts, out);
    if bound.timestamp != INFINITY_TIMESTAMP {
        *prev_timestamp = bound.timestamp;
    }
    let len = bound.id_prefix.len().min(ID_BYTES);
    write_varint(len as u64, out);
    out.extend_from_slice(bound.id_prefix.get(..len).unwrap_or(&[]));
}

fn decode_bound(
    buf: &[u8],
    cursor: &mut usize,
    prev_timestamp: &mut u64,
) -> Result<NegBound, NegentropyError> {
    let ts_field = read_varint(buf, cursor)?;
    let timestamp = if ts_field == RESERVED_TIMESTAMP_INFINITY_OFFSET {
        INFINITY_TIMESTAMP
    } else {
        let value = prev_timestamp.saturating_add(ts_field.saturating_sub(1));
        *prev_timestamp = value;
        value
    };
    let len_u64 = read_varint(buf, cursor)?;
    let len = usize::try_from(len_u64).map_err(|_| NegentropyError::VarintOverflow)?;
    if len > ID_BYTES {
        return Err(NegentropyError::PayloadTruncated { expected: len });
    }
    let chunk = read_chunk(buf, cursor, len)?;
    Ok(NegBound {
        timestamp,
        id_prefix: chunk.to_vec(),
    })
}

fn encode_range(range: &NegRange, prev_timestamp: &mut u64, out: &mut Vec<u8>) {
    encode_bound(&range.upper_bound, prev_timestamp, out);
    match &range.mode {
        NegRangeMode::Skip => write_varint(0, out),
        NegRangeMode::Fingerprint(fp) => {
            write_varint(1, out);
            out.extend_from_slice(fp);
        }
        NegRangeMode::IdList(ids) => {
            write_varint(2, out);
            write_varint(ids.len() as u64, out);
            for id in ids {
                out.extend_from_slice(id);
            }
        }
    }
}

fn read_chunk<'a>(
    buf: &'a [u8],
    cursor: &mut usize,
    len: usize,
) -> Result<&'a [u8], NegentropyError> {
    let end = cursor
        .checked_add(len)
        .ok_or(NegentropyError::VarintOverflow)?;
    let chunk = buf.get(*cursor..end);
    chunk.map_or_else(
        || {
            Err(NegentropyError::PayloadTruncated {
                expected: end.saturating_sub(buf.len()),
            })
        },
        |chunk| {
            *cursor = end;
            Ok(chunk)
        },
    )
}

fn decode_range(
    buf: &[u8],
    cursor: &mut usize,
    prev_timestamp: &mut u64,
) -> Result<NegRange, NegentropyError> {
    let upper_bound = decode_bound(buf, cursor, prev_timestamp)?;
    let mode = read_varint(buf, cursor)?;
    let mode = match mode {
        0 => NegRangeMode::Skip,
        1 => {
            let chunk = read_chunk(buf, cursor, FINGERPRINT_BYTES)?;
            let mut fp = [0u8; FINGERPRINT_BYTES];
            fp.copy_from_slice(chunk);
            NegRangeMode::Fingerprint(fp)
        }
        2 => {
            let count_u64 = read_varint(buf, cursor)?;
            let count = usize::try_from(count_u64).map_err(|_| NegentropyError::VarintOverflow)?;
            let mut ids = Vec::with_capacity(count);
            for _ in 0..count {
                let chunk = read_chunk(buf, cursor, ID_BYTES)?;
                let mut id = [0u8; ID_BYTES];
                id.copy_from_slice(chunk);
                ids.push(id);
            }
            NegRangeMode::IdList(ids)
        }
        other => return Err(NegentropyError::UnknownRangeMode(other)),
    };
    Ok(NegRange { upper_bound, mode })
}

/// Encode a [`NegPayload`] to its raw bytes. Use `hex::encode` to
/// produce the wire-format hex string carried by [`NegMessage`].
#[must_use]
pub fn encode_payload(payload: &NegPayload) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + payload.ranges.len() * 32);
    out.push(payload.version.as_byte());
    let mut prev_timestamp: u64 = 0;
    for range in &payload.ranges {
        encode_range(range, &mut prev_timestamp, &mut out);
    }
    out
}

/// Decode raw bytes into a [`NegPayload`].
///
/// # Errors
///
/// See [`NegentropyError`] for the failure modes.
pub fn decode_payload(buf: &[u8]) -> Result<NegPayload, NegentropyError> {
    let (version_byte, rest) = buf.split_first().ok_or(NegentropyError::UnexpectedEof)?;
    let version = NegProtocolVersion::from_byte(*version_byte)
        .ok_or(NegentropyError::UnsupportedVersion(*version_byte))?;
    let mut cursor = 0;
    let mut prev_timestamp: u64 = 0;
    let mut ranges = Vec::new();
    while cursor < rest.len() {
        ranges.push(decode_range(rest, &mut cursor, &mut prev_timestamp)?);
    }
    Ok(NegPayload { version, ranges })
}

/// Encode the payload as the wire-format hex string carried by
/// [`NegMessage::Open`] / [`NegMessage::Msg`].
#[must_use]
pub fn encode_payload_hex(payload: &NegPayload) -> String {
    hex::encode(encode_payload(payload))
}

/// Decode the wire-format hex payload.
///
/// # Errors
///
/// Wraps `hex` decoding errors and propagates [`NegentropyError`]
/// from the binary decoder.
pub fn decode_payload_hex(hex_str: &str) -> Result<NegPayload, NegentropyError> {
    let bytes = hex::decode(hex_str).map_err(|e| NegentropyError::Hex(e.to_string()))?;
    decode_payload(&bytes)
}

/// Compute a Negentropy v1 fingerprint over a list of event IDs.
///
/// 1. Sum the IDs as 32-byte little-endian unsigned integers modulo
///    `2**256`.
/// 2. Append the count as a varint.
/// 3. SHA-256 the concatenation.
/// 4. Take the first 16 bytes.
#[must_use]
pub fn fingerprint(ids: &[[u8; ID_BYTES]]) -> [u8; FINGERPRINT_BYTES] {
    let mut sum = [0u8; ID_BYTES];
    for id in ids {
        let mut carry: u16 = 0;
        for (sum_byte, id_byte) in sum.iter_mut().zip(id.iter()) {
            let total = u16::from(*sum_byte) + u16::from(*id_byte) + carry;
            *sum_byte = u8::try_from(total & 0xff).unwrap_or(0);
            carry = total >> 8;
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(sum);
    let mut count_buf = Vec::new();
    write_varint(ids.len() as u64, &mut count_buf);
    hasher.update(&count_buf);
    let digest = hasher.finalize();
    let mut out = [0u8; FINGERPRINT_BYTES];
    for (slot, byte) in out.iter_mut().zip(digest.iter()) {
        *slot = *byte;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trip() {
        for &value in &[0u64, 1, 127, 128, 300, 1_000_000, u64::MAX / 2] {
            let mut buf = Vec::new();
            write_varint(value, &mut buf);
            let mut cursor = 0;
            assert_eq!(read_varint(&buf, &mut cursor).unwrap(), value);
            assert_eq!(cursor, buf.len());
        }
    }

    #[test]
    fn payload_round_trip() {
        let payload = NegPayload {
            version: NegProtocolVersion::V1,
            ranges: vec![
                NegRange {
                    upper_bound: NegBound {
                        timestamp: 1_700_000_000,
                        id_prefix: vec![0xab, 0xcd],
                    },
                    mode: NegRangeMode::Fingerprint([0xff; FINGERPRINT_BYTES]),
                },
                NegRange {
                    upper_bound: NegBound::infinity(),
                    mode: NegRangeMode::Skip,
                },
            ],
        };
        let bytes = encode_payload(&payload);
        let parsed = decode_payload(&bytes).unwrap();
        assert_eq!(parsed, payload);
    }

    #[test]
    fn id_list_payload_round_trip() {
        let ids = vec![[0x11; 32], [0x22; 32]];
        let payload = NegPayload {
            version: NegProtocolVersion::V1,
            ranges: vec![NegRange {
                upper_bound: NegBound::infinity(),
                mode: NegRangeMode::IdList(ids.clone()),
            }],
        };
        let hex_str = encode_payload_hex(&payload);
        let parsed = decode_payload_hex(&hex_str).unwrap();
        match &parsed.ranges[0].mode {
            NegRangeMode::IdList(decoded) => assert_eq!(decoded, &ids),
            other => panic!("unexpected mode {other:?}"),
        }
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let bytes = vec![0x10];
        assert!(matches!(
            decode_payload(&bytes),
            Err(NegentropyError::UnsupportedVersion(0x10))
        ));
    }

    #[test]
    fn fingerprint_is_stable() {
        let ids = vec![[1u8; 32], [2u8; 32]];
        let fp = fingerprint(&ids);
        let fp_again = fingerprint(&ids);
        assert_eq!(fp, fp_again);
        let fp_other = fingerprint(&[[3u8; 32]]);
        assert_ne!(fp, fp_other);
    }
}
