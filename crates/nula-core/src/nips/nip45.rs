//! [NIP-45] Event Counts (`COUNT` verb).
//!
//! Adds a relay-side `COUNT` verb that mirrors `REQ` filters but
//! returns just an integer count (optionally with a `HyperLogLog`
//! sketch). This module surfaces:
//!
//! - [`CountRequest`] / [`CountResponse`] — typed wrappers for the
//!   wire arrays.
//! - [`HyperLogLog`] — a fixed-256-register sketch with merge and
//!   estimate helpers.
//! - [`hll_offset_for_value`] — the deterministic offset rule the
//!   spec pins for cacheable counts.
//!
//! The wire serialisation lives behind [`CountRequest::to_wire`] and
//! [`CountResponse::to_wire`] so callers can plug it into their own
//! WebSocket transport without forcing this crate to take a
//! `serde_json::Value` round-trip.
//!
//! [NIP-45]: https://github.com/nostr-protocol/nips/blob/master/45.md
#![cfg_attr(docsrs, doc(cfg(feature = "nip45")))]

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::filter::Filter;
use crate::message::SubscriptionId;
use crate::util::hex;

const HLL_REGISTERS: usize = 256;
const HLL_HEX_LEN: usize = HLL_REGISTERS * 2;

/// `["COUNT", <subscription_id>, <filter>...]` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountRequest {
    /// Subscription identifier.
    pub subscription_id: SubscriptionId,
    /// One or more filters (OR-combined per spec §"Filters and return
    /// values").
    pub filters: Vec<Filter>,
}

/// `["COUNT", <subscription_id>, {"count": ...}]` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CountResponse {
    /// Subscription identifier the count belongs to.
    pub subscription_id: SubscriptionId,
    /// Reported count.
    pub count: u64,
    /// Whether the count is a probabilistic estimate.
    pub approximate: bool,
    /// Optional `HyperLogLog` sketch.
    pub hll: Option<HyperLogLog>,
}

/// 256-register `HyperLogLog` sketch as defined by NIP-45.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HyperLogLog {
    registers: [u8; HLL_REGISTERS],
}

#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "saturating cast is intentional and bounded by the branches above"
)]
fn f64_to_u64_saturating(value: f64) -> u64 {
    if value.is_nan() || value <= 0.0 {
        0
    } else if value >= u64::MAX as f64 {
        u64::MAX
    } else {
        value as u64
    }
}

/// Errors raised by NIP-45 helpers.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CountError {
    /// `hll` hex string was not exactly 512 characters.
    #[error("hll must be {HLL_HEX_LEN} hex characters, got {0}")]
    HllLength(usize),
    /// `hll` hex string failed to decode.
    #[error("hll hex decode failure: {0}")]
    HllHex(String),
}

impl HyperLogLog {
    /// Construct an empty sketch (all registers zero).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            registers: [0u8; HLL_REGISTERS],
        }
    }

    /// Borrow the underlying register array.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; HLL_REGISTERS] {
        &self.registers
    }

    /// Construct a sketch from a register array.
    #[must_use]
    pub const fn from_bytes(registers: &[u8; HLL_REGISTERS]) -> Self {
        Self {
            registers: *registers,
        }
    }

    /// Render the sketch as a 512-character lowercase hex string.
    #[must_use]
    pub fn to_hex(self) -> String {
        hex::encode(self.registers)
    }

    /// Parse a 512-character hex sketch.
    ///
    /// # Errors
    ///
    /// Returns [`CountError::HllLength`] when the input is not 512
    /// characters or [`CountError::HllHex`] for non-hex input.
    pub fn from_hex(hex_str: &str) -> Result<Self, CountError> {
        if hex_str.len() != HLL_HEX_LEN {
            return Err(CountError::HllLength(hex_str.len()));
        }
        let bytes = hex::decode(hex_str).map_err(|e| CountError::HllHex(e.to_string()))?;
        let registers: [u8; HLL_REGISTERS] = bytes
            .try_into()
            .map_err(|v: Vec<u8>| CountError::HllLength(v.len() * 2))?;
        Ok(Self { registers })
    }

    /// Apply an event ID / pubkey to the sketch using the supplied
    /// offset (see [`hll_offset_for_value`]).
    ///
    /// Returns `false` when `offset` falls outside the spec's `8..=23`
    /// range, leaving the sketch untouched.
    pub fn observe(&mut self, offset: usize, hash: &[u8; 32]) -> bool {
        if !(8..=23).contains(&offset) {
            return false;
        }
        let Some(&register_byte) = hash.get(offset) else {
            return false;
        };
        let register_index = register_byte as usize;
        let tail = hash.get(offset + 1..).unwrap_or(&[]);
        // Count leading zero bits starting at `offset + 1` (within
        // the remaining bytes). Add 1 per spec.
        let mut zeros: u8 = 0;
        for byte in tail {
            if *byte == 0 {
                zeros = zeros.saturating_add(8);
            } else {
                let leading = u8::try_from(byte.leading_zeros()).unwrap_or(u8::MAX);
                zeros = zeros.saturating_add(leading);
                break;
            }
        }
        let value = zeros.saturating_add(1);
        let Some(slot) = self.registers.get_mut(register_index) else {
            return false;
        };
        if value > *slot {
            *slot = value;
        }
        true
    }

    /// Merge another sketch into this one, taking the per-register
    /// max (the spec's recommended client-side combine).
    pub fn merge(&mut self, other: &Self) {
        for (a, b) in self.registers.iter_mut().zip(other.registers.iter()) {
            if *b > *a {
                *a = *b;
            }
        }
    }

    /// Estimate the cardinality using the standard `HyperLogLog`
    /// formula with the spec's 256 registers. Saturates to
    /// [`u64::MAX`] for absurd inputs (e.g. NaNs).
    #[must_use]
    pub fn estimate(&self) -> u64 {
        const M_F64: f64 = HLL_REGISTERS as f64;
        let alpha_m = 0.7213_f64 / 1.079_f64.mul_add(1.0 / M_F64, 1.0);
        let mut sum = 0.0_f64;
        let mut zero_registers = 0_u32;
        for &r in &self.registers {
            if r == 0 {
                zero_registers += 1;
            }
            sum += 2.0_f64.powi(-i32::from(r));
        }
        let raw = alpha_m * M_F64 * M_F64 / sum;
        let estimate = if raw <= 2.5 * M_F64 && zero_registers > 0 {
            M_F64 * (M_F64 / f64::from(zero_registers)).ln()
        } else {
            raw
        };
        f64_to_u64_saturating(estimate.round())
    }
}

impl Default for HyperLogLog {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the spec's deterministic HLL offset for a single tag-value
/// `value`.
///
/// - 64-character hex strings (event ids / pubkeys) are used as-is.
/// - Coordinates of the form `<kind>:<pubkey>:<d>` use the `<pubkey>`
///   half.
/// - Anything else is SHA-256 hashed.
///
/// The 33rd hex character (index 32) is read as a base-16 digit and
/// `8` is added — yielding an offset in the inclusive range `8..=23`.
#[must_use]
pub fn hll_offset_for_value(value: &str) -> usize {
    let hex_str = canonical_hex_for_value(value);
    let nibble = hex_str
        .as_bytes()
        .get(32)
        .copied()
        .map_or(0u8, hex_digit_value);
    8 + nibble as usize
}

fn canonical_hex_for_value(value: &str) -> String {
    if is_64_hex(value) {
        return value.to_ascii_lowercase();
    }
    if let Some(pubkey) = coordinate_pubkey_part(value)
        && is_64_hex(pubkey)
    {
        return pubkey.to_ascii_lowercase();
    }
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    hex::encode(digest)
}

fn is_64_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn coordinate_pubkey_part(s: &str) -> Option<&str> {
    let mut parts = s.splitn(3, ':');
    let _kind = parts.next()?;
    let pubkey = parts.next()?;
    parts.next()?;
    Some(pubkey)
}

const fn hex_digit_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hll_round_trip_hex() {
        let mut hll = HyperLogLog::new();
        hll.registers[0] = 5;
        hll.registers[255] = 8;
        let hex_str = hll.to_hex();
        assert_eq!(hex_str.len(), HLL_HEX_LEN);
        let parsed = HyperLogLog::from_hex(&hex_str).unwrap();
        assert_eq!(parsed, hll);
    }

    #[test]
    fn hll_merge_keeps_max() {
        let mut a = HyperLogLog::new();
        a.registers[0] = 3;
        let mut b = HyperLogLog::new();
        b.registers[0] = 5;
        a.merge(&b);
        assert_eq!(a.registers[0], 5);
    }

    #[test]
    fn hll_offset_for_event_id() {
        let event_id = "0".repeat(32) + "f" + &"0".repeat(31);
        // Position 32 is `f` ⇒ 15. Plus 8 ⇒ 23.
        assert_eq!(hll_offset_for_value(&event_id), 23);
    }

    #[test]
    fn hll_offset_for_arbitrary_string_uses_sha256() {
        // SHA-256("hello world") = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        // The 33rd char (position 32) is 'c' (12) → offset = 12 + 8 = 20.
        let v = hll_offset_for_value("hello world");
        assert_eq!(v, 20);
    }

    #[test]
    fn hll_observe_records_leading_zeros() {
        let mut hll = HyperLogLog::new();
        // Single non-zero byte at the offset, rest zero ⇒ tail is all
        // zero bytes (23 of them ⇒ 184 leading zero bits, plus the
        // spec's `+1`).
        let mut hash = [0u8; 32];
        hash[8] = 0xff;
        assert!(hll.observe(8, &hash));
        assert_eq!(
            hll.registers[0xff],
            8u8.saturating_mul(23).saturating_add(1)
        );
    }

    #[test]
    fn hll_observe_records_high_first_bit() {
        let mut hll = HyperLogLog::new();
        let mut hash = [0u8; 32];
        hash[8] = 0xff;
        hash[9] = 0x80;
        assert!(hll.observe(8, &hash));
        // Tail starts with `0x80` ⇒ zero leading zero bits ⇒ register
        // value = 1.
        assert_eq!(hll.registers[0xff], 1);
    }
}
