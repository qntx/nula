// Fixed-offset byte writes into well-sized arrays; the bounds are
// constants known at compile time, but clippy still flags each
// `out[..]` as "may panic". Suppress at the module level since the
// pattern repeats everywhere.
#![allow(
    clippy::indexing_slicing,
    reason = "fixed-offset writes into pre-sized arrays; bounds are const-known"
)]

//! Lexicographic key encoding for the secondary indexes.
//!
//! Every secondary index uses raw bytes as its key so LMDB's natural
//! byte-order iteration matches the logical order we want:
//!
//! - **`Timestamp`** — big-endian `u64`. Ascending byte order =
//!   ascending numeric. We iterate `iter_rev` for newest-first
//!   queries; encoding is otherwise vanilla.
//! - **`Kind`** — big-endian `u16`.
//! - **`PublicKey` / `EventId`** — raw 32-byte fixed-width form.
//!
//! The layout of each index is documented next to its builder
//! function. Adding a new index means writing a new builder here and
//! a new dbi handle in `store.rs`.

use nula_core::event::{EventId, Kind};
use nula_core::key::PublicKey;
use nula_core::types::Timestamp;

/// Length of a serialised `EventId`.
pub(crate) const ID_LEN: usize = 32;
/// Length of a serialised `PublicKey`.
pub(crate) const PUBKEY_LEN: usize = 32;
/// Length of a big-endian `Timestamp`.
pub(crate) const TS_LEN: usize = 8;
/// Length of a big-endian `Kind`.
pub(crate) const KIND_LEN: usize = 2;

/// `by_created_at` key: `[ts_be(8)] [event_id(32)]`.
///
/// Length 40. Iterating the dbi ascending visits oldest-first;
/// iterating descending visits newest-first.
pub(crate) fn by_created_at(ts: Timestamp, id: &EventId) -> [u8; TS_LEN + ID_LEN] {
    let mut out = [0u8; TS_LEN + ID_LEN];
    out[..TS_LEN].copy_from_slice(&ts.as_secs().to_be_bytes());
    out[TS_LEN..].copy_from_slice(&id.to_byte_array());
    out
}

/// `by_author_ts` key: `[pubkey(32)] [ts_be(8)] [event_id(32)]`.
///
/// Length 72. Range scans over a single author fix the leading 32
/// bytes; iteration then walks all that author's events in
/// timestamp order.
pub(crate) fn by_author_ts(
    pubkey: &PublicKey,
    ts: Timestamp,
    id: &EventId,
) -> [u8; PUBKEY_LEN + TS_LEN + ID_LEN] {
    let mut out = [0u8; PUBKEY_LEN + TS_LEN + ID_LEN];
    out[..PUBKEY_LEN].copy_from_slice(&pubkey.to_byte_array());
    out[PUBKEY_LEN..PUBKEY_LEN + TS_LEN].copy_from_slice(&ts.as_secs().to_be_bytes());
    out[PUBKEY_LEN + TS_LEN..].copy_from_slice(&id.to_byte_array());
    out
}

/// `by_kind_author_ts` key: `[kind_be(2)] [pubkey(32)] [ts_be(8)] [event_id(32)]`.
///
/// Length 74. Range scans for `(kind, author)` fix the leading
/// 34 bytes; the most common Nostr filter shape lands here.
pub(crate) fn by_kind_author_ts(
    kind: Kind,
    pubkey: &PublicKey,
    ts: Timestamp,
    id: &EventId,
) -> [u8; KIND_LEN + PUBKEY_LEN + TS_LEN + ID_LEN] {
    let mut out = [0u8; KIND_LEN + PUBKEY_LEN + TS_LEN + ID_LEN];
    out[..KIND_LEN].copy_from_slice(&kind.as_u16().to_be_bytes());
    let mut cursor = KIND_LEN;
    out[cursor..cursor + PUBKEY_LEN].copy_from_slice(&pubkey.to_byte_array());
    cursor += PUBKEY_LEN;
    out[cursor..cursor + TS_LEN].copy_from_slice(&ts.as_secs().to_be_bytes());
    cursor += TS_LEN;
    out[cursor..].copy_from_slice(&id.to_byte_array());
    out
}

/// `by_coordinate` key: `[kind_be(2)] [pubkey(32)] [identifier_utf8(..)]`.
///
/// Variable length. Identifier is appended verbatim; LMDB compares
/// the resulting byte slices lexicographically, which gives us the
/// canonical NIP-33 ordering.
pub(crate) fn by_coordinate(kind: Kind, pubkey: &PublicKey, identifier: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(KIND_LEN + PUBKEY_LEN + identifier.len());
    out.extend_from_slice(&kind.as_u16().to_be_bytes());
    out.extend_from_slice(&pubkey.to_byte_array());
    out.extend_from_slice(identifier.as_bytes());
    out
}

/// Encode a `(kind, pubkey)` prefix for range scans over
/// `by_kind_author_ts`.
pub(crate) fn kind_author_prefix(kind: Kind, pubkey: &PublicKey) -> [u8; KIND_LEN + PUBKEY_LEN] {
    let mut out = [0u8; KIND_LEN + PUBKEY_LEN];
    out[..KIND_LEN].copy_from_slice(&kind.as_u16().to_be_bytes());
    out[KIND_LEN..].copy_from_slice(&pubkey.to_byte_array());
    out
}

/// Encode a `pubkey` prefix for range scans over `by_author_ts`.
pub(crate) fn author_prefix(pubkey: &PublicKey) -> [u8; PUBKEY_LEN] {
    pubkey.to_byte_array()
}

/// Upper-bound key for a range scan with the given prefix.
///
/// `upper_bound(prefix)` returns the first byte slice that compares
/// strictly greater than every key whose prefix matches `prefix`. It
/// works by bumping the rightmost non-`0xFF` byte; if every byte is
/// `0xFF` the prefix occupies the very end of the key space and the
/// scan should run until the end of the dbi.
pub(crate) fn upper_bound(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut out = prefix.to_vec();
    for byte in out.iter_mut().rev() {
        if *byte == 0xFF {
            *byte = 0;
        } else {
            *byte = byte.wrapping_add(1);
            return Some(out);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upper_bound_bumps_last_non_ff_byte() {
        assert_eq!(
            upper_bound(&[0x01, 0x02]).as_deref(),
            Some(&[0x01, 0x03][..])
        );
        assert_eq!(
            upper_bound(&[0x01, 0xFF]).as_deref(),
            Some(&[0x02, 0x00][..])
        );
    }

    #[test]
    fn upper_bound_returns_none_for_all_ff() {
        assert_eq!(upper_bound(&[0xFF, 0xFF]), None);
    }
}
