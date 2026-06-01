// Copyright (c) 2026 QNTX <https://qntx.fun>
// Distributed under the MIT or Apache-2.0 license.

//! Interop-boundary contract: wire inputs where nula's parsers are
//! deliberately **stricter** than rust-nostr (and, by extension,
//! nostr-tools / go-nostr). Each case is pinned so the divergence is
//! documented and cannot silently drift in either direction.
//!
//! Every assertion below was verified against BOTH code bases before
//! being written (no assumed divergences):
//!
//! - nula     — `crates/nula-core/src/...`
//! - upstream — `3rdparty/nostr/crates/nostr/src/...`
//!
//! These are not bugs: refusing lightly-malformed wire data is the safer
//! default. The point of this file is to tell downstream users exactly
//! which inputs nula rejects (or parses differently) that other stacks
//! tolerate, so they can make an informed interop decision.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::tests_outside_test_module,
    unused_crate_dependencies,
    reason = "integration tests inherit the crate's full dev-dep set; \
              dev-deps this file does not consume would otherwise trip \
              `unused_crate_dependencies`. Test code may also panic for brevity."
)]

use bech32::{Bech32, Hrp};
use nula_core::Coordinate;
use nula_core::FromBech32;
use nula_core::nips::nip19::{FromBech32Error, Nip19Event};

/// NIP-19 TLV tag for the entity-specific payload (event id here).
const SPECIAL: u8 = 0;
/// NIP-19 TLV tag for an author public key.
const AUTHOR: u8 = 2;
/// NIP-19 TLV tag for an event kind (`u32` big-endian).
const KIND: u8 = 3;

/// Append one `[tag][len][value]` TLV record to `buf`.
fn push_tlv(buf: &mut Vec<u8>, tag: u8, value: &[u8]) {
    buf.push(tag);
    buf.push(u8::try_from(value.len()).expect("test TLV value fits in one byte"));
    buf.extend_from_slice(value);
}

/// bech32-encode a TLV payload under `hrp` (mirrors nula's internal
/// `encode_raw`, so the result is exactly what a peer impl would emit).
fn bech32_nip19(hrp: &str, payload: &[u8]) -> String {
    bech32::encode::<Bech32>(Hrp::parse(hrp).expect("valid hrp"), payload).expect("bech32 encode")
}

/// `nevent` with a kind that overflows 16 bits.
///
/// Upstream `nips/nip19.rs:466-468` narrows the 32-bit TLV value with a
/// lossy `as u16` cast (`65_537 -> 1`) and *accepts* the string. nula
/// `nips/nip19/mod.rs:520` rejects it with `KindOutOfRange` because its
/// [`nula_core::Kind`] is a 16-bit type and silent truncation would
/// fabricate a different kind than the wire declared.
#[test]
fn nevent_kind_out_of_range_is_rejected() {
    let mut tlv = Vec::new();
    push_tlv(&mut tlv, SPECIAL, &[0xab; 32]);
    push_tlv(&mut tlv, KIND, &65_537_u32.to_be_bytes());
    let wire = bech32_nip19("nevent", &tlv);

    let err = Nip19Event::from_bech32(&wire).expect_err("kind 65537 exceeds nula's 16-bit Kind");
    assert!(
        matches!(err, FromBech32Error::KindOutOfRange { raw: 65_537 }),
        "expected KindOutOfRange, got {err:?}",
    );
}

/// `nevent` carrying an author TLV that is not a 32-byte key.
///
/// Upstream `nips/nip19.rs:455-456` decodes the author with
/// `PublicKey::from_slice(bytes).ok()` and, per its own comment, does
/// **not** propagate the error — the malformed author is silently
/// dropped and the `nevent` still parses. nula `nips/nip19/mod.rs:417`
/// requires exactly 32 bytes and fails the whole parse instead of
/// returning an event with a quietly-discarded field.
#[test]
fn nevent_invalid_author_is_rejected() {
    let mut tlv = Vec::new();
    push_tlv(&mut tlv, SPECIAL, &[0xab; 32]);
    push_tlv(&mut tlv, AUTHOR, &[0x01; 31]); // 31 bytes: too short for a key
    let wire = bech32_nip19("nevent", &tlv);

    assert!(
        Nip19Event::from_bech32(&wire).is_err(),
        "a 31-byte author TLV must be rejected, not silently dropped",
    );
}

/// `<kind>:<pubkey>:<identifier>` (`a`-tag form) whose identifier
/// contains colons.
///
/// Upstream `nips/nip01/mod.rs:144-149` splits on every `:` and keeps
/// only the third field, so `weird:id:with:colons` is **truncated** to
/// `weird`. nula `event/coordinate.rs:100` uses `splitn(3, ':')` and
/// preserves the full identifier — the spec does not forbid colons in a
/// `d` tag, so truncation would corrupt a legitimate address.
#[test]
fn coordinate_preserves_colons_in_identifier() {
    let pubkey = "aa4fc8665f5696e33db7e1a572e3b0f5b3d615837b0f362dcb1c8068b098c7b4";
    let coord = Coordinate::parse(format!("30023:{pubkey}:weird:id:with:colons"))
        .expect("valid kind:pubkey:identifier triple");
    assert_eq!(
        coord.identifier, "weird:id:with:colons",
        "nula must preserve colons in the identifier (upstream truncates to `weird`)",
    );
}
