//! NIP-19 decode → re-encode → decode round-trip fuzz target.
//!
//! Property under test: for every input string `s` such that
//! `Nip19Entity::from_bech32(s)` returns `Ok(entity)`,
//! `entity.to_bech32().unwrap()` MUST parse back to a structurally
//! equal entity. Failure implies one of:
//!
//! - The TLV decoder accepts inputs that the encoder cannot reproduce
//!   (silent data loss).
//! - The encoder normalises in ways the decoder rejects (asymmetric
//!   serialisation).
//!
//! Both shapes are spec violations.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nula_core::nips::nip19::{FromBech32, Nip19Entity, ToBech32};

fuzz_target!(|input: &[u8]| {
    // bech32 is ASCII-only; non-UTF-8 inputs cannot be valid anyway.
    let Ok(text) = std::str::from_utf8(input) else {
        return;
    };

    // Empty / whitespace inputs are uninteresting and short-circuit
    // before we touch the bech32 decoder.
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return;
    }

    let Ok(entity) = Nip19Entity::from_bech32(trimmed) else {
        return;
    };

    let reencoded = entity
        .to_bech32()
        .expect("a successfully-decoded entity must always re-encode");

    let recovered = Nip19Entity::from_bech32(&reencoded)
        .expect("a freshly-encoded entity must always re-decode");

    assert_eq!(
        entity, recovered,
        "decode→encode→decode is not idempotent: input={trimmed:?} encoded={reencoded:?}",
    );

    // Second-pass encode must be byte-identical to the first. This
    // catches non-deterministic ordering of TLV records or relay
    // lists that survived the equality check by sheer luck.
    let reencoded_again = recovered
        .to_bech32()
        .expect("re-encoded entity must encode again");
    assert_eq!(
        reencoded, reencoded_again,
        "encode is not deterministic for entity={entity:?}",
    );
});
