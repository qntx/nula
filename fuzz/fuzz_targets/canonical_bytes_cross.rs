//! Cross-check `compute_event_id` against a hand-rolled reference
//! that serialises the canonical NIP-01 tuple directly through
//! `serde_json::to_vec`.
//!
//! Any disagreement implies one of:
//! - The internal canonical serializer drifted from NIP-01 §32
//!   (control-char escapes, tuple ordering, integer encoding).
//! - The reference path mis-encodes an edge case (caught by SHA-256
//!   diff vs the in-tree code).
//!
//! Both outcomes are valuable findings.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use nula_core::event::{Kind, Tag, Tags, compute_event_id};
use nula_core::key::PublicKey;
use nula_core::types::Timestamp;
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Structured input drawn from the fuzzer corpus.
#[derive(Debug, Arbitrary)]
struct Input {
    pubkey_seed: [u8; 32],
    created_at: u32,
    kind: u16,
    tags: Vec<Vec<String>>,
    content: String,
}

#[derive(Serialize)]
struct Canonical<'a>(
    u8,
    &'a str,
    u64,
    u16,
    &'a [Vec<String>],
    &'a str,
);

fuzz_target!(|input: Input| {
    // Derive a real BIP-340 pubkey from the 32-byte seed. Any seed
    // that does not parse maps to a known-good fixture so we still
    // exercise the canonical path.
    let pubkey = pubkey_from_seed(input.pubkey_seed);
    let pubkey_hex = pubkey.to_hex();

    let timestamp = Timestamp::from_secs(u64::from(input.created_at));
    let kind = Kind::new(input.kind);

    // Build a `Tags` instance — every tag row needs `Tag::new` so we
    // round-trip through nula's tag normalization rules too. Empty
    // rows would violate `Tag` invariants, so skip them.
    let typed_tags: Vec<Tag> = input
        .tags
        .iter()
        .filter(|row| !row.is_empty())
        .filter_map(|row| Tag::new(row.iter().map(String::as_str)).ok())
        .collect();
    let tags = Tags::from_vec(typed_tags.clone());

    // Path A: production canonicalisation + hash.
    let production_id = compute_event_id(&pubkey, timestamp, kind, &tags, &input.content);

    // Path B: reference canonicalisation via `serde_json::to_vec`
    // directly on the spec tuple. SHA-256 must match production.
    let reference_tags: Vec<Vec<String>> = typed_tags
        .iter()
        .map(|t| t.values().to_vec())
        .collect();
    let canonical = Canonical(
        0,
        &pubkey_hex,
        timestamp.as_secs(),
        kind.as_u16(),
        &reference_tags,
        &input.content,
    );
    let Ok(reference_bytes) = serde_json::to_vec(&canonical) else {
        // serde_json should never fail on a Vec writer for these
        // primitive types; if it ever does, that is itself a finding.
        panic!("reference serialization failed");
    };
    let mut hasher = Sha256::new();
    hasher.update(&reference_bytes);
    let reference_digest: [u8; 32] = hasher.finalize().into();

    assert_eq!(
        production_id.to_byte_array(),
        reference_digest,
        "canonical_bytes drifted from reference encoding (input: {input:?})",
    );

    // Re-parsing the reference bytes must yield the same tuple shape
    // (length 6, first element 0). Keeps the fuzzer honest about JSON
    // structure preservation.
    let Ok(parsed): Result<serde_json::Value, _> = serde_json::from_slice(&reference_bytes) else {
        panic!("reference bytes are not valid JSON");
    };
    let arr = parsed.as_array().expect("canonical form is an array");
    assert_eq!(arr.len(), 6, "canonical tuple must have 6 elements");
    assert_eq!(arr[0].as_u64(), Some(0), "tuple header must be 0");

});

fn pubkey_from_seed(seed: [u8; 32]) -> PublicKey {
    // Try the seed as an x-only pubkey directly. ~50% of random
    // 32-byte values are valid x-coordinates; the rest fall through
    // to a hard-coded fixture so the fuzzer still makes progress.
    if let Ok(pk) = PublicKey::from_byte_array(seed) {
        return pk;
    }
    // Generator point's x-coordinate — guaranteed parseable.
    PublicKey::parse("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
        .expect("generator x-only pubkey parses")
}
