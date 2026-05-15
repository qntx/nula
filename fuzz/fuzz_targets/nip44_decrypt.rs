//! NIP-44 v2 decrypt fuzz target.
//!
//! Property under test: `decrypt` MUST NOT panic for any input —
//! ill-formed base64, bogus version byte, truncated ciphertext, or
//! a mismatched MAC must all return a typed `Nip44Error`.
//!
//! A panic here would surface as an unrecoverable crash for any
//! relay or signer that decrypts attacker-controlled payloads.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use nula_core::key::{PublicKey, SecretKey};
use nula_core::nips::nip44;

#[derive(Debug, Arbitrary)]
struct Input {
    secret_seed: [u8; 32],
    peer_seed: [u8; 32],
    payload: String,
}

fuzz_target!(|input: Input| {
    let Some(secret) = secret_from_seed(input.secret_seed) else {
        return;
    };
    let peer = pubkey_from_seed(input.peer_seed);

    // Whatever happens, this call MUST return — never panic, never
    // overflow, never wedge in a side-effecting loop.
    let _ = nip44::decrypt(&secret, &peer, &input.payload);
});

fn secret_from_seed(seed: [u8; 32]) -> Option<SecretKey> {
    SecretKey::from_byte_array(seed).ok()
}

fn pubkey_from_seed(seed: [u8; 32]) -> PublicKey {
    PublicKey::from_byte_array(seed).unwrap_or_else(|_| {
        // Generator x-coordinate fallback — guaranteed valid.
        PublicKey::parse("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .expect("generator x-only pubkey parses")
    })
}
