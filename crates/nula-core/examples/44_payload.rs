//! NIP-44 v2 encrypted payload round-trip with payload-size guards.
//!
//! NIP-44 is the modern, authenticated, length-padded successor to
//! NIP-04. The example covers:
//!
//! 1. encrypt → decrypt happy path,
//! 2. payload-size limits surfaced through [`nula_core::limits`],
//! 3. failure mode when a peer key is wrong.
//!
//! ```bash
//! cargo run --example 44_payload --features nip44
//! ```

#![allow(
    clippy::print_stdout,
    clippy::missing_assert_message,
    clippy::panic_in_result_fn,
    clippy::indexing_slicing,
    clippy::uninlined_format_args,
    clippy::useless_vec,
    unused_crate_dependencies,
    reason = "runnable demo: stdout output is the whole point, panic-on-failure is acceptable in a script-like context, and the binary inherits the lib's dep set"
)]

use nula_core::Keys;
use nula_core::limits::{NIP44_MAX_PLAINTEXT_BYTES, NIP44_MIN_PLAINTEXT_BYTES};
use nula_core::nips::nip44;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let alice = Keys::generate()?;
    let bob = Keys::generate()?;

    println!(
        "plaintext bounds : {NIP44_MIN_PLAINTEXT_BYTES} ..= {NIP44_MAX_PLAINTEXT_BYTES} bytes"
    );
    println!("alice            : {}", alice.public_key().to_hex());
    println!("bob              : {}", bob.public_key().to_hex());

    // Happy path: Alice encrypts toward Bob; Bob decrypts back.
    let plaintext = "🌶 nip-44 v2 — authenticated, padded, secure.";
    let payload = nip44::encrypt(alice.secret_key(), bob.public_key(), plaintext)?;
    println!("payload bytes    : {}", payload.len());
    let recovered = nip44::decrypt(bob.secret_key(), alice.public_key(), &payload)?;
    assert_eq!(
        plaintext, recovered,
        "round-trip MUST preserve the plaintext"
    );
    println!("round-trip       : OK");

    // Sanity: the same payload encrypted twice MUST differ — NIP-44
    // mixes a fresh nonce on every call.
    let twice = nip44::encrypt(alice.secret_key(), bob.public_key(), plaintext)?;
    assert_ne!(payload, twice, "every NIP-44 payload MUST be unique");
    println!("nonce uniqueness : OK");

    // Negative path: a different recipient cannot decrypt.
    let mallory = Keys::generate()?;
    let err = nip44::decrypt(mallory.secret_key(), alice.public_key(), &payload);
    println!("wrong-key error  : {err:?}");
    assert!(err.is_err(), "decryption MUST fail for a wrong recipient");

    // Payload-size guard: empty plaintext is rejected by the
    // encryptor (NIP-44 mandates a non-empty payload).
    let empty = nip44::encrypt(alice.secret_key(), bob.public_key(), "");
    println!("empty rejected   : {empty:?}");
    assert!(empty.is_err(), "empty plaintext MUST be rejected");

    Ok(())
}
