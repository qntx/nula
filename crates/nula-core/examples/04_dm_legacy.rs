//! NIP-04 legacy direct-message round-trip between Alice and Bob.
//!
//! NIP-04 is deprecated in favour of NIP-44 / NIP-17, but is still
//! the format relays MUST accept for backwards compatibility. This
//! example shows symmetric encryption + decryption between two BIP-340
//! peers and confirms the recovered plaintext matches the original.
//!
//! ```bash
//! cargo run --example 04_dm_legacy --features nip04
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
use nula_core::nips::nip04;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let alice = Keys::generate()?;
    let bob = Keys::generate()?;
    println!("alice : {}", alice.public_key().to_hex());
    println!("bob   : {}", bob.public_key().to_hex());

    let plaintext = "🥷 secret meeting at 21:00 sats UTC";
    println!("plain : {plaintext}");

    // Alice encrypts toward Bob's public key. The output is the
    // NIP-04 wire payload `"<ciphertext-b64>?iv=<iv-b64>"`.
    let payload = nip04::encrypt(alice.secret_key(), bob.public_key(), plaintext)?;
    println!("wire  : {payload}");
    assert!(
        payload.contains("?iv="),
        "wire form must carry the IV suffix"
    );

    // Bob decrypts using HIS secret + ALICE's public key. ECDH is
    // symmetric, so the same shared secret recovers the plaintext.
    let recovered = nip04::decrypt(bob.secret_key(), alice.public_key(), &payload)?;
    println!("plain': {recovered}");
    assert_eq!(plaintext, recovered, "round-trip must be lossless");

    // Tampering: flip a single ciphertext byte and watch decryption
    // fail. NIP-04 has no MAC, so the failure surfaces as a padding
    // error rather than an authentication error — yet another reason
    // new clients should prefer NIP-44.
    let mut tampered: Vec<u8> = payload.bytes().collect();
    tampered[0] ^= 0x01;
    let tampered = String::from_utf8(tampered).unwrap_or_default();
    let err = nip04::decrypt(bob.secret_key(), alice.public_key(), &tampered);
    println!("tamper: {err:?}");
    assert!(err.is_err(), "tampered ciphertext must be rejected");

    Ok(())
}
