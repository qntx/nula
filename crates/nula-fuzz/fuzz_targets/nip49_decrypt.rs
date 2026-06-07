//! NIP-49 (`ncryptsec`) decode + decrypt fuzz target.
//!
//! Property under test: decoding an arbitrary string as an
//! [`EncryptedSecretKey`] and decrypting it with an arbitrary password
//! MUST NOT panic. Malformed bech32, an unsupported version byte, an
//! out-of-range scrypt `log_n`, a truncated payload, or simply the
//! wrong password must all surface as a typed `Nip49Error`.
//!
//! `ncryptsec` strings are imported from untrusted sources (QR codes,
//! clipboards, backups), so a panic on the decrypt path is an
//! attacker-triggerable crash for any wallet or signer.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use nula_core::nips::nip49::EncryptedSecretKey;

#[derive(Debug, Arbitrary)]
struct Input {
    /// Candidate `ncryptsec1…` bech32 string.
    ncryptsec: String,
    /// Candidate decryption password.
    password: String,
}

fuzz_target!(|input: Input| {
    // Decoding rejects almost everything; only well-formed payloads
    // reach `decrypt`, which must still never panic on a wrong password
    // or a forged-but-well-formed header.
    if let Ok(encrypted) = EncryptedSecretKey::from_bech32(&input.ncryptsec) {
        let _ = encrypted.decrypt(&input.password);
    }
});
