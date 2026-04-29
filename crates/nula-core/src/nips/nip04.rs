//! [NIP-04] Encrypted Direct Messages — *deprecated*.
//!
//! NIP-04 is the **legacy** direct-message scheme: AES-256-CBC over a
//! raw secp256k1 ECDH X coordinate (no key-derivation function), wire-
//! encoded as `<base64(ciphertext)>?iv=<base64(iv)>` and carried in
//! kind-4 events.
//!
//! The scheme is officially superseded by [NIP-17] (which composes
//! [NIP-44] v2 + [NIP-59] gift wrapping) and is known to:
//!
//! - leak conversation graph metadata (recipient pubkey is in the
//!   public `p` tag, sender pubkey is in the public `pubkey` field, and
//!   the kind itself signals "this is a DM"),
//! - expose plaintext lengths via padding-free CBC,
//! - reuse the unhashed ECDH `X` as a key, which collides on weak
//!   curves and lets an attacker perform offline correlation across
//!   conversations.
//!
//! `nula-core` keeps the implementation only for **backwards
//! compatibility** with the existing on-relay corpus and to satisfy
//! NIP-46 remote-signer requests that still target it. New clients
//! SHOULD prefer NIP-17.
//!
//! # Wire format
//!
//! ```text
//! base64(ciphertext) ?iv= base64(16-byte IV)
//! ```
//!
//! Both halves use the standard (`+`/`/`) base64 alphabet with `=`
//! padding, per the spec.
//!
//! [NIP-04]: https://github.com/nostr-protocol/nips/blob/master/04.md
//! [NIP-17]: https://github.com/nostr-protocol/nips/blob/master/17.md
//! [NIP-44]: https://github.com/nostr-protocol/nips/blob/master/44.md
//! [NIP-59]: https://github.com/nostr-protocol/nips/blob/master/59.md

use aes::Aes256;
use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use secp256k1::{Parity, ecdh};
use thiserror::Error;
use zeroize::Zeroize;

use crate::key::{PublicKey, SecretKey};
use crate::util::rng::{self, RngError};

/// AES-256 key length.
const KEY_BYTES: usize = 32;
/// CBC initialisation vector length (== AES block size).
const IV_BYTES: usize = 16;
/// Wire separator between the ciphertext and the IV.
const SEPARATOR: &str = "?iv=";

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

/// Errors raised by [`encrypt`] and [`decrypt`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Nip04Error {
    /// The wire payload did not contain the `?iv=` separator.
    #[error("payload is missing the `?iv=` separator")]
    MissingIvSeparator,
    /// The ciphertext or IV failed base64 decoding.
    #[error("base64 decode failed: {0}")]
    Base64(#[from] base64::DecodeError),
    /// The IV had an unexpected length.
    #[error("IV must be {expected} bytes, got {actual}")]
    InvalidIvLength {
        /// Required length per the spec.
        expected: usize,
        /// Length actually decoded.
        actual: usize,
    },
    /// AES-256-CBC unpadding failed. The payload was either decrypted
    /// with the wrong shared key (peer mismatch) or has been tampered
    /// with — NIP-04 has no MAC, so a bit-flip on the wire surfaces here
    /// as a padding error rather than as authenticated rejection.
    #[error("AES-256-CBC unpadding failed (wrong key or tampered payload)")]
    Unpad,
    /// The decrypted bytes are not valid UTF-8.
    #[error("decrypted plaintext is not valid UTF-8")]
    InvalidUtf8,
    /// RNG failed to provide entropy for the IV.
    #[error(transparent)]
    Rng(#[from] RngError),
}

/// Compute the unhashed 32-byte ECDH X coordinate used by NIP-04.
///
/// Lifts the peer's x-only key with even parity (the cross-impl
/// convention) and runs `secp256k1` ECDH. Returns the first 32 bytes
/// of the 64-byte serialized point — i.e. just `X`, with no KDF. This
/// is the protocol-mandated weakness that NIP-44 v2 fixes via HKDF.
fn shared_secret_x(secret: &SecretKey, peer: &PublicKey) -> [u8; KEY_BYTES] {
    let normalized = secp256k1::PublicKey::from_x_only_public_key(*peer.as_inner(), Parity::Even);
    let ssp = ecdh::shared_secret_point(&normalized, secret.as_inner());
    let mut x = [0_u8; KEY_BYTES];
    x.copy_from_slice(&ssp[..KEY_BYTES]);
    x
}

/// Encrypt `plaintext` for `peer` using the NIP-04 wire format.
///
/// Generates a fresh 16-byte IV from the OS RNG on every call. The
/// returned string is `base64(ciphertext)?iv=base64(iv)` — caller is
/// responsible for placing it in a kind-4 event's `content` field.
///
/// # Errors
///
/// Returns [`Nip04Error::Rng`] if the OS entropy source fails.
pub fn encrypt(
    secret: &SecretKey,
    peer: &PublicKey,
    plaintext: &str,
) -> Result<String, Nip04Error> {
    let mut key = shared_secret_x(secret, peer);
    let iv = rng::random_bytes::<IV_BYTES>()?;

    let ciphertext = Aes256CbcEnc::new((&key).into(), (&iv).into())
        .encrypt_padded_vec::<Pkcs7>(plaintext.as_bytes());

    // Best-effort wipe; the compiler may still elide under aggressive
    // optimisation but `zeroize` issues volatile writes.
    key.zeroize();

    Ok(format!(
        "{}{SEPARATOR}{}",
        BASE64.encode(&ciphertext),
        BASE64.encode(iv),
    ))
}

/// Decrypt a NIP-04 wire payload sent by `peer`.
///
/// Expects exactly one `?iv=` separator; an absent or duplicate
/// separator is rejected. Both halves must be valid standard base64.
/// The IV must be exactly 16 bytes after decoding.
///
/// # Errors
///
/// Returns [`Nip04Error::MissingIvSeparator`] / [`Nip04Error::Base64`]
/// for malformed wire framing, [`Nip04Error::InvalidIvLength`] when the
/// IV is not 16 bytes, [`Nip04Error::Unpad`] when AES rejects the
/// padding (wrong peer or tampered ciphertext — NIP-04 has no MAC), and
/// [`Nip04Error::InvalidUtf8`] when the recovered bytes are not UTF-8.
pub fn decrypt(secret: &SecretKey, peer: &PublicKey, payload: &str) -> Result<String, Nip04Error> {
    let (ciphertext_b64, iv_b64) = payload
        .split_once(SEPARATOR)
        .ok_or(Nip04Error::MissingIvSeparator)?;

    let mut ciphertext = BASE64.decode(ciphertext_b64)?;
    let iv_bytes = BASE64.decode(iv_b64)?;
    let iv: [u8; IV_BYTES] =
        iv_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Nip04Error::InvalidIvLength {
                expected: IV_BYTES,
                actual: iv_bytes.len(),
            })?;

    let mut key = shared_secret_x(secret, peer);
    let plaintext = Aes256CbcDec::new((&key).into(), (&iv).into())
        .decrypt_padded::<Pkcs7>(&mut ciphertext)
        .map_err(|_| Nip04Error::Unpad)?;

    let result = core::str::from_utf8(plaintext)
        .map_err(|_| Nip04Error::InvalidUtf8)?
        .to_owned();

    key.zeroize();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::Keys;

    fn keys_alice() -> Keys {
        Keys::parse("000000000000000000000000000000000000000000000000000000000000a1ce").unwrap()
    }

    fn keys_bob() -> Keys {
        Keys::parse("00000000000000000000000000000000000000000000000000000000000000b0").unwrap()
    }

    #[test]
    fn round_trip_short_message() {
        let alice = keys_alice();
        let bob = keys_bob();
        let ciphertext = encrypt(alice.secret_key(), bob.public_key(), "hello").unwrap();
        let recovered = decrypt(bob.secret_key(), alice.public_key(), &ciphertext).unwrap();
        assert_eq!(recovered, "hello");
    }

    #[test]
    fn round_trip_unicode_payload() {
        // Multi-byte UTF-8 boundaries — a regression that bit early
        // ports of NIP-04 because PKCS7 unpadding is byte-wise.
        let alice = keys_alice();
        let bob = keys_bob();
        let msg = "你好，nostr 🦀";
        let ciphertext = encrypt(alice.secret_key(), bob.public_key(), msg).unwrap();
        let recovered = decrypt(bob.secret_key(), alice.public_key(), &ciphertext).unwrap();
        assert_eq!(recovered, msg);
    }

    #[test]
    fn fresh_iv_per_call_yields_distinct_ciphertexts() {
        // Encrypting the same plaintext twice must produce different
        // wire payloads — proves the IV is sampled per call.
        let alice = keys_alice();
        let bob = keys_bob();
        let a = encrypt(alice.secret_key(), bob.public_key(), "same").unwrap();
        let b = encrypt(alice.secret_key(), bob.public_key(), "same").unwrap();
        assert_ne!(a, b, "two encryptions of the same plaintext must differ");
    }

    #[test]
    fn empty_plaintext_round_trip() {
        // PKCS7 unambiguously encodes the empty string as one full
        // padding block — confirm the round trip handles it.
        let alice = keys_alice();
        let bob = keys_bob();
        let ciphertext = encrypt(alice.secret_key(), bob.public_key(), "").unwrap();
        let recovered = decrypt(bob.secret_key(), alice.public_key(), &ciphertext).unwrap();
        assert_eq!(recovered, "");
    }

    #[test]
    fn missing_separator_is_rejected() {
        let alice = keys_alice();
        let bob = keys_bob();
        let err = decrypt(alice.secret_key(), bob.public_key(), "no-separator-here").unwrap_err();
        assert!(matches!(err, Nip04Error::MissingIvSeparator));
    }

    #[test]
    fn malformed_base64_is_rejected() {
        let alice = keys_alice();
        let bob = keys_bob();
        let err = decrypt(
            alice.secret_key(),
            bob.public_key(),
            "!!not-base64!!?iv=!!neither!!",
        )
        .unwrap_err();
        assert!(matches!(err, Nip04Error::Base64(_)));
    }

    #[test]
    fn wrong_iv_length_is_rejected() {
        let alice = keys_alice();
        let bob = keys_bob();
        // 8-byte IV, 16 expected.
        let payload = format!(
            "{}{SEPARATOR}{}",
            BASE64.encode([0_u8; 32]),
            BASE64.encode([0_u8; 8]),
        );
        let err = decrypt(alice.secret_key(), bob.public_key(), &payload).unwrap_err();
        assert!(matches!(
            err,
            Nip04Error::InvalidIvLength {
                expected: 16,
                actual: 8,
            }
        ));
    }

    #[test]
    fn wrong_peer_yields_unpad_error() {
        // Symmetric ECDH means the *only* way to fail is a totally
        // unrelated peer. The error surface should be `Unpad`, not a
        // panic, because NIP-04 has no MAC.
        let alice = keys_alice();
        let bob = keys_bob();
        let mallory =
            Keys::parse("00000000000000000000000000000000000000000000000000000000000ca800")
                .unwrap();

        let ciphertext = encrypt(alice.secret_key(), bob.public_key(), "for bob").unwrap();
        let err = decrypt(mallory.secret_key(), alice.public_key(), &ciphertext).unwrap_err();
        // Either Unpad (most common) or InvalidUtf8 (occasional, when
        // garbage bytes happen to pad-validate); both are acceptable
        // failures, but never a panic.
        assert!(matches!(err, Nip04Error::Unpad | Nip04Error::InvalidUtf8));
    }
}
