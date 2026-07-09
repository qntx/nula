//! [NIP-49] Private Key Encryption (`ncryptsec`).
//!
//! Encrypts a 32-byte secp256k1 secret key with a user-supplied
//! password and returns a `bech32`-encoded `ncryptsec1...` string. The
//! format is *intentionally* expensive to brute-force: the password is
//! NFKC-normalised, then run through `scrypt` with caller-chosen
//! `log_n`, then the secret is sealed under XChaCha20-Poly1305 with
//! the security-level byte as authenticated data.
//!
//! # Wire layout (91 bytes before bech32)
//!
//! ```text
//! ┌─ 1 ─┬─ 1 ──┬───── 16 ─────┬───── 24 ─────┬─ 1 ──┬───── 48 ─────┐
//! │ ver │log_n │     salt     │     nonce    │ aad  │  ciphertext  │
//! └─────┴──────┴──────────────┴──────────────┴──────┴──────────────┘
//!   0x02   user      random        random      KS      32B+16B tag
//! ```
//!
//! - `version` is fixed at `0x02` (the only one defined by spec).
//! - `aad` is the [`KeySecurity`] byte; binding it into the AEAD means
//!   tampering with the security level invalidates the MAC.
//! - `ciphertext` is the secret key (32 bytes) plus the Poly1305 tag
//!   (16 bytes).
//!
//! # Cost
//!
//! `log_n` is a power-of-two scrypt iteration count. The spec table
//! recommends `16` (≈100 ms / 64 MiB) for client UX and `21` for
//! cold-storage backups. We expose the dial unmodified.
//!
//! [NIP-49]: https://github.com/nostr-protocol/nips/blob/master/49.md

#![expect(
    clippy::expect_used,
    clippy::unwrap_in_result,
    clippy::missing_panics_doc,
    reason = "every `expect` here guards a length invariant the surrounding \
              code has just *proved* (e.g. an `if bytes.len() != \
              PAYLOAD_BYTES { return Err(...) }` directly above a chain \
              of `split_first_chunk::<N>` calls whose total fixed sizes \
              add up to `PAYLOAD_BYTES`). The clippy lints are tuned for \
              application code; cryptographic primitives cannot avoid \
              `expect` without giving up the spec-mandated `Result`-only \
              signatures of `XChaCha20Poly1305::encrypt`, \
              `bech32::Hrp::parse`, and friends. Each call carries a \
              comment that documents the exact guarantee it relies on."
)]

use bech32::Bech32;
use bech32::primitives::decode::{CheckedHrpstring, CheckedHrpstringError};
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use scrypt::{Params as ScryptParams, scrypt};
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroize;

use crate::key::{SecretKey, SecretKeyError};
use crate::util::rng::{self, RngError};

/// Wire HRP for the bech32 encoding.
pub const HRP: &str = "ncryptsec";
/// NIP-49 version byte (the only one defined by spec).
pub const VERSION_BYTE: u8 = 0x02;
/// scrypt salt length.
pub const SALT_BYTES: usize = 16;
/// XChaCha20-Poly1305 nonce length.
pub const NONCE_BYTES: usize = 24;
/// Symmetric key length (scrypt output).
const SYM_KEY_BYTES: usize = 32;
/// Plaintext (secret key) length.
const SECRET_BYTES: usize = 32;
/// Poly1305 tag length.
const TAG_BYTES: usize = 16;
/// Sealed ciphertext length: secret + tag.
const CIPHERTEXT_BYTES: usize = SECRET_BYTES + TAG_BYTES;
/// Total wire length (before bech32 encoding).
pub const PAYLOAD_BYTES: usize =
    1 /* version */ + 1 /* log_n */ + SALT_BYTES + NONCE_BYTES + 1 /* aad */ + CIPHERTEXT_BYTES;

/// scrypt's published soft maximum for `log_n` on a 64-bit host. Going
/// past this risks `Params::new` returning `Err(InvalidParams)`.
///
/// Exposed so the [`Nip49Error::LogNTooLarge`] doc-link resolves in
/// the public rustdoc tree, and so callers wiring a UI cost slider
/// have the value to bound it against without having to redefine it
/// downstream.
pub const MAX_LOG_N: u8 = 30;

/// scrypt parallelism factor (`p`). Spec § Symmetric Encryption Key
/// derivation says `p = 1`.
const SCRYPT_P: u32 = 1;
/// scrypt block size (`r`). Spec says `r = 8`.
const SCRYPT_R: u32 = 8;

/// Author-declared key-security level, baked into the ciphertext as
/// AEAD additional-authenticated-data so it cannot be forged after the
/// fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum KeySecurity {
    /// `0x00` — author admits the key has been handled insecurely
    /// (cut-and-pasted, kept in plaintext, etc.).
    Weak = 0x00,
    /// `0x01` — author asserts the key has only ever lived inside an
    /// encrypted container.
    Strong = 0x01,
    /// `0x02` — author does not track this signal.
    Untracked = 0x02,
}

impl KeySecurity {
    /// Round-trip from the `u8` byte found on the wire.
    ///
    /// # Errors
    ///
    /// Returns [`Nip49Error::InvalidKeySecurity`] for any byte outside
    /// `0x00..=0x02`.
    pub const fn from_byte(byte: u8) -> Result<Self, Nip49Error> {
        match byte {
            0x00 => Ok(Self::Weak),
            0x01 => Ok(Self::Strong),
            0x02 => Ok(Self::Untracked),
            _ => Err(Nip49Error::InvalidKeySecurity(byte)),
        }
    }
}

/// Errors raised by NIP-49 helpers.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Nip49Error {
    /// scrypt rejected the requested parameters (typically `log_n` too
    /// large for the running architecture, or memory exhaustion on the
    /// host).
    #[error("invalid scrypt parameters (log_n={log_n}): {message}")]
    InvalidParams {
        /// Caller-supplied `log_n`.
        log_n: u8,
        /// Backend message.
        message: String,
    },
    /// `log_n` exceeded [`MAX_LOG_N`]. Picking values above this bound
    /// makes the on-host derivation either impossibly slow or rejected
    /// by the scrypt crate; we cap proactively so callers get a clear
    /// diagnostic.
    #[error("log_n {0} exceeds the supported cap of {MAX_LOG_N}")]
    LogNTooLarge(u8),
    /// scrypt failed during derivation (output buffer length mismatch).
    #[error("scrypt key derivation failed: {0}")]
    Scrypt(String),
    /// XChaCha20-Poly1305 encryption / decryption failed.
    ///
    /// On encrypt this is unreachable in practice (ChaCha20-Poly1305
    /// only fails when the message exceeds `2^32 - 1` blocks, which a
    /// 32-byte secret cannot). On decrypt this fires when the password
    /// is wrong, the ciphertext was tampered with, or the
    /// [`KeySecurity`] byte was rewritten — the AEAD tag catches all
    /// three.
    #[error("XChaCha20-Poly1305 operation failed (wrong password or tampered ciphertext)")]
    Aead,
    /// The `ncryptsec1...` payload was the wrong length.
    #[error("ncryptsec payload is {got} bytes, expected {PAYLOAD_BYTES}")]
    InvalidLength {
        /// Actual length on the wire.
        got: usize,
    },
    /// The version byte was not `0x02`.
    #[error("unsupported NIP-49 version byte: {0:#04x}")]
    UnsupportedVersion(u8),
    /// The key-security byte was outside `0x00..=0x02`.
    #[error("invalid key-security byte: {0:#04x}")]
    InvalidKeySecurity(u8),
    /// bech32 decoding failed.
    #[error("bech32 decoding failed: {0}")]
    Decode(#[from] CheckedHrpstringError),
    /// bech32 encoding failed.
    #[error("bech32 encoding failed: {0}")]
    Encode(#[from] bech32::EncodeError),
    /// The bech32 HRP was not `"ncryptsec"`.
    #[error("expected HRP `ncryptsec`, got `{0}`")]
    UnexpectedHrp(String),
    /// The decrypted bytes did not parse as a valid secp256k1 secret.
    #[error(transparent)]
    SecretKey(#[from] SecretKeyError),
    /// OS RNG failed.
    #[error(transparent)]
    Rng(#[from] RngError),
}

/// An encrypted secret key, ready to be bech32-encoded as `ncryptsec1...`.
///
/// `Debug` redacts every byte so the value can be safely logged.
///
/// We deliberately do **not** implement `Copy`: even though every
/// field is `Copy`-eligible, silently duplicating an encrypted secret
/// across the stack would violate the principle that callers must
/// reason explicitly about every place the ciphertext lives. Use
/// [`Clone`] when you really need a second owned copy.
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedSecretKey {
    log_n: u8,
    salt: [u8; SALT_BYTES],
    nonce: [u8; NONCE_BYTES],
    security: KeySecurity,
    ciphertext: [u8; CIPHERTEXT_BYTES],
}

impl std::fmt::Debug for EncryptedSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedSecretKey")
            .field("log_n", &self.log_n)
            .field("security", &self.security)
            .field("salt", &"<redacted>")
            .field("nonce", &"<redacted>")
            .field("ciphertext", &"<redacted>")
            .finish()
    }
}

impl Drop for EncryptedSecretKey {
    /// Best-effort zeroize on drop.
    ///
    /// `ciphertext` is encrypted, but `salt` and `nonce` are
    /// privacy-relevant inputs to the scrypt KDF — wiping them
    /// reduces the chance that a freed allocation hands them to
    /// the next allocator caller. The compiler may still elide
    /// some writes under aggressive optimisation; the
    /// [`zeroize`](https://docs.rs/zeroize) crate's volatile-write
    /// implementation is the best portable mitigation we have.
    fn drop(&mut self) {
        self.salt.zeroize();
        self.nonce.zeroize();
        self.ciphertext.zeroize();
        // `log_n` and `security` are `Copy` enums/integers; nothing
        // we can do about them, and they're not sensitive on their own.
    }
}

impl EncryptedSecretKey {
    /// Encrypt `secret` under `password` with a random salt and nonce.
    ///
    /// `log_n` is the scrypt cost parameter; spec recommends `16` for
    /// client UX and `21+` for cold-storage. `security` is recorded as
    /// AAD so any later tamper is caught by the AEAD.
    ///
    /// # Errors
    ///
    /// Returns [`Nip49Error::LogNTooLarge`] / [`Nip49Error::InvalidParams`] when
    /// scrypt rejects the cost, or [`Nip49Error::Rng`] when the OS RNG is
    /// unavailable.
    pub fn encrypt(
        secret: &SecretKey,
        password: &str,
        log_n: u8,
        security: KeySecurity,
    ) -> Result<Self, Nip49Error> {
        let mut salt = [0u8; SALT_BYTES];
        let mut nonce = [0u8; NONCE_BYTES];
        rng::fill_bytes(&mut salt)?;
        rng::fill_bytes(&mut nonce)?;
        Self::encrypt_with(secret, password, log_n, security, salt, nonce)
    }

    /// Encrypt with a caller-supplied salt and nonce.
    ///
    /// **Use with care**: reusing a `(password, salt, nonce)` triple
    /// across two encryptions defeats the AEAD. Reserved for
    /// known-answer test vectors and deterministic fixtures.
    ///
    /// # Errors
    ///
    /// See [`Self::encrypt`].
    pub fn encrypt_with(
        secret: &SecretKey,
        password: &str,
        log_n: u8,
        security: KeySecurity,
        salt: [u8; SALT_BYTES],
        nonce: [u8; NONCE_BYTES],
    ) -> Result<Self, Nip49Error> {
        if log_n > MAX_LOG_N {
            return Err(Nip49Error::LogNTooLarge(log_n));
        }
        let sym_key = derive_symmetric_key(password, &salt, log_n)?;
        let cipher = XChaCha20Poly1305::new(&sym_key.into());

        let aad_byte = [security as u8];
        let secret_bytes = secret.to_byte_array();
        let payload = Payload {
            msg: &secret_bytes,
            aad: &aad_byte,
        };
        let ct = cipher
            .encrypt(&nonce.into(), payload)
            .map_err(|_| Nip49Error::Aead)?;
        // Length is statically `SECRET_BYTES + TAG_BYTES`; convert to
        // the fixed-size array form.
        let ciphertext: [u8; CIPHERTEXT_BYTES] = ct
            .as_slice()
            .try_into()
            .expect("XChaCha20-Poly1305 always emits plaintext+16 bytes");

        Ok(Self {
            log_n,
            salt,
            nonce,
            security,
            ciphertext,
        })
    }

    /// Recover the secret key with the same password used to encrypt.
    ///
    /// # Errors
    ///
    /// Returns [`Nip49Error::Aead`] when the password is wrong or the
    /// ciphertext / security byte was tampered with, [`Nip49Error::SecretKey`]
    /// when the decrypted bytes do not encode a valid secp256k1 scalar,
    /// or [`Nip49Error::InvalidParams`] / [`Nip49Error::Scrypt`] for derivation
    /// failures.
    pub fn decrypt(&self, password: &str) -> Result<SecretKey, Nip49Error> {
        let sym_key = derive_symmetric_key(password, &self.salt, self.log_n)?;
        let cipher = XChaCha20Poly1305::new(&sym_key.into());
        let aad_byte = [self.security as u8];
        let payload = Payload {
            msg: &self.ciphertext,
            aad: &aad_byte,
        };
        let plaintext = cipher
            .decrypt(&self.nonce.into(), payload)
            .map_err(|_| Nip49Error::Aead)?;
        let secret_array: [u8; SECRET_BYTES] =
            plaintext
                .as_slice()
                .try_into()
                .map_err(|_| Nip49Error::InvalidLength {
                    got: plaintext.len(),
                })?;
        SecretKey::from_byte_array(secret_array).map_err(Nip49Error::from)
    }

    /// Cost parameter the secret was encrypted under.
    #[must_use]
    pub const fn log_n(&self) -> u8 {
        self.log_n
    }

    /// Security level the author declared at encryption time.
    #[must_use]
    pub const fn security(&self) -> KeySecurity {
        self.security
    }

    /// Encode as the spec-mandated `ncryptsec1...` bech32 string.
    ///
    /// # Errors
    ///
    /// Returns [`Nip49Error::Encode`] only if the underlying `bech32` crate
    /// rejects the payload, which on a 91-byte buffer is statically
    /// impossible.
    pub fn to_bech32(&self) -> Result<String, Nip49Error> {
        let bytes = self.to_payload_bytes();
        let hrp = bech32::Hrp::parse(HRP).expect("HRP is statically valid");
        Ok(bech32::encode::<Bech32>(hrp, &bytes)?)
    }

    /// Decode from the `ncryptsec1...` bech32 string.
    ///
    /// # Errors
    ///
    /// Returns [`Nip49Error::Decode`] for malformed bech32, [`Nip49Error::UnexpectedHrp`]
    /// when the HRP is not `ncryptsec`, [`Nip49Error::InvalidLength`] when
    /// the decoded payload is not exactly [`PAYLOAD_BYTES`] long, and
    /// [`Nip49Error::UnsupportedVersion`] / [`Nip49Error::InvalidKeySecurity`]
    /// when the payload header is malformed.
    pub fn from_bech32(input: &str) -> Result<Self, Nip49Error> {
        let parsed = CheckedHrpstring::new::<Bech32>(input)?;
        let hrp = parsed.hrp().to_lowercase();
        if hrp != HRP {
            return Err(Nip49Error::UnexpectedHrp(hrp));
        }
        let bytes: Vec<u8> = parsed.byte_iter().collect();
        Self::from_payload_bytes(&bytes)
    }

    fn to_payload_bytes(&self) -> [u8; PAYLOAD_BYTES] {
        // Build the 91-byte payload by concatenation. We accumulate
        // into a `Vec` and convert at the end so the layout reads as
        // a list of fields (no offset arithmetic), avoiding the
        // `clippy::indexing_slicing` lint while keeping the wire
        // layout obvious.
        let mut buf: Vec<u8> = Vec::with_capacity(PAYLOAD_BYTES);
        buf.push(VERSION_BYTE);
        buf.push(self.log_n);
        buf.extend_from_slice(&self.salt);
        buf.extend_from_slice(&self.nonce);
        buf.push(self.security as u8);
        buf.extend_from_slice(&self.ciphertext);
        // The pushes above sum to exactly `PAYLOAD_BYTES`; the
        // `try_into` cannot fail.
        buf.try_into()
            .expect("PAYLOAD_BYTES = 1 + 1 + SALT_BYTES + NONCE_BYTES + 1 + CIPHERTEXT_BYTES")
    }

    fn from_payload_bytes(bytes: &[u8]) -> Result<Self, Nip49Error> {
        if bytes.len() != PAYLOAD_BYTES {
            return Err(Nip49Error::InvalidLength { got: bytes.len() });
        }
        // Walk the buffer with `split_first_chunk::<N>` so every slice
        // is a fixed-size array reference. The length check above
        // proves each split below has enough bytes left, so the
        // subsequent `expect`s are statically unreachable.
        let (head, rest) = bytes
            .split_first_chunk::<2>()
            .expect("PAYLOAD_BYTES >= 2 (version + log_n)");
        let &[version, log_n] = head;
        if version != VERSION_BYTE {
            return Err(Nip49Error::UnsupportedVersion(version));
        }
        let (salt, rest) = rest
            .split_first_chunk::<SALT_BYTES>()
            .expect("PAYLOAD_BYTES leaves SALT_BYTES after the 2-byte header");
        let (nonce, rest) = rest
            .split_first_chunk::<NONCE_BYTES>()
            .expect("PAYLOAD_BYTES leaves NONCE_BYTES after the salt");
        let (aad_chunk, ciphertext_slice) = rest
            .split_first_chunk::<1>()
            .expect("PAYLOAD_BYTES leaves >= 1 byte after the nonce");
        let &[aad_byte] = aad_chunk;
        let security = KeySecurity::from_byte(aad_byte)?;
        let ciphertext = ciphertext_slice
            .first_chunk::<CIPHERTEXT_BYTES>()
            .copied()
            .expect("PAYLOAD_BYTES leaves CIPHERTEXT_BYTES after the AAD byte");
        Ok(Self {
            log_n,
            salt: *salt,
            nonce: *nonce,
            security,
            ciphertext,
        })
    }
}

fn derive_symmetric_key(
    password: &str,
    salt: &[u8; SALT_BYTES],
    log_n: u8,
) -> Result<[u8; SYM_KEY_BYTES], Nip49Error> {
    // Spec § Symmetric Encryption Key derivation: NFKC-normalise the
    // password before scrypt. This guarantees that visually-identical
    // strings entered on different OS / IME stacks produce the same
    // symmetric key.
    let normalized: String = password.nfkc().collect();
    // `scrypt 0.12` dropped the output-length argument from `Params::new`
    // (the length is fixed at the caller's `&mut` buffer in
    // `scrypt::scrypt`). The previous (log_n, r, p, len) signature is
    // gone.
    let params =
        ScryptParams::new(log_n, SCRYPT_R, SCRYPT_P).map_err(|err| Nip49Error::InvalidParams {
            log_n,
            message: err.to_string(),
        })?;
    let mut key = [0u8; SYM_KEY_BYTES];
    scrypt(normalized.as_bytes(), salt, &params, &mut key)
        .map_err(|err| Nip49Error::Scrypt(err.to_string()))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;

    fn fixture_secret() -> SecretKey {
        let bytes = [
            0x35, 0x01, 0x45, 0x41, 0x35, 0x01, 0x45, 0x41, 0x35, 0x01, 0x45, 0x41, 0x35, 0x01,
            0x45, 0x41, 0x35, 0x01, 0x45, 0x41, 0x3f, 0xef, 0xb0, 0x22, 0x27, 0xe4, 0x49, 0xe5,
            0x7c, 0xf4, 0xd3, 0xa3,
        ];
        SecretKey::from_byte_array(bytes).expect("32-byte fixture is a valid scalar")
    }

    #[test]
    fn round_trip_default_log_n() {
        let secret = fixture_secret();
        // Use log_n=4 (16 iterations) — fastest possible — so tests run
        // in milliseconds instead of seconds.
        let encrypted =
            EncryptedSecretKey::encrypt(&secret, "correct horse", 4, KeySecurity::Weak).unwrap();
        let recovered = encrypted.decrypt("correct horse").unwrap();
        assert_eq!(recovered.to_byte_array(), secret.to_byte_array());
    }

    #[test]
    fn wrong_password_is_rejected() {
        let secret = fixture_secret();
        let encrypted =
            EncryptedSecretKey::encrypt(&secret, "right password", 4, KeySecurity::Strong).unwrap();
        let err = encrypted.decrypt("WRONG password").unwrap_err();
        assert!(matches!(err, Nip49Error::Aead));
    }

    #[test]
    fn bech32_round_trip() {
        let secret = fixture_secret();
        let encrypted =
            EncryptedSecretKey::encrypt(&secret, "p", 4, KeySecurity::Untracked).unwrap();
        let s = encrypted.to_bech32().unwrap();
        assert!(s.starts_with("ncryptsec1"));
        let parsed = EncryptedSecretKey::from_bech32(&s).unwrap();
        assert_eq!(parsed, encrypted);
        assert_eq!(
            parsed.decrypt("p").unwrap().to_byte_array(),
            secret.to_byte_array()
        );
    }

    #[test]
    fn rejects_wrong_hrp() {
        // Generate a bech32 string with a different HRP.
        let hrp = bech32::Hrp::parse("nsec").unwrap();
        let bogus = bech32::encode::<Bech32>(hrp, &[0u8; PAYLOAD_BYTES]).unwrap();
        let err = EncryptedSecretKey::from_bech32(&bogus).unwrap_err();
        assert!(matches!(err, Nip49Error::UnexpectedHrp(s) if s == "nsec"));
    }

    #[test]
    fn rejects_unsupported_version() {
        // Manually craft a payload with version byte = 0x01 (reserved).
        let mut payload = [0u8; PAYLOAD_BYTES];
        payload[0] = 0x01;
        // log_n + everything else can stay at zero; `from_payload_bytes`
        // surfaces the version mismatch first.
        let hrp = bech32::Hrp::parse(HRP).unwrap();
        let bogus = bech32::encode::<Bech32>(hrp, &payload).unwrap();
        let err = EncryptedSecretKey::from_bech32(&bogus).unwrap_err();
        assert!(matches!(err, Nip49Error::UnsupportedVersion(0x01)));
    }

    #[test]
    fn rejects_invalid_key_security() {
        let mut payload = [0u8; PAYLOAD_BYTES];
        payload[0] = VERSION_BYTE;
        // Salt + nonce stay zeros; the AAD byte (right after version,
        // log_n, salt, nonce) is at offset `2 + 16 + 24 = 42`.
        payload[42] = 0x09;
        let hrp = bech32::Hrp::parse(HRP).unwrap();
        let bogus = bech32::encode::<Bech32>(hrp, &payload).unwrap();
        let err = EncryptedSecretKey::from_bech32(&bogus).unwrap_err();
        assert!(matches!(err, Nip49Error::InvalidKeySecurity(0x09)));
    }

    #[test]
    fn nfkc_normalization_makes_passwords_equivalent() {
        let secret = fixture_secret();
        // "ÅΩẛ̣" composed two different ways. Spec § Test Data § Password
        // Unicode Normalization gives both forms; they must produce the
        // same symmetric key.
        let composed = "\u{00C5}\u{03A9}\u{1E69}";
        let decomposed = "\u{212B}\u{2126}\u{1E9B}\u{0323}";
        let salt = [0xab; SALT_BYTES];
        let nonce = [0xcd; NONCE_BYTES];

        let from_composed =
            EncryptedSecretKey::encrypt_with(&secret, composed, 4, KeySecurity::Weak, salt, nonce)
                .unwrap();
        let from_decomposed = EncryptedSecretKey::encrypt_with(
            &secret,
            decomposed,
            4,
            KeySecurity::Weak,
            salt,
            nonce,
        )
        .unwrap();

        assert_eq!(from_composed.ciphertext, from_decomposed.ciphertext);
        assert_eq!(
            from_decomposed.decrypt(composed).unwrap().to_byte_array(),
            secret.to_byte_array(),
        );
    }

    #[test]
    fn log_n_above_cap_is_rejected() {
        let secret = fixture_secret();
        let err = EncryptedSecretKey::encrypt(&secret, "p", MAX_LOG_N + 1, KeySecurity::Weak)
            .unwrap_err();
        assert!(matches!(err, Nip49Error::LogNTooLarge(_)));
    }

    /// NIP-49 spec § Test Data fixture.
    ///
    /// `ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p`
    /// password=`nostr`, `log_n=16` → secret hex
    /// `3501454135014541350145413501453fefb02227e449e57cf4d3a3ce05378683`.
    ///
    /// We pin this one as a regression because every other implementation
    /// (rust-nostr, nostr-tools, nak) uses the same fixture, and a
    /// silent drift here would cripple ncryptsec interop. The slow
    /// scrypt cost makes this test ~100ms — leave it gated under
    /// `--release` runs only? No: even at debug it's fast enough on
    /// modern hardware (<1 s) and the safety guarantee is worth it.
    #[test]
    fn spec_vector_decrypt() {
        let ncryptsec = "ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p";
        let parsed = EncryptedSecretKey::from_bech32(ncryptsec).unwrap();
        assert_eq!(parsed.log_n(), 16);
        let secret = parsed.decrypt("nostr").unwrap();
        let expected_hex = "3501454135014541350145413501453fefb02227e449e57cf4d3a3ce05378683";
        let actual_hex = secret.to_hex();
        assert_eq!(actual_hex, expected_hex);

        // And the recovered key is a usable Nostr identity.
        let _keys = Keys::from_secret_key(secret);
    }
}
