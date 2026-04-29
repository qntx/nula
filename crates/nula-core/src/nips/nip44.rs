//! [NIP-44] Encrypted Payloads (Versioned).
//!
//! `nula-core` ships **only the v2 algorithm** spelled out by the NIP:
//! `secp256k1` ECDH + HKDF-SHA256 + `ChaCha20` + HMAC-SHA256 + base64.
//! v1 is reserved by the spec and v0 is forbidden, so a single namespace
//! [`encrypt`] / [`decrypt`] keeps the surface tight; future versions
//! (`Version::V3`, …) can be added as opt-in helpers without touching the
//! v2 entry points.
//!
//! # Threat model
//!
//! NIP-44 v2 provides *confidentiality* and *integrity* of the payload,
//! plus *deniability after key compromise* (the MAC is symmetric, so a
//! compromised key can forge ciphertexts in either direction). It does
//! **not** provide forward secrecy, post-compromise security, or sender
//! anonymity — those are layered via NIP-59 gift wrapping. Treat the
//! encrypted payload as something the recipient can authenticate to
//! themselves but not to a third party.
//!
//! # Padding
//!
//! Plaintext is padded to the next power-of-two boundary (32-byte
//! minimum) per NIP-44 §Encryption step 4. We strictly enforce the
//! spec's `1..=65535` plaintext range; non-spec extensions (e.g. the
//! 4-byte length prefix some implementations carry for >64 KiB messages)
//! are rejected on decrypt to keep round-trip behaviour identical to
//! `nostr-tools`, `rust-nostr`, and the reference Python implementation.
//!
//! # Test vectors
//!
//! The crate's integration tests exercise the official
//! `nip44.vectors.json` shipped by `nostr-protocol/nips`. See
//! `tests/nip44_vectors.rs`.
//!
//! [NIP-44]: https://github.com/nostr-protocol/nips/blob/master/44.md

// `expect` and `unwrap_in_result` are gated at the module level because
// each `expect` here guards a length-only invariant that the
// surrounding code has *already proved* — e.g. a 32-byte slice fed
// into `[u8; 32]: TryFrom<&[u8]>` after a length check, or
// `Hkdf::from_prk` over a 32-byte PRK. Spelling out an `#[allow]` per
// call site would add ~15 lines of noise; the trade-off is that any
// new `expect` in this module needs to come with a comment proving its
// own infallibility (the convention is enforced by code review).
//
// `clippy::panic` and `clippy::missing_panics_doc` are *not* lifted at
// module scope: the only `panic!`s are local to `MessageKeys::*` const
// fn accessors (where `?`/`expect` are not const-stable). Those
// methods carry their own targeted `#[allow]`.
#![allow(
    clippy::expect_used,
    clippy::unwrap_in_result,
    reason = "see module-level comment above the attribute: every expect \
              guards a precondition the surrounding code has already \
              checked; replacing them with `?` would force every caller \
              to handle errors that cannot occur in practice."
)]

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use secp256k1::{Parity, ecdh};
use sha2::Sha256;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::key::{PublicKey, SecretKey};
use crate::util::rng;

/// Wire version byte for NIP-44 v2.
pub const VERSION: u8 = 2;

/// Salt fed into the HKDF-Extract step ("nip44-v2", per spec).
const HKDF_SALT: &[u8] = b"nip44-v2";

/// Spec-mandated plaintext range (§Encryption step 4).
const MIN_PLAINTEXT_BYTES: usize = 1;
const MAX_PLAINTEXT_BYTES: usize = 65_535;

/// Wire-level constants (§Encryption step 7, §Decryption step 2).
const NONCE_BYTES: usize = 32;
const HMAC_BYTES: usize = 32;
const VERSION_BYTE: usize = 1;

/// Min/max payload length **after** base64 decoding, per §Decryption.
const MIN_PAYLOAD_BYTES: usize = 99;
const MAX_PAYLOAD_BYTES: usize = 65_603;

/// Min/max base64-encoded length (§Decryption step 2 hard limit).
const MIN_PAYLOAD_CHARS: usize = 132;
const MAX_PAYLOAD_CHARS: usize = 87_472;

/// HKDF-Expand output sliced into `ChaCha20` key (0..32), `ChaCha20`
/// nonce (32..44), and HMAC key (44..76). Sub-slicing happens via
/// `split_at` inside the [`MessageKeys`] accessors so the offsets stay
/// close to the only place that consumes them.
const MESSAGE_KEYS_BYTES: usize = 76;
const CHACHA_KEY_BYTES: usize = 32;
const CHACHA_NONCE_BYTES: usize = 12;
const MESSAGE_KEY_HMAC_OFFSET: usize = CHACHA_KEY_BYTES + CHACHA_NONCE_BYTES;

/// Errors raised by [`encrypt`], [`decrypt`], and [`ConversationKey::derive`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Nip44Error {
    /// Plaintext is empty (NIP-44 v2 requires at least 1 byte).
    #[error("plaintext is empty")]
    EmptyPlaintext,
    /// Plaintext exceeds the v2 cap of `65_535` bytes.
    #[error("plaintext too long: {0} bytes (max {MAX_PLAINTEXT_BYTES})")]
    PlaintextTooLong(usize),
    /// The base64 string is shorter than the smallest possible payload.
    #[error("payload too short: {0} characters (min {MIN_PAYLOAD_CHARS})")]
    PayloadTooShort(usize),
    /// The base64 string exceeds the v2 cap.
    #[error("payload too long: {0} characters (max {MAX_PAYLOAD_CHARS})")]
    PayloadTooLong(usize),
    /// The decoded payload is shorter than the smallest possible
    /// (1-byte version + 32-byte nonce + 34-byte ciphertext + 32-byte MAC).
    #[error("decoded payload too short: {0} bytes")]
    DecodedTooShort(usize),
    /// The decoded payload exceeds the v2 cap.
    #[error("decoded payload too long: {0} bytes")]
    DecodedTooLong(usize),
    /// The version byte is not `0x02`. NIP-44 reserves a leading `'#'` for
    /// future non-base64 framings; either case ends up here.
    #[error("unsupported NIP-44 version byte: {0:#04x}")]
    UnsupportedVersion(u8),
    /// `base64` could not decode the payload.
    #[error("invalid base64: {0}")]
    InvalidBase64(#[from] base64::DecodeError),
    /// HMAC verification failed: the payload was tampered with or the
    /// conversation key is wrong.
    #[error("invalid MAC")]
    InvalidMac,
    /// The padded plaintext could not be unpadded according to the spec.
    #[error("invalid padding")]
    InvalidPadding,
    /// The decrypted plaintext was not valid UTF-8 (NIP-44 carries
    /// arbitrary bytes, but the public string API insists on UTF-8 so
    /// callers cannot accidentally hand non-text to JSON serialisers).
    #[error("plaintext is not valid UTF-8")]
    InvalidUtf8,
    /// Failed to read the operating system entropy source.
    #[error("entropy source failed: {0}")]
    Rng(#[from] rng::RngError),
}

/// 32-byte HKDF-Extract result over the secp256k1 ECDH shared X coordinate.
///
/// Two parties holding the same `(secret, peer_public)` pair *and* the
/// reverse pair derive **bit-identical** conversation keys: NIP-44 uses
/// the unhashed shared X coordinate, which is symmetric in
/// `(sk, pk_peer)` ↔ `(sk_peer, pk)`. Cache and reuse the
/// [`ConversationKey`] across messages between the same two pubkeys —
/// it does not depend on the per-message nonce.
///
/// The struct zeroes its bytes on drop; clone explicitly when handing
/// the key to long-lived state.
#[derive(Clone, ZeroizeOnDrop)]
pub struct ConversationKey([u8; 32]);

impl core::fmt::Debug for ConversationKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ConversationKey(<redacted>)")
    }
}

impl ConversationKey {
    /// Derive a conversation key from `(secret, peer_public)`.
    ///
    /// The derivation is `HKDF-Extract(salt = "nip44-v2", ikm = ecdh_x)`
    /// where `ecdh_x` is the unhashed 32-byte X coordinate of the
    /// shared point produced by secp256k1 ECDH.
    #[must_use]
    pub fn derive(secret: &SecretKey, peer_public: &PublicKey) -> Self {
        // NIP-44 §Encryption step 1: lift the peer's x-only key with
        // even parity and run ECDH. The parity choice is convention —
        // both even and odd parities produce the same X coordinate, but
        // the ecosystem (rust-nostr, nostr-tools, paulmillr/nip44) uses
        // even, so we match.
        let normalized =
            secp256k1::PublicKey::from_x_only_public_key(*peer_public.as_inner(), Parity::Even);
        let ssp = ecdh::shared_secret_point(&normalized, secret.as_inner());

        // Take only the X coordinate (first 32 bytes of the 64-byte
        // serialized point). This must be unhashed per the spec.
        let mut shared_x = [0u8; 32];
        shared_x.copy_from_slice(&ssp[..32]);

        // HKDF-Extract is just `HMAC-SHA256(salt, ikm)`. We use the
        // `hkdf` crate's typed `Hkdf::extract` for clarity.
        let (prk, _) = Hkdf::<Sha256>::extract(Some(HKDF_SALT), &shared_x);

        // Wipe the local copy of the shared X coordinate before
        // returning. The compiler cannot elide this because `prk`
        // doesn't depend on `shared_x` after `extract` returns.
        shared_x.zeroize();

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(prk.as_slice());
        Self(bytes)
    }

    /// Construct from raw 32 bytes.
    ///
    /// Useful for deserializing test vectors or persisted state. The
    /// bytes must be a valid HKDF-SHA256 PRK; we do not (and cannot)
    /// validate that property, so callers MUST treat any value coming
    /// from outside [`Self::derive`] as untrusted.
    #[must_use]
    pub const fn from_byte_array(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// View as raw 32 bytes (for serialization / vectors).
    #[must_use]
    pub const fn as_byte_array(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Per-message HKDF-Expand output split into `ChaCha20` key, `ChaCha20`
/// nonce, and HMAC key. Lives in this module only; we never expose the
/// individual sub-keys.
struct MessageKeys([u8; MESSAGE_KEYS_BYTES]);

impl MessageKeys {
    fn derive(conversation_key: &ConversationKey, nonce: &[u8; NONCE_BYTES]) -> Self {
        let hk = Hkdf::<Sha256>::from_prk(conversation_key.as_byte_array())
            .expect("PRK is exactly 32 bytes — HKDF::from_prk only fails on length");
        let mut okm = [0u8; MESSAGE_KEYS_BYTES];
        hk.expand(nonce, &mut okm)
            .expect("76 bytes <= 255*32 — Hkdf::expand only fails when the OKM exceeds that");
        Self(okm)
    }

    /// `ChaCha20` key slice (bytes 0..32 of the 76-byte OKM).
    ///
    /// # Panics
    ///
    /// Statically unreachable: [`Self`]'s inner buffer is exactly
    /// `MESSAGE_KEYS_BYTES` long by construction, so `first_chunk::<32>`
    /// always returns `Some`. The `panic!` is there because `?` and
    /// `expect` are not yet `const`-stable, and we want this accessor
    /// to be `const` for use inside other `const fn`.
    #[allow(
        clippy::panic,
        clippy::missing_panics_doc,
        reason = "panic guard for a const fn that operates on a fixed-size buffer; the # Panics doc explains the guarantee"
    )]
    const fn chacha_key(&self) -> &[u8; CHACHA_KEY_BYTES] {
        match self.0.first_chunk::<CHACHA_KEY_BYTES>() {
            Some(arr) => arr,
            None => panic!("OKM is 76 bytes; first 32 always present"),
        }
    }

    /// `ChaCha20` nonce slice (bytes 32..44 of the 76-byte OKM).
    ///
    /// # Panics
    ///
    /// Statically unreachable for the same reason as [`Self::chacha_key`].
    #[allow(
        clippy::panic,
        clippy::missing_panics_doc,
        reason = "panic guard for a const fn that operates on a fixed-size buffer; the # Panics doc explains the guarantee"
    )]
    const fn chacha_nonce(&self) -> &[u8; CHACHA_NONCE_BYTES] {
        let (_, tail) = self.0.split_at(CHACHA_KEY_BYTES);
        match tail.first_chunk::<CHACHA_NONCE_BYTES>() {
            Some(arr) => arr,
            None => panic!("OKM tail is 44 bytes; first 12 always present"),
        }
    }

    /// HMAC key slice (bytes 44..76 of the 76-byte OKM).
    const fn hmac_key(&self) -> &[u8] {
        let (_, tail) = self.0.split_at(MESSAGE_KEY_HMAC_OFFSET);
        tail
    }
}

impl Drop for MessageKeys {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Encrypt `plaintext` to `peer_public_key` and return the base64 NIP-44 v2 payload.
///
/// The 32-byte nonce is sourced from the OS entropy pool. To exercise
/// known-answer test vectors where the nonce must be controlled, use
/// [`encrypt_with_nonce`].
///
/// # Errors
///
/// Returns [`Nip44Error::EmptyPlaintext`] for an empty input,
/// [`Nip44Error::PlaintextTooLong`] for inputs above 65 535 bytes, or
/// [`Nip44Error::Rng`] if the OS RNG is unavailable.
pub fn encrypt(
    secret: &SecretKey,
    peer_public_key: &PublicKey,
    plaintext: &str,
) -> Result<String, Nip44Error> {
    let mut nonce = [0u8; NONCE_BYTES];
    rng::fill_bytes(&mut nonce)?;
    let conversation_key = ConversationKey::derive(secret, peer_public_key);
    encrypt_inner(&conversation_key, plaintext, &nonce)
}

/// Encrypt with an explicit 32-byte nonce.
///
/// Reserved for round-tripping known-answer test vectors and for
/// callers that derive a deterministic per-message nonce from a
/// higher-level protocol. Production code should call [`encrypt`] and
/// let the OS RNG pick the nonce.
///
/// # Errors
///
/// Same as [`encrypt`]: [`Nip44Error::EmptyPlaintext`] /
/// [`Nip44Error::PlaintextTooLong`].
pub fn encrypt_with_nonce(
    conversation_key: &ConversationKey,
    plaintext: &str,
    nonce: &[u8; NONCE_BYTES],
) -> Result<String, Nip44Error> {
    encrypt_inner(conversation_key, plaintext, nonce)
}

fn encrypt_inner(
    conversation_key: &ConversationKey,
    plaintext: &str,
    nonce: &[u8; NONCE_BYTES],
) -> Result<String, Nip44Error> {
    let mks = MessageKeys::derive(conversation_key, nonce);

    // Pad. The padded buffer is `prefix(2) || plaintext || zeros`.
    let mut buffer = pad(plaintext.as_bytes())?;

    // Encrypt in place.
    let mut cipher = ChaCha20::new(mks.chacha_key().into(), mks.chacha_nonce().into());
    cipher.apply_keystream(&mut buffer);

    // HMAC over `nonce || ciphertext` (NIP-44 §Encryption step 6 AAD).
    let hmac = compute_hmac(mks.hmac_key(), nonce, &buffer);

    // Compose `version || nonce || ciphertext || hmac` and base64 it.
    let mut payload = Vec::with_capacity(VERSION_BYTE + NONCE_BYTES + buffer.len() + HMAC_BYTES);
    payload.push(VERSION);
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(&buffer);
    payload.extend_from_slice(&hmac);

    Ok(BASE64.encode(payload))
}

/// Decrypt a NIP-44 v2 payload from `peer_public_key`.
///
/// `payload` must be the exact base64-encoded string carried by the
/// outer event's `content` (or `tags`); do not pre-decode.
///
/// # Errors
///
/// Returns [`Nip44Error::InvalidMac`] when the payload was tampered with or
/// when the conversation key is wrong, [`Nip44Error::UnsupportedVersion`]
/// for any byte other than `0x02`, [`Nip44Error::InvalidPadding`] for a
/// malformed padded plaintext, and [`Nip44Error::InvalidUtf8`] when the
/// plaintext is not valid UTF-8.
pub fn decrypt(
    secret: &SecretKey,
    peer_public_key: &PublicKey,
    payload: &str,
) -> Result<String, Nip44Error> {
    let conversation_key = ConversationKey::derive(secret, peer_public_key);
    decrypt_with_conversation_key(&conversation_key, payload)
}

/// Decrypt with a pre-derived conversation key.
///
/// Use this when the same `(secret, peer)` pair is reused across many
/// messages and re-deriving the conversation key per call is wasteful.
///
/// # Errors
///
/// See [`decrypt`].
///
/// # Panics
///
/// Will not panic in practice: every `expect` inside the body guards a
/// length invariant that the surrounding bounds checks have already
/// proved (e.g. a 32-byte slice fed into `[u8; 32]: TryFrom<&[u8]>`).
pub fn decrypt_with_conversation_key(
    conversation_key: &ConversationKey,
    payload: &str,
) -> Result<String, Nip44Error> {
    let plen = payload.len();
    if plen < MIN_PAYLOAD_CHARS {
        return Err(Nip44Error::PayloadTooShort(plen));
    }
    if plen > MAX_PAYLOAD_CHARS {
        return Err(Nip44Error::PayloadTooLong(plen));
    }

    // NIP-44 §Decryption step 1: a leading `#` flags a future
    // non-base64 framing. Surface it as `UnsupportedVersion` so callers
    // can distinguish it from a corrupted base64 string.
    if payload.starts_with('#') {
        return Err(Nip44Error::UnsupportedVersion(b'#'));
    }

    let bytes = BASE64.decode(payload)?;
    let blen = bytes.len();
    if blen < MIN_PAYLOAD_BYTES {
        return Err(Nip44Error::DecodedTooShort(blen));
    }
    if blen > MAX_PAYLOAD_BYTES {
        return Err(Nip44Error::DecodedTooLong(blen));
    }

    // Carve `version || nonce || ciphertext || mac` from the buffer
    // using `split_at` chains so every slice index is statically
    // checked. The length-bounds above prove every split is in-range.
    let (version_slice, rest) = bytes.split_at(VERSION_BYTE);
    let version = *version_slice
        .first()
        .expect("VERSION_BYTE = 1, slice is non-empty after MIN_PAYLOAD_BYTES check");
    if version != VERSION {
        return Err(Nip44Error::UnsupportedVersion(version));
    }

    let (nonce_slice, body_with_mac) = rest.split_at(NONCE_BYTES);
    let nonce: [u8; NONCE_BYTES] = nonce_slice
        .try_into()
        .expect("NONCE_BYTES = 32 by construction");
    let mac_start = body_with_mac.len() - HMAC_BYTES;
    let (ciphertext, mac) = body_with_mac.split_at(mac_start);

    let mks = MessageKeys::derive(conversation_key, &nonce);

    // Verify HMAC in constant time before touching ChaCha20: prevents
    // padding-oracle / chosen-ciphertext attacks against the cipher
    // state machine.
    let computed_mac = compute_hmac(mks.hmac_key(), &nonce, ciphertext);
    if !hmac_eq(&computed_mac, mac) {
        return Err(Nip44Error::InvalidMac);
    }

    // Decrypt and unpad.
    let mut buffer = ciphertext.to_vec();
    let mut cipher = ChaCha20::new(mks.chacha_key().into(), mks.chacha_nonce().into());
    cipher.apply_keystream(&mut buffer);

    let unpadded = unpad(&buffer)?;
    String::from_utf8(unpadded.to_vec()).map_err(|_| Nip44Error::InvalidUtf8)
}

fn pad(plaintext: &[u8]) -> Result<Vec<u8>, Nip44Error> {
    let len = plaintext.len();
    if len < MIN_PLAINTEXT_BYTES {
        return Err(Nip44Error::EmptyPlaintext);
    }
    if len > MAX_PLAINTEXT_BYTES {
        return Err(Nip44Error::PlaintextTooLong(len));
    }
    let padded_len = padded_length(len);
    let mut out = Vec::with_capacity(2 + padded_len);
    // `len <= MAX_PLAINTEXT_BYTES = 65_535` proven on the previous line,
    // and `MAX_PLAINTEXT_BYTES + 1 == u16::MAX + 1`. The cast cannot
    // truncate.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "len <= 65535 is enforced two lines above"
    )]
    let prefix = (len as u16).to_be_bytes();
    out.extend_from_slice(&prefix);
    out.extend_from_slice(plaintext);
    out.resize(2 + padded_len, 0);
    Ok(out)
}

fn unpad(padded: &[u8]) -> Result<&[u8], Nip44Error> {
    let header: &[u8; 2] = padded
        .first_chunk::<2>()
        .ok_or(Nip44Error::InvalidPadding)?;
    let prefix = u16::from_be_bytes(*header) as usize;
    if prefix < MIN_PLAINTEXT_BYTES {
        return Err(Nip44Error::InvalidPadding);
    }
    if prefix > MAX_PLAINTEXT_BYTES {
        return Err(Nip44Error::InvalidPadding);
    }
    let expected_len = 2 + padded_length(prefix);
    if padded.len() != expected_len {
        return Err(Nip44Error::InvalidPadding);
    }
    padded.get(2..2 + prefix).ok_or(Nip44Error::InvalidPadding)
}

/// Compute padded length per NIP-44 v2 spec.
///
/// - `len <= 32` → 32 (single chunk)
/// - else, round up to a chunk size of `next_pow2(len-1) / 8` (or 32 if smaller)
const fn padded_length(len: usize) -> usize {
    if len <= 32 {
        return 32;
    }
    let next_power = 1usize << (log2_floor(len - 1) + 1);
    let chunk = if next_power <= 256 {
        32
    } else {
        next_power / 8
    };
    chunk * (((len - 1) / chunk) + 1)
}

/// `floor(log2(x))` for `x > 0`. Defined as 0 for `x == 0` to keep the
/// arithmetic in [`padded_length`] total. Equivalent to `(usize::BITS-1) - x.leading_zeros()`.
const fn log2_floor(x: usize) -> u32 {
    if x == 0 {
        0
    } else {
        (usize::BITS - 1) - x.leading_zeros()
    }
}

fn compute_hmac(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> [u8; HMAC_BYTES] {
    // `Hmac::new_from_slice` only fails for keys longer than the block
    // size of the underlying hash, but HMAC-SHA256 has no upper bound
    // (it just rehashes oversized keys). 32-byte keys are well below.
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(nonce);
    mac.update(ciphertext);
    mac.finalize().into_bytes().into()
}

/// Constant-time equality comparison of two 32-byte HMAC values.
///
/// `hmac::Mac::verify_slice` would do the same, but we already have the
/// raw bytes in hand and want to keep the call site explicit.
fn hmac_eq(a: &[u8; HMAC_BYTES], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    // Black-box the iteration so the compiler cannot short-circuit.
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::Keys;

    fn key_pair_a() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000001").unwrap()
    }

    fn key_pair_b() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000002").unwrap()
    }

    #[test]
    fn round_trip_short_message() {
        let a = key_pair_a();
        let b = key_pair_b();
        let payload = encrypt(a.secret_key(), b.public_key(), "hello, nostr").unwrap();
        let recovered = decrypt(b.secret_key(), a.public_key(), &payload).unwrap();
        assert_eq!(recovered, "hello, nostr");
    }

    #[test]
    fn round_trip_min_size() {
        let a = key_pair_a();
        let b = key_pair_b();
        let payload = encrypt(a.secret_key(), b.public_key(), "x").unwrap();
        let recovered = decrypt(b.secret_key(), a.public_key(), &payload).unwrap();
        assert_eq!(recovered, "x");
    }

    #[test]
    fn round_trip_max_size() {
        let a = key_pair_a();
        let b = key_pair_b();
        let plaintext = "a".repeat(MAX_PLAINTEXT_BYTES);
        let payload = encrypt(a.secret_key(), b.public_key(), &plaintext).unwrap();
        let recovered = decrypt(b.secret_key(), a.public_key(), &payload).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn empty_plaintext_rejected() {
        let a = key_pair_a();
        let b = key_pair_b();
        let err = encrypt(a.secret_key(), b.public_key(), "").unwrap_err();
        assert!(matches!(err, Nip44Error::EmptyPlaintext));
    }

    #[test]
    fn oversize_plaintext_rejected() {
        let a = key_pair_a();
        let b = key_pair_b();
        let plaintext = "a".repeat(MAX_PLAINTEXT_BYTES + 1);
        let err = encrypt(a.secret_key(), b.public_key(), &plaintext).unwrap_err();
        assert!(matches!(err, Nip44Error::PlaintextTooLong(_)));
    }

    #[test]
    fn conversation_key_is_symmetric() {
        let a = key_pair_a();
        let b = key_pair_b();
        let key_ab = ConversationKey::derive(a.secret_key(), b.public_key());
        let key_ba = ConversationKey::derive(b.secret_key(), a.public_key());
        assert_eq!(key_ab.as_byte_array(), key_ba.as_byte_array());
    }

    #[test]
    fn tampered_mac_is_detected() {
        let a = key_pair_a();
        let b = key_pair_b();
        let payload = encrypt(a.secret_key(), b.public_key(), "secret").unwrap();
        // Flip a bit in the last char (which lands inside the HMAC after
        // base64 decoding).
        let mut bytes: Vec<u8> = payload.into_bytes();
        let last = bytes.len() - 2;
        bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(bytes).unwrap();
        let err = decrypt(b.secret_key(), a.public_key(), &tampered).unwrap_err();
        // Either the base64 still parses but HMAC fails, or base64 itself
        // chokes — either way the tamper is caught.
        assert!(matches!(
            err,
            Nip44Error::InvalidMac | Nip44Error::InvalidBase64(_)
        ));
    }

    #[test]
    fn unsupported_version_byte_is_rejected() {
        // Construct a syntactically-valid base64 payload that decodes to
        // something starting with `0x01` (reserved-undefined version).
        let mut bogus = vec![0x01_u8; MIN_PAYLOAD_BYTES];
        // Fill with non-zero so the length checks pass. The `i & 0xff`
        // mask makes the truncation cast lossless by construction.
        #[allow(
            clippy::cast_possible_truncation,
            reason = "`i & 0xff` always fits in u8"
        )]
        for (i, b) in bogus.iter_mut().enumerate().skip(1) {
            *b = (i & 0xff) as u8;
        }
        let s = BASE64.encode(&bogus);
        let key = ConversationKey::from_byte_array([0u8; 32]);
        let err = decrypt_with_conversation_key(&key, &s).unwrap_err();
        assert!(matches!(err, Nip44Error::UnsupportedVersion(0x01)));
    }

    #[test]
    fn padded_length_matches_official_vectors() {
        // Subset of the official `nip44.vectors.json` `calc_padded_len`
        // entries — sanity check before the integration-test suite
        // hammers the full vector set.
        assert_eq!(padded_length(1), 32);
        assert_eq!(padded_length(16), 32);
        assert_eq!(padded_length(32), 32);
        assert_eq!(padded_length(33), 64);
        assert_eq!(padded_length(64), 64);
        assert_eq!(padded_length(65), 96);
        assert_eq!(padded_length(100), 128);
        assert_eq!(padded_length(200), 224);
        assert_eq!(padded_length(250), 256);
        assert_eq!(padded_length(320), 320);
        assert_eq!(padded_length(384), 384);
        assert_eq!(padded_length(400), 448);
        assert_eq!(padded_length(515), 640);
        assert_eq!(padded_length(900), 1024);
        assert_eq!(padded_length(1020), 1024);
        assert_eq!(padded_length(65_536 - 1), 65_536);
    }

    #[test]
    fn payload_too_short_is_rejected() {
        let key = ConversationKey::from_byte_array([0u8; 32]);
        let err = decrypt_with_conversation_key(&key, "AAAA").unwrap_err();
        assert!(matches!(err, Nip44Error::PayloadTooShort(_)));
    }

    #[test]
    fn future_framing_marker_is_rejected() {
        let key = ConversationKey::from_byte_array([0u8; 32]);
        // First check: the per-payload length cap rejects the input
        // before even looking at the `#` framing marker.
        let oversize = format!("#{}", "A".repeat(MAX_PAYLOAD_CHARS));
        let err = decrypt_with_conversation_key(&key, &oversize).unwrap_err();
        assert!(matches!(err, Nip44Error::PayloadTooLong(_)));
        // Second check: a payload that *fits* the length window but
        // starts with the future-framing marker surfaces as
        // `UnsupportedVersion(b'#')`.
        let in_range = format!("#{}", "A".repeat(MIN_PAYLOAD_CHARS - 1));
        let err_in_range = decrypt_with_conversation_key(&key, &in_range).unwrap_err();
        assert!(matches!(err_in_range, Nip44Error::UnsupportedVersion(b'#')));
    }
}
