//! [NIP-06] Basic key derivation from a mnemonic seed phrase.
//!
//! NIP-06 anchors a Nostr identity to a [BIP-39] mnemonic via the
//! [BIP-32] hierarchical-deterministic derivation path:
//!
//! ```text
//! m / 44' / 1237' / <account>' / <chain_type> / <index>
//! ```
//!
//! - `44'` — BIP-44 purpose constant.
//! - `1237'` — Nostr's coin type registered in [SLIP-44].
//! - `account`, `chain_type`, `index` — caller-controlled selectors;
//!   `account = 0`, `chain_type = 0`, `index = 0` is the canonical
//!   "first identity" path and what every interoperable client uses by
//!   default (see the spec test vectors).
//!
//! # Pipeline
//!
//! 1. [BIP-39] parses the mnemonic into entropy + checksum and runs
//!    PBKDF2-HMAC-SHA512 over the (NFKD) sentence + an optional
//!    passphrase, producing a 512-bit seed.
//! 2. [BIP-32] derives the master extended private key from that seed
//!    via `HMAC-SHA512(key = "Bitcoin seed", msg = seed)`.
//! 3. We walk the path above. Hardened steps (`'`) feed only the
//!    parent secret to the HMAC; non-hardened steps feed the
//!    compressed parent public key. The leaf secret is the Nostr
//!    private key.
//!
//! The implementation here is **self-contained**: a private
//! [`mod bip32`] block ships exactly the BIP-32 surface NIP-06 needs
//! (master derivation + private→private CKD), without pulling in a
//! full wallet crate.
//!
//! # Examples
//!
//! ```
//! # #[cfg(feature = "nip06")] {
//! use nula_core::nips::nip06;
//!
//! // The first vector from the NIP-06 spec.
//! let keys = nip06::derive_keys(
//!     "leader monkey parrot ring guide accident before fence cannon height naive bean",
//!     None,
//! )
//! .unwrap();
//! assert_eq!(
//!     keys.secret_key().to_hex(),
//!     "7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a",
//! );
//! # }
//! ```
//!
//! [NIP-06]: https://github.com/nostr-protocol/nips/blob/master/06.md
//! [BIP-32]: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
//! [BIP-39]: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
//! [SLIP-44]: https://github.com/satoshilabs/slips/blob/master/slip-0044.md

pub use bip39::{Language, Mnemonic};
use thiserror::Error;
use zeroize::Zeroize;

use crate::key::{Keys, SecretKey};

/// BIP-44 "purpose" constant (`44'`).
const PURPOSE: u32 = 44;
/// SLIP-44 Nostr coin type (`1237'`).
const COIN_TYPE: u32 = 1237;

/// Number of words a fresh mnemonic should contain.
///
/// Each variant corresponds to a different entropy size; 12 words is
/// the minimum allowed by BIP-39 and 24 the maximum. Most consumer
/// wallets default to 12; security-conscious deployments prefer 24.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum WordCount {
    /// 12 words / 128 bits of entropy.
    Twelve,
    /// 15 words / 160 bits of entropy.
    Fifteen,
    /// 18 words / 192 bits of entropy.
    Eighteen,
    /// 21 words / 224 bits of entropy.
    TwentyOne,
    /// 24 words / 256 bits of entropy.
    TwentyFour,
}

impl WordCount {
    /// Decimal length (e.g. `12`).
    #[must_use]
    pub const fn as_count(self) -> usize {
        match self {
            Self::Twelve => 12,
            Self::Fifteen => 15,
            Self::Eighteen => 18,
            Self::TwentyOne => 21,
            Self::TwentyFour => 24,
        }
    }
}

/// Errors raised by NIP-06 helpers.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Nip06Error {
    /// The mnemonic could not be parsed (bad checksum, unknown word,
    /// wrong word count, …).
    #[error("invalid BIP-39 mnemonic: {0}")]
    Mnemonic(#[from] bip39::Error),
    /// The BIP-32 derivation produced an invalid scalar (probability
    /// ~1/2^127, but the spec mandates we surface it rather than panic).
    #[error("BIP-32 derivation produced an invalid secp256k1 scalar")]
    InvalidDerivedKey,
    /// The OS entropy source failed during fresh-mnemonic generation.
    #[error(transparent)]
    Rng(#[from] crate::util::rng::RngError),
}

/// Generate a fresh English BIP-39 mnemonic of the requested length.
///
/// Entropy is drawn from the OS-provided random source via
/// [`crate::util::rng`].
///
/// # Errors
///
/// Returns [`Nip06Error::Rng`] when the OS RNG is unavailable.
pub fn generate_mnemonic(word_count: WordCount) -> Result<Mnemonic, Nip06Error> {
    // BIP-39 entropy size in bytes: count = (entropy_bits + checksum) / 11,
    // checksum = entropy_bits / 32. Solving gives entropy_bytes =
    // count * 11 / 33 * 4.
    let entropy_bytes = word_count.as_count() * 4 / 3;

    // Fixed-size dispatch keeps the OS-RNG buffer on the stack and
    // avoids the const-generic gymnastics that a generic
    // `random_bytes::<N>()` would force on the caller.
    let mnemonic = match entropy_bytes {
        16 => Mnemonic::from_entropy_in(Language::English, &fresh::<16>()?)?,
        20 => Mnemonic::from_entropy_in(Language::English, &fresh::<20>()?)?,
        24 => Mnemonic::from_entropy_in(Language::English, &fresh::<24>()?)?,
        28 => Mnemonic::from_entropy_in(Language::English, &fresh::<28>()?)?,
        32 => Mnemonic::from_entropy_in(Language::English, &fresh::<32>()?)?,
        // `WordCount` is a closed enum; the match is therefore total
        // and this arm is unreachable.
        _ => unreachable!("WordCount only yields 16/20/24/28/32 entropy bytes"),
    };
    Ok(mnemonic)
}

fn fresh<const N: usize>() -> Result<[u8; N], crate::util::rng::RngError> {
    crate::util::rng::random_bytes::<N>()
}

/// Derive the canonical Nostr [`Keys`] from a mnemonic.
///
/// Walks `m/44'/1237'/0'/0/0`, the path mandated by NIP-06 for the
/// "first identity" — every NIP-06-compatible client agrees on this
/// derivation, so a mnemonic round-trips between clients.
///
/// `passphrase` is the optional [BIP-39 §Wallet seed]
/// passphrase ("seed extension"); pass `None` for the empty passphrase
/// most clients use.
///
/// # Errors
///
/// See [`Nip06Error`].
///
/// [BIP-39 §Wallet seed]: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki#from-mnemonic-to-seed
pub fn derive_keys(mnemonic: &str, passphrase: Option<&str>) -> Result<Keys, Nip06Error> {
    derive_keys_advanced(mnemonic, passphrase, 0, 0, 0)
}

/// Derive [`Keys`] from a mnemonic with a fully custom BIP-32 path.
///
/// `account` controls `m/44'/1237'/<account>'`, `chain_type` the next
/// non-hardened level (typically `0`, sometimes `1` for "change-style"
/// accounts), and `index` the leaf. Every component fits in
/// [`u32::MAX / 2`] (the BIP-32 hard cap on indices).
///
/// # Errors
///
/// Returns [`Nip06Error::Mnemonic`] for a malformed sentence and
/// [`Nip06Error::InvalidDerivedKey`] if any HMAC step yields a key
/// outside the secp256k1 group order (probability ~1/2^127).
pub fn derive_keys_advanced(
    mnemonic: &str,
    passphrase: Option<&str>,
    account: u32,
    chain_type: u32,
    index: u32,
) -> Result<Keys, Nip06Error> {
    let parsed = Mnemonic::parse_normalized(mnemonic)?;
    let mut seed = parsed.to_seed_normalized(passphrase.unwrap_or_default());

    let secret_bytes = bip32::derive_nostr_path(&seed, account, chain_type, index)?;
    seed.zeroize();

    let secret =
        SecretKey::from_byte_array(secret_bytes).map_err(|_| Nip06Error::InvalidDerivedKey)?;
    Ok(Keys::from_secret_key(secret))
}

/// Self-contained BIP-32 helper, scoped private to NIP-06.
///
/// The full BIP-32 surface (xpub serialisation, fingerprints, public
/// CKD, …) would be ~10× this code; NIP-06 only needs master
/// derivation and the hardened/normal private→private step, so we
/// inline exactly that.
//
// `expect_used` / `unwrap_in_result` are gated at the module level
// because every `expect` here guards an invariant that is statically
// proved at the call site:
//
// - `<HmacSha512>::new_from_slice` only fails when the key exceeds the
//   underlying hash's block size (128 B for SHA-512). The two call
//   sites pass `b"Bitcoin seed"` (12 B) and a 32-byte chain code,
//   both safely within bounds.
// - `<[u8; 64]>::split_first_chunk::<32>` is `Some` because 32 ≤ 64.
//
// Any new `expect` in this module needs to come with the same kind of
// proof in a comment, enforced by code review.
#[allow(
    clippy::expect_used,
    clippy::unwrap_in_result,
    reason = "see module-level comment: every expect guards a statically proved length invariant"
)]
mod bip32 {
    use hmac::digest::KeyInit;
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    use zeroize::Zeroize;

    use super::{COIN_TYPE, Nip06Error, PURPOSE};

    /// Hard-coded BIP-32 master-derivation salt (`"Bitcoin seed"`).
    const MASTER_KEY: &[u8] = b"Bitcoin seed";
    /// Bit set on hardened child indices.
    const HARDENED_OFFSET: u32 = 0x8000_0000;
    /// Width of one half of an HMAC-SHA512 output.
    const HALF: usize = 32;

    type HmacSha512 = Hmac<Sha512>;

    /// Derive `m/44'/COIN_TYPE'/account'/chain_type/index` from `seed`
    /// and return the leaf 32-byte secret.
    ///
    /// `seed` must be 64 bytes (the BIP-39 PBKDF2 output); shorter or
    /// longer inputs are accepted but produce non-standard master keys.
    pub(super) fn derive_nostr_path(
        seed: &[u8; 64],
        account: u32,
        chain_type: u32,
        index: u32,
    ) -> Result<[u8; 32], Nip06Error> {
        // Step 1: master key from the seed.
        let (mut k, mut c) = master_key(seed);

        // Step 2: walk the 5-level Nostr path. The first three levels
        // are hardened per BIP-44; the last two are not.
        for &(idx, hardened) in &[
            (PURPOSE, true),
            (COIN_TYPE, true),
            (account, true),
            (chain_type, false),
            (index, false),
        ] {
            (k, c) = ckd_priv(&k, &c, idx, hardened)?;
        }

        // Best-effort wipe the chain code on the way out; the caller
        // owns `k` (the leaf secret) and is responsible for it.
        c.zeroize();
        Ok(k)
    }

    /// Split a 64-byte HMAC-SHA512 output into `(left, right)` halves.
    ///
    /// Statically infallible: 32 ≤ 64. Implemented via
    /// [`<[u8; 64]>::split_first_chunk`] so the compiler can prove the
    /// bounds at the type level rather than relying on a runtime
    /// length check.
    fn split_halves(bytes: [u8; 64]) -> ([u8; HALF], [u8; HALF]) {
        let (left, rest) = bytes
            .split_first_chunk::<HALF>()
            .expect("32 <= 64, statically");
        let right: [u8; HALF] = rest.try_into().expect("64 - 32 = 32, statically");
        (*left, right)
    }

    /// `HMAC-SHA512(MASTER_KEY, seed)` → `(secret_left || chain_code_right)`.
    fn master_key(seed: &[u8]) -> ([u8; HALF], [u8; HALF]) {
        let mut mac = <HmacSha512 as KeyInit>::new_from_slice(MASTER_KEY)
            .expect("HMAC-SHA512 accepts any key up to its 128-byte block size");
        mac.update(seed);
        let bytes: [u8; 64] = mac.finalize().into_bytes().into();
        split_halves(bytes)
    }

    /// Private→private child key derivation step.
    ///
    /// For hardened indices (`hardened = true`), the HMAC input is
    /// `0x00 || parent_secret || index`; for non-hardened indices it is
    /// `compressed_parent_public_key || index`. The output's left half
    /// is added (mod n) to the parent secret to produce the child
    /// secret; the right half becomes the new chain code.
    fn ckd_priv(
        parent_secret: &[u8; HALF],
        parent_chain: &[u8; HALF],
        index: u32,
        hardened: bool,
    ) -> Result<([u8; HALF], [u8; HALF]), Nip06Error> {
        let parent_sk = secp256k1::SecretKey::from_byte_array(*parent_secret)
            .map_err(|_| Nip06Error::InvalidDerivedKey)?;

        let child_index = if hardened {
            index | HARDENED_OFFSET
        } else {
            index
        };

        let mut mac = <HmacSha512 as KeyInit>::new_from_slice(parent_chain)
            .expect("HMAC-SHA512 accepts any key up to its 128-byte block size");

        if hardened {
            mac.update(&[0x00]);
            mac.update(parent_secret);
        } else {
            // Compressed serialization of the parent public key
            // (33 bytes: 0x02/0x03 prefix + 32-byte X coordinate).
            let parent_pk = secp256k1::PublicKey::from_secret_key_global(&parent_sk);
            mac.update(&parent_pk.serialize());
        }
        mac.update(&child_index.to_be_bytes());

        let bytes: [u8; 64] = mac.finalize().into_bytes().into();
        let (mut left, chain) = split_halves(bytes);

        // child_secret = (left + parent_secret) mod n. `add_tweak`
        // returns `Err` when the addition lands on `0` mod n; the
        // probability is ~1/2^127, but BIP-32 mandates we surface it.
        let scalar =
            secp256k1::Scalar::from_be_bytes(left).map_err(|_| Nip06Error::InvalidDerivedKey)?;
        let child_sk = parent_sk
            .add_tweak(&scalar)
            .map_err(|_| Nip06Error::InvalidDerivedKey)?;

        let child_bytes = child_sk.secret_bytes();
        left.zeroize();
        Ok((child_bytes, chain))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test vectors lifted from NIP-06 itself
    /// (<https://github.com/nostr-protocol/nips/blob/master/06.md#test-vectors>).
    /// `(mnemonic, expected_hex_secret)` for the canonical
    /// `m/44'/1237'/0'/0/0` derivation.
    const SPEC_VECTORS: &[(&str, &str)] = &[
        (
            "leader monkey parrot ring guide accident before fence cannon height naive bean",
            "7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a",
        ),
        (
            "what bleak badge arrange retreat wolf trade produce cricket blur garlic valid proud rude strong choose busy staff weather area salt hollow arm fade",
            "c15d739894c81a2fcfd3a2df85a0d2c0dbc47a280d092799f144d73d7ae78add",
        ),
    ];

    #[test]
    fn spec_vectors_match() {
        for (sentence, expected) in SPEC_VECTORS {
            let keys = derive_keys(sentence, None).unwrap();
            assert_eq!(
                keys.secret_key().to_hex(),
                *expected,
                "mismatch on mnemonic: {sentence}",
            );
        }
    }

    #[test]
    fn passphrase_changes_derived_key() {
        // BIP-39 spec: any non-empty passphrase MUST produce a
        // completely different seed (no plausible collision).
        let mnemonic = SPEC_VECTORS[0].0;
        let plain = derive_keys(mnemonic, None).unwrap();
        let with_pw = derive_keys(mnemonic, Some("nostr")).unwrap();
        assert_ne!(plain.secret_key().to_hex(), with_pw.secret_key().to_hex());
    }

    #[test]
    fn account_changes_derived_key() {
        // Different `account` levels must produce different keys —
        // this is the whole point of the BIP-44 hierarchy.
        let mnemonic = SPEC_VECTORS[0].0;
        let acct0 = derive_keys_advanced(mnemonic, None, 0, 0, 0).unwrap();
        let acct1 = derive_keys_advanced(mnemonic, None, 1, 0, 0).unwrap();
        assert_ne!(acct0.secret_key().to_hex(), acct1.secret_key().to_hex());
    }

    #[test]
    fn index_changes_derived_key() {
        let mnemonic = SPEC_VECTORS[0].0;
        let i0 = derive_keys_advanced(mnemonic, None, 0, 0, 0).unwrap();
        let i1 = derive_keys_advanced(mnemonic, None, 0, 0, 1).unwrap();
        assert_ne!(i0.secret_key().to_hex(), i1.secret_key().to_hex());
    }

    #[test]
    fn malformed_mnemonic_rejected() {
        let err = derive_keys("not a real mnemonic just words here", None).unwrap_err();
        assert!(matches!(err, Nip06Error::Mnemonic(_)));
    }

    #[test]
    fn generate_mnemonic_round_trips_through_derive() {
        // Generated mnemonics must be parseable and yield a valid
        // secret key for every supported word count.
        for &count in &[
            WordCount::Twelve,
            WordCount::Fifteen,
            WordCount::Eighteen,
            WordCount::TwentyOne,
            WordCount::TwentyFour,
        ] {
            let mnemonic = generate_mnemonic(count).unwrap();
            assert_eq!(mnemonic.word_count(), count.as_count());
            let _ = derive_keys(&mnemonic.to_string(), None).unwrap();
        }
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        // BIP-39 wordlists are case-sensitive ASCII (uppercase variants
        // are *not* valid words), but `parse_normalized` does collapse
        // surrounding/internal whitespace and NFKD/NFC differences.
        // Verify the whitespace half here.
        let canonical = SPEC_VECTORS[0].0;
        let padded = format!("\t  {canonical}  \n");
        let a = derive_keys(canonical, None).unwrap();
        let b = derive_keys(&padded, None).unwrap();
        assert_eq!(a.secret_key().to_hex(), b.secret_key().to_hex());
    }

    #[test]
    fn uppercase_mnemonic_is_rejected() {
        // Pin the contract: BIP-39 demands the canonical lowercase
        // wordlist. Casing the sentence yields words that are not in
        // the wordlist and parsing must fail.
        let err = derive_keys(&SPEC_VECTORS[0].0.to_uppercase(), None).unwrap_err();
        assert!(matches!(err, Nip06Error::Mnemonic(_)));
    }
}
