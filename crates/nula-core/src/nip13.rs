//! [NIP-13] Proof of Work.
//!
//! NIP-13 mines an event so that its [`EventId`] has at least `D` leading
//! zero bits. The author commits to the targeted difficulty via the
//! `["nonce", "<nonce>", "<committed-difficulty>"]` tag; relays/clients can
//! reject events whose actual or committed difficulty is below their policy.
//!
//! This module provides three layers:
//!
//! - [`count_leading_zero_bits`] / [`event_id_difficulty`] — pure helpers.
//! - [`verify_pow`] — full NIP-13 validation including committed
//!   difficulty.
//! - [`mine`] / [`mine_and_sign`] — blocking miners that brute-force a
//!   nonce until the event id satisfies `D`.
//!
//! The miners are intentionally synchronous; offload them to a worker pool
//! when integrating into an interactive client.
//!
//! [NIP-13]: https://github.com/nostr-protocol/nips/blob/master/13.md
//! [`EventId`]: crate::EventId

use thiserror::Error;

use crate::event::{Event, EventBuilder, EventBuilderError, EventId, Tag, TagKind, Tags};
use crate::key::{Keys, PublicKey};
use crate::types::{Timestamp, TimestampError};

/// Wire name of the NIP-13 nonce tag (`nonce`).
pub const NONCE_TAG: &str = "nonce";

/// Errors raised by [`verify_pow`] and [`verify_pow_strict`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum PowError {
    /// The event's id has fewer leading zero bits than required.
    #[error("event id has {actual} leading zero bits, need {expected}")]
    InsufficientWork {
        /// Bits the id actually starts with.
        actual: u8,
        /// Minimum required by the caller.
        expected: u8,
    },
    /// The author's committed difficulty (the third element of the `nonce`
    /// tag) is below what the caller demands. NIP-13 §commitment requires
    /// the commitment to match or exceed the verifier's threshold so that
    /// random low-difficulty matches cannot be passed off as `PoW`.
    #[error("committed difficulty {actual} < {expected}")]
    InsufficientCommitment {
        /// Difficulty advertised by the author.
        actual: u8,
        /// Minimum required by the caller.
        expected: u8,
    },
    /// The `nonce` tag carried a non-integer commitment that we could not
    /// parse.
    #[error("nonce tag commitment is not a valid u8 integer")]
    InvalidCommitment,
    /// The strict-mode verifier required a committed difficulty but the
    /// event carried no `nonce` tag (or the tag had no commitment column).
    #[error("strict PoW verification requires a committed difficulty")]
    MissingCommitment,
}

/// Errors raised by [`mine`] / [`mine_and_sign`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MineError {
    /// The wall clock could not be read.
    #[error(transparent)]
    Clock(#[from] TimestampError),
    /// Forwarded from event signing.
    #[error(transparent)]
    Builder(#[from] EventBuilderError),
    /// The nonce search exhausted the full `u64` space without finding a
    /// matching id at the requested difficulty.
    ///
    /// In practice unreachable for any real-world `difficulty`; the variant
    /// exists so the mining loop never silently saturates and never spins
    /// forever. Callers may recover by re-mining with a different
    /// `created_at` (NIP-13 explicitly suggests refreshing it).
    #[error("nonce search exhausted u64 space; refresh created_at and retry")]
    NonceExhausted,
}

/// Count the leading zero bits in a byte slice.
///
/// `[0xff, …]` returns `0`; `[0x00, 0xff, …]` returns `8`; `[0x00, 0x00, …]`
/// returns at least `16`. Empty slices return `0`.
#[must_use]
pub fn count_leading_zero_bits(bytes: &[u8]) -> u8 {
    let mut total: u8 = 0;
    for &b in bytes {
        if b == 0 {
            total = total.saturating_add(8);
        } else {
            // `b.leading_zeros()` returns a value in `0..=8`, which fits in
            // `u8`; `try_from` makes the narrowing explicit for clippy and
            // gives us a sound `0` fallback that this branch never reaches.
            let z = u8::try_from(b.leading_zeros()).unwrap_or(0);
            return total.saturating_add(z);
        }
    }
    total
}

/// Number of leading zero bits in `id`.
#[must_use]
pub fn event_id_difficulty(id: &EventId) -> u8 {
    count_leading_zero_bits(&id.to_byte_array())
}

/// Read the committed difficulty (third element of the `nonce` tag), if
/// present and well formed.
///
/// Returns `Some(d)` when the tag exists and parses as `u8`. Returns
/// `None` when the tag is missing or has fewer than 3 elements. Returns an
/// `Err` when the third element is present but unparseable.
///
/// # Errors
///
/// Returns [`PowError::InvalidCommitment`] when the third element exists
/// but is not a non-negative integer that fits in `u8`.
pub fn committed_difficulty(event: &Event) -> Result<Option<u8>, PowError> {
    let kind = TagKind::from_wire(NONCE_TAG);
    let Some(tag) = event.tags.find_first(&kind) else {
        return Ok(None);
    };
    let Some(commitment) = tag.values().get(2) else {
        return Ok(None);
    };
    commitment
        .parse::<u8>()
        .map(Some)
        .map_err(|_| PowError::InvalidCommitment)
}

/// Verify that `event` satisfies `min_difficulty` according to NIP-13.
///
/// Specifically, the event's id must have at least `min_difficulty` leading
/// zero bits, and — if the author included a `nonce` commitment — that
/// commitment must also be at least `min_difficulty`.
///
/// `min_difficulty == 0` accepts every event.
///
/// # Errors
///
/// Returns [`PowError::InsufficientWork`] when the id is below the bar,
/// [`PowError::InsufficientCommitment`] when the commitment falls short,
/// or [`PowError::InvalidCommitment`] when the commitment is malformed.
pub fn verify_pow(event: &Event, min_difficulty: u8) -> Result<(), PowError> {
    let actual = event_id_difficulty(&event.id);
    if actual < min_difficulty {
        return Err(PowError::InsufficientWork {
            actual,
            expected: min_difficulty,
        });
    }
    if let Some(commitment) = committed_difficulty(event)?
        && commitment < min_difficulty
    {
        return Err(PowError::InsufficientCommitment {
            actual: commitment,
            expected: min_difficulty,
        });
    }
    Ok(())
}

/// Strict version of [`verify_pow`]: also rejects events that lack a
/// committed difficulty entirely.
///
/// NIP-13 §commitment notes that "without a committed target difficulty
/// you could not reject" a low-difficulty grind that happened to land on
/// a high zero-bit count. Strict verifiers (relays enforcing `PoW`
/// policies) should call this entry point so an absent commitment is
/// treated as a policy violation rather than silently accepted.
///
/// # Errors
///
/// Returns the matching [`PowError`] variant; in particular,
/// [`PowError::MissingCommitment`] when the event has no usable `nonce`
/// commitment column.
pub fn verify_pow_strict(event: &Event, min_difficulty: u8) -> Result<(), PowError> {
    verify_pow(event, min_difficulty)?;
    if min_difficulty > 0 && committed_difficulty(event)?.is_none() {
        return Err(PowError::MissingCommitment);
    }
    Ok(())
}

/// Mine a [`PowAttempt`] until the event id has `difficulty` leading zero
/// bits. Returns the unsigned, mined attempt; the caller signs it.
///
/// # Errors
///
/// Returns [`MineError::Clock`] if the wall clock cannot be read while
/// fixing `created_at`.
pub fn mine(
    builder: &EventBuilder,
    pubkey: PublicKey,
    difficulty: u8,
) -> Result<PowAttempt, MineError> {
    PowAttempt::mine(builder, pubkey, difficulty)
}

/// Mine a NIP-13 `PoW` for `builder` and sign it with `keys`.
///
/// `keys` must own the public key that will appear on the event; this is
/// the same constraint [`crate::UnsignedEvent::sign_with_keys`] enforces.
///
/// # Errors
///
/// Returns [`MineError::Clock`] if the system clock cannot be read or
/// [`MineError::Builder`] if the signer rejects the unsigned event.
pub fn mine_and_sign(
    builder: &EventBuilder,
    keys: &Keys,
    difficulty: u8,
) -> Result<Event, MineError> {
    let attempt = PowAttempt::mine(builder, *keys.public_key(), difficulty)?;
    Ok(attempt.into_signed_with_keys(keys)?)
}

/// Outcome of a successful mining run.
#[derive(Debug, Clone)]
pub struct PowAttempt {
    /// The mined unsigned event.
    pub unsigned: crate::event::UnsignedEvent,
    /// Number of nonces tried (counts the winning attempt as `1`).
    pub iterations: u64,
    /// Difficulty the miner targeted (also the commitment).
    pub difficulty: u8,
}

impl PowAttempt {
    /// Run the mining loop synchronously until the id has `difficulty`
    /// leading zero bits.
    pub(crate) fn mine(
        builder: &EventBuilder,
        pubkey: PublicKey,
        difficulty: u8,
    ) -> Result<Self, MineError> {
        let created_at = match builder.current_created_at() {
            Some(ts) => ts,
            None => Timestamp::now()?,
        };
        let kind = builder.current_kind();
        let content = builder.current_content().to_owned();
        let nonce_kind = TagKind::from_wire(NONCE_TAG);
        // Snapshot the user-supplied tags once, dropping any prior nonce
        // tag (the miner owns that slot).
        let prefix: Vec<Tag> = builder
            .current_tags()
            .iter()
            .filter(|t| t.kind() != nonce_kind)
            .cloned()
            .collect();

        let mut iterations: u64 = 0;
        loop {
            iterations = iterations.checked_add(1).ok_or(MineError::NonceExhausted)?;
            let mut tags = prefix.clone();
            tags.push(make_nonce_tag(iterations, difficulty));
            let unsigned = crate::event::UnsignedEvent::new(
                pubkey,
                created_at,
                kind,
                Tags::from_vec(tags),
                content.clone(),
            );
            if event_id_difficulty(&unsigned.id) >= difficulty {
                return Ok(Self {
                    unsigned,
                    iterations,
                    difficulty,
                });
            }
        }
    }

    /// Sign the mined event with `keys`.
    ///
    /// # Errors
    ///
    /// Returns [`EventBuilderError::Signer`] if the signer rejects the
    /// event.
    pub fn into_signed_with_keys(self, keys: &Keys) -> Result<Event, EventBuilderError> {
        Ok(self.unsigned.sign_with_keys(keys)?)
    }
}

fn make_nonce_tag(nonce: u64, difficulty: u8) -> Tag {
    Tag::with(
        &TagKind::from_wire(NONCE_TAG),
        [nonce.to_string(), difficulty.to_string()],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Kind;

    fn keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    #[test]
    fn count_zero_bits_examples() {
        assert_eq!(count_leading_zero_bits(&[]), 0);
        assert_eq!(count_leading_zero_bits(&[0xff]), 0);
        assert_eq!(count_leading_zero_bits(&[0x80]), 0);
        assert_eq!(count_leading_zero_bits(&[0x40]), 1);
        assert_eq!(count_leading_zero_bits(&[0x01]), 7);
        assert_eq!(count_leading_zero_bits(&[0x00, 0xff]), 8);
        assert_eq!(count_leading_zero_bits(&[0x00, 0x80]), 8);
        assert_eq!(count_leading_zero_bits(&[0x00, 0x00, 0x10]), 19);
        assert_eq!(count_leading_zero_bits(&[0x00; 4]), 32);
    }

    #[test]
    fn mine_low_difficulty() {
        let builder = EventBuilder::text_note("hello").created_at(Timestamp::from_secs(1));
        let event = mine_and_sign(&builder, &keys(), 8).unwrap();
        assert_eq!(event.kind, Kind::TEXT_NOTE);
        verify_pow(&event, 8).unwrap();
        event.verify().unwrap();
    }

    #[test]
    fn mine_writes_nonce_commitment() {
        let builder = EventBuilder::text_note("commit").created_at(Timestamp::from_secs(2));
        let event = mine_and_sign(&builder, &keys(), 6).unwrap();
        let commitment = committed_difficulty(&event).unwrap();
        assert_eq!(commitment, Some(6));
    }

    #[test]
    fn mine_replaces_existing_nonce_tag() {
        let builder = EventBuilder::text_note("ignore-me")
            .created_at(Timestamp::from_secs(3))
            .tag(Tag::new(["nonce", "0", "0"]).unwrap());
        let event = mine_and_sign(&builder, &keys(), 4).unwrap();
        // Exactly one nonce tag should remain — the one written by the miner.
        let count = event
            .tags
            .iter()
            .filter(|t| t.kind() == TagKind::from_wire(NONCE_TAG))
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn verify_pow_rejects_low_id_difficulty() {
        let event = EventBuilder::text_note("no-pow")
            .created_at(Timestamp::from_secs(4))
            .sign_with_keys(&keys())
            .unwrap();
        // Difficulty 32 is virtually impossible without mining.
        let err = verify_pow(&event, 32).unwrap_err();
        assert!(matches!(err, PowError::InsufficientWork { .. }));
    }

    #[test]
    fn verify_pow_rejects_low_commitment() {
        // Mine to 8, then verify against 16: the id may or may not have 16
        // leading zeros, but the commitment is definitely 8 < 16, so the
        // commitment check must fire (or the id check first if luck wins).
        let builder = EventBuilder::text_note("commit-fail").created_at(Timestamp::from_secs(5));
        let event = mine_and_sign(&builder, &keys(), 8).unwrap();
        let err = verify_pow(&event, 16).unwrap_err();
        assert!(matches!(
            err,
            PowError::InsufficientWork { .. } | PowError::InsufficientCommitment { actual: 8, .. }
        ));
    }

    #[test]
    fn verify_pow_zero_difficulty_accepts_anything() {
        let event = EventBuilder::text_note("anything")
            .created_at(Timestamp::from_secs(6))
            .sign_with_keys(&keys())
            .unwrap();
        verify_pow(&event, 0).unwrap();
    }

    #[test]
    fn invalid_commitment_is_reported() {
        let event = EventBuilder::text_note("bad-commit")
            .created_at(Timestamp::from_secs(7))
            .tag(Tag::new(["nonce", "1", "abc"]).unwrap())
            .sign_with_keys(&keys())
            .unwrap();
        let err = committed_difficulty(&event).unwrap_err();
        assert!(matches!(err, PowError::InvalidCommitment));
    }

    #[test]
    fn verify_pow_strict_rejects_missing_commitment() {
        // Plain text note, no nonce tag -> verify_pow accepts at any
        // difficulty if the id happens to satisfy it; verify_pow_strict
        // must reject for any min_difficulty > 0.
        let event = EventBuilder::text_note("no-nonce")
            .created_at(Timestamp::from_secs(8))
            .sign_with_keys(&keys())
            .unwrap();
        let err = verify_pow_strict(&event, 1).unwrap_err();
        assert!(matches!(err, PowError::MissingCommitment));
        // min_difficulty == 0 means "no PoW required" so strict mode
        // accepts even unmined events for parity with verify_pow.
        verify_pow_strict(&event, 0).unwrap();
    }

    #[test]
    fn verify_pow_strict_accepts_when_commitment_meets_floor() {
        let builder = EventBuilder::text_note("strict-ok").created_at(Timestamp::from_secs(9));
        let event = mine_and_sign(&builder, &keys(), 6).unwrap();
        verify_pow_strict(&event, 6).unwrap();
        // Asking for 7 still rejects via the existing commitment check.
        let err = verify_pow_strict(&event, 7).unwrap_err();
        assert!(matches!(
            err,
            PowError::InsufficientWork { .. } | PowError::InsufficientCommitment { actual: 6, .. }
        ));
    }

    /// NIP-13 §"Example mined note" reference vector. The leading bytes of
    /// the published id (`000006d8…`) encode 5 nibbles of zeroes plus the
    /// upper bit of `6 = 0b0110`, for a total of 21 leading zero bits. The
    /// author's nonce tag commits to difficulty 20.
    ///
    /// This regression test exercises every public verification path so
    /// the spec example would catch any drift in `count_leading_zero_bits`,
    /// `event_id_difficulty`, `committed_difficulty`, or the commitment vs.
    /// id-difficulty interplay inside `verify_pow`.
    #[test]
    fn nip13_spec_example_difficulty_and_commitment() {
        let id_hex = "000006d8c378af1779d2feebc7603a125d99eca0ccf1085959b307f64e5dd358";
        let id = id_hex.parse::<EventId>().unwrap();

        // The spec calls out 21 leading zero bits for this id.
        assert_eq!(event_id_difficulty(&id), 21);

        // Build the synthetic event the spec would have produced. The
        // signature is a placeholder: verify_pow only inspects `id` and
        // the `nonce` tag, never the signature.
        let pubkey =
            PublicKey::parse("a48380f4cfcc1ad5378294fcac36439770f9c878dd880ffa94bb74ea54a6f243")
                .unwrap();
        let event = Event::from_parts(
            id,
            pubkey,
            Timestamp::from_secs(1_651_794_653),
            Kind::TEXT_NOTE,
            Tags::from_vec(vec![Tag::new(["nonce", "776797", "20"]).unwrap()]),
            "It's just me mining my own business".to_owned(),
            keys().sign_schnorr(&[0u8; 32]),
        );

        // The committed difficulty advertised by the author is 20.
        assert_eq!(committed_difficulty(&event).unwrap(), Some(20));

        // verify against ≤ 20 must pass: id has 21 zero bits, commitment is 20.
        verify_pow(&event, 0).unwrap();
        verify_pow(&event, 20).unwrap();

        // NIP-13 anti-grinding rule: even though the id happens to satisfy
        // 21 zero bits, the *committed* difficulty is only 20, so a
        // verifier asking for 21 must reject with InsufficientCommitment.
        let commitment_short = verify_pow(&event, 21).unwrap_err();
        assert!(matches!(
            commitment_short,
            PowError::InsufficientCommitment {
                actual: 20,
                expected: 21,
            }
        ));

        // Asking for 22 hits the id-difficulty check first.
        let id_short = verify_pow(&event, 22).unwrap_err();
        assert!(matches!(
            id_short,
            PowError::InsufficientWork {
                actual: 21,
                expected: 22,
            }
        ));
    }
}
