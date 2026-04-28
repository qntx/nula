// Copyright (c) 2026 QNTX <https://qntx.fun>
// Distributed under the MIT or Apache-2.0 license.

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

/// Errors raised by [`verify_pow`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
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
}

/// Errors raised by [`mine`] / [`mine_and_sign`].
#[derive(Debug, Error)]
pub enum MineError {
    /// The wall clock could not be read.
    #[error(transparent)]
    Clock(#[from] TimestampError),
    /// Forwarded from event signing.
    #[error(transparent)]
    Builder(#[from] EventBuilderError),
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
        let created_at = match builder.created_at {
            Some(ts) => ts,
            None => Timestamp::now()?,
        };
        let kind = builder.kind;
        let content = builder.content.clone();
        let nonce_kind = TagKind::from_wire(NONCE_TAG);
        // Snapshot the user-supplied tags once, dropping any prior nonce
        // tag (the miner owns that slot).
        let prefix: Vec<Tag> = builder
            .tags
            .iter()
            .filter(|t| t.kind() != nonce_kind)
            .cloned()
            .collect();

        let mut iterations: u64 = 0;
        loop {
            iterations = iterations.saturating_add(1);
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
}
