//! [NIP-59] Gift Wrap.
//!
//! Gift wrapping turns an unsigned *rumor* into a sealed, anonymously
//! publishable event. It is the metadata-hiding envelope that NIP-17
//! private direct messages and other privacy-sensitive flows ride on.
//!
//! # Pipeline
//!
//! ```text
//! sender_keys, recipient_pk, rumor (UnsignedEvent, no sig)
//!                |
//!                v
//!   ┌─────────────────────────────┐
//!   │  Seal (kind 13)             │
//!   │  - tags: []                 │
//!   │  - content: nip44(rumor)    │
//!   │  - signed by sender         │
//!   │  - randomized created_at    │
//!   └─────────────────────────────┘
//!                |
//!                v
//!   ┌─────────────────────────────┐
//!   │  GiftWrap (kind 1059)       │
//!   │  - tags: [["p", recipient]] │
//!   │  - content: nip44(seal)     │
//!   │  - signed by RANDOM key     │
//!   │  - randomized created_at    │
//!   └─────────────────────────────┘
//! ```
//!
//! The outer signer is throw-away keymaterial, so a relay snooping the
//! event sees neither the sender's identity nor the inner content. Only
//! the recipient — who holds the private half of `recipient_pk` — can
//! peel the two layers off.
//!
//! # Timestamp randomization
//!
//! Both the seal and the gift wrap pin a `created_at` value drawn
//! uniformly from `[now - 2 days, now]`. This keeps relays from
//! correlating outgoing wraps by their precise emission time. Use the
//! [`wrap_with_timestamps`] entry point to plug in deterministic
//! timestamps for tests.
//!
//! # Layering with NIP-17
//!
//! NIP-17 private DMs build a `kind 14` rumor and run it through this
//! module without ever signing the rumor itself: the spec mandates that
//! the inner event stay unsigned so leaks remain *deniable*.
//!
//! [NIP-59]: https://github.com/nostr-protocol/nips/blob/master/59.md

use thiserror::Error;

use crate::event::{Event, EventBuilder, EventError, Kind, Tag, TagKind, Tags, UnsignedEvent};
use crate::key::{Keys, PublicKey};
use crate::nip44;
use crate::types::{RelayUrl, Timestamp, TimestampError};
use crate::util::JsonUtil;
use crate::util::rng::{self, RngError};

/// 2-day randomization window for `created_at` (in seconds).
const TWO_DAYS_SECS: u64 = 2 * 24 * 60 * 60;

/// Errors raised by the gift-wrap pipeline.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Nip59Error {
    /// Wall clock could not be read.
    #[error(transparent)]
    Clock(#[from] TimestampError),
    /// OS RNG failed.
    #[error(transparent)]
    Rng(#[from] RngError),
    /// NIP-44 encryption / decryption failed.
    #[error(transparent)]
    Nip44(#[from] nip44::Nip44Error),
    /// JSON encoding / decoding failed.
    #[error("JSON serialization failed: {0}")]
    Json(String),
    /// Outer signature did not verify.
    #[error(transparent)]
    Event(#[from] EventError),
    /// The wrapped event was not the expected kind.
    #[error("expected kind {expected}, got {got}")]
    UnexpectedKind {
        /// What we asked for (`Kind::SEAL` or `Kind::GIFT_WRAP`).
        expected: u16,
        /// What the event actually carried.
        got: u16,
    },
    /// The seal's `pubkey` did not match the rumor's `pubkey`.
    ///
    /// This is the spec-mandated impersonation defence (§Encrypting):
    /// "Clients MUST verify if pubkey of the kind:13 is the same pubkey
    /// on the kind:14, otherwise any sender can impersonate others by
    /// simply changing the pubkey on kind:14."
    #[error("seal pubkey does not match rumor pubkey (impersonation attempt)")]
    PubkeyMismatch,
}

/// Build a NIP-59 *rumor*: an [`UnsignedEvent`] whose `pubkey` is set to
/// the sender, all other fields filled, and `id` computed.
///
/// The rumor is **never signed**. Per NIP-17 (and the broader gift-wrap
/// model), an unsigned rumor preserves deniability: a leaked rumor
/// cannot be traced back to a signature, so the sender retains the
/// option to disclaim it.
///
/// `created_at`, `kind`, `tags`, and `content` come from `template`.
/// Missing fields default to `(now, kind, [], "")`.
#[must_use]
pub fn build_rumor(
    sender: &Keys,
    kind: Kind,
    tags: Tags,
    content: impl Into<String>,
    created_at: Timestamp,
) -> UnsignedEvent {
    UnsignedEvent::new(*sender.public_key(), created_at, kind, tags, content)
}

/// Wrap a rumor into a [`Seal`](Kind::SEAL) event signed by `sender`.
///
/// `seal_created_at` controls the seal's outer timestamp; pass
/// [`random_past_timestamp`] for production use.
///
/// # Errors
///
/// See [`Nip59Error`].
pub fn create_seal(
    sender: &Keys,
    recipient: &PublicKey,
    rumor: &UnsignedEvent,
    seal_created_at: Timestamp,
) -> Result<Event, Nip59Error> {
    let rumor_json = rumor
        .try_to_json()
        .map_err(|e| Nip59Error::Json(e.to_string()))?;
    let ciphertext = nip44::encrypt(sender.secret_key(), recipient, &rumor_json)?;
    let seal = EventBuilder::new(Kind::SEAL, ciphertext)
        .created_at(seal_created_at)
        .sign_with_keys(sender)
        .map_err(|e| match e {
            crate::event::EventBuilderError::Clock(c) => Nip59Error::Clock(c),
            crate::event::EventBuilderError::Signer(s) => {
                // SignerMismatch from a Keys signer is unreachable, but
                // surface it as a JSON error rather than panic so the
                // function stays total.
                Nip59Error::Json(format!("seal signing failed unexpectedly: {s}"))
            }
        })?;
    Ok(seal)
}

/// Wrap a [`Seal`](Kind::SEAL) inside a [`GiftWrap`](Kind::GIFT_WRAP)
/// signed by a fresh ephemeral key.
///
/// `wrap_created_at` controls the wrap's outer timestamp; pass
/// [`random_past_timestamp`] for production use. `relay_hint` is
/// optional and feeds the third element of the `p` tag.
///
/// # Errors
///
/// See [`Nip59Error`].
pub fn create_gift_wrap(
    seal: &Event,
    recipient: &PublicKey,
    relay_hint: Option<&RelayUrl>,
    wrap_created_at: Timestamp,
) -> Result<Event, Nip59Error> {
    let ephemeral = Keys::generate().map_err(|e| match e {
        crate::key::SecretKeyError::Rng(r) => Nip59Error::Rng(r),
        // Other variants from `SecretKey::generate` never surface in the
        // happy path; collapse them into Json/format for completeness.
        other => Nip59Error::Json(format!("ephemeral key generation failed: {other}")),
    })?;

    let seal_json = seal
        .try_to_json()
        .map_err(|e| Nip59Error::Json(e.to_string()))?;
    let ciphertext = nip44::encrypt(ephemeral.secret_key(), recipient, &seal_json)?;

    let p_tag = Tag::with(
        &TagKind::single_letter(crate::SingleLetterTag::lowercase(crate::event::Alphabet::P)),
        relay_hint.map_or_else(
            || vec![recipient.to_hex()],
            |url| vec![recipient.to_hex(), url.as_str().to_owned()],
        ),
    );

    let wrap = EventBuilder::new(Kind::GIFT_WRAP, ciphertext)
        .created_at(wrap_created_at)
        .tag(p_tag)
        .sign_with_keys(&ephemeral)
        .map_err(|e| match e {
            crate::event::EventBuilderError::Clock(c) => Nip59Error::Clock(c),
            crate::event::EventBuilderError::Signer(s) => {
                Nip59Error::Json(format!("wrap signing failed unexpectedly: {s}"))
            }
        })?;
    Ok(wrap)
}

/// One-shot helper: build a rumor from `(kind, tags, content)`, seal it,
/// and gift-wrap the seal to `recipient` with random timestamps.
///
/// `rumor_created_at` is normally the wall clock; the seal and wrap each
/// pick their own timestamp uniformly from the past 2 days.
///
/// # Errors
///
/// See [`Nip59Error`]. Both the seal and wrap stages share the same error
/// channel.
pub fn wrap(
    sender: &Keys,
    recipient: &PublicKey,
    rumor_kind: Kind,
    rumor_tags: Tags,
    rumor_content: impl Into<String>,
    rumor_created_at: Timestamp,
    relay_hint: Option<&RelayUrl>,
) -> Result<Event, Nip59Error> {
    let rumor = build_rumor(
        sender,
        rumor_kind,
        rumor_tags,
        rumor_content,
        rumor_created_at,
    );
    let seal = create_seal(sender, recipient, &rumor, random_past_timestamp()?)?;
    create_gift_wrap(&seal, recipient, relay_hint, random_past_timestamp()?)
}

/// Bundle of explicit timestamps used by [`wrap_with_timestamps`].
///
/// Production code should pass [`Timestamps::random_past`] or
/// [`Timestamps::all_at`] for tests; mixing wall-clock-derived values
/// with hand-picked ones across the three layers is intentionally
/// awkward to discourage subtle bugs (e.g. picking the same value for
/// `rumor` and `wrap` and accidentally leaking the rumor timestamp via
/// the wrap).
#[derive(Debug, Clone, Copy)]
pub struct Timestamps {
    /// Author-supplied `created_at` of the inner rumor.
    pub rumor: Timestamp,
    /// Outer `created_at` of the seal (kind 13).
    pub seal: Timestamp,
    /// Outer `created_at` of the gift wrap (kind 1059).
    pub wrap: Timestamp,
}

impl Timestamps {
    /// Pick all three timestamps at the same instant.
    ///
    /// Convenient for round-trip tests where leakage is irrelevant.
    #[must_use]
    pub const fn all_at(ts: Timestamp) -> Self {
        Self {
            rumor: ts,
            seal: ts,
            wrap: ts,
        }
    }

    /// Wall-clock rumor + two independent `[now - 2 days, now]` draws
    /// for the seal and wrap.
    ///
    /// # Errors
    ///
    /// Returns [`Nip59Error::Clock`] / [`Nip59Error::Rng`] if the wall clock or
    /// OS RNG is unavailable.
    pub fn random_past() -> Result<Self, Nip59Error> {
        Ok(Self {
            rumor: Timestamp::now()?,
            seal: random_past_timestamp()?,
            wrap: random_past_timestamp()?,
        })
    }
}

/// Same as [`wrap`] but every `created_at` is supplied explicitly.
///
/// Use [`Timestamps::all_at`] for deterministic round-trip tests and
/// [`Timestamps::random_past`] for the production randomization rules.
///
/// # Errors
///
/// See [`Nip59Error`].
pub fn wrap_with_timestamps(
    sender: &Keys,
    recipient: &PublicKey,
    rumor_kind: Kind,
    rumor_tags: Tags,
    rumor_content: impl Into<String>,
    timestamps: Timestamps,
    relay_hint: Option<&RelayUrl>,
) -> Result<Event, Nip59Error> {
    let rumor = build_rumor(
        sender,
        rumor_kind,
        rumor_tags,
        rumor_content,
        timestamps.rumor,
    );
    let seal = create_seal(sender, recipient, &rumor, timestamps.seal)?;
    create_gift_wrap(&seal, recipient, relay_hint, timestamps.wrap)
}

/// Peel a [`GiftWrap`](Kind::GIFT_WRAP) and recover the inner rumor.
///
/// The function does **not** verify the gift wrap's outer signature; the
/// outer signer is by design throw-away keymaterial, and a tampered
/// outer signature would still produce ciphertext that the inner NIP-44
/// MAC catches. Callers that *want* to enforce a wire-level signature
/// check (e.g. a relay validating before forwarding) should call
/// [`Event::verify`] separately on the wrap.
///
/// What we DO verify, in order:
///
/// 1. The wrap's `kind` is `1059`.
/// 2. NIP-44 decryption of the wrap's content under
///    `(recipient_secret, wrap.pubkey)` succeeds — implies the wrap was
///    encrypted to us.
/// 3. The decrypted seal parses as a kind-13 event and its outer
///    signature verifies (the seal *is* the sender-signed layer, so its
///    signature must hold).
/// 4. NIP-44 decryption of the seal's content under
///    `(recipient_secret, seal.pubkey)` succeeds.
/// 5. The decrypted rumor's `pubkey` matches the seal's `pubkey`
///    (impersonation defence per §Encrypting).
///
/// # Errors
///
/// See [`Nip59Error`]. Returns [`Nip59Error::Nip44`] on tampered ciphertext,
/// [`Nip59Error::UnexpectedKind`] when either layer is wrong, [`Nip59Error::Event`]
/// when the seal's signature does not verify, and
/// [`Nip59Error::PubkeyMismatch`] when the rumor's author was rewritten by a
/// malicious sender.
pub fn unwrap(recipient: &Keys, gift_wrap: &Event) -> Result<UnsignedEvent, Nip59Error> {
    if gift_wrap.kind != Kind::GIFT_WRAP {
        return Err(Nip59Error::UnexpectedKind {
            expected: Kind::GIFT_WRAP.as_u16(),
            got: gift_wrap.kind.as_u16(),
        });
    }

    // Layer 1: peel the wrap.
    let seal_json = nip44::decrypt(
        recipient.secret_key(),
        &gift_wrap.pubkey,
        &gift_wrap.content,
    )?;
    let seal: Event = Event::from_json(seal_json).map_err(|e| Nip59Error::Json(e.to_string()))?;
    if seal.kind != Kind::SEAL {
        return Err(Nip59Error::UnexpectedKind {
            expected: Kind::SEAL.as_u16(),
            got: seal.kind.as_u16(),
        });
    }
    // The seal carries a real Schnorr signature from the sender; it
    // must verify or downstream code would attribute the rumor to the
    // wrong identity.
    seal.verify()?;

    // Layer 2: peel the seal.
    let rumor_json = nip44::decrypt(recipient.secret_key(), &seal.pubkey, &seal.content)?;
    let rumor: UnsignedEvent =
        UnsignedEvent::from_json(rumor_json).map_err(|e| Nip59Error::Json(e.to_string()))?;

    // Spec defence: the rumor must claim authorship by the same key
    // that signed the seal. Otherwise the sender could re-pubkey the
    // rumor at will.
    if rumor.pubkey != seal.pubkey {
        return Err(Nip59Error::PubkeyMismatch);
    }

    Ok(rumor)
}

/// Pick a [`Timestamp`] uniformly from `[now - 2 days, now]`.
///
/// # Errors
///
/// Returns [`Nip59Error::Clock`] if the wall clock cannot be read or
/// [`Nip59Error::Rng`] if the OS RNG is unavailable.
pub fn random_past_timestamp() -> Result<Timestamp, Nip59Error> {
    let now = Timestamp::now()?;
    let mut bytes = [0u8; 8];
    rng::fill_bytes(&mut bytes)?;
    let offset = u64::from_le_bytes(bytes) % TWO_DAYS_SECS;
    Ok(Timestamp::from_secs(now.as_secs().saturating_sub(offset)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;

    fn keys_alice() -> Keys {
        // Distinct, deterministic 32-byte fixture keys. Lowest non-zero
        // bytes encode the human-readable handle so test failures point
        // at a recognisable identity (`a1ce`, `b0b`, `ca8`, `ba1d`).
        Keys::parse("000000000000000000000000000000000000000000000000000000000000a1ce").unwrap()
    }

    fn keys_bob() -> Keys {
        Keys::parse("00000000000000000000000000000000000000000000000000000000000000b0").unwrap()
    }

    #[test]
    fn wrap_round_trip_recovers_rumor() {
        let alice = keys_alice();
        let bob = keys_bob();
        let now = Timestamp::from_secs(1_700_000_000);
        let seal_ts = Timestamp::from_secs(1_699_900_000);
        let wrap_ts = Timestamp::from_secs(1_699_800_000);

        let wrap = wrap_with_timestamps(
            &alice,
            bob.public_key(),
            Kind::PRIVATE_DIRECT_MESSAGE,
            Tags::new(),
            "secret hello",
            Timestamps {
                rumor: now,
                seal: seal_ts,
                wrap: wrap_ts,
            },
            None,
        )
        .unwrap();
        wrap.verify().unwrap();
        assert_eq!(wrap.kind, Kind::GIFT_WRAP);

        let rumor = unwrap(&bob, &wrap).unwrap();
        assert_eq!(rumor.kind, Kind::PRIVATE_DIRECT_MESSAGE);
        assert_eq!(rumor.pubkey, *alice.public_key());
        assert_eq!(rumor.content, "secret hello");
        assert_eq!(rumor.created_at, now);
    }

    #[test]
    fn wrap_picks_random_timestamps() {
        let alice = keys_alice();
        let bob = keys_bob();
        let now = Timestamp::from_secs(1_700_000_000);

        let wrap1 = wrap(
            &alice,
            bob.public_key(),
            Kind::PRIVATE_DIRECT_MESSAGE,
            Tags::new(),
            "msg",
            now,
            None,
        )
        .unwrap();
        // Wrap timestamp must be in `[now - 2 days, now]`.
        assert!(wrap1.created_at <= Timestamp::now().unwrap());
    }

    #[test]
    fn unwrap_rejects_wrong_kind() {
        let bob = keys_bob();
        let bogus = EventBuilder::text_note("not a wrap")
            .created_at(Timestamp::from_secs(1))
            .sign_with_keys(&bob)
            .unwrap();
        let err = unwrap(&bob, &bogus).unwrap_err();
        assert!(matches!(
            err,
            Nip59Error::UnexpectedKind {
                expected: 1059,
                got: 1
            }
        ));
    }

    #[test]
    fn unwrap_rejects_recipient_mismatch() {
        let alice = keys_alice();
        let bob = keys_bob();
        let carol = Keys::parse("00000000000000000000000000000000000000000000000000000000000ca800")
            .unwrap();
        let now = Timestamp::from_secs(1_700_000_000);

        // Wrap targeted at Bob.
        let wrap_for_bob = wrap_with_timestamps(
            &alice,
            bob.public_key(),
            Kind::PRIVATE_DIRECT_MESSAGE,
            Tags::new(),
            "for bob only",
            Timestamps::all_at(now),
            None,
        )
        .unwrap();

        // Carol cannot decrypt — the NIP-44 MAC catches it.
        let err = unwrap(&carol, &wrap_for_bob).unwrap_err();
        assert!(matches!(err, Nip59Error::Nip44(_)));
    }

    #[test]
    fn unwrap_detects_pubkey_substitution() {
        // We construct a wrap whose seal claims one author but whose
        // rumor claims another, and verify the impersonation defence
        // surfaces it as `PubkeyMismatch`. Building the malicious wrap
        // requires manual surgery: reuse the public surface to encrypt
        // a tampered rumor under the seal's keys.
        let alice = keys_alice();
        let bob = keys_bob();
        let mallory =
            Keys::parse("00000000000000000000000000000000000000000000000000000000000ba1d0")
                .unwrap();
        let now = Timestamp::from_secs(1_700_000_000);

        // Mallory builds a rumor *claiming* Alice as the author.
        let tampered_rumor = UnsignedEvent::new(
            *alice.public_key(),
            now,
            Kind::PRIVATE_DIRECT_MESSAGE,
            Tags::new(),
            "alice did NOT write this",
        );
        let tampered_rumor_json = tampered_rumor.try_to_json().unwrap();
        // Mallory seals it with HER OWN key (so the seal pubkey is
        // mallory, not alice — the spec says reject).
        let ciphertext =
            nip44::encrypt(mallory.secret_key(), bob.public_key(), &tampered_rumor_json).unwrap();
        let seal = EventBuilder::new(Kind::SEAL, ciphertext)
            .created_at(now)
            .sign_with_keys(&mallory)
            .unwrap();
        let wrap_evt = create_gift_wrap(&seal, bob.public_key(), None, now).unwrap();

        let err = unwrap(&bob, &wrap_evt).unwrap_err();
        assert!(matches!(err, Nip59Error::PubkeyMismatch));
    }

    #[test]
    fn random_past_timestamp_in_window() {
        let now = Timestamp::now().unwrap();
        for _ in 0..10 {
            let ts = random_past_timestamp().unwrap();
            assert!(ts <= now);
            assert!(ts.as_secs() + TWO_DAYS_SECS >= now.as_secs());
        }
    }
}
