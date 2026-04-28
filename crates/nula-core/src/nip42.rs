// Copyright (c) 2026 QNTX <https://qntx.fun>
// Distributed under the MIT or Apache-2.0 license.

//! [NIP-42] Authentication of clients to relays.
//!
//! NIP-42 lets a relay challenge a connected client and the client prove
//! ownership of a public key. The flow is:
//!
//! 1. Relay sends `["AUTH", "<challenge>"]`.
//! 2. Client signs a kind-`22242` event whose tags include
//!    `["relay", "<relay-url>"]` and `["challenge", "<challenge>"]`, then
//!    replies with `["AUTH", <event>]`.
//! 3. Relay verifies the event matches its expected relay URL and
//!    challenge, and that `created_at` falls inside an acceptable window
//!    (NIP-42 recommends ±10 minutes).
//!
//! This module provides:
//!
//! - [`auth_event`] — fluent constructor that yields an [`EventBuilder`]
//!   pre-populated with the kind, relay tag, and challenge tag.
//! - [`verify_auth_event`] — full server-side check (kind, tags, freshness).
//!
//! [NIP-42]: https://github.com/nostr-protocol/nips/blob/master/42.md

use thiserror::Error;

use crate::event::{Event, EventBuilder, Kind, Tag, TagKind};
use crate::types::{RelayUrl, RelayUrlError, Timestamp};

/// Wire name of the NIP-42 relay tag (`relay`).
pub const RELAY_TAG: &str = "relay";
/// Wire name of the NIP-42 challenge tag (`challenge`).
pub const CHALLENGE_TAG: &str = "challenge";
/// Recommended freshness window: 10 minutes on either side of `now`.
pub const DEFAULT_MAX_AGE_SECS: u64 = 10 * 60;

/// Errors raised when verifying a NIP-42 auth event.
#[derive(Debug, Clone, Error)]
#[non_exhaustive]
pub enum Error {
    /// The event's kind was not `22242`.
    #[error("expected kind 22242, got {0}")]
    UnexpectedKind(u16),
    /// The `relay` tag was missing or empty.
    #[error("`relay` tag is missing or empty")]
    MissingRelayTag,
    /// The `challenge` tag was missing or empty.
    #[error("`challenge` tag is missing or empty")]
    MissingChallengeTag,
    /// The `relay` tag value did not parse as a [`RelayUrl`].
    #[error(transparent)]
    InvalidRelay(#[from] RelayUrlError),
    /// The `relay` tag did not match the expected relay URL.
    #[error("relay mismatch: expected `{expected}`, got `{got}`")]
    RelayMismatch {
        /// Relay URL the verifier expected.
        expected: String,
        /// Relay URL the event actually claimed.
        got: String,
    },
    /// The `challenge` tag did not match the expected challenge string.
    #[error("challenge mismatch")]
    ChallengeMismatch,
    /// `created_at` is more than `max_age` seconds old.
    #[error("auth event is too old: created_at {created_at} vs now {now} (max age {max_age}s)")]
    TooOld {
        /// `event.created_at` (seconds since the epoch).
        created_at: u64,
        /// Verifier's `now`.
        now: u64,
        /// Maximum tolerated age.
        max_age: u64,
    },
    /// `created_at` is more than `max_age` seconds in the future.
    #[error(
        "auth event is too far in the future: created_at {created_at} vs now {now} (max skew {max_age}s)"
    )]
    TooFuture {
        /// `event.created_at` (seconds since the epoch).
        created_at: u64,
        /// Verifier's `now`.
        now: u64,
        /// Maximum tolerated future skew.
        max_age: u64,
    },
}

/// Build a NIP-42 auth event.
///
/// The returned [`EventBuilder`] has the kind set to `22242` and carries
/// the two NIP-42 tags. Callers can attach additional tags or pin
/// `created_at` before signing.
#[must_use]
pub fn auth_event(relay: &RelayUrl, challenge: impl Into<String>) -> EventBuilder {
    EventBuilder::new(Kind::AUTHENTICATION, "")
        .tag(Tag::with(
            &TagKind::from_wire(RELAY_TAG),
            [relay.as_str().to_owned()],
        ))
        .tag(Tag::with(
            &TagKind::from_wire(CHALLENGE_TAG),
            [challenge.into()],
        ))
}

/// Verify that `event` is a valid NIP-42 auth response for `(relay,
/// challenge)` at time `now`.
///
/// `max_age` bounds the freshness window in seconds: a value of `600`
/// matches NIP-42's recommended ±10-minute window. The check rejects
/// events older than `now - max_age` *and* events that come from more than
/// `max_age` seconds in the future, both of which suggest replay or clock
/// abuse.
///
/// This function does **not** verify the event's signature; call
/// [`Event::verify`] separately when the event arrives over the wire.
///
/// # Errors
///
/// Returns the matching [`Error`] variant on the first failed check.
pub fn verify_auth_event(
    event: &Event,
    relay: &RelayUrl,
    challenge: &str,
    now: Timestamp,
    max_age: u64,
) -> Result<(), Error> {
    verify_auth_event_against(event, relay, &[challenge], now, max_age)
}

/// Verify a NIP-42 auth event against a *set* of in-flight challenges.
///
/// Long-lived relay connections may rotate the AUTH challenge; client
/// implementations sometimes lag behind the latest one. This entry point
/// accepts any challenge in `accepted` and returns success on the first
/// match. All other verification rules — kind, relay tag, freshness
/// window — match [`verify_auth_event`].
///
/// `accepted` must be non-empty. An empty slice is treated as
/// "accept nothing" and produces [`Error::ChallengeMismatch`].
///
/// As with [`verify_auth_event`], this function does **not** verify the
/// event's Schnorr signature; call [`Event::verify`] separately.
///
/// # Errors
///
/// Returns the matching [`Error`] variant on the first failed check.
pub fn verify_auth_event_against(
    event: &Event,
    relay: &RelayUrl,
    accepted: &[&str],
    now: Timestamp,
    max_age: u64,
) -> Result<(), Error> {
    if event.kind != Kind::AUTHENTICATION {
        return Err(Error::UnexpectedKind(event.kind.as_u16()));
    }

    let relay_tag = TagKind::from_wire(RELAY_TAG);
    let claimed_relay = event
        .tags
        .find_first(&relay_tag)
        .and_then(|t| t.values().get(1))
        .ok_or(Error::MissingRelayTag)?;
    let claimed_relay = RelayUrl::parse(claimed_relay)?;
    if claimed_relay != *relay {
        return Err(Error::RelayMismatch {
            expected: relay.as_str().to_owned(),
            got: claimed_relay.as_str().to_owned(),
        });
    }

    let challenge_tag = TagKind::from_wire(CHALLENGE_TAG);
    let claimed_challenge = event
        .tags
        .find_first(&challenge_tag)
        .and_then(|t| t.values().get(1))
        .filter(|s| !s.is_empty())
        .ok_or(Error::MissingChallengeTag)?;
    if !accepted.contains(&claimed_challenge.as_str()) {
        return Err(Error::ChallengeMismatch);
    }

    let now_secs = now.as_secs();
    let created_at = event.created_at.as_secs();
    if now_secs > created_at && now_secs.saturating_sub(created_at) > max_age {
        return Err(Error::TooOld {
            created_at,
            now: now_secs,
            max_age,
        });
    }
    if created_at > now_secs && created_at.saturating_sub(now_secs) > max_age {
        return Err(Error::TooFuture {
            created_at,
            now: now_secs,
            max_age,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;

    fn keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    fn relay() -> RelayUrl {
        RelayUrl::parse("wss://relay.example/").unwrap()
    }

    fn signed(challenge: &str, ts: Timestamp) -> Event {
        auth_event(&relay(), challenge)
            .created_at(ts)
            .sign_with_keys(&keys())
            .unwrap()
    }

    #[test]
    fn auth_event_builder_sets_kind_and_tags() {
        let event = signed("c1", Timestamp::from_secs(100));
        assert_eq!(event.kind, Kind::AUTHENTICATION);
        let relay_tag = event
            .tags
            .find_first(&TagKind::from_wire(RELAY_TAG))
            .unwrap();
        assert_eq!(
            relay_tag.values().get(1).map(String::as_str),
            Some(relay().as_str())
        );
        let challenge_tag = event
            .tags
            .find_first(&TagKind::from_wire(CHALLENGE_TAG))
            .unwrap();
        assert_eq!(
            challenge_tag.values().get(1).map(String::as_str),
            Some("c1")
        );
    }

    #[test]
    fn verify_happy_path() {
        let event = signed("c1", Timestamp::from_secs(100));
        verify_auth_event(&event, &relay(), "c1", Timestamp::from_secs(100), 600).unwrap();
    }

    #[test]
    fn verify_rejects_wrong_kind() {
        let event = EventBuilder::text_note("nope")
            .created_at(Timestamp::from_secs(1))
            .sign_with_keys(&keys())
            .unwrap();
        let err =
            verify_auth_event(&event, &relay(), "c1", Timestamp::from_secs(1), 600).unwrap_err();
        assert!(matches!(err, Error::UnexpectedKind(1)));
    }

    #[test]
    fn verify_rejects_relay_mismatch() {
        let event = signed("c1", Timestamp::from_secs(1));
        let other = RelayUrl::parse("wss://other.example/").unwrap();
        let err =
            verify_auth_event(&event, &other, "c1", Timestamp::from_secs(1), 600).unwrap_err();
        assert!(matches!(err, Error::RelayMismatch { .. }));
    }

    #[test]
    fn verify_rejects_challenge_mismatch() {
        let event = signed("c1", Timestamp::from_secs(1));
        let err = verify_auth_event(&event, &relay(), "different", Timestamp::from_secs(1), 600)
            .unwrap_err();
        assert!(matches!(err, Error::ChallengeMismatch));
    }

    #[test]
    fn verify_rejects_old_event() {
        let event = signed("c1", Timestamp::from_secs(100));
        let err = verify_auth_event(&event, &relay(), "c1", Timestamp::from_secs(1_000), 100)
            .unwrap_err();
        assert!(matches!(err, Error::TooOld { .. }));
    }

    #[test]
    fn verify_rejects_future_event() {
        let event = signed("c1", Timestamp::from_secs(2_000));
        let err = verify_auth_event(&event, &relay(), "c1", Timestamp::from_secs(1_000), 100)
            .unwrap_err();
        assert!(matches!(err, Error::TooFuture { .. }));
    }

    #[test]
    fn verify_rejects_missing_relay_tag() {
        let event = EventBuilder::new(Kind::AUTHENTICATION, "")
            .created_at(Timestamp::from_secs(1))
            .tag(Tag::with(
                &TagKind::from_wire(CHALLENGE_TAG),
                ["c1".to_owned()],
            ))
            .sign_with_keys(&keys())
            .unwrap();
        let err =
            verify_auth_event(&event, &relay(), "c1", Timestamp::from_secs(1), 600).unwrap_err();
        assert!(matches!(err, Error::MissingRelayTag));
    }

    #[test]
    fn verify_rejects_missing_challenge_tag() {
        let event = EventBuilder::new(Kind::AUTHENTICATION, "")
            .created_at(Timestamp::from_secs(1))
            .tag(Tag::with(
                &TagKind::from_wire(RELAY_TAG),
                [relay().as_str().to_owned()],
            ))
            .sign_with_keys(&keys())
            .unwrap();
        let err =
            verify_auth_event(&event, &relay(), "c1", Timestamp::from_secs(1), 600).unwrap_err();
        assert!(matches!(err, Error::MissingChallengeTag));
    }

    #[test]
    fn verify_against_multi_challenge_accepts_any_match() {
        // Client signs against the older "c1"; server now also offers "c2".
        let event = signed("c1", Timestamp::from_secs(1));
        verify_auth_event_against(
            &event,
            &relay(),
            &["c2", "c1"],
            Timestamp::from_secs(1),
            600,
        )
        .unwrap();
    }

    #[test]
    fn verify_against_multi_challenge_rejects_when_none_match() {
        let event = signed("c1", Timestamp::from_secs(1));
        let err = verify_auth_event_against(
            &event,
            &relay(),
            &["c2", "c3"],
            Timestamp::from_secs(1),
            600,
        )
        .unwrap_err();
        assert!(matches!(err, Error::ChallengeMismatch));
    }

    #[test]
    fn verify_against_empty_challenge_set_rejects() {
        let event = signed("c1", Timestamp::from_secs(1));
        let err = verify_auth_event_against(&event, &relay(), &[], Timestamp::from_secs(1), 600)
            .unwrap_err();
        assert!(matches!(err, Error::ChallengeMismatch));
    }
}
