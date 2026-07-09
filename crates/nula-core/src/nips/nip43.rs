//! [NIP-43] Relay Access Metadata and Requests.
//!
//! Lets relays advertise membership and lets clients request admission
//! on behalf of users. Five event shapes, all carrying the NIP-70
//! protected `["-"]` tag:
//!
//! | Kind    | Author         | Meaning                              |
//! |---------|----------------|--------------------------------------|
//! | `13534` | relay (`self`) | Membership list (`member` tags)      |
//! | `8000`  | relay (`self`) | Member added (`p` tag)               |
//! | `8001`  | relay (`self`) | Member removed (`p` tag)             |
//! | `28934` | user           | Join request (`claim` tag)           |
//! | `28935` | relay (`self`) | Invite — ephemeral claim handout     |
//! | `28936` | user           | Leave request                        |
//!
//! Relay-signed events MUST be signed by the pubkey in the `self`
//! field of the relay's NIP-11 document; enforcing that binding is
//! the caller's job since it needs the NIP-11 fetch.
//!
//! Failed join claims surface through `OK` messages with the NIP-42
//! `restricted:` prefix — see [`crate::message::MachineReadablePrefix`].
//!
//! [NIP-43]: https://github.com/nostr-protocol/nips/blob/master/43.md

use thiserror::Error;

use crate::event::{Event, EventBuilder, Kind, Tag, TagKind};
use crate::key::PublicKey;
use crate::nips::nip70;

/// `kind: 13534` — relay membership list.
pub const KIND_MEMBERSHIP_LIST: Kind = Kind::RELAY_MEMBERSHIP_LIST;
/// `kind: 8000` — member added.
pub const KIND_MEMBER_ADDED: Kind = Kind::RELAY_MEMBER_ADDED;
/// `kind: 8001` — member removed.
pub const KIND_MEMBER_REMOVED: Kind = Kind::RELAY_MEMBER_REMOVED;
/// `kind: 28934` — join request.
pub const KIND_JOIN_REQUEST: Kind = Kind::RELAY_JOIN_REQUEST;
/// `kind: 28935` — invite (ephemeral claim handout).
pub const KIND_INVITE: Kind = Kind::RELAY_INVITE;
/// `kind: 28936` — leave request.
pub const KIND_LEAVE_REQUEST: Kind = Kind::RELAY_LEAVE_REQUEST;

const MEMBER_TAG: &str = "member";
const CLAIM_TAG: &str = "claim";

/// Errors raised while parsing NIP-43 events.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RelayAccessError {
    /// Event kind does not match the expected NIP-43 shape.
    #[error("unexpected kind for NIP-43: {}", .0.as_u16())]
    WrongKind(Kind),
    /// The NIP-70 `["-"]` tag required by every NIP-43 shape is missing.
    #[error("NIP-43 event missing required protected `-` tag")]
    MissingProtectedTag,
    /// The required `p` tag is missing or malformed.
    #[error("NIP-43 event missing a valid `p` tag")]
    MissingMember,
    /// The required `claim` tag is missing.
    #[error("NIP-43 event missing required `claim` tag")]
    MissingClaim,
}

fn ensure(event: &Event, kind: Kind) -> Result<(), RelayAccessError> {
    if event.kind != kind {
        return Err(RelayAccessError::WrongKind(event.kind));
    }
    if !nip70::is_protected(event) {
        return Err(RelayAccessError::MissingProtectedTag);
    }
    Ok(())
}

fn member_from_p_tag(event: &Event) -> Result<PublicKey, RelayAccessError> {
    event
        .tags
        .public_keys()
        .next()
        .ok_or(RelayAccessError::MissingMember)
}

fn claim_from_tags(event: &Event) -> Result<String, RelayAccessError> {
    event
        .tags
        .find_first(&TagKind::custom(CLAIM_TAG))
        .and_then(Tag::content)
        .map(str::to_owned)
        .ok_or(RelayAccessError::MissingClaim)
}

/// Typed bundle for a `kind: 13534` relay membership list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipList {
    /// Pubkeys carried by `member` tags. Not exhaustive or
    /// authoritative per spec.
    pub members: Vec<PublicKey>,
}

impl MembershipList {
    /// Parse a `kind: 13534` membership-list event.
    ///
    /// # Errors
    ///
    /// See [`RelayAccessError`] for the failure modes.
    pub fn from_event(event: &Event) -> Result<Self, RelayAccessError> {
        ensure(event, KIND_MEMBERSHIP_LIST)?;
        let members = event
            .tags
            .iter()
            .filter(|tag| tag.name() == MEMBER_TAG)
            .filter_map(|tag| PublicKey::parse(tag.content()?).ok())
            .collect();
        Ok(Self { members })
    }
}

/// Membership change (`kind: 8000` add / `kind: 8001` remove).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MembershipChange {
    /// The affected member (`p` tag).
    pub member: PublicKey,
    /// `true` for `kind: 8000` (added), `false` for `kind: 8001`.
    pub added: bool,
}

impl MembershipChange {
    /// Parse a `kind: 8000` / `kind: 8001` membership-change event.
    ///
    /// # Errors
    ///
    /// See [`RelayAccessError`] for the failure modes.
    pub fn from_event(event: &Event) -> Result<Self, RelayAccessError> {
        let added = match event.kind {
            KIND_MEMBER_ADDED => true,
            KIND_MEMBER_REMOVED => false,
            other => return Err(RelayAccessError::WrongKind(other)),
        };
        ensure(event, event.kind)?;
        Ok(Self {
            member: member_from_p_tag(event)?,
            added,
        })
    }
}

/// Extract the invite code from a `kind: 28934` join request or a
/// `kind: 28935` invite.
///
/// # Errors
///
/// See [`RelayAccessError`] for the failure modes.
pub fn claim_from_event(event: &Event) -> Result<String, RelayAccessError> {
    match event.kind {
        KIND_JOIN_REQUEST | KIND_INVITE => {}
        other => return Err(RelayAccessError::WrongKind(other)),
    }
    ensure(event, event.kind)?;
    claim_from_tags(event)
}

/// Validate a `kind: 28936` leave request.
///
/// # Errors
///
/// See [`RelayAccessError`] for the failure modes.
pub fn validate_leave_request(event: &Event) -> Result<(), RelayAccessError> {
    ensure(event, KIND_LEAVE_REQUEST)
}

impl EventBuilder {
    /// Author a `kind: 13534` relay membership list.
    #[must_use]
    pub fn relay_membership_list<I>(members: I) -> Self
    where
        I: IntoIterator<Item = PublicKey>,
    {
        let head = TagKind::custom(MEMBER_TAG);
        Self::new(KIND_MEMBERSHIP_LIST, "").protected().tags(
            members
                .into_iter()
                .map(|pk: PublicKey| Tag::with(&head, [pk.to_hex()])),
        )
    }

    /// Author a `kind: 8000` (added) or `kind: 8001` (removed)
    /// membership-change event.
    #[must_use]
    pub fn relay_membership_change(change: MembershipChange) -> Self {
        let kind = if change.added {
            KIND_MEMBER_ADDED
        } else {
            KIND_MEMBER_REMOVED
        };
        Self::new(kind, "").protected().tag(Tag::p(change.member))
    }

    /// Author a `kind: 28934` join request carrying an invite code.
    ///
    /// The spec requires `created_at` to be current; the builder's
    /// default wall-clock timestamp satisfies that.
    #[must_use]
    pub fn relay_join_request<S: Into<String>>(claim: S) -> Self {
        Self::new(KIND_JOIN_REQUEST, "")
            .protected()
            .tag(Tag::with(&TagKind::custom(CLAIM_TAG), [claim.into()]))
    }

    /// Author a `kind: 28935` invite handing out an invite code.
    #[must_use]
    pub fn relay_invite<S: Into<String>>(claim: S) -> Self {
        Self::new(KIND_INVITE, "")
            .protected()
            .tag(Tag::with(&TagKind::custom(CLAIM_TAG), [claim.into()]))
    }

    /// Author a `kind: 28936` leave request.
    #[must_use]
    pub fn relay_leave_request() -> Self {
        Self::new(KIND_LEAVE_REQUEST, "").protected()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;

    fn keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    fn member() -> PublicKey {
        *keys().public_key()
    }

    #[test]
    fn membership_list_round_trip() {
        let event = EventBuilder::relay_membership_list([member()])
            .sign_with_keys(&keys())
            .unwrap();
        let list = MembershipList::from_event(&event).unwrap();
        assert_eq!(list.members, vec![member()]);
    }

    #[test]
    fn membership_change_round_trip() {
        for added in [true, false] {
            let change = MembershipChange {
                member: member(),
                added,
            };
            let event = EventBuilder::relay_membership_change(change)
                .sign_with_keys(&keys())
                .unwrap();
            assert_eq!(MembershipChange::from_event(&event).unwrap(), change);
        }
    }

    #[test]
    fn join_request_round_trip() {
        let event = EventBuilder::relay_join_request("secret-invite")
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(claim_from_event(&event).unwrap(), "secret-invite");
    }

    #[test]
    fn invite_round_trip() {
        let event = EventBuilder::relay_invite("code-123")
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(claim_from_event(&event).unwrap(), "code-123");
    }

    #[test]
    fn leave_request_round_trip() {
        let event = EventBuilder::relay_leave_request()
            .sign_with_keys(&keys())
            .unwrap();
        validate_leave_request(&event).unwrap();
    }

    #[test]
    fn missing_protected_tag_is_rejected() {
        let event = EventBuilder::new(KIND_JOIN_REQUEST, "")
            .tag(Tag::with(&TagKind::custom(CLAIM_TAG), ["x"]))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            claim_from_event(&event),
            Err(RelayAccessError::MissingProtectedTag)
        ));
    }

    #[test]
    fn wrong_kind_is_rejected() {
        let event = EventBuilder::text_note("nope")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            MembershipList::from_event(&event),
            Err(RelayAccessError::WrongKind(_))
        ));
    }

    #[test]
    fn missing_claim_is_rejected() {
        let event = EventBuilder::new(KIND_JOIN_REQUEST, "")
            .protected()
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            claim_from_event(&event),
            Err(RelayAccessError::MissingClaim)
        ));
    }
}
