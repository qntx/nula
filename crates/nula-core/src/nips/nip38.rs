//! [NIP-38] User Statuses.
//!
//! `kind: 30315` ("User Status") is an **addressable**, optionally
//! **expiring** event. The `d` tag — the addressable identifier —
//! also doubles as the *status type*: NIP-38 standardises `general`
//! and `music` but leaves every other value open. The event body is
//! the human-readable status text; an empty body is a spec-level
//! signal to clear the status.
//!
//! Optional content:
//!
//! - a single link via an `r` / `p` / `e` / `a` tag (NIP-38 accepts
//!   any of the four — this module exposes all four through
//!   [`StatusLink`]);
//! - a NIP-40 `expiration` tag (handled by the existing builder
//!   helper and re-used here).
//!
//! # Authoring and reading
//!
//! Use [`EventBuilder::user_status`] to author, and [`UserStatus::from_event`]
//! to parse an existing event back into the typed bundle. The
//! builder guarantees:
//!
//! - `kind = 30315`;
//! - exactly one `d` tag with the status-type identifier;
//! - at most one link tag (the last `with_link` call wins);
//! - the NIP-40 `expiration` tag when [`UserStatus::expires_at`] is
//!   set.
//!
//! [NIP-38]: https://github.com/nostr-protocol/nips/blob/master/38.md

use thiserror::Error;

use crate::event::{
    Alphabet, Coordinate, Event, EventBuilder, EventId, Kind, SingleLetterTag, Tag, TagKind,
};
use crate::key::PublicKey;
use crate::types::Timestamp;

/// `kind: 30315` — user status addressable event.
pub const KIND_USER_STATUS: Kind = Kind::new(30_315);

/// `d`-tag identifier for the "general" status type.
pub const STATUS_TYPE_GENERAL: &str = "general";

/// `d`-tag identifier for the "music" status type.
pub const STATUS_TYPE_MUSIC: &str = "music";

/// Status *type* (the `d`-tag identifier, doubling as the
/// addressable coordinate).
///
/// NIP-38 standardises `general` and `music` but explicitly leaves
/// room for other values through [`Self::Custom`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StatusType {
    /// `general` — freeform status such as "Working", "Hiking".
    General,
    /// `music` — live-listening status; usually paired with an
    /// `expiration` tag set to the track's end time.
    Music,
    /// Any other status type.
    Custom(String),
}

impl StatusType {
    /// Parse a `d`-tag identifier.
    #[must_use]
    pub fn parse(identifier: &str) -> Self {
        match identifier {
            STATUS_TYPE_GENERAL => Self::General,
            STATUS_TYPE_MUSIC => Self::Music,
            other => Self::Custom(other.to_owned()),
        }
    }

    /// Render back to the wire identifier.
    #[must_use]
    pub const fn as_str(&self) -> &str {
        match self {
            Self::General => STATUS_TYPE_GENERAL,
            Self::Music => STATUS_TYPE_MUSIC,
            Self::Custom(s) => s.as_str(),
        }
    }
}

impl std::fmt::Display for StatusType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Optional link attached to a user status.
///
/// NIP-38 mentions an `r`, `p`, `e`, or `a` tag; we surface all four
/// via this enum so the builder and reader keep the semantics
/// round-trippable.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StatusLink {
    /// `r` tag — external URI. NIP-38 explicitly shows non-HTTP
    /// schemes such as `spotify:search:…` in its examples, so the
    /// variant carries a plain [`String`] rather than a
    /// [`Url`](crate::types::Url) (which is strict about absolute
    /// HTTP-family URLs).
    Web(String),
    /// `p` tag — referenced profile.
    Profile(PublicKey),
    /// `e` tag — referenced regular event id.
    Event(EventId),
    /// `a` tag — referenced addressable coordinate.
    Addressable(Coordinate),
}

impl StatusLink {
    /// Convert this link into the corresponding [`Tag`].
    #[must_use]
    pub fn to_tag(&self) -> Tag {
        match self {
            Self::Web(uri) => {
                let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::R));
                Tag::with(&head, [uri.clone()])
            }
            Self::Profile(pk) => Tag::p(*pk),
            Self::Event(id) => Tag::e(*id),
            Self::Addressable(coord) => {
                let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::A));
                Tag::with(&head, [coord.to_wire()])
            }
        }
    }
}

/// A parsed or freshly constructed user status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserStatus {
    /// Status type (maps to the addressable `d` tag).
    pub status_type: StatusType,
    /// Status text. An empty string is a spec-level clear signal.
    pub content: String,
    /// Optional link (at most one; see [`StatusLink`]).
    pub link: Option<StatusLink>,
    /// Optional NIP-40 expiration.
    pub expires_at: Option<Timestamp>,
}

impl UserStatus {
    /// Construct a new status with only the two required pieces.
    #[must_use]
    pub fn new(status_type: StatusType, content: impl Into<String>) -> Self {
        Self {
            status_type,
            content: content.into(),
            link: None,
            expires_at: None,
        }
    }

    /// Attach a link. At most one link is carried; subsequent calls
    /// replace the previous value (matches the builder's behaviour).
    #[must_use]
    pub fn with_link(mut self, link: StatusLink) -> Self {
        self.link = Some(link);
        self
    }

    /// Attach an NIP-40 expiration.
    #[must_use]
    pub const fn with_expiration(mut self, ts: Timestamp) -> Self {
        self.expires_at = Some(ts);
        self
    }

    /// `true` when [`Self::content`] is empty — the spec's clear
    /// signal.
    #[must_use]
    pub const fn is_clear(&self) -> bool {
        self.content.is_empty()
    }

    /// Parse a NIP-38 event back into the typed bundle.
    ///
    /// # Errors
    ///
    /// - [`UserStatusError::WrongKind`] for any kind other than
    ///   [`KIND_USER_STATUS`].
    /// - [`UserStatusError::MissingDTag`] when the addressable
    ///   `d`-identifier is absent.
    pub fn from_event(event: &Event) -> Result<Self, UserStatusError> {
        if event.kind != KIND_USER_STATUS {
            return Err(UserStatusError::WrongKind(event.kind));
        }
        let d = find_d_tag(event).ok_or(UserStatusError::MissingDTag)?;
        let status_type = StatusType::parse(d);
        let link = parse_link(event);
        let expires_at = event.expiration().ok().flatten();
        Ok(Self {
            status_type,
            content: event.content.clone(),
            link,
            expires_at,
        })
    }
}

/// Errors raised when reading a [`UserStatus`] off an [`Event`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum UserStatusError {
    /// The event was not `kind: 30315`.
    #[error("expected kind 30315 (user status), got kind {}", .0.as_u16())]
    WrongKind(Kind),
    /// The required `d` tag was absent.
    #[error("NIP-38 event must carry exactly one `d` tag")]
    MissingDTag,
}

fn find_d_tag(event: &Event) -> Option<&str> {
    let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::D));
    event.tags.find_first(&head).and_then(|tag| tag.get(1))
}

fn parse_link(event: &Event) -> Option<StatusLink> {
    for tag in &event.tags {
        let TagKind::SingleLetter(letter) = tag.kind() else {
            continue;
        };
        if letter.uppercase {
            continue;
        }
        let Some(value) = tag.get(1) else {
            continue;
        };
        let link = match letter.character {
            Alphabet::R => Some(StatusLink::Web(value.to_owned())),
            Alphabet::P => PublicKey::parse(value).ok().map(StatusLink::Profile),
            Alphabet::E => EventId::parse(value).ok().map(StatusLink::Event),
            Alphabet::A => Coordinate::parse(value).ok().map(StatusLink::Addressable),
            _ => None,
        };
        if let Some(link) = link {
            return Some(link);
        }
    }
    None
}

impl EventBuilder {
    /// Author a NIP-38 user-status event.
    ///
    /// The builder pins `kind = 30315` and always emits the `d` tag
    /// carrying the status-type identifier. The NIP-40 expiration
    /// tag is attached through the existing
    /// [`EventBuilder::expiration`] path when
    /// [`UserStatus::expires_at`] is set, so callers that also
    /// chain `.expiration(ts)` manually will get a single
    /// consolidated tag.
    #[must_use]
    pub fn user_status(status: UserStatus) -> Self {
        let mut builder =
            Self::new(KIND_USER_STATUS, status.content).tag(Tag::d(status.status_type.as_str()));
        if let Some(link) = status.link {
            builder = builder.tag(link.to_tag());
        }
        if let Some(ts) = status.expires_at {
            builder = builder.expiration(ts);
        }
        builder
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;

    fn keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    #[test]
    fn status_type_round_trips_through_parse_and_as_str() {
        for (s, v) in [
            ("general", StatusType::General),
            ("music", StatusType::Music),
            ("lunar-phase", StatusType::Custom("lunar-phase".into())),
        ] {
            let parsed = StatusType::parse(s);
            assert_eq!(parsed, v);
            assert_eq!(parsed.as_str(), s);
        }
    }

    #[test]
    fn builder_emits_kind_and_d_tag() {
        let status = UserStatus::new(StatusType::General, "Working");
        let event = EventBuilder::user_status(status)
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, KIND_USER_STATUS);
        assert_eq!(event.content, "Working");
        let d = find_d_tag(&event).unwrap();
        assert_eq!(d, STATUS_TYPE_GENERAL);
    }

    #[test]
    fn builder_attaches_web_link_and_expiration() {
        let uri = "spotify:search:Intergalatic".to_owned();
        let status = UserStatus::new(StatusType::Music, "Intergalatic - Beastie Boys")
            .with_link(StatusLink::Web(uri.clone()))
            .with_expiration(Timestamp::from_secs(1_692_845_589));
        let event = EventBuilder::user_status(status)
            .sign_with_keys(&keys())
            .unwrap();

        let parsed = UserStatus::from_event(&event).unwrap();
        assert_eq!(parsed.status_type, StatusType::Music);
        assert_eq!(parsed.content, "Intergalatic - Beastie Boys");
        assert_eq!(parsed.link, Some(StatusLink::Web(uri)));
        assert_eq!(parsed.expires_at, Some(Timestamp::from_secs(1_692_845_589)));
    }

    #[test]
    fn from_event_round_trips_profile_link() {
        let pk = *keys().public_key();
        let status =
            UserStatus::new(StatusType::General, "mentoring").with_link(StatusLink::Profile(pk));
        let event = EventBuilder::user_status(status)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = UserStatus::from_event(&event).unwrap();
        assert_eq!(parsed.link, Some(StatusLink::Profile(pk)));
    }

    #[test]
    fn from_event_rejects_wrong_kind() {
        let event = EventBuilder::text_note("not a status")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            UserStatus::from_event(&event),
            Err(UserStatusError::WrongKind(_))
        ));
    }

    #[test]
    fn empty_content_signals_a_clear() {
        let status = UserStatus::new(StatusType::General, "");
        assert!(status.is_clear());
    }

    #[test]
    fn custom_status_type_round_trips_on_d_tag() {
        let status = UserStatus::new(StatusType::Custom("focus".into()), "heads-down");
        let event = EventBuilder::user_status(status)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = UserStatus::from_event(&event).unwrap();
        assert_eq!(parsed.status_type, StatusType::Custom("focus".into()));
    }
}
