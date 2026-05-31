//! [NIP-29] Relay-based Groups.
//!
//! Groups are relay-side closed-membership constructs. Every group has
//! a string identifier and is hosted by exactly one relay (though a
//! group can be forked across relays under the same id). The crate
//! models four lanes:
//!
//! - **Membership** ([`JoinRequest`] / [`LeaveRequest`]) — events
//!   sent by users.
//! - **Moderation** ([`ModerationAction`] + [`ModerationKind`]) — the
//!   `9000-9020` range of admin events that mutate group state.
//! - **Group state** ([`GroupMetadata`] / [`GroupAdmins`] /
//!   [`GroupMembers`] / [`GroupRoles`]) — addressable events the
//!   relay master key publishes.
//! - **Identifier** ([`GroupId`]) — the spec's `<host>'<group-id>`
//!   pair, with `_` reserved for relay-local discussions.
//!
//! All event-authoring helpers carry the spec-required `h` tag for
//! user-side events and the `d` tag for state events.
//!
//! [NIP-29]: https://github.com/nostr-protocol/nips/blob/master/29.md

use thiserror::Error;

use crate::event::{
    Alphabet, Coordinate, Event, EventBuilder, EventId, EventIdError, Kind, SingleLetterTag, Tag,
    TagKind,
};
use crate::key::{PublicKey, PublicKeyError};
use crate::types::{Url, UrlError};

/// `kind: 9000` — put-user moderation event.
pub const KIND_GROUP_PUT_USER: Kind = Kind::GROUP_PUT_USER;
/// `kind: 9001` — remove-user moderation event.
pub const KIND_GROUP_REMOVE_USER: Kind = Kind::GROUP_REMOVE_USER;
/// `kind: 9002` — edit-metadata moderation event.
pub const KIND_GROUP_EDIT_METADATA: Kind = Kind::GROUP_EDIT_METADATA;
/// `kind: 9005` — delete-event moderation event.
pub const KIND_GROUP_DELETE_EVENT: Kind = Kind::GROUP_DELETE_EVENT;
/// `kind: 9007` — create-group moderation event.
pub const KIND_GROUP_CREATE: Kind = Kind::GROUP_CREATE;
/// `kind: 9008` — delete-group moderation event.
pub const KIND_GROUP_DELETE: Kind = Kind::GROUP_DELETE;
/// `kind: 9009` — create-invite moderation event.
pub const KIND_GROUP_CREATE_INVITE: Kind = Kind::GROUP_CREATE_INVITE;
/// `kind: 9021` — group join request.
pub const KIND_GROUP_JOIN_REQUEST: Kind = Kind::GROUP_JOIN_REQUEST;
/// `kind: 9022` — group leave request.
pub const KIND_GROUP_LEAVE_REQUEST: Kind = Kind::GROUP_LEAVE_REQUEST;
/// `kind: 39000` — group metadata.
pub const KIND_GROUP_METADATA: Kind = Kind::GROUP_METADATA;
/// `kind: 39001` — group admins.
pub const KIND_GROUP_ADMINS: Kind = Kind::GROUP_ADMINS;
/// `kind: 39002` — group members.
pub const KIND_GROUP_MEMBERS: Kind = Kind::GROUP_MEMBERS;
/// `kind: 39003` — group roles.
pub const KIND_GROUP_ROLES: Kind = Kind::GROUP_ROLES;

const H_TAG: &str = "h";
const PREVIOUS_TAG: &str = "previous";
const NAME_TAG: &str = "name";
const PICTURE_TAG: &str = "picture";
const ABOUT_TAG: &str = "about";
const PRIVATE_TAG: &str = "private";
const RESTRICTED_TAG: &str = "restricted";
const HIDDEN_TAG: &str = "hidden";
const CLOSED_TAG: &str = "closed";
const ROLE_TAG: &str = "role";
const CODE_TAG: &str = "code";

/// Sentinel reserved for the relay-local discussion group when the
/// caller drops the `'<id>` part of a group reference.
pub const RELAY_LOCAL_GROUP: &str = "_";

/// Group identifier `<host>'<group-id>` (or just `<host>` ⇒
/// [`RELAY_LOCAL_GROUP`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GroupId {
    /// Host portion (relay hostname without the `wss://` prefix).
    pub host: String,
    /// Per-group identifier (lowercase `[a-z0-9-_]+`).
    pub id: String,
}

impl GroupId {
    /// Construct a group reference, defaulting to the relay-local
    /// sentinel id when `id` is `None`.
    #[must_use]
    pub fn new(host: impl Into<String>, id: Option<String>) -> Self {
        Self {
            host: host.into(),
            id: id.unwrap_or_else(|| RELAY_LOCAL_GROUP.to_owned()),
        }
    }

    /// Render as the spec's wire form (`<host>'<group-id>`). When the
    /// id is the sentinel `_`, the trailing `'_` is omitted to match
    /// shorthand notation.
    #[must_use]
    pub fn to_wire(&self) -> String {
        if self.id == RELAY_LOCAL_GROUP {
            self.host.clone()
        } else {
            format!("{}'{}", self.host, self.id)
        }
    }

    /// Parse from `<host>['<id>]`.
    ///
    /// # Errors
    ///
    /// Returns [`GroupIdError`] when the `<host>` portion is empty
    /// or when `<id>` contains characters outside `[a-z0-9-_]`.
    pub fn parse(input: &str) -> Result<Self, GroupIdError> {
        let (host, id) = input.split_once('\'').map_or_else(
            || (input.to_owned(), None),
            |(h, i)| (h.to_owned(), Some(i.to_owned())),
        );
        if host.is_empty() {
            return Err(GroupIdError::EmptyHost);
        }
        if let Some(id_str) = &id
            && !is_valid_id(id_str)
        {
            return Err(GroupIdError::InvalidId(id_str.clone()));
        }
        Ok(Self::new(host, id))
    }
}

fn is_valid_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Errors raised by [`GroupId::parse`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum GroupIdError {
    /// `<host>` portion was empty.
    #[error("group id missing host portion")]
    EmptyHost,
    /// `<id>` portion contained non-`[a-z0-9-_]` characters.
    #[error("group id `{0}` contains invalid characters (allowed: [a-z0-9-_])")]
    InvalidId(String),
}

/// `["previous", ...]` 4-byte event-id-prefix references.
pub type PreviousReferences = Vec<String>;

/// `["h", "<group-id>"]` based event metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRef {
    /// Per-group identifier (string after the `'`).
    pub id: String,
    /// Optional 4-byte previous-event-id prefixes (anti-context-out).
    pub previous: PreviousReferences,
}

impl GroupRef {
    /// Construct a reference with no `previous` prefixes.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            previous: Vec::new(),
        }
    }
}

/// `kind: 9021` — request to join a group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinRequest {
    /// Reason or note (mirrors `.content`).
    pub reason: String,
    /// Group identifier.
    pub group: GroupRef,
    /// Optional invite code (`code` tag).
    pub code: Option<String>,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

/// `kind: 9022` — request to leave a group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaveRequest {
    /// Reason or note (mirrors `.content`).
    pub reason: String,
    /// Group identifier.
    pub group: GroupRef,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

/// Per-NIP-29 moderation kind plus a forward-compatible passthrough
/// for the rest of the `9000..=9020` range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModerationKind {
    /// `9000` put-user.
    PutUser {
        /// Pubkey to add or update.
        pubkey: PublicKey,
        /// Optional list of role labels.
        roles: Vec<String>,
    },
    /// `9001` remove-user.
    RemoveUser(PublicKey),
    /// `9002` edit-metadata.
    EditMetadata(GroupMetadataPatch),
    /// `9005` delete-event.
    DeleteEvent(EventId),
    /// `9007` create-group.
    CreateGroup,
    /// `9008` delete-group.
    DeleteGroup,
    /// `9009` create-invite.
    CreateInvite {
        /// Pre-authorisation code.
        code: String,
    },
    /// Reserved range passthrough.
    Custom {
        /// Underlying numeric kind.
        kind: Kind,
        /// Verbatim tags carried by the moderation event (excluding
        /// the canonical `h` and `previous` ones).
        tags: Vec<Tag>,
    },
}

/// Bitset for the four flag-style metadata tags (`private` /
/// `restricted` / `hidden` / `closed`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct GroupFlags(u8);

impl GroupFlags {
    /// `private` — only members can read.
    pub const PRIVATE: Self = Self(0b0001);
    /// `restricted` — only members can write.
    pub const RESTRICTED: Self = Self(0b0010);
    /// `hidden` — non-members cannot fetch metadata.
    pub const HIDDEN: Self = Self(0b0100);
    /// `closed` — join requests are ignored.
    pub const CLOSED: Self = Self(0b1000);

    /// Empty flag set.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// True when every bit in `other` is set in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl std::ops::BitOr for GroupFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for GroupFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Subset of [`GroupMetadata`] updatable through `kind: 9002`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GroupMetadataPatch {
    /// `name` tag.
    pub name: Option<String>,
    /// `picture` tag.
    pub picture: Option<Url>,
    /// `about` tag.
    pub about: Option<String>,
    /// Flag-style tags.
    pub flags: GroupFlags,
}

/// `kind: 9000-9020` — moderation action authored by an admin (or
/// the relay master key for `9007` / `9008`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModerationAction {
    /// Reason or note (mirrors `.content`).
    pub reason: String,
    /// Group identifier.
    pub group: GroupRef,
    /// The action itself.
    pub action: ModerationKind,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

/// `kind: 39000` — group metadata addressable event.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GroupMetadata {
    /// Group identifier (`d` tag).
    pub identifier: String,
    /// `name` tag.
    pub name: Option<String>,
    /// `picture` tag.
    pub picture: Option<Url>,
    /// `about` tag.
    pub about: Option<String>,
    /// Flag-style tags.
    pub flags: GroupFlags,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

/// A pubkey + roles row used by [`GroupAdmins`] / [`GroupMembers`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupAdminEntry {
    /// Admin pubkey.
    pub pubkey: PublicKey,
    /// Role labels (zero or more, `["p", <pubkey>, <role>...]`).
    pub roles: Vec<String>,
}

/// `kind: 39001` — group admins addressable event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupAdmins {
    /// Group identifier (`d` tag).
    pub identifier: String,
    /// Free-form description (mirrors `.content`).
    pub content: String,
    /// One row per admin.
    pub admins: Vec<GroupAdminEntry>,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

/// `kind: 39002` — group members addressable event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMembers {
    /// Group identifier (`d` tag).
    pub identifier: String,
    /// Free-form description (mirrors `.content`).
    pub content: String,
    /// One pubkey per member (no roles per spec).
    pub members: Vec<PublicKey>,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

/// A `role` tag column on a [`GroupRoles`] event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRole {
    /// Role label.
    pub name: String,
    /// Optional description.
    pub description: Option<String>,
}

/// `kind: 39003` — group roles addressable event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRoles {
    /// Group identifier (`d` tag).
    pub identifier: String,
    /// Free-form description (mirrors `.content`).
    pub content: String,
    /// Role definitions in publication order.
    pub roles: Vec<GroupRole>,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

/// Errors raised while parsing NIP-29 events.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum GroupError {
    /// Event kind does not match the expected NIP-29 kind.
    #[error("unexpected kind for NIP-29 event: {}", .0.as_u16())]
    WrongKind(Kind),
    /// `h` tag missing on a user-side event.
    #[error("NIP-29 event missing required `h` tag")]
    MissingGroupRef,
    /// `d` tag missing on a state event.
    #[error("NIP-29 state event missing required `d` tag")]
    MissingIdentifier,
    /// `p` tag missing on a moderation event that requires it.
    #[error("NIP-29 moderation event missing required `p` tag")]
    MissingPubkey,
    /// `e` tag missing on a `9005` delete-event.
    #[error("NIP-29 delete-event missing required `e` tag")]
    MissingEvent,
    /// `code` tag missing on `9009` create-invite.
    #[error("NIP-29 create-invite missing required `code` tag")]
    MissingCode,
    /// Group id parsing error.
    #[error(transparent)]
    InvalidGroupId(#[from] GroupIdError),
    /// Wrapped pubkey parser error.
    #[error(transparent)]
    InvalidPublicKey(#[from] PublicKeyError),
    /// Wrapped URL parser error.
    #[error(transparent)]
    InvalidUrl(#[from] UrlError),
    /// Wrapped event-id parser error.
    #[error(transparent)]
    InvalidEventId(#[from] EventIdError),
}


fn h_tag_value(event: &Event) -> Option<&str> {
    event
        .tags
        .iter()
        .find(|tag| tag.name() == H_TAG)
        .and_then(|tag| tag.get(1))
}

fn d_tag_value(event: &Event) -> Option<&str> {
    let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::D));
    event.tags.find_first(&head).and_then(|tag| tag.get(1))
}

fn previous_from_event(event: &Event) -> PreviousReferences {
    event
        .tags
        .iter()
        .find(|tag| tag.name() == PREVIOUS_TAG)
        .map_or_else(Vec::new, |tag| {
            tag.values().iter().skip(1).cloned().collect()
        })
}

fn group_ref_tag(group: &GroupRef) -> Vec<Tag> {
    let mut tags = vec![Tag::with(&TagKind::from_wire(H_TAG), [group.id.clone()])];
    if !group.previous.is_empty() {
        let mut cols = vec![PREVIOUS_TAG.to_owned()];
        cols.extend(group.previous.iter().cloned());
        if let Ok(tag) = Tag::new(cols) {
            tags.push(tag);
        }
    }
    tags
}

fn metadata_apply_flags(builder: &mut EventBuilder, patch: &GroupMetadataPatch) {
    if let Some(name) = &patch.name {
        *builder = builder
            .clone()
            .tag(Tag::with(&TagKind::from_wire(NAME_TAG), [name.clone()]));
    }
    if let Some(picture) = &patch.picture {
        *builder = builder.clone().tag(Tag::with(
            &TagKind::from_wire(PICTURE_TAG),
            [picture.as_str().to_owned()],
        ));
    }
    if let Some(about) = &patch.about {
        *builder = builder
            .clone()
            .tag(Tag::with(&TagKind::from_wire(ABOUT_TAG), [about.clone()]));
    }
    for (bit, name) in [
        (GroupFlags::PRIVATE, PRIVATE_TAG),
        (GroupFlags::RESTRICTED, RESTRICTED_TAG),
        (GroupFlags::HIDDEN, HIDDEN_TAG),
        (GroupFlags::CLOSED, CLOSED_TAG),
    ] {
        if patch.flags.contains(bit) {
            *builder = builder
                .clone()
                .tag(Tag::with(&TagKind::from_wire(name), Vec::<String>::new()));
        }
    }
}


impl JoinRequest {
    /// Parse a `kind: 9021` join request.
    ///
    /// # Errors
    ///
    /// See [`GroupError`] for the failure modes.
    pub fn from_event(event: &Event) -> Result<Self, GroupError> {
        if event.kind != KIND_GROUP_JOIN_REQUEST {
            return Err(GroupError::WrongKind(event.kind));
        }
        let id = h_tag_value(event)
            .ok_or(GroupError::MissingGroupRef)?
            .to_owned();
        let mut code: Option<String> = None;
        let mut extra_tags: Vec<Tag> = Vec::new();
        for tag in &event.tags {
            match tag.name() {
                H_TAG | PREVIOUS_TAG => {}
                CODE_TAG => code = tag.get(1).map(str::to_owned),
                _ => extra_tags.push(tag.clone()),
            }
        }
        Ok(Self {
            reason: event.content.clone(),
            group: GroupRef {
                id,
                previous: previous_from_event(event),
            },
            code,
            extra_tags,
        })
    }
}

impl LeaveRequest {
    /// Parse a `kind: 9022` leave request.
    ///
    /// # Errors
    ///
    /// See [`GroupError`] for the failure modes.
    pub fn from_event(event: &Event) -> Result<Self, GroupError> {
        if event.kind != KIND_GROUP_LEAVE_REQUEST {
            return Err(GroupError::WrongKind(event.kind));
        }
        let id = h_tag_value(event)
            .ok_or(GroupError::MissingGroupRef)?
            .to_owned();
        let mut extra_tags: Vec<Tag> = Vec::new();
        for tag in &event.tags {
            match tag.name() {
                H_TAG | PREVIOUS_TAG => {}
                _ => extra_tags.push(tag.clone()),
            }
        }
        Ok(Self {
            reason: event.content.clone(),
            group: GroupRef {
                id,
                previous: previous_from_event(event),
            },
            extra_tags,
        })
    }
}


impl ModerationAction {
    /// Parse a `kind: 9000-9020` moderation event.
    ///
    /// # Errors
    ///
    /// See [`GroupError`] for the failure modes.
    pub fn from_event(event: &Event) -> Result<Self, GroupError> {
        let kind = event.kind;
        if !(9_000..=9_020).contains(&kind.as_u16()) {
            return Err(GroupError::WrongKind(kind));
        }
        let group_id = h_tag_value(event)
            .ok_or(GroupError::MissingGroupRef)?
            .to_owned();
        let action = parse_moderation_kind(event)?;
        let mut extra_tags: Vec<Tag> = Vec::new();
        for tag in &event.tags {
            if !is_canonical_moderation_tag(tag, &action) {
                extra_tags.push(tag.clone());
            }
        }
        Ok(Self {
            reason: event.content.clone(),
            group: GroupRef {
                id: group_id,
                previous: previous_from_event(event),
            },
            action,
            extra_tags,
        })
    }
}

fn is_canonical_moderation_tag(tag: &Tag, action: &ModerationKind) -> bool {
    matches!(
        (tag.name(), action),
        (H_TAG | PREVIOUS_TAG, _)
            | (
                "p",
                ModerationKind::PutUser { .. } | ModerationKind::RemoveUser(_)
            )
            | ("e", ModerationKind::DeleteEvent(_))
            | (CODE_TAG, ModerationKind::CreateInvite { .. })
            | (
                NAME_TAG
                    | PICTURE_TAG
                    | ABOUT_TAG
                    | PRIVATE_TAG
                    | RESTRICTED_TAG
                    | HIDDEN_TAG
                    | CLOSED_TAG,
                ModerationKind::EditMetadata(_)
            )
    )
}

fn parse_moderation_kind(event: &Event) -> Result<ModerationKind, GroupError> {
    match event.kind {
        KIND_GROUP_PUT_USER => {
            let tag = event
                .tags
                .iter()
                .find(|t| matches!(t.kind(), TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::P))
                .ok_or(GroupError::MissingPubkey)?;
            let pk_hex = tag.get(1).ok_or(GroupError::MissingPubkey)?;
            let pubkey = PublicKey::parse(pk_hex)?;
            let roles = tag.values().iter().skip(2).cloned().collect();
            Ok(ModerationKind::PutUser { pubkey, roles })
        }
        KIND_GROUP_REMOVE_USER => {
            let tag = event
                .tags
                .iter()
                .find(|t| matches!(t.kind(), TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::P))
                .ok_or(GroupError::MissingPubkey)?;
            let pk_hex = tag.get(1).ok_or(GroupError::MissingPubkey)?;
            Ok(ModerationKind::RemoveUser(PublicKey::parse(pk_hex)?))
        }
        KIND_GROUP_EDIT_METADATA => Ok(ModerationKind::EditMetadata(parse_metadata_patch(event)?)),
        KIND_GROUP_DELETE_EVENT => {
            let tag = event
                .tags
                .iter()
                .find(|t| matches!(t.kind(), TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::E))
                .ok_or(GroupError::MissingEvent)?;
            let id_hex = tag.get(1).ok_or(GroupError::MissingEvent)?;
            Ok(ModerationKind::DeleteEvent(EventId::parse(id_hex)?))
        }
        KIND_GROUP_CREATE => Ok(ModerationKind::CreateGroup),
        KIND_GROUP_DELETE => Ok(ModerationKind::DeleteGroup),
        KIND_GROUP_CREATE_INVITE => {
            let code = event
                .tags
                .iter()
                .find(|t| t.name() == CODE_TAG)
                .and_then(|t| t.get(1))
                .ok_or(GroupError::MissingCode)?
                .to_owned();
            Ok(ModerationKind::CreateInvite { code })
        }
        other => Ok(ModerationKind::Custom {
            kind: other,
            tags: event
                .tags
                .iter()
                .filter(|t| t.name() != H_TAG && t.name() != PREVIOUS_TAG)
                .cloned()
                .collect(),
        }),
    }
}

fn parse_metadata_patch(event: &Event) -> Result<GroupMetadataPatch, GroupError> {
    let mut out = GroupMetadataPatch::default();
    for tag in &event.tags {
        match tag.name() {
            NAME_TAG => out.name = tag.get(1).map(str::to_owned),
            PICTURE_TAG => {
                if let Some(raw) = tag.get(1) {
                    out.picture = Some(Url::parse(raw)?);
                }
            }
            ABOUT_TAG => out.about = tag.get(1).map(str::to_owned),
            PRIVATE_TAG => out.flags |= GroupFlags::PRIVATE,
            RESTRICTED_TAG => out.flags |= GroupFlags::RESTRICTED,
            HIDDEN_TAG => out.flags |= GroupFlags::HIDDEN,
            CLOSED_TAG => out.flags |= GroupFlags::CLOSED,
            _ => {}
        }
    }
    Ok(out)
}


impl GroupMetadata {
    /// Build the addressable coordinate for this metadata.
    #[must_use]
    pub fn coordinate(&self, author: PublicKey) -> Coordinate {
        Coordinate::new(KIND_GROUP_METADATA, author, self.identifier.clone())
    }

    /// Parse a `kind: 39000` group-metadata event.
    ///
    /// # Errors
    ///
    /// See [`GroupError`] for the failure modes.
    pub fn from_event(event: &Event) -> Result<Self, GroupError> {
        if event.kind != KIND_GROUP_METADATA {
            return Err(GroupError::WrongKind(event.kind));
        }
        let identifier = d_tag_value(event)
            .ok_or(GroupError::MissingIdentifier)?
            .to_owned();
        let patch = parse_metadata_patch(event)?;
        let extra_tags = event
            .tags
            .iter()
            .filter(|tag| {
                let name = tag.name();
                name != "d"
                    && name != NAME_TAG
                    && name != PICTURE_TAG
                    && name != ABOUT_TAG
                    && name != PRIVATE_TAG
                    && name != RESTRICTED_TAG
                    && name != HIDDEN_TAG
                    && name != CLOSED_TAG
            })
            .cloned()
            .collect();
        Ok(Self {
            identifier,
            name: patch.name,
            picture: patch.picture,
            about: patch.about,
            flags: patch.flags,
            extra_tags,
        })
    }
}

impl GroupAdmins {
    /// Parse a `kind: 39001` group-admins event.
    ///
    /// # Errors
    ///
    /// See [`GroupError`] for the failure modes.
    pub fn from_event(event: &Event) -> Result<Self, GroupError> {
        if event.kind != KIND_GROUP_ADMINS {
            return Err(GroupError::WrongKind(event.kind));
        }
        let identifier = d_tag_value(event)
            .ok_or(GroupError::MissingIdentifier)?
            .to_owned();
        let mut admins: Vec<GroupAdminEntry> = Vec::new();
        let mut extra_tags: Vec<Tag> = Vec::new();
        for tag in &event.tags {
            match tag.kind() {
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::P => {
                    let pk_hex = tag.get(1).ok_or(GroupError::MissingPubkey)?;
                    let pubkey = PublicKey::parse(pk_hex)?;
                    let roles = tag.values().iter().skip(2).cloned().collect();
                    admins.push(GroupAdminEntry { pubkey, roles });
                }
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::D => {}
                _ => extra_tags.push(tag.clone()),
            }
        }
        Ok(Self {
            identifier,
            content: event.content.clone(),
            admins,
            extra_tags,
        })
    }
}

impl GroupMembers {
    /// Parse a `kind: 39002` group-members event.
    ///
    /// # Errors
    ///
    /// See [`GroupError`] for the failure modes.
    pub fn from_event(event: &Event) -> Result<Self, GroupError> {
        if event.kind != KIND_GROUP_MEMBERS {
            return Err(GroupError::WrongKind(event.kind));
        }
        let identifier = d_tag_value(event)
            .ok_or(GroupError::MissingIdentifier)?
            .to_owned();
        let mut members: Vec<PublicKey> = Vec::new();
        let mut extra_tags: Vec<Tag> = Vec::new();
        for tag in &event.tags {
            match tag.kind() {
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::P => {
                    let pk_hex = tag.get(1).ok_or(GroupError::MissingPubkey)?;
                    members.push(PublicKey::parse(pk_hex)?);
                }
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::D => {}
                _ => extra_tags.push(tag.clone()),
            }
        }
        Ok(Self {
            identifier,
            content: event.content.clone(),
            members,
            extra_tags,
        })
    }
}

impl GroupRoles {
    /// Parse a `kind: 39003` group-roles event.
    ///
    /// # Errors
    ///
    /// See [`GroupError`] for the failure modes.
    pub fn from_event(event: &Event) -> Result<Self, GroupError> {
        if event.kind != KIND_GROUP_ROLES {
            return Err(GroupError::WrongKind(event.kind));
        }
        let identifier = d_tag_value(event)
            .ok_or(GroupError::MissingIdentifier)?
            .to_owned();
        let mut roles: Vec<GroupRole> = Vec::new();
        let mut extra_tags: Vec<Tag> = Vec::new();
        for tag in &event.tags {
            match tag.name() {
                ROLE_TAG => {
                    let name = tag.get(1).ok_or(GroupError::MissingPubkey)?.to_owned();
                    let description = tag.get(2).map(str::to_owned);
                    roles.push(GroupRole { name, description });
                }
                "d" => {}
                _ => extra_tags.push(tag.clone()),
            }
        }
        Ok(Self {
            identifier,
            content: event.content.clone(),
            roles,
            extra_tags,
        })
    }
}


impl EventBuilder {
    /// Author a NIP-29 `kind: 9021` join request.
    #[must_use]
    pub fn group_join_request(req: &JoinRequest) -> Self {
        let mut builder = Self::new(KIND_GROUP_JOIN_REQUEST, req.reason.clone());
        for tag in group_ref_tag(&req.group) {
            builder = builder.tag(tag);
        }
        if let Some(code) = &req.code {
            builder = builder.tag(Tag::with(&TagKind::from_wire(CODE_TAG), [code.clone()]));
        }
        for tag in &req.extra_tags {
            builder = builder.tag(tag.clone());
        }
        builder
    }

    /// Author a NIP-29 `kind: 9022` leave request.
    #[must_use]
    pub fn group_leave_request(req: &LeaveRequest) -> Self {
        let mut builder = Self::new(KIND_GROUP_LEAVE_REQUEST, req.reason.clone());
        for tag in group_ref_tag(&req.group) {
            builder = builder.tag(tag);
        }
        for tag in &req.extra_tags {
            builder = builder.tag(tag.clone());
        }
        builder
    }

    /// Author a NIP-29 moderation event.
    #[must_use]
    pub fn group_moderation(action: &ModerationAction) -> Self {
        let kind = match &action.action {
            ModerationKind::PutUser { .. } => KIND_GROUP_PUT_USER,
            ModerationKind::RemoveUser(_) => KIND_GROUP_REMOVE_USER,
            ModerationKind::EditMetadata(_) => KIND_GROUP_EDIT_METADATA,
            ModerationKind::DeleteEvent(_) => KIND_GROUP_DELETE_EVENT,
            ModerationKind::CreateGroup => KIND_GROUP_CREATE,
            ModerationKind::DeleteGroup => KIND_GROUP_DELETE,
            ModerationKind::CreateInvite { .. } => KIND_GROUP_CREATE_INVITE,
            ModerationKind::Custom { kind, .. } => *kind,
        };
        let mut builder = Self::new(kind, action.reason.clone());
        for tag in group_ref_tag(&action.group) {
            builder = builder.tag(tag);
        }
        match &action.action {
            ModerationKind::PutUser { pubkey, roles } => {
                let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::P));
                let mut cols = vec![pubkey.to_hex()];
                cols.extend(roles.iter().cloned());
                builder = builder.tag(Tag::with(&head, cols));
            }
            ModerationKind::RemoveUser(pubkey) => {
                builder = builder.tag(Tag::p(*pubkey));
            }
            ModerationKind::EditMetadata(patch) => metadata_apply_flags(&mut builder, patch),
            ModerationKind::DeleteEvent(id) => builder = builder.tag(Tag::e(*id)),
            ModerationKind::CreateGroup | ModerationKind::DeleteGroup => {}
            ModerationKind::CreateInvite { code } => {
                builder = builder.tag(Tag::with(&TagKind::from_wire(CODE_TAG), [code.clone()]));
            }
            ModerationKind::Custom { tags, .. } => {
                for tag in tags {
                    builder = builder.tag(tag.clone());
                }
            }
        }
        for tag in &action.extra_tags {
            builder = builder.tag(tag.clone());
        }
        builder
    }

    /// Author a NIP-29 `kind: 39000` group-metadata event.
    #[must_use]
    pub fn group_metadata(metadata: &GroupMetadata) -> Self {
        let mut builder = Self::new(KIND_GROUP_METADATA, "");
        builder = builder.tag(Tag::d(&metadata.identifier));
        let patch = GroupMetadataPatch {
            name: metadata.name.clone(),
            picture: metadata.picture.clone(),
            about: metadata.about.clone(),
            flags: metadata.flags,
        };
        metadata_apply_flags(&mut builder, &patch);
        for tag in &metadata.extra_tags {
            builder = builder.tag(tag.clone());
        }
        builder
    }

    /// Author a NIP-29 `kind: 39001` group-admins event.
    #[must_use]
    pub fn group_admins(admins: &GroupAdmins) -> Self {
        let mut builder = Self::new(KIND_GROUP_ADMINS, admins.content.clone());
        builder = builder.tag(Tag::d(&admins.identifier));
        for entry in &admins.admins {
            let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::P));
            let mut cols = vec![entry.pubkey.to_hex()];
            cols.extend(entry.roles.iter().cloned());
            builder = builder.tag(Tag::with(&head, cols));
        }
        for tag in &admins.extra_tags {
            builder = builder.tag(tag.clone());
        }
        builder
    }

    /// Author a NIP-29 `kind: 39002` group-members event.
    #[must_use]
    pub fn group_members(members: &GroupMembers) -> Self {
        let mut builder = Self::new(KIND_GROUP_MEMBERS, members.content.clone());
        builder = builder.tag(Tag::d(&members.identifier));
        for pubkey in &members.members {
            builder = builder.tag(Tag::p(*pubkey));
        }
        for tag in &members.extra_tags {
            builder = builder.tag(tag.clone());
        }
        builder
    }

    /// Author a NIP-29 `kind: 39003` group-roles event.
    #[must_use]
    pub fn group_roles(roles: &GroupRoles) -> Self {
        let mut builder = Self::new(KIND_GROUP_ROLES, roles.content.clone());
        builder = builder.tag(Tag::d(&roles.identifier));
        for role in &roles.roles {
            let head = TagKind::from_wire(ROLE_TAG);
            let cols = role.description.as_ref().map_or_else(
                || vec![role.name.clone()],
                |desc| vec![role.name.clone(), desc.clone()],
            );
            builder = builder.tag(Tag::with(&head, cols));
        }
        for tag in &roles.extra_tags {
            builder = builder.tag(tag.clone());
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
    fn group_id_parse_and_render() {
        let g = GroupId::parse("groups.example.com'pizzalovers").unwrap();
        assert_eq!(g.host, "groups.example.com");
        assert_eq!(g.id, "pizzalovers");
        assert_eq!(g.to_wire(), "groups.example.com'pizzalovers");

        let local = GroupId::parse("groups.example.com").unwrap();
        assert_eq!(local.id, RELAY_LOCAL_GROUP);
        assert_eq!(local.to_wire(), "groups.example.com");
    }

    #[test]
    fn group_id_invalid_chars() {
        assert!(matches!(
            GroupId::parse("groups.example.com'BAD ID"),
            Err(GroupIdError::InvalidId(_))
        ));
    }

    #[test]
    fn join_request_round_trip() {
        let req = JoinRequest {
            reason: "please".into(),
            group: GroupRef::new("pizzalovers"),
            code: Some("invite-1".into()),
            extra_tags: Vec::new(),
        };
        let event = EventBuilder::group_join_request(&req)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = JoinRequest::from_event(&event).unwrap();
        assert_eq!(parsed, req);
    }

    #[test]
    fn put_user_moderation_round_trip() {
        let action = ModerationAction {
            reason: "promotion".into(),
            group: GroupRef::new("pizzalovers"),
            action: ModerationKind::PutUser {
                pubkey: *keys().public_key(),
                roles: vec!["ceo".into()],
            },
            extra_tags: Vec::new(),
        };
        let event = EventBuilder::group_moderation(&action)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = ModerationAction::from_event(&event).unwrap();
        assert_eq!(parsed.group.id, "pizzalovers");
        match parsed.action {
            ModerationKind::PutUser { pubkey, roles } => {
                assert_eq!(pubkey, *keys().public_key());
                assert_eq!(roles, vec!["ceo".to_owned()]);
            }
            other => panic!("unexpected moderation kind {other:?}"),
        }
    }

    #[test]
    fn metadata_round_trip() {
        let metadata = GroupMetadata {
            identifier: "pizzalovers".into(),
            name: Some("Pizza Lovers".into()),
            picture: Some(Url::parse("https://pizza.example/icon.png").unwrap()),
            about: Some("a group for pizza fans".into()),
            flags: GroupFlags::PRIVATE | GroupFlags::CLOSED,
            extra_tags: Vec::new(),
        };
        let event = EventBuilder::group_metadata(&metadata)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = GroupMetadata::from_event(&event).unwrap();
        assert_eq!(parsed, metadata);
    }

    #[test]
    fn members_round_trip() {
        let members = GroupMembers {
            identifier: "pizzalovers".into(),
            content: "members".into(),
            members: vec![*keys().public_key()],
            extra_tags: Vec::new(),
        };
        let event = EventBuilder::group_members(&members)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = GroupMembers::from_event(&event).unwrap();
        assert_eq!(parsed, members);
    }

    #[test]
    fn roles_round_trip() {
        let roles = GroupRoles {
            identifier: "pizzalovers".into(),
            content: "roles".into(),
            roles: vec![
                GroupRole {
                    name: "ceo".into(),
                    description: Some("the leader".into()),
                },
                GroupRole {
                    name: "chef".into(),
                    description: None,
                },
            ],
            extra_tags: Vec::new(),
        };
        let event = EventBuilder::group_roles(&roles)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = GroupRoles::from_event(&event).unwrap();
        assert_eq!(parsed, roles);
    }

    #[test]
    fn delete_event_moderation_round_trip() {
        let event_id = EventId::from_byte_array([0x44; 32]);
        let action = ModerationAction {
            reason: "spam".into(),
            group: GroupRef::new("pizzalovers"),
            action: ModerationKind::DeleteEvent(event_id),
            extra_tags: Vec::new(),
        };
        let event = EventBuilder::group_moderation(&action)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = ModerationAction::from_event(&event).unwrap();
        assert_eq!(parsed.action, ModerationKind::DeleteEvent(event_id));
    }
}
