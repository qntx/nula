//! [NIP-53] Live Activities.
//!
//! Five kinds model a range of live / synchronous experiences:
//!
//! | Kind    | Form              | Target use                         |
//! |---------|-------------------|------------------------------------|
//! | `30311` | addressable       | Live streaming event               |
//! | `30312` | addressable       | Meeting space (configuration)      |
//! | `30313` | addressable       | Meeting room (scheduled / ongoing) |
//! | `1311`  | regular           | Live chat message                  |
//! | `10312` | regular-replaceable | Room presence signal            |
//!
//! Shared concepts:
//!
//! - **[`LiveStatus`]** — the spec's `planned`/`live`/`ended`
//!   tri-state plus a forward-compatible `Custom(String)` escape hatch
//!   for producers using extensions (the spec §"Meeting Space" hints at
//!   `open`/`private`/`closed`, which are exposed through
//!   [`SpaceStatus`]).
//! - **[`LiveParticipant`]** — the `p` tag shape (`pubkey`, relay hint,
//!   role marker, optional proof). Spec §"Proof of Agreement to
//!   Participate" pins the 5th column: a SHA-256 of the host's `a`
//!   coordinate signed with each participant's private key.
//!
//! Unknown tags round-trip through the per-bundle `extra_tags` vector.
//!
//! [NIP-53]: https://github.com/nostr-protocol/nips/blob/master/53.md

use thiserror::Error;

use crate::event::{
    Alphabet, Coordinate, CoordinateError, Event, EventBuilder, EventId, EventIdError, Kind,
    SingleLetterTag, Tag, TagKind, Tags,
};
use crate::key::{PublicKey, PublicKeyError};
use crate::types::{RelayUrl, RelayUrlError, Timestamp, TimestampError, Url, UrlError};

/// `kind: 30311` — live streaming event.
pub const KIND_LIVE_STREAM: Kind = Kind::LIVE_STREAM;

/// `kind: 30312` — meeting space event.
pub const KIND_MEETING_SPACE: Kind = Kind::MEETING_SPACE;

/// `kind: 30313` — meeting room event.
pub const KIND_MEETING_ROOM: Kind = Kind::MEETING_ROOM;

/// `kind: 1311` — live chat message.
pub const KIND_LIVE_CHAT: Kind = Kind::LIVE_CHAT_MESSAGE;

/// `kind: 10312` — room presence signal.
pub const KIND_ROOM_PRESENCE: Kind = Kind::ROOM_PRESENCE;

const TITLE_TAG: &str = "title";
const SUMMARY_TAG: &str = "summary";
const IMAGE_TAG: &str = "image";
const STREAMING_TAG: &str = "streaming";
const RECORDING_TAG: &str = "recording";
const STARTS_TAG: &str = "starts";
const ENDS_TAG: &str = "ends";
const STATUS_TAG: &str = "status";
const CURRENT_PARTICIPANTS_TAG: &str = "current_participants";
const TOTAL_PARTICIPANTS_TAG: &str = "total_participants";
const PINNED_TAG: &str = "pinned";
const RELAYS_TAG: &str = "relays";
const ROOM_TAG: &str = "room";
const SERVICE_TAG: &str = "service";
const ENDPOINT_TAG: &str = "endpoint";
const HAND_TAG: &str = "hand";

/// Spec-defined wire tokens for the live-event `status` column
/// (`30311` / `30313`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LiveStatus {
    /// `planned`.
    Planned,
    /// `live`.
    Live,
    /// `ended`.
    Ended,
    /// Forward-compatible passthrough for unknown tokens.
    Custom(String),
}

impl LiveStatus {
    /// Wire token.
    #[must_use]
    #[expect(
        clippy::missing_const_for_fn,
        reason = "`Self::Custom` borrows from a heap `String`"
    )]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Planned => "planned",
            Self::Live => "live",
            Self::Ended => "ended",
            Self::Custom(s) => s.as_str(),
        }
    }

    /// Parse a wire token. Always succeeds: unknown tokens decode
    /// as [`Self::Custom`].
    #[must_use]
    pub fn parse(token: &str) -> Self {
        match token {
            "planned" => Self::Planned,
            "live" => Self::Live,
            "ended" => Self::Ended,
            _ => Self::Custom(token.to_owned()),
        }
    }
}

/// Spec-defined wire tokens for the meeting-space `status` column
/// (`30312`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SpaceStatus {
    /// `open` — the space is accepting participants.
    Open,
    /// `private` — the space is access-controlled.
    Private,
    /// `closed` — the space is not in operation.
    Closed,
    /// Forward-compatible passthrough for unknown tokens.
    Custom(String),
}

impl SpaceStatus {
    /// Wire token.
    #[must_use]
    #[expect(
        clippy::missing_const_for_fn,
        reason = "`Self::Custom` borrows from a heap `String`"
    )]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Open => "open",
            Self::Private => "private",
            Self::Closed => "closed",
            Self::Custom(s) => s.as_str(),
        }
    }

    /// Parse a wire token.
    #[must_use]
    pub fn parse(token: &str) -> Self {
        match token {
            "open" => Self::Open,
            "private" => Self::Private,
            "closed" => Self::Closed,
            _ => Self::Custom(token.to_owned()),
        }
    }
}

/// A `p` participant tag on a live / meeting event. Model shared by
/// all four host-side kinds (`30311`, `30312`, `30313`) and the
/// `10312` presence row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveParticipant {
    /// Participant pubkey.
    pub pubkey: PublicKey,
    /// Optional recommended relay URL.
    pub relay_hint: Option<RelayUrl>,
    /// Display role marker (`Host`, `Speaker`, `Moderator`, custom).
    pub role: Option<String>,
    /// Optional proof column: SHA-256 of the host event's
    /// addressable coordinate signed with the participant's private
    /// key (spec §"Proof of Agreement to Participate").
    pub proof: Option<String>,
}

impl LiveParticipant {
    /// Construct a participant with no relay hint, role, or proof.
    #[must_use]
    pub const fn new(pubkey: PublicKey) -> Self {
        Self {
            pubkey,
            relay_hint: None,
            role: None,
            proof: None,
        }
    }

    /// Attach a relay hint.
    #[must_use]
    pub fn relay_hint(mut self, relay: RelayUrl) -> Self {
        self.relay_hint = Some(relay);
        self
    }

    /// Attach a display role.
    #[must_use]
    pub fn role(mut self, role: impl Into<String>) -> Self {
        self.role = Some(role.into());
        self
    }

    /// Attach a participation proof.
    #[must_use]
    pub fn proof(mut self, proof: impl Into<String>) -> Self {
        self.proof = Some(proof.into());
        self
    }

    /// Render as a `p` tag.
    #[must_use]
    pub fn to_tag(&self) -> Tag {
        let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::P));
        let relay = self
            .relay_hint
            .as_ref()
            .map_or_else(String::new, |r| r.as_str().to_owned());
        match (&self.role, &self.proof) {
            (Some(role), Some(proof)) => Tag::with(
                &head,
                [self.pubkey.to_hex(), relay, role.clone(), proof.clone()],
            ),
            (Some(role), None) => Tag::with(&head, [self.pubkey.to_hex(), relay, role.clone()]),
            (None, _) if self.relay_hint.is_some() => {
                Tag::with(&head, [self.pubkey.to_hex(), relay])
            }
            _ => Tag::with(&head, [self.pubkey.to_hex()]),
        }
    }

    /// Parse a `p` tag.
    ///
    /// # Errors
    ///
    /// - [`LiveError::MalformedParticipant`] when column 1 is
    ///   absent.
    /// - Wrapped [`PublicKeyError`] / [`RelayUrlError`] for invalid
    ///   values.
    pub fn from_tag(tag: &Tag) -> Result<Self, LiveError> {
        let pk_hex = tag.get(1).ok_or(LiveError::MalformedParticipant)?;
        let pubkey = PublicKey::parse(pk_hex)?;
        let relay_hint = match tag.get(2) {
            Some(s) if !s.is_empty() => Some(RelayUrl::parse(s)?),
            _ => None,
        };
        let role = tag.get(3).filter(|s| !s.is_empty()).map(str::to_owned);
        let proof = tag.get(4).filter(|s| !s.is_empty()).map(str::to_owned);
        Ok(Self {
            pubkey,
            relay_hint,
            role,
            proof,
        })
    }
}

/// Typed bundle for a `kind: 30311` live streaming event.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LiveStream {
    /// `d` identifier.
    pub identifier: String,
    /// `title`.
    pub title: Option<String>,
    /// `summary`.
    pub summary: Option<String>,
    /// `image` preview URL.
    pub image: Option<Url>,
    /// `streaming` URL.
    pub streaming_url: Option<Url>,
    /// `recording` URL (posted once the activity ends).
    pub recording_url: Option<Url>,
    /// `starts` Unix timestamp.
    pub starts: Option<Timestamp>,
    /// `ends` Unix timestamp.
    pub ends: Option<Timestamp>,
    /// `status`.
    pub status: Option<LiveStatus>,
    /// `current_participants` count.
    pub current_participants: Option<u64>,
    /// `total_participants` count.
    pub total_participants: Option<u64>,
    /// `p` participants.
    pub participants: Vec<LiveParticipant>,
    /// `t` hashtags (lower-cased).
    pub hashtags: Vec<String>,
    /// `relays` recommendations.
    pub relays: Vec<RelayUrl>,
    /// `pinned` live-chat message event ids.
    pub pinned: Vec<EventId>,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

/// Typed bundle for a `kind: 30312` meeting space event.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MeetingSpace {
    /// `d` identifier.
    pub identifier: String,
    /// `room` display name (required).
    pub room: Option<String>,
    /// `summary`.
    pub summary: Option<String>,
    /// `image` preview URL.
    pub image: Option<Url>,
    /// `status` (`open`/`private`/`closed`).
    pub status: Option<SpaceStatus>,
    /// `service` URL (required per spec).
    pub service_url: Option<Url>,
    /// Optional `endpoint` URL.
    pub endpoint_url: Option<Url>,
    /// `t` hashtags (lower-cased).
    pub hashtags: Vec<String>,
    /// `p` participants (at least one MUST hold `Host` role).
    pub participants: Vec<LiveParticipant>,
    /// `relays` recommendations.
    pub relays: Vec<RelayUrl>,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

/// Typed bundle for a `kind: 30313` meeting room event (scheduled
/// session within a space).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MeetingRoom {
    /// `d` identifier.
    pub identifier: String,
    /// Parent `30312` space coordinate (required `a` tag).
    pub space: Option<Coordinate>,
    /// Optional relay hint for the parent space.
    pub space_relay_hint: Option<RelayUrl>,
    /// `title` (required).
    pub title: Option<String>,
    /// `summary`.
    pub summary: Option<String>,
    /// `image` preview URL.
    pub image: Option<Url>,
    /// `starts` Unix timestamp (required).
    pub starts: Option<Timestamp>,
    /// `ends` Unix timestamp.
    pub ends: Option<Timestamp>,
    /// `status` (required).
    pub status: Option<LiveStatus>,
    /// `total_participants` count.
    pub total_participants: Option<u64>,
    /// `current_participants` count.
    pub current_participants: Option<u64>,
    /// `p` participants.
    pub participants: Vec<LiveParticipant>,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

/// Typed bundle for a `kind: 1311` live chat message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveChatMessage {
    /// `.content` body.
    pub content: String,
    /// Required `a` tag pointing at the host event (30311 / 30313 /
    /// 30312).
    pub host: Coordinate,
    /// Optional relay hint for the host coordinate.
    pub host_relay_hint: Option<RelayUrl>,
    /// Optional thread-marker on the host `a` tag (`root`, etc).
    pub host_marker: Option<String>,
    /// Optional `e` tag pointing at the parent chat message.
    pub parent_id: Option<EventId>,
    /// Optional relay hint for [`Self::parent_id`].
    pub parent_id_relay_hint: Option<RelayUrl>,
    /// Optional `q` tag (NIP-21 citation).
    pub quote_id: Option<EventId>,
    /// Optional relay hint for [`Self::quote_id`].
    pub quote_id_relay_hint: Option<RelayUrl>,
    /// Optional quoted-event author pubkey (4th column of `q`).
    pub quote_author: Option<PublicKey>,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

/// Typed bundle for a `kind: 10312` room presence signal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomPresence {
    /// Required `a` tag referencing the room/space.
    pub room: Coordinate,
    /// Optional relay hint.
    pub room_relay_hint: Option<RelayUrl>,
    /// Optional thread-marker on the `a` tag (`root`, etc).
    pub room_marker: Option<String>,
    /// Whether the `hand` flag is raised (spec example).
    pub hand_raised: bool,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

/// Errors raised by NIP-53 parsers.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LiveError {
    /// Event kind is not one of the NIP-53 kinds.
    #[error("unexpected kind for NIP-53 event: {}", .0.as_u16())]
    WrongKind(Kind),
    /// `d` tag is absent on an addressable kind.
    #[error("NIP-53 event missing `d` tag")]
    MissingIdentifier,
    /// `a` tag is absent on a kind that requires it
    /// (`1311`, `10312`, `30313`).
    #[error("NIP-53 event missing required `a` tag")]
    MissingAddress,
    /// `p` tag is missing the pubkey column.
    #[error("`p` participant tag missing pubkey")]
    MalformedParticipant,
    /// Numeric tag (`current_participants`, `total_participants`,
    /// `starts`, `ends`) failed to parse.
    #[error("invalid numeric tag `{tag}` value `{value}`")]
    InvalidNumber {
        /// Name of the offending tag.
        tag: String,
        /// Raw string value that failed to parse.
        value: String,
    },
    /// Wrapped pubkey parser error.
    #[error(transparent)]
    InvalidPublicKey(#[from] PublicKeyError),
    /// Wrapped relay-URL parser error.
    #[error(transparent)]
    InvalidRelayUrl(#[from] RelayUrlError),
    /// Wrapped URL parser error.
    #[error(transparent)]
    InvalidUrl(#[from] UrlError),
    /// Wrapped timestamp parser error.
    #[error(transparent)]
    InvalidTimestamp(#[from] TimestampError),
    /// Wrapped event-id parser error.
    #[error(transparent)]
    InvalidEventId(#[from] EventIdError),
    /// Wrapped coordinate parser error.
    #[error(transparent)]
    InvalidCoordinate(#[from] CoordinateError),
}

// -----------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------

fn parse_u64(tag: &str, value: &str) -> Result<u64, LiveError> {
    value.parse::<u64>().map_err(|_| LiveError::InvalidNumber {
        tag: tag.to_owned(),
        value: value.to_owned(),
    })
}

fn parse_relay_hint(raw: Option<&str>) -> Result<Option<RelayUrl>, RelayUrlError> {
    match raw {
        Some(s) if !s.is_empty() => RelayUrl::parse(s).map(Some),
        _ => Ok(None),
    }
}

fn parse_coordinate_tag(
    tag: &Tag,
) -> Result<(Coordinate, Option<RelayUrl>, Option<String>), LiveError> {
    let coord_str = tag.get(1).ok_or(LiveError::MissingAddress)?;
    let coordinate = Coordinate::parse(coord_str)?;
    let relay_hint = parse_relay_hint(tag.get(2))?;
    let marker = tag.get(3).filter(|s| !s.is_empty()).map(str::to_owned);
    Ok((coordinate, relay_hint, marker))
}

fn parse_event_ref(tag: &Tag) -> Result<(EventId, Option<RelayUrl>), LiveError> {
    let id_hex = tag.get(1).ok_or(LiveError::MissingAddress)?;
    let id = EventId::parse(id_hex)?;
    let relay_hint = parse_relay_hint(tag.get(2))?;
    Ok((id, relay_hint))
}

fn coordinate_tag(coord: &Coordinate, relay: Option<&RelayUrl>, marker: Option<&str>) -> Tag {
    let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::A));
    let relay_str = relay.map_or_else(String::new, |r| r.as_str().to_owned());
    match marker {
        Some(m) => Tag::with(&head, [coord.to_wire(), relay_str, m.to_owned()]),
        None if relay.is_some() => Tag::with(&head, [coord.to_wire(), relay_str]),
        None => Tag::with(&head, [coord.to_wire()]),
    }
}

fn event_ref_tag(id: EventId, relay: Option<&RelayUrl>) -> Tag {
    let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::E));
    relay.map_or_else(
        || Tag::with(&head, [id.to_hex()]),
        |r| Tag::with(&head, [id.to_hex(), r.as_str().to_owned()]),
    )
}

fn d_value(tags: &Tags) -> Option<&str> {
    let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::D));
    tags.find_first(&head).and_then(|tag| tag.get(1))
}

// -----------------------------------------------------------------
// Parsing: LiveStream (30311)
// -----------------------------------------------------------------

impl LiveStream {
    /// Construct a stream with the identifier seeded.
    #[must_use]
    pub fn new(identifier: impl Into<String>) -> Self {
        Self {
            identifier: identifier.into(),
            ..Self::default()
        }
    }

    /// Build the stream's addressable coordinate.
    #[must_use]
    pub fn coordinate(&self, author: PublicKey) -> Coordinate {
        Coordinate::new(KIND_LIVE_STREAM, author, self.identifier.clone())
    }

    /// Parse a `kind: 30311` event.
    ///
    /// # Errors
    ///
    /// See [`LiveError`] for the failure modes.
    pub fn from_event(event: &Event) -> Result<Self, LiveError> {
        if event.kind != KIND_LIVE_STREAM {
            return Err(LiveError::WrongKind(event.kind));
        }
        let identifier = d_value(&event.tags)
            .ok_or(LiveError::MissingIdentifier)?
            .to_owned();
        let mut out = Self::new(identifier);
        for tag in &event.tags {
            absorb_live_stream_tag(tag, &mut out)?;
        }
        Ok(out)
    }
}

fn absorb_live_stream_tag(tag: &Tag, out: &mut LiveStream) -> Result<(), LiveError> {
    if absorb_live_stream_single_letter(tag, out)? {
        return Ok(());
    }
    let col1 = tag.get(1);
    match tag.name() {
        TITLE_TAG => out.title = col1.map(str::to_owned),
        SUMMARY_TAG => out.summary = col1.map(str::to_owned),
        IMAGE_TAG => absorb_optional_url(col1, &mut out.image)?,
        STREAMING_TAG => absorb_optional_url(col1, &mut out.streaming_url)?,
        RECORDING_TAG => absorb_optional_url(col1, &mut out.recording_url)?,
        STARTS_TAG => absorb_optional_timestamp(col1, &mut out.starts)?,
        ENDS_TAG => absorb_optional_timestamp(col1, &mut out.ends)?,
        STATUS_TAG => out.status = col1.map(LiveStatus::parse),
        CURRENT_PARTICIPANTS_TAG => {
            absorb_optional_u64(
                CURRENT_PARTICIPANTS_TAG,
                col1,
                &mut out.current_participants,
            )?;
        }
        TOTAL_PARTICIPANTS_TAG => {
            absorb_optional_u64(TOTAL_PARTICIPANTS_TAG, col1, &mut out.total_participants)?;
        }
        PINNED_TAG => {
            if let Some(raw) = col1 {
                out.pinned.push(EventId::parse(raw)?);
            }
        }
        RELAYS_TAG => absorb_relay_list(tag, &mut out.relays)?,
        _ => out.extra_tags.push(tag.clone()),
    }
    Ok(())
}

fn absorb_live_stream_single_letter(tag: &Tag, out: &mut LiveStream) -> Result<bool, LiveError> {
    match tag.kind() {
        TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::D => Ok(true),
        TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::P => {
            out.participants.push(LiveParticipant::from_tag(tag)?);
            Ok(true)
        }
        TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::T => {
            if let Some(raw) = tag.get(1) {
                out.hashtags.push(raw.to_ascii_lowercase());
            }
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn absorb_optional_url(col1: Option<&str>, slot: &mut Option<Url>) -> Result<(), LiveError> {
    if let Some(raw) = col1 {
        *slot = Some(Url::parse(raw)?);
    }
    Ok(())
}

fn absorb_optional_timestamp(
    col1: Option<&str>,
    slot: &mut Option<Timestamp>,
) -> Result<(), LiveError> {
    if let Some(raw) = col1 {
        *slot = Some(raw.parse::<Timestamp>()?);
    }
    Ok(())
}

fn absorb_optional_u64(
    name: &str,
    col1: Option<&str>,
    slot: &mut Option<u64>,
) -> Result<(), LiveError> {
    if let Some(raw) = col1 {
        *slot = Some(parse_u64(name, raw)?);
    }
    Ok(())
}

fn absorb_relay_list(tag: &Tag, relays: &mut Vec<RelayUrl>) -> Result<(), LiveError> {
    for raw in tag.values().iter().skip(1) {
        relays.push(RelayUrl::parse(raw)?);
    }
    Ok(())
}

// -----------------------------------------------------------------
// Parsing: MeetingSpace (30312)
// -----------------------------------------------------------------

impl MeetingSpace {
    /// Construct a space with the identifier seeded.
    #[must_use]
    pub fn new(identifier: impl Into<String>) -> Self {
        Self {
            identifier: identifier.into(),
            ..Self::default()
        }
    }

    /// Build the space's addressable coordinate.
    #[must_use]
    pub fn coordinate(&self, author: PublicKey) -> Coordinate {
        Coordinate::new(KIND_MEETING_SPACE, author, self.identifier.clone())
    }

    /// Parse a `kind: 30312` event.
    ///
    /// # Errors
    ///
    /// See [`LiveError`] for the failure modes.
    pub fn from_event(event: &Event) -> Result<Self, LiveError> {
        if event.kind != KIND_MEETING_SPACE {
            return Err(LiveError::WrongKind(event.kind));
        }
        let identifier = d_value(&event.tags)
            .ok_or(LiveError::MissingIdentifier)?
            .to_owned();
        let mut out = Self::new(identifier);
        for tag in &event.tags {
            absorb_meeting_space_tag(tag, &mut out)?;
        }
        Ok(out)
    }
}

fn absorb_meeting_space_tag(tag: &Tag, out: &mut MeetingSpace) -> Result<(), LiveError> {
    match tag.kind() {
        TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::D => {}
        TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::P => {
            out.participants.push(LiveParticipant::from_tag(tag)?);
        }
        TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::T => {
            if let Some(raw) = tag.get(1) {
                out.hashtags.push(raw.to_ascii_lowercase());
            }
        }
        _ => absorb_meeting_space_named_tag(tag, out)?,
    }
    Ok(())
}

fn absorb_meeting_space_named_tag(tag: &Tag, out: &mut MeetingSpace) -> Result<(), LiveError> {
    let col1 = tag.get(1);
    match tag.name() {
        ROOM_TAG => out.room = col1.map(str::to_owned),
        SUMMARY_TAG => out.summary = col1.map(str::to_owned),
        IMAGE_TAG => absorb_optional_url(col1, &mut out.image)?,
        STATUS_TAG => out.status = col1.map(SpaceStatus::parse),
        SERVICE_TAG => absorb_optional_url(col1, &mut out.service_url)?,
        ENDPOINT_TAG => absorb_optional_url(col1, &mut out.endpoint_url)?,
        RELAYS_TAG => absorb_relay_list(tag, &mut out.relays)?,
        _ => out.extra_tags.push(tag.clone()),
    }
    Ok(())
}

// -----------------------------------------------------------------
// Parsing: MeetingRoom (30313)
// -----------------------------------------------------------------

impl MeetingRoom {
    /// Construct a room with the identifier seeded.
    #[must_use]
    pub fn new(identifier: impl Into<String>) -> Self {
        Self {
            identifier: identifier.into(),
            ..Self::default()
        }
    }

    /// Build the room's addressable coordinate.
    #[must_use]
    pub fn coordinate(&self, author: PublicKey) -> Coordinate {
        Coordinate::new(KIND_MEETING_ROOM, author, self.identifier.clone())
    }

    /// Parse a `kind: 30313` event.
    ///
    /// # Errors
    ///
    /// See [`LiveError`] for the failure modes.
    pub fn from_event(event: &Event) -> Result<Self, LiveError> {
        if event.kind != KIND_MEETING_ROOM {
            return Err(LiveError::WrongKind(event.kind));
        }
        let identifier = d_value(&event.tags)
            .ok_or(LiveError::MissingIdentifier)?
            .to_owned();
        let mut out = Self::new(identifier);
        for tag in &event.tags {
            absorb_meeting_room_tag(tag, &mut out)?;
        }
        if out.space.is_none() {
            return Err(LiveError::MissingAddress);
        }
        Ok(out)
    }
}

fn absorb_meeting_room_tag(tag: &Tag, out: &mut MeetingRoom) -> Result<(), LiveError> {
    match tag.kind() {
        TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::D => {}
        TagKind::SingleLetter(s)
            if !s.uppercase && s.character == Alphabet::A && out.space.is_none() =>
        {
            let (coord, relay, _) = parse_coordinate_tag(tag)?;
            out.space = Some(coord);
            out.space_relay_hint = relay;
        }
        TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::P => {
            out.participants.push(LiveParticipant::from_tag(tag)?);
        }
        _ => absorb_meeting_room_named_tag(tag, out)?,
    }
    Ok(())
}

fn absorb_meeting_room_named_tag(tag: &Tag, out: &mut MeetingRoom) -> Result<(), LiveError> {
    let col1 = tag.get(1);
    match tag.name() {
        TITLE_TAG => out.title = col1.map(str::to_owned),
        SUMMARY_TAG => out.summary = col1.map(str::to_owned),
        IMAGE_TAG => absorb_optional_url(col1, &mut out.image)?,
        STARTS_TAG => absorb_optional_timestamp(col1, &mut out.starts)?,
        ENDS_TAG => absorb_optional_timestamp(col1, &mut out.ends)?,
        STATUS_TAG => out.status = col1.map(LiveStatus::parse),
        CURRENT_PARTICIPANTS_TAG => {
            absorb_optional_u64(
                CURRENT_PARTICIPANTS_TAG,
                col1,
                &mut out.current_participants,
            )?;
        }
        TOTAL_PARTICIPANTS_TAG => {
            absorb_optional_u64(TOTAL_PARTICIPANTS_TAG, col1, &mut out.total_participants)?;
        }
        _ => out.extra_tags.push(tag.clone()),
    }
    Ok(())
}

// -----------------------------------------------------------------
// Parsing: LiveChatMessage (1311)
// -----------------------------------------------------------------

impl LiveChatMessage {
    /// Construct a chat message targeted at `host`.
    #[must_use]
    pub fn new(content: impl Into<String>, host: Coordinate) -> Self {
        Self {
            content: content.into(),
            host,
            host_relay_hint: None,
            host_marker: Some("root".to_owned()),
            parent_id: None,
            parent_id_relay_hint: None,
            quote_id: None,
            quote_id_relay_hint: None,
            quote_author: None,
            extra_tags: Vec::new(),
        }
    }

    /// Parse a `kind: 1311` event.
    ///
    /// # Errors
    ///
    /// See [`LiveError`] for the failure modes.
    pub fn from_event(event: &Event) -> Result<Self, LiveError> {
        if event.kind != KIND_LIVE_CHAT {
            return Err(LiveError::WrongKind(event.kind));
        }
        let mut host: Option<(Coordinate, Option<RelayUrl>, Option<String>)> = None;
        let mut parent: Option<(EventId, Option<RelayUrl>)> = None;
        let mut quote: Option<(EventId, Option<RelayUrl>, Option<PublicKey>)> = None;
        let mut extra_tags: Vec<Tag> = Vec::new();
        for tag in &event.tags {
            match tag.kind() {
                TagKind::SingleLetter(s)
                    if !s.uppercase && s.character == Alphabet::A && host.is_none() =>
                {
                    host = Some(parse_coordinate_tag(tag)?);
                }
                TagKind::SingleLetter(s)
                    if !s.uppercase && s.character == Alphabet::E && parent.is_none() =>
                {
                    parent = Some(parse_event_ref(tag)?);
                }
                TagKind::SingleLetter(s)
                    if !s.uppercase && s.character == Alphabet::Q && quote.is_none() =>
                {
                    quote = Some(parse_quote_tag(tag)?);
                }
                _ => extra_tags.push(tag.clone()),
            }
        }
        let (host_coord, host_relay_hint, host_marker) = host.ok_or(LiveError::MissingAddress)?;
        Ok(Self {
            content: event.content.clone(),
            host: host_coord,
            host_relay_hint,
            host_marker,
            parent_id: parent.as_ref().map(|(id, _)| *id),
            parent_id_relay_hint: parent.and_then(|(_, relay)| relay),
            quote_id: quote.as_ref().map(|(id, _, _)| *id),
            quote_id_relay_hint: quote.as_ref().and_then(|(_, relay, _)| relay.clone()),
            quote_author: quote.and_then(|(_, _, pk)| pk),
            extra_tags,
        })
    }
}

fn parse_quote_tag(tag: &Tag) -> Result<(EventId, Option<RelayUrl>, Option<PublicKey>), LiveError> {
    let id_hex = tag.get(1).ok_or(LiveError::MissingAddress)?;
    let id = EventId::parse(id_hex)?;
    let relay_hint = parse_relay_hint(tag.get(2))?;
    let pk = match tag.get(3) {
        Some(s) if !s.is_empty() => Some(PublicKey::parse(s)?),
        _ => None,
    };
    Ok((id, relay_hint, pk))
}

// -----------------------------------------------------------------
// Parsing: RoomPresence (10312)
// -----------------------------------------------------------------

impl RoomPresence {
    /// Construct a presence row targeted at `room`.
    #[must_use]
    pub fn new(room: Coordinate) -> Self {
        Self {
            room,
            room_relay_hint: None,
            room_marker: Some("root".to_owned()),
            hand_raised: false,
            extra_tags: Vec::new(),
        }
    }

    /// Set [`Self::hand_raised`].
    #[must_use]
    pub const fn hand_raised(mut self, raised: bool) -> Self {
        self.hand_raised = raised;
        self
    }

    /// Parse a `kind: 10312` event.
    ///
    /// # Errors
    ///
    /// See [`LiveError`] for the failure modes.
    pub fn from_event(event: &Event) -> Result<Self, LiveError> {
        if event.kind != KIND_ROOM_PRESENCE {
            return Err(LiveError::WrongKind(event.kind));
        }
        let mut room: Option<(Coordinate, Option<RelayUrl>, Option<String>)> = None;
        let mut hand_raised = false;
        let mut extra_tags: Vec<Tag> = Vec::new();
        for tag in &event.tags {
            match tag.kind() {
                TagKind::SingleLetter(s)
                    if !s.uppercase && s.character == Alphabet::A && room.is_none() =>
                {
                    room = Some(parse_coordinate_tag(tag)?);
                }
                _ if tag.name() == HAND_TAG => {
                    hand_raised = tag.get(1).is_some_and(|v| v == "1");
                }
                _ => extra_tags.push(tag.clone()),
            }
        }
        let (room_coord, room_relay_hint, room_marker) = room.ok_or(LiveError::MissingAddress)?;
        Ok(Self {
            room: room_coord,
            room_relay_hint,
            room_marker,
            hand_raised,
            extra_tags,
        })
    }
}

// -----------------------------------------------------------------
// EventBuilder helpers
// -----------------------------------------------------------------

impl EventBuilder {
    /// Author a NIP-53 `kind: 30311` live streaming event.
    #[must_use]
    pub fn live_stream(stream: &LiveStream) -> Self {
        let mut builder = Self::new(KIND_LIVE_STREAM, "");
        builder = builder.tag(Tag::d(&stream.identifier));
        builder = push_option_text_tag(builder, TITLE_TAG, stream.title.as_deref());
        builder = push_option_text_tag(builder, SUMMARY_TAG, stream.summary.as_deref());
        builder = push_option_url_tag(builder, IMAGE_TAG, stream.image.as_ref());
        builder = push_option_url_tag(builder, STREAMING_TAG, stream.streaming_url.as_ref());
        builder = push_option_url_tag(builder, RECORDING_TAG, stream.recording_url.as_ref());
        if let Some(ts) = stream.starts {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(STARTS_TAG),
                [ts.as_secs().to_string()],
            ));
        }
        if let Some(ts) = stream.ends {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(ENDS_TAG),
                [ts.as_secs().to_string()],
            ));
        }
        if let Some(status) = &stream.status {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(STATUS_TAG),
                [status.as_str().to_owned()],
            ));
        }
        if let Some(n) = stream.current_participants {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(CURRENT_PARTICIPANTS_TAG),
                [n.to_string()],
            ));
        }
        if let Some(n) = stream.total_participants {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(TOTAL_PARTICIPANTS_TAG),
                [n.to_string()],
            ));
        }
        for participant in &stream.participants {
            builder = builder.tag(participant.to_tag());
        }
        for hashtag in &stream.hashtags {
            builder = builder.tag(Tag::t(hashtag));
        }
        for id in &stream.pinned {
            builder = builder.tag(Tag::with(&TagKind::from_wire(PINNED_TAG), [id.to_hex()]));
        }
        if !stream.relays.is_empty() {
            builder = builder.tag(relays_tag(&stream.relays));
        }
        for tag in &stream.extra_tags {
            builder = builder.tag(tag.clone());
        }
        builder
    }

    /// Author a NIP-53 `kind: 30312` meeting space event.
    #[must_use]
    pub fn meeting_space(space: &MeetingSpace) -> Self {
        let mut builder = Self::new(KIND_MEETING_SPACE, "");
        builder = builder.tag(Tag::d(&space.identifier));
        builder = push_option_text_tag(builder, ROOM_TAG, space.room.as_deref());
        builder = push_option_text_tag(builder, SUMMARY_TAG, space.summary.as_deref());
        builder = push_option_url_tag(builder, IMAGE_TAG, space.image.as_ref());
        if let Some(status) = &space.status {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(STATUS_TAG),
                [status.as_str().to_owned()],
            ));
        }
        builder = push_option_url_tag(builder, SERVICE_TAG, space.service_url.as_ref());
        builder = push_option_url_tag(builder, ENDPOINT_TAG, space.endpoint_url.as_ref());
        for hashtag in &space.hashtags {
            builder = builder.tag(Tag::t(hashtag));
        }
        for participant in &space.participants {
            builder = builder.tag(participant.to_tag());
        }
        if !space.relays.is_empty() {
            builder = builder.tag(relays_tag(&space.relays));
        }
        for tag in &space.extra_tags {
            builder = builder.tag(tag.clone());
        }
        builder
    }

    /// Author a NIP-53 `kind: 30313` meeting room event.
    ///
    /// # Errors
    ///
    /// Returns [`LiveError::MissingAddress`] when
    /// [`MeetingRoom::space`] is `None`.
    pub fn meeting_room(room: &MeetingRoom) -> Result<Self, LiveError> {
        let space = room.space.as_ref().ok_or(LiveError::MissingAddress)?;
        let mut builder = Self::new(KIND_MEETING_ROOM, "");
        builder = builder.tag(Tag::d(&room.identifier)).tag(coordinate_tag(
            space,
            room.space_relay_hint.as_ref(),
            None,
        ));
        builder = push_option_text_tag(builder, TITLE_TAG, room.title.as_deref());
        builder = push_option_text_tag(builder, SUMMARY_TAG, room.summary.as_deref());
        builder = push_option_url_tag(builder, IMAGE_TAG, room.image.as_ref());
        if let Some(ts) = room.starts {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(STARTS_TAG),
                [ts.as_secs().to_string()],
            ));
        }
        if let Some(ts) = room.ends {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(ENDS_TAG),
                [ts.as_secs().to_string()],
            ));
        }
        if let Some(status) = &room.status {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(STATUS_TAG),
                [status.as_str().to_owned()],
            ));
        }
        if let Some(n) = room.total_participants {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(TOTAL_PARTICIPANTS_TAG),
                [n.to_string()],
            ));
        }
        if let Some(n) = room.current_participants {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(CURRENT_PARTICIPANTS_TAG),
                [n.to_string()],
            ));
        }
        for participant in &room.participants {
            builder = builder.tag(participant.to_tag());
        }
        for tag in &room.extra_tags {
            builder = builder.tag(tag.clone());
        }
        Ok(builder)
    }

    /// Author a NIP-53 `kind: 1311` live chat message.
    #[must_use]
    pub fn live_chat_message(msg: &LiveChatMessage) -> Self {
        let mut builder = Self::new(KIND_LIVE_CHAT, msg.content.clone());
        builder = builder.tag(coordinate_tag(
            &msg.host,
            msg.host_relay_hint.as_ref(),
            msg.host_marker.as_deref(),
        ));
        if let Some(id) = msg.parent_id {
            builder = builder.tag(event_ref_tag(id, msg.parent_id_relay_hint.as_ref()));
        }
        if let Some(id) = msg.quote_id {
            builder = builder.tag(quote_tag(
                id,
                msg.quote_id_relay_hint.as_ref(),
                msg.quote_author,
            ));
        }
        for tag in &msg.extra_tags {
            builder = builder.tag(tag.clone());
        }
        builder
    }

    /// Author a NIP-53 `kind: 10312` room presence signal.
    #[must_use]
    pub fn room_presence(presence: &RoomPresence) -> Self {
        let mut builder = Self::new(KIND_ROOM_PRESENCE, "");
        builder = builder.tag(coordinate_tag(
            &presence.room,
            presence.room_relay_hint.as_ref(),
            presence.room_marker.as_deref(),
        ));
        if presence.hand_raised {
            builder = builder.tag(Tag::with(&TagKind::from_wire(HAND_TAG), ["1"]));
        }
        for tag in &presence.extra_tags {
            builder = builder.tag(tag.clone());
        }
        builder
    }
}

fn push_option_text_tag(
    mut builder: EventBuilder,
    name: &str,
    value: Option<&str>,
) -> EventBuilder {
    if let Some(v) = value {
        builder = builder.tag(Tag::with(&TagKind::from_wire(name), [v.to_owned()]));
    }
    builder
}

fn push_option_url_tag(mut builder: EventBuilder, name: &str, value: Option<&Url>) -> EventBuilder {
    if let Some(v) = value {
        builder = builder.tag(Tag::with(
            &TagKind::from_wire(name),
            [v.as_str().to_owned()],
        ));
    }
    builder
}

fn relays_tag(relays: &[RelayUrl]) -> Tag {
    let mut cols: Vec<String> = Vec::with_capacity(relays.len() + 1);
    cols.push(RELAYS_TAG.to_owned());
    for relay in relays {
        cols.push(relay.as_str().to_owned());
    }
    Tag::new(cols).unwrap_or_else(|_| unreachable!("`cols` always contains the tag head"))
}

fn quote_tag(id: EventId, relay: Option<&RelayUrl>, author: Option<PublicKey>) -> Tag {
    let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::Q));
    let relay_str = relay.map_or_else(String::new, |r| r.as_str().to_owned());
    match author {
        Some(pk) => Tag::with(&head, [id.to_hex(), relay_str, pk.to_hex()]),
        None if relay.is_some() => Tag::with(&head, [id.to_hex(), relay_str]),
        None => Tag::with(&head, [id.to_hex()]),
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
    fn live_stream_round_trip() {
        let stream = LiveStream {
            identifier: "stream-1".into(),
            title: Some("Demo".into()),
            summary: Some("Live demo".into()),
            image: Some(Url::parse("https://example.com/p.jpg").unwrap()),
            streaming_url: Some(Url::parse("https://stream.example.com/live.m3u8").unwrap()),
            recording_url: None,
            starts: Some(Timestamp::from_secs(1_700_000_000)),
            ends: Some(Timestamp::from_secs(1_700_003_600)),
            status: Some(LiveStatus::Live),
            current_participants: Some(12),
            total_participants: Some(100),
            participants: vec![
                LiveParticipant::new(*keys().public_key())
                    .relay_hint(RelayUrl::parse("wss://relay.example/").unwrap())
                    .role("Host")
                    .proof("deadbeef"),
            ],
            hashtags: vec!["music".into()],
            relays: vec![RelayUrl::parse("wss://one.example/").unwrap()],
            pinned: vec![EventId::from_byte_array([0x11; 32])],
            extra_tags: Vec::new(),
        };
        let event = EventBuilder::live_stream(&stream)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = LiveStream::from_event(&event).unwrap();
        assert_eq!(parsed, stream);
    }

    #[test]
    fn meeting_space_round_trip() {
        let space = MeetingSpace {
            identifier: "conf-1".into(),
            room: Some("Main Hall".into()),
            summary: Some("Primary space".into()),
            image: None,
            status: Some(SpaceStatus::Open),
            service_url: Some(Url::parse("https://meet.example.com/hall").unwrap()),
            endpoint_url: Some(Url::parse("https://api.example.com/hall").unwrap()),
            hashtags: vec!["conference".into()],
            participants: vec![LiveParticipant::new(*keys().public_key()).role("Host")],
            relays: vec![RelayUrl::parse("wss://relay.example/").unwrap()],
            extra_tags: Vec::new(),
        };
        let event = EventBuilder::meeting_space(&space)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = MeetingSpace::from_event(&event).unwrap();
        assert_eq!(parsed, space);
    }

    #[test]
    fn meeting_room_round_trip() {
        let space = Coordinate::new(
            KIND_MEETING_SPACE,
            *keys().public_key(),
            "conf-1".to_owned(),
        );
        let room = MeetingRoom {
            identifier: "annual-2025".into(),
            space: Some(space),
            space_relay_hint: Some(RelayUrl::parse("wss://relay.example/").unwrap()),
            title: Some("Annual Meeting".into()),
            summary: Some("Yearly company-wide".into()),
            image: None,
            starts: Some(Timestamp::from_secs(1_700_000_000)),
            ends: Some(Timestamp::from_secs(1_700_003_600)),
            status: Some(LiveStatus::Live),
            total_participants: Some(180),
            current_participants: Some(175),
            participants: Vec::new(),
            extra_tags: Vec::new(),
        };
        let event = EventBuilder::meeting_room(&room)
            .unwrap()
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = MeetingRoom::from_event(&event).unwrap();
        assert_eq!(parsed, room);
    }

    #[test]
    fn meeting_room_missing_space_is_rejected() {
        let room = MeetingRoom::new("no-space");
        assert!(matches!(
            EventBuilder::meeting_room(&room),
            Err(LiveError::MissingAddress)
        ));
    }

    #[test]
    fn live_chat_round_trip() {
        let host = Coordinate::new(
            KIND_LIVE_STREAM,
            *keys().public_key(),
            "stream-1".to_owned(),
        );
        let msg = LiveChatMessage {
            content: "hi".into(),
            host,
            host_relay_hint: Some(RelayUrl::parse("wss://relay.example/").unwrap()),
            host_marker: Some("root".into()),
            parent_id: Some(EventId::from_byte_array([0x22; 32])),
            parent_id_relay_hint: None,
            quote_id: Some(EventId::from_byte_array([0x33; 32])),
            quote_id_relay_hint: Some(RelayUrl::parse("wss://relay2.example/").unwrap()),
            quote_author: Some(*keys().public_key()),
            extra_tags: Vec::new(),
        };
        let event = EventBuilder::live_chat_message(&msg)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = LiveChatMessage::from_event(&event).unwrap();
        assert_eq!(parsed, msg);
    }

    #[test]
    fn room_presence_round_trip() {
        let room = Coordinate::new(
            KIND_MEETING_SPACE,
            *keys().public_key(),
            "room-1".to_owned(),
        );
        let presence = RoomPresence::new(room).hand_raised(true);
        let event = EventBuilder::room_presence(&presence)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = RoomPresence::from_event(&event).unwrap();
        assert_eq!(parsed, presence);
    }

    #[test]
    fn live_status_forward_compatible() {
        assert_eq!(
            LiveStatus::parse("unknown"),
            LiveStatus::Custom("unknown".into())
        );
        assert_eq!(
            SpaceStatus::parse("unknown"),
            SpaceStatus::Custom("unknown".into())
        );
    }

    #[test]
    fn wrong_kind_is_rejected() {
        let event = EventBuilder::text_note("nope")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            LiveStream::from_event(&event),
            Err(LiveError::WrongKind(_))
        ));
        assert!(matches!(
            MeetingSpace::from_event(&event),
            Err(LiveError::WrongKind(_))
        ));
        assert!(matches!(
            MeetingRoom::from_event(&event),
            Err(LiveError::WrongKind(_))
        ));
        assert!(matches!(
            LiveChatMessage::from_event(&event),
            Err(LiveError::WrongKind(_))
        ));
        assert!(matches!(
            RoomPresence::from_event(&event),
            Err(LiveError::WrongKind(_))
        ));
    }
}
