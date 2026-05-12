//! [NIP-52] Calendar Events.
//!
//! Four addressable kinds:
//!
//! - **`kind: 31922` Date-based calendar event** — all-day /
//!   multi-day events. `start` is an ISO-8601 `YYYY-MM-DD` and must
//!   precede the optional `end`.
//! - **`kind: 31923` Time-based calendar event** — spans between
//!   Unix-seconds timestamps, optionally timezone-qualified via
//!   `start_tzid` / `end_tzid`. `D` day-granularity floor timestamps
//!   may repeat for multi-day ranges.
//! - **`kind: 31924` Calendar** — an addressable list of calendar
//!   events (`a` tags pointing at `31922` or `31923` events).
//! - **`kind: 31925` Calendar event RSVP** — response to a specific
//!   calendar event; carries `status` (`accepted`/`declined`/
//!   `tentative`) plus optional `fb` free/busy hint.
//!
//! Common tags shared by both event kinds (`title`, `summary`,
//! `image`, `location` repeated, `g` geohash, `p` participants with
//! role, `t` hashtags, `r` references, and `a` collaborative
//! requests) are modelled uniformly on [`CalendarEventCommon`]. Each
//! kind-specific bundle composes that common struct with its own
//! required columns.
//!
//! # Dates and timestamps
//!
//! - Date-based events use [`CalendarDate`], a newtype over `String`
//!   that validates the `YYYY-MM-DD` shape without pulling in a full
//!   calendar library. Parsing verifies numeric ranges (month
//!   `1..=12`, day `1..=31`) but does not enforce real-month bounds
//!   (e.g. April 31) to stay permissive for malformed producers.
//! - Time-based events reuse [`Timestamp`] for `start`/`end` and
//!   keep `start_tzid` / `end_tzid` as opaque `String`s (IANA zone
//!   identifiers).
//!
//! [NIP-52]: https://github.com/nostr-protocol/nips/blob/master/52.md

use core::{fmt, num::ParseIntError, str::FromStr};

use thiserror::Error;

use crate::event::{
    Alphabet, Coordinate, CoordinateError, Event, EventBuilder, EventId, EventIdError, Kind,
    SingleLetterTag, Tag, TagKind, Tags,
};
use crate::key::{PublicKey, PublicKeyError};
use crate::types::{RelayUrl, RelayUrlError, Timestamp, TimestampError, Url, UrlError};

/// `kind: 31922` — date-based calendar event.
pub const KIND_DATE_EVENT: Kind = Kind::CALENDAR_DATE_EVENT;

/// `kind: 31923` — time-based calendar event.
pub const KIND_TIME_EVENT: Kind = Kind::CALENDAR_TIME_EVENT;

/// `kind: 31924` — calendar.
pub const KIND_CALENDAR: Kind = Kind::CALENDAR;

/// `kind: 31925` — calendar event RSVP.
pub const KIND_RSVP: Kind = Kind::CALENDAR_RSVP;

const TITLE_TAG: &str = "title";
const SUMMARY_TAG: &str = "summary";
const IMAGE_TAG: &str = "image";
const LOCATION_TAG: &str = "location";
const START_TAG: &str = "start";
const END_TAG: &str = "end";
const START_TZID_TAG: &str = "start_tzid";
const END_TZID_TAG: &str = "end_tzid";
const STATUS_TAG: &str = "status";
const FREE_BUSY_TAG: &str = "fb";
const SECONDS_PER_DAY: i64 = 86_400;

/// `YYYY-MM-DD` date string used by date-based calendar events.
///
/// The constructor validates the shape (10 chars, `-` separators,
/// numeric month/day ranges) without pulling in a full calendar
/// crate — producers stay permissive enough to round-trip malformed
/// spec-adjacent content.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CalendarDate(String);

impl CalendarDate {
    /// Parse a `YYYY-MM-DD` string.
    ///
    /// # Errors
    ///
    /// Returns [`CalendarDateError`] when the input does not match
    /// the spec-required shape or has out-of-range columns.
    pub fn parse(input: &str) -> Result<Self, CalendarDateError> {
        if input.len() != 10 {
            return Err(CalendarDateError::WrongLength);
        }
        let bytes = input.as_bytes();
        if bytes.get(4) != Some(&b'-') || bytes.get(7) != Some(&b'-') {
            return Err(CalendarDateError::MissingSeparator);
        }
        let year: u16 = input
            .get(0..4)
            .ok_or(CalendarDateError::WrongLength)?
            .parse()?;
        let month: u8 = input
            .get(5..7)
            .ok_or(CalendarDateError::WrongLength)?
            .parse()?;
        let day: u8 = input
            .get(8..10)
            .ok_or(CalendarDateError::WrongLength)?
            .parse()?;
        if !(1..=12).contains(&month) {
            return Err(CalendarDateError::InvalidMonth(month));
        }
        if !(1..=31).contains(&day) {
            return Err(CalendarDateError::InvalidDay(day));
        }
        // Canonical form: zero-pad components so comparisons sort
        // chronologically without date-library dependencies.
        Ok(Self(format!("{year:04}-{month:02}-{day:02}")))
    }

    /// View as the canonical `YYYY-MM-DD` string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume and yield the canonical string.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for CalendarDate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for CalendarDate {
    type Err = CalendarDateError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

/// Errors raised by [`CalendarDate::parse`].
#[derive(Debug, Error)]
pub enum CalendarDateError {
    /// Input did not contain exactly 10 characters.
    #[error("calendar date must be 10 characters long (`YYYY-MM-DD`)")]
    WrongLength,
    /// `-` separators missing at the expected positions.
    #[error("calendar date must use `-` separators at positions 4 and 7")]
    MissingSeparator,
    /// Month column outside the `1..=12` range.
    #[error("calendar date month out of range: {0}")]
    InvalidMonth(u8),
    /// Day column outside the `1..=31` range.
    #[error("calendar date day out of range: {0}")]
    InvalidDay(u8),
    /// Year / month / day column failed to parse.
    #[error(transparent)]
    InvalidNumber(#[from] ParseIntError),
}

/// A `p` participant tag on a calendar event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Participant {
    /// Participant pubkey.
    pub pubkey: PublicKey,
    /// Optional relay hint column.
    pub relay_hint: Option<RelayUrl>,
    /// Optional display role (`Host`, `Speaker`, …). Free-form per
    /// spec.
    pub role: Option<String>,
}

impl Participant {
    /// Construct a participant with no relay hint or role.
    #[must_use]
    pub const fn new(pubkey: PublicKey) -> Self {
        Self {
            pubkey,
            relay_hint: None,
            role: None,
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

    /// Render as a `p` tag.
    #[must_use]
    pub fn to_tag(&self) -> Tag {
        let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::P));
        let relay = self
            .relay_hint
            .as_ref()
            .map_or_else(String::new, |r| r.as_str().to_owned());
        if let Some(role) = &self.role {
            Tag::with(&head, [self.pubkey.to_hex(), relay, role.clone()])
        } else if self.relay_hint.is_some() {
            Tag::with(&head, [self.pubkey.to_hex(), relay])
        } else {
            Tag::with(&head, [self.pubkey.to_hex()])
        }
    }

    /// Parse a `p` tag into a [`Participant`].
    ///
    /// # Errors
    ///
    /// - [`CalendarError::MalformedParticipant`] when column 1 is
    ///   absent.
    /// - Wrapped [`PublicKeyError`] / [`RelayUrlError`] for invalid
    ///   values.
    pub fn from_tag(tag: &Tag) -> Result<Self, CalendarError> {
        let pk_hex = tag.get(1).ok_or(CalendarError::MalformedParticipant)?;
        let pubkey = PublicKey::parse(pk_hex)?;
        let relay_hint = match tag.get(2) {
            Some(s) if !s.is_empty() => Some(RelayUrl::parse(s)?),
            _ => None,
        };
        let role = tag.get(3).filter(|s| !s.is_empty()).map(str::to_owned);
        Ok(Self {
            pubkey,
            relay_hint,
            role,
        })
    }
}

/// An `a` tag requesting inclusion in a calendar (spec
/// §"Collaborative Calendar Event Requests").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalendarRequest {
    /// Target calendar coordinate.
    pub calendar: Coordinate,
    /// Optional relay hint.
    pub relay_hint: Option<RelayUrl>,
}

/// Fields shared by both date-based and time-based calendar events.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CalendarEventCommon {
    /// Markdown / plain-text description (`.content`).
    pub content: String,
    /// Required `d` identifier.
    pub identifier: String,
    /// Required `title` (per spec).
    pub title: String,
    /// Optional `summary`.
    pub summary: Option<String>,
    /// Optional `image` URL.
    pub image: Option<Url>,
    /// `location` tags (repeated).
    pub locations: Vec<String>,
    /// `g` geohash.
    pub geohash: Option<String>,
    /// `p` participants.
    pub participants: Vec<Participant>,
    /// `t` hashtags (lower-cased).
    pub hashtags: Vec<String>,
    /// `r` references.
    pub references: Vec<Url>,
    /// Collaborative-request `a` tags pointing at parent calendars.
    pub calendar_requests: Vec<CalendarRequest>,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

/// Typed bundle for a `kind: 31922` date-based calendar event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DateCalendarEvent {
    /// Fields common to every calendar event.
    pub common: CalendarEventCommon,
    /// Inclusive start date (required).
    pub start: CalendarDate,
    /// Exclusive end date (optional). If absent, the event ends on
    /// the same day as `start`.
    pub end: Option<CalendarDate>,
}

/// Typed bundle for a `kind: 31923` time-based calendar event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeCalendarEvent {
    /// Fields common to every calendar event.
    pub common: CalendarEventCommon,
    /// Inclusive start Unix timestamp.
    pub start: Timestamp,
    /// Exclusive end Unix timestamp. If absent, the event ends
    /// instantaneously (spec §"Time-Based Calendar Event").
    pub end: Option<Timestamp>,
    /// Optional `start_tzid` IANA time-zone identifier.
    pub start_tzid: Option<String>,
    /// Optional `end_tzid` IANA time-zone identifier.
    pub end_tzid: Option<String>,
}

impl TimeCalendarEvent {
    /// Compute the spec-required `D` day-granularity floor
    /// timestamps spanning `start`..=`end`.
    ///
    /// The spec §"Time-Based Calendar Event" requires
    /// `D = floor(unix_seconds() / seconds_in_one_day)` and multiple
    /// tags to span the range. If `end` is `None`, a single `D` row
    /// is emitted for `start`.
    #[must_use]
    pub fn day_floors(&self) -> Vec<i64> {
        let start_day = i64::try_from(self.start.as_secs())
            .unwrap_or(i64::MAX)
            .div_euclid(SECONDS_PER_DAY);
        let end_day = self.end.map_or(start_day, |e| {
            i64::try_from(e.as_secs())
                .unwrap_or(i64::MAX)
                .div_euclid(SECONDS_PER_DAY)
        });
        if end_day < start_day {
            return vec![start_day];
        }
        (start_day..=end_day).collect()
    }
}

/// `kind: 31924` calendar bundle.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Calendar {
    /// `d` identifier.
    pub identifier: String,
    /// Required `title`.
    pub title: String,
    /// `.content` — calendar description.
    pub content: String,
    /// Event references (`a` tags).
    pub events: Vec<CalendarRequest>,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

/// Spec-defined wire tokens for the RSVP `status` tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RsvpStatus {
    /// `accepted`.
    Accepted,
    /// `declined`.
    Declined,
    /// `tentative`.
    Tentative,
}

impl RsvpStatus {
    /// Wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Declined => "declined",
            Self::Tentative => "tentative",
        }
    }

    /// Parse a wire token.
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        match token {
            "accepted" => Some(Self::Accepted),
            "declined" => Some(Self::Declined),
            "tentative" => Some(Self::Tentative),
            _ => None,
        }
    }
}

/// Spec-defined wire tokens for the RSVP `fb` (free/busy) tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FreeBusy {
    /// `free`.
    Free,
    /// `busy`.
    Busy,
}

impl FreeBusy {
    /// Wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::Busy => "busy",
        }
    }

    /// Parse a wire token.
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        match token {
            "free" => Some(Self::Free),
            "busy" => Some(Self::Busy),
            _ => None,
        }
    }
}

/// `kind: 31925` RSVP bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rsvp {
    /// `d` identifier (unique per RSVP).
    pub identifier: String,
    /// Referenced calendar-event coordinate (`a` tag — required).
    pub event_coordinate: Coordinate,
    /// Optional relay hint for the coordinate.
    pub event_coordinate_relay_hint: Option<RelayUrl>,
    /// Optional specific revision (`e` tag).
    pub event_id: Option<EventId>,
    /// Optional relay hint for the revision.
    pub event_id_relay_hint: Option<RelayUrl>,
    /// Required `status`.
    pub status: RsvpStatus,
    /// Optional `fb` free/busy hint (ignored when
    /// `status == Declined` per spec).
    pub free_busy: Option<FreeBusy>,
    /// Optional `p` tag — author of the referenced event.
    pub event_author: Option<PublicKey>,
    /// Optional relay hint for the author.
    pub event_author_relay_hint: Option<RelayUrl>,
    /// `.content` — free-form note.
    pub content: String,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

/// Errors raised by NIP-52 parsers.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CalendarError {
    /// Unexpected event kind.
    #[error("unexpected kind for NIP-52 event: {}", .0.as_u16())]
    WrongKind(Kind),
    /// `d` tag is absent.
    #[error("NIP-52 event missing `d` tag")]
    MissingIdentifier,
    /// `title` tag is absent.
    #[error("NIP-52 event missing `title` tag")]
    MissingTitle,
    /// `start` tag is absent.
    #[error("NIP-52 event missing `start` tag")]
    MissingStart,
    /// RSVP `a` tag is absent.
    #[error("NIP-52 RSVP missing calendar-event coordinate")]
    MissingRsvpCoordinate,
    /// RSVP `status` tag is absent.
    #[error("NIP-52 RSVP missing `status` tag")]
    MissingRsvpStatus,
    /// `status` token is not one of the spec-defined values.
    #[error("invalid RSVP status: `{0}`")]
    InvalidRsvpStatus(String),
    /// `fb` token is not `free` or `busy`.
    #[error("invalid free/busy value: `{0}`")]
    InvalidFreeBusy(String),
    /// `p` tag is missing the pubkey column.
    #[error("`p` participant tag missing pubkey")]
    MalformedParticipant,
    /// `a` tag is missing the coordinate column.
    #[error("`a` tag missing coordinate")]
    MalformedAddress,
    /// `image` tag is missing the URL column.
    #[error("`image` tag missing URL")]
    MalformedImage,
    /// Wrapped calendar-date parser error.
    #[error(transparent)]
    InvalidCalendarDate(#[from] CalendarDateError),
    /// Wrapped timestamp parser error.
    #[error(transparent)]
    InvalidTimestamp(#[from] TimestampError),
    /// Wrapped pubkey parser error.
    #[error(transparent)]
    InvalidPublicKey(#[from] PublicKeyError),
    /// Wrapped coordinate parser error.
    #[error(transparent)]
    InvalidCoordinate(#[from] CoordinateError),
    /// Wrapped event-id parser error.
    #[error(transparent)]
    InvalidEventId(#[from] EventIdError),
    /// Wrapped URL parser error.
    #[error(transparent)]
    InvalidUrl(#[from] UrlError),
    /// Wrapped relay-URL parser error.
    #[error(transparent)]
    InvalidRelayUrl(#[from] RelayUrlError),
}

// -----------------------------------------------------------------
// Parsing / building: date-based events
// -----------------------------------------------------------------

impl DateCalendarEvent {
    /// Construct a date-based calendar event with the spec-required
    /// columns.
    #[must_use]
    pub fn new(
        identifier: impl Into<String>,
        title: impl Into<String>,
        start: CalendarDate,
    ) -> Self {
        Self {
            common: CalendarEventCommon {
                identifier: identifier.into(),
                title: title.into(),
                ..CalendarEventCommon::default()
            },
            start,
            end: None,
        }
    }

    /// Set the exclusive end date.
    #[must_use]
    pub fn end(mut self, end: CalendarDate) -> Self {
        self.end = Some(end);
        self
    }

    /// Build the event's addressable coordinate.
    #[must_use]
    pub fn coordinate(&self, author: PublicKey) -> Coordinate {
        Coordinate::new(KIND_DATE_EVENT, author, self.common.identifier.clone())
    }

    /// Parse a `kind: 31922` event into a typed bundle.
    ///
    /// # Errors
    ///
    /// See [`CalendarError`] for the failure modes.
    pub fn from_event(event: &Event) -> Result<Self, CalendarError> {
        if event.kind != KIND_DATE_EVENT {
            return Err(CalendarError::WrongKind(event.kind));
        }
        let (common, mut state) = parse_common(event)?;
        let start = state.start_date.take().ok_or(CalendarError::MissingStart)?;
        let end = state.end_date.take();
        Ok(Self { common, start, end })
    }
}

// -----------------------------------------------------------------
// Parsing / building: time-based events
// -----------------------------------------------------------------

impl TimeCalendarEvent {
    /// Construct a time-based calendar event with the spec-required
    /// columns.
    #[must_use]
    pub fn new(identifier: impl Into<String>, title: impl Into<String>, start: Timestamp) -> Self {
        Self {
            common: CalendarEventCommon {
                identifier: identifier.into(),
                title: title.into(),
                ..CalendarEventCommon::default()
            },
            start,
            end: None,
            start_tzid: None,
            end_tzid: None,
        }
    }

    /// Set the exclusive end timestamp.
    #[must_use]
    pub const fn end(mut self, end: Timestamp) -> Self {
        self.end = Some(end);
        self
    }

    /// Set the `start_tzid` IANA identifier.
    #[must_use]
    pub fn start_tzid(mut self, tzid: impl Into<String>) -> Self {
        self.start_tzid = Some(tzid.into());
        self
    }

    /// Set the `end_tzid` IANA identifier.
    #[must_use]
    pub fn end_tzid(mut self, tzid: impl Into<String>) -> Self {
        self.end_tzid = Some(tzid.into());
        self
    }

    /// Build the event's addressable coordinate.
    #[must_use]
    pub fn coordinate(&self, author: PublicKey) -> Coordinate {
        Coordinate::new(KIND_TIME_EVENT, author, self.common.identifier.clone())
    }

    /// Parse a `kind: 31923` event into a typed bundle.
    ///
    /// # Errors
    ///
    /// See [`CalendarError`] for the failure modes.
    pub fn from_event(event: &Event) -> Result<Self, CalendarError> {
        if event.kind != KIND_TIME_EVENT {
            return Err(CalendarError::WrongKind(event.kind));
        }
        let (common, mut state) = parse_common(event)?;
        let start = state.start_ts.take().ok_or(CalendarError::MissingStart)?;
        let end = state.end_ts.take();
        let start_tzid = state.start_tzid.take();
        let end_tzid = state.end_tzid.take();
        Ok(Self {
            common,
            start,
            end,
            start_tzid,
            end_tzid,
        })
    }
}

// -----------------------------------------------------------------
// Parsing / building: calendars
// -----------------------------------------------------------------

impl Calendar {
    /// Construct a calendar with the spec-required columns.
    #[must_use]
    pub fn new(identifier: impl Into<String>, title: impl Into<String>) -> Self {
        Self {
            identifier: identifier.into(),
            title: title.into(),
            content: String::new(),
            events: Vec::new(),
            extra_tags: Vec::new(),
        }
    }

    /// Set the description body.
    #[must_use]
    pub fn content(mut self, content: impl Into<String>) -> Self {
        self.content = content.into();
        self
    }

    /// Append a referenced event.
    #[must_use]
    pub fn event(mut self, request: CalendarRequest) -> Self {
        self.events.push(request);
        self
    }

    /// Build the calendar's addressable coordinate.
    #[must_use]
    pub fn coordinate(&self, author: PublicKey) -> Coordinate {
        Coordinate::new(KIND_CALENDAR, author, self.identifier.clone())
    }

    /// Parse a `kind: 31924` event into a typed bundle.
    ///
    /// # Errors
    ///
    /// See [`CalendarError`] for the failure modes.
    pub fn from_event(event: &Event) -> Result<Self, CalendarError> {
        if event.kind != KIND_CALENDAR {
            return Err(CalendarError::WrongKind(event.kind));
        }
        let identifier = d_value(&event.tags)
            .ok_or(CalendarError::MissingIdentifier)?
            .to_owned();
        let mut out = Self {
            identifier,
            content: event.content.clone(),
            ..Self::default()
        };
        for tag in &event.tags {
            match tag.kind() {
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::D => {}
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::A => {
                    out.events.push(parse_calendar_request(tag)?);
                }
                _ if tag.name() == TITLE_TAG => {
                    out.title = tag.get(1).map(str::to_owned).unwrap_or_default();
                }
                _ => out.extra_tags.push(tag.clone()),
            }
        }
        if out.title.is_empty() {
            return Err(CalendarError::MissingTitle);
        }
        Ok(out)
    }
}

// -----------------------------------------------------------------
// Parsing / building: RSVP
// -----------------------------------------------------------------

impl Rsvp {
    /// Construct an RSVP with the spec-required columns.
    #[must_use]
    pub fn new(
        identifier: impl Into<String>,
        event_coordinate: Coordinate,
        status: RsvpStatus,
    ) -> Self {
        Self {
            identifier: identifier.into(),
            event_coordinate,
            event_coordinate_relay_hint: None,
            event_id: None,
            event_id_relay_hint: None,
            status,
            free_busy: None,
            event_author: None,
            event_author_relay_hint: None,
            content: String::new(),
            extra_tags: Vec::new(),
        }
    }

    /// Attach a free/busy hint.
    ///
    /// Per spec §"Calendar Event RSVP", the `fb` tag is MUST be
    /// omitted when `status == Declined`; this builder doesn't
    /// enforce that — callers should respect the invariant.
    #[must_use]
    pub const fn free_busy(mut self, fb: FreeBusy) -> Self {
        self.free_busy = Some(fb);
        self
    }

    /// Attach the referenced event's author pubkey.
    #[must_use]
    pub const fn event_author(mut self, pubkey: PublicKey) -> Self {
        self.event_author = Some(pubkey);
        self
    }

    /// Attach a specific event-id revision.
    #[must_use]
    pub const fn event_id(mut self, id: EventId) -> Self {
        self.event_id = Some(id);
        self
    }

    /// Set the free-form note.
    #[must_use]
    pub fn content(mut self, content: impl Into<String>) -> Self {
        self.content = content.into();
        self
    }

    /// Build the RSVP's addressable coordinate.
    #[must_use]
    pub fn coordinate(&self, author: PublicKey) -> Coordinate {
        Coordinate::new(KIND_RSVP, author, self.identifier.clone())
    }

    /// Parse a `kind: 31925` event into a typed bundle.
    ///
    /// # Errors
    ///
    /// See [`CalendarError`] for the failure modes.
    pub fn from_event(event: &Event) -> Result<Self, CalendarError> {
        if event.kind != KIND_RSVP {
            return Err(CalendarError::WrongKind(event.kind));
        }
        let identifier = d_value(&event.tags)
            .ok_or(CalendarError::MissingIdentifier)?
            .to_owned();
        let mut coord: Option<(Coordinate, Option<RelayUrl>)> = None;
        let mut evid: Option<(EventId, Option<RelayUrl>)> = None;
        let mut status: Option<RsvpStatus> = None;
        let mut free_busy: Option<FreeBusy> = None;
        let mut author: Option<(PublicKey, Option<RelayUrl>)> = None;
        let mut extra_tags: Vec<Tag> = Vec::new();
        for tag in &event.tags {
            match tag.kind() {
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::D => {}
                TagKind::SingleLetter(s)
                    if !s.uppercase && s.character == Alphabet::A && coord.is_none() =>
                {
                    let req = parse_calendar_request(tag)?;
                    coord = Some((req.calendar, req.relay_hint));
                }
                TagKind::SingleLetter(s)
                    if !s.uppercase && s.character == Alphabet::E && evid.is_none() =>
                {
                    evid = Some(parse_event_ref(tag)?);
                }
                TagKind::SingleLetter(s)
                    if !s.uppercase && s.character == Alphabet::P && author.is_none() =>
                {
                    author = Some(parse_pubkey_ref(tag)?);
                }
                _ if tag.name() == STATUS_TAG => {
                    let raw = tag.get(1).ok_or(CalendarError::MissingRsvpStatus)?;
                    status = Some(
                        RsvpStatus::parse(raw)
                            .ok_or_else(|| CalendarError::InvalidRsvpStatus(raw.to_owned()))?,
                    );
                }
                _ if tag.name() == FREE_BUSY_TAG => free_busy = parse_free_busy_tag(tag)?,
                _ => extra_tags.push(tag.clone()),
            }
        }
        let (event_coordinate, event_coordinate_relay_hint) =
            coord.ok_or(CalendarError::MissingRsvpCoordinate)?;
        let status = status.ok_or(CalendarError::MissingRsvpStatus)?;
        let (event_id, event_id_relay_hint) =
            evid.map_or((None, None), |(id, relay)| (Some(id), relay));
        let (event_author, event_author_relay_hint) =
            author.map_or((None, None), |(pk, relay)| (Some(pk), relay));
        Ok(Self {
            identifier,
            event_coordinate,
            event_coordinate_relay_hint,
            event_id,
            event_id_relay_hint,
            status,
            free_busy,
            event_author,
            event_author_relay_hint,
            content: event.content.clone(),
            extra_tags,
        })
    }
}

// -----------------------------------------------------------------
// Shared parsing helpers
// -----------------------------------------------------------------

#[derive(Default)]
struct CommonParseState {
    start_date: Option<CalendarDate>,
    end_date: Option<CalendarDate>,
    start_ts: Option<Timestamp>,
    end_ts: Option<Timestamp>,
    start_tzid: Option<String>,
    end_tzid: Option<String>,
}

fn parse_common(event: &Event) -> Result<(CalendarEventCommon, CommonParseState), CalendarError> {
    let identifier = d_value(&event.tags)
        .ok_or(CalendarError::MissingIdentifier)?
        .to_owned();
    let mut common = CalendarEventCommon {
        identifier,
        content: event.content.clone(),
        ..CalendarEventCommon::default()
    };
    let mut state = CommonParseState::default();
    for tag in &event.tags {
        if absorb_common_single_letter(tag, &mut common)? {
            continue;
        }
        absorb_common_named_tag(tag, event.kind, &mut common, &mut state)?;
    }
    if common.title.is_empty() {
        return Err(CalendarError::MissingTitle);
    }
    Ok((common, state))
}

fn absorb_common_single_letter(
    tag: &Tag,
    common: &mut CalendarEventCommon,
) -> Result<bool, CalendarError> {
    let TagKind::SingleLetter(s) = tag.kind() else {
        return Ok(false);
    };
    if s.uppercase {
        return Ok(false);
    }
    match s.character {
        Alphabet::D => Ok(true),
        Alphabet::G => {
            common.geohash = tag.get(1).map(str::to_owned);
            Ok(true)
        }
        Alphabet::P => {
            common.participants.push(Participant::from_tag(tag)?);
            Ok(true)
        }
        Alphabet::T => {
            if let Some(raw) = tag.get(1) {
                common.hashtags.push(raw.to_ascii_lowercase());
            }
            Ok(true)
        }
        Alphabet::R => {
            if let Some(raw) = tag.get(1) {
                common.references.push(Url::parse(raw)?);
            }
            Ok(true)
        }
        Alphabet::A => {
            common.calendar_requests.push(parse_calendar_request(tag)?);
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn absorb_common_named_tag(
    tag: &Tag,
    kind: Kind,
    common: &mut CalendarEventCommon,
    state: &mut CommonParseState,
) -> Result<(), CalendarError> {
    match tag.name() {
        TITLE_TAG => {
            common.title = tag.get(1).map(str::to_owned).unwrap_or_default();
        }
        SUMMARY_TAG => common.summary = tag.get(1).map(str::to_owned),
        IMAGE_TAG => {
            let raw = tag.get(1).ok_or(CalendarError::MalformedImage)?;
            common.image = Some(Url::parse(raw)?);
        }
        LOCATION_TAG => {
            if let Some(raw) = tag.get(1) {
                common.locations.push(raw.to_owned());
            }
        }
        START_TAG => parse_start_tag(kind, tag, state)?,
        END_TAG => parse_end_tag(kind, tag, state)?,
        START_TZID_TAG => state.start_tzid = tag.get(1).map(str::to_owned),
        END_TZID_TAG => state.end_tzid = tag.get(1).map(str::to_owned),
        // Drop the `D` day-floor tags — they're derivable from
        // `start`/`end` and should not round-trip independently.
        "D" => {}
        _ => common.extra_tags.push(tag.clone()),
    }
    Ok(())
}

fn parse_free_busy_tag(tag: &Tag) -> Result<Option<FreeBusy>, CalendarError> {
    let Some(raw) = tag.get(1) else {
        return Ok(None);
    };
    let fb = FreeBusy::parse(raw).ok_or_else(|| CalendarError::InvalidFreeBusy(raw.to_owned()))?;
    Ok(Some(fb))
}

fn parse_start_tag(
    kind: Kind,
    tag: &Tag,
    state: &mut CommonParseState,
) -> Result<(), CalendarError> {
    let Some(raw) = tag.get(1) else {
        return Ok(());
    };
    if kind == KIND_DATE_EVENT {
        state.start_date = Some(CalendarDate::parse(raw)?);
    } else {
        state.start_ts = Some(raw.parse::<Timestamp>()?);
    }
    Ok(())
}

fn parse_end_tag(kind: Kind, tag: &Tag, state: &mut CommonParseState) -> Result<(), CalendarError> {
    let Some(raw) = tag.get(1) else {
        return Ok(());
    };
    if kind == KIND_DATE_EVENT {
        state.end_date = Some(CalendarDate::parse(raw)?);
    } else {
        state.end_ts = Some(raw.parse::<Timestamp>()?);
    }
    Ok(())
}

fn parse_calendar_request(tag: &Tag) -> Result<CalendarRequest, CalendarError> {
    let coord_str = tag.get(1).ok_or(CalendarError::MalformedAddress)?;
    let calendar = Coordinate::parse(coord_str)?;
    let relay_hint = match tag.get(2) {
        Some(s) if !s.is_empty() => Some(RelayUrl::parse(s)?),
        _ => None,
    };
    Ok(CalendarRequest {
        calendar,
        relay_hint,
    })
}

fn parse_event_ref(tag: &Tag) -> Result<(EventId, Option<RelayUrl>), CalendarError> {
    let id_hex = tag.get(1).ok_or(CalendarError::MalformedAddress)?;
    let id = EventId::parse(id_hex)?;
    let relay_hint = match tag.get(2) {
        Some(s) if !s.is_empty() => Some(RelayUrl::parse(s)?),
        _ => None,
    };
    Ok((id, relay_hint))
}

fn parse_pubkey_ref(tag: &Tag) -> Result<(PublicKey, Option<RelayUrl>), CalendarError> {
    let pk_hex = tag.get(1).ok_or(CalendarError::MalformedParticipant)?;
    let pubkey = PublicKey::parse(pk_hex)?;
    let relay_hint = match tag.get(2) {
        Some(s) if !s.is_empty() => Some(RelayUrl::parse(s)?),
        _ => None,
    };
    Ok((pubkey, relay_hint))
}

fn d_value(tags: &Tags) -> Option<&str> {
    let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::D));
    tags.find_first(&head).and_then(|tag| tag.get(1))
}

// -----------------------------------------------------------------
// EventBuilder
// -----------------------------------------------------------------

fn apply_common(common: &CalendarEventCommon, mut builder: EventBuilder) -> EventBuilder {
    if let Some(summary) = &common.summary {
        builder = builder.tag(Tag::with(
            &TagKind::from_wire(SUMMARY_TAG),
            [summary.clone()],
        ));
    }
    if let Some(image) = &common.image {
        builder = builder.tag(Tag::with(
            &TagKind::from_wire(IMAGE_TAG),
            [image.as_str().to_owned()],
        ));
    }
    for location in &common.locations {
        builder = builder.tag(Tag::with(
            &TagKind::from_wire(LOCATION_TAG),
            [location.clone()],
        ));
    }
    if let Some(g) = &common.geohash {
        let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::G));
        builder = builder.tag(Tag::with(&head, [g.clone()]));
    }
    for participant in &common.participants {
        builder = builder.tag(participant.to_tag());
    }
    for hashtag in &common.hashtags {
        builder = builder.tag(Tag::t(hashtag));
    }
    for url in &common.references {
        let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::R));
        builder = builder.tag(Tag::with(&head, [url.as_str().to_owned()]));
    }
    for req in &common.calendar_requests {
        builder = builder.tag(calendar_request_tag(req));
    }
    for tag in &common.extra_tags {
        builder = builder.tag(tag.clone());
    }
    builder
}

fn calendar_request_tag(req: &CalendarRequest) -> Tag {
    let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::A));
    req.relay_hint.as_ref().map_or_else(
        || Tag::with(&head, [req.calendar.to_wire()]),
        |relay| Tag::with(&head, [req.calendar.to_wire(), relay.as_str().to_owned()]),
    )
}

impl EventBuilder {
    /// Author a NIP-52 `kind: 31922` date-based calendar event.
    #[must_use]
    pub fn calendar_date_event(event: &DateCalendarEvent) -> Self {
        let mut builder = Self::new(KIND_DATE_EVENT, event.common.content.clone());
        builder = builder
            .tag(Tag::d(&event.common.identifier))
            .tag(Tag::with(
                &TagKind::from_wire(TITLE_TAG),
                [event.common.title.clone()],
            ))
            .tag(Tag::with(
                &TagKind::from_wire(START_TAG),
                [event.start.as_str().to_owned()],
            ));
        if let Some(end) = &event.end {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(END_TAG),
                [end.as_str().to_owned()],
            ));
        }
        apply_common(&event.common, builder)
    }

    /// Author a NIP-52 `kind: 31923` time-based calendar event.
    #[must_use]
    pub fn calendar_time_event(event: &TimeCalendarEvent) -> Self {
        let mut builder = Self::new(KIND_TIME_EVENT, event.common.content.clone());
        builder = builder
            .tag(Tag::d(&event.common.identifier))
            .tag(Tag::with(
                &TagKind::from_wire(TITLE_TAG),
                [event.common.title.clone()],
            ))
            .tag(Tag::with(
                &TagKind::from_wire(START_TAG),
                [event.start.as_secs().to_string()],
            ));
        if let Some(end) = event.end {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(END_TAG),
                [end.as_secs().to_string()],
            ));
        }
        for floor in event.day_floors() {
            builder = builder.tag(Tag::with(&TagKind::from_wire("D"), [floor.to_string()]));
        }
        if let Some(tzid) = &event.start_tzid {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(START_TZID_TAG),
                [tzid.clone()],
            ));
        }
        if let Some(tzid) = &event.end_tzid {
            builder = builder.tag(Tag::with(&TagKind::from_wire(END_TZID_TAG), [tzid.clone()]));
        }
        apply_common(&event.common, builder)
    }

    /// Author a NIP-52 `kind: 31924` calendar event.
    #[must_use]
    pub fn calendar(calendar: &Calendar) -> Self {
        let mut builder = Self::new(KIND_CALENDAR, calendar.content.clone())
            .tag(Tag::d(&calendar.identifier))
            .tag(Tag::with(
                &TagKind::from_wire(TITLE_TAG),
                [calendar.title.clone()],
            ));
        for req in &calendar.events {
            builder = builder.tag(calendar_request_tag(req));
        }
        for tag in &calendar.extra_tags {
            builder = builder.tag(tag.clone());
        }
        builder
    }

    /// Author a NIP-52 `kind: 31925` RSVP event.
    #[must_use]
    pub fn calendar_rsvp(rsvp: &Rsvp) -> Self {
        let mut builder = Self::new(KIND_RSVP, rsvp.content.clone());
        builder = builder
            .tag(Tag::d(&rsvp.identifier))
            .tag(calendar_request_tag(&CalendarRequest {
                calendar: rsvp.event_coordinate.clone(),
                relay_hint: rsvp.event_coordinate_relay_hint.clone(),
            }))
            .tag(Tag::with(
                &TagKind::from_wire(STATUS_TAG),
                [rsvp.status.as_str().to_owned()],
            ));
        if let Some(id) = rsvp.event_id {
            let head_e = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::E));
            builder = builder.tag(rsvp.event_id_relay_hint.as_ref().map_or_else(
                || Tag::with(&head_e, [id.to_hex()]),
                |relay| Tag::with(&head_e, [id.to_hex(), relay.as_str().to_owned()]),
            ));
        }
        if let Some(fb) = rsvp.free_busy
            && rsvp.status != RsvpStatus::Declined
        {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(FREE_BUSY_TAG),
                [fb.as_str().to_owned()],
            ));
        }
        if let Some(pk) = rsvp.event_author {
            let head_p = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::P));
            builder = builder.tag(rsvp.event_author_relay_hint.as_ref().map_or_else(
                || Tag::with(&head_p, [pk.to_hex()]),
                |relay| Tag::with(&head_p, [pk.to_hex(), relay.as_str().to_owned()]),
            ));
        }
        for tag in &rsvp.extra_tags {
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
    fn calendar_date_parses() {
        let d = CalendarDate::parse("2025-01-09").unwrap();
        assert_eq!(d.as_str(), "2025-01-09");
        assert!(matches!(
            CalendarDate::parse("2025/01/09"),
            Err(CalendarDateError::MissingSeparator)
        ));
        assert!(matches!(
            CalendarDate::parse("2025-13-09"),
            Err(CalendarDateError::InvalidMonth(13))
        ));
    }

    #[test]
    fn date_event_round_trip() {
        let event = DateCalendarEvent::new(
            "holiday",
            "Holiday",
            CalendarDate::parse("2025-12-24").unwrap(),
        )
        .end(CalendarDate::parse("2025-12-26").unwrap());
        let signed = EventBuilder::calendar_date_event(&event)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = DateCalendarEvent::from_event(&signed).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn time_event_round_trip_with_participants() {
        let start = Timestamp::from_secs(1_700_000_000);
        let end = Timestamp::from_secs(1_700_003_600);
        let participant = Participant::new(*keys().public_key())
            .relay_hint(RelayUrl::parse("wss://relay.example/").unwrap())
            .role("Speaker");
        let mut event = TimeCalendarEvent::new("meet", "Meet", start)
            .end(end)
            .start_tzid("America/Costa_Rica")
            .end_tzid("America/Costa_Rica");
        event.common.participants.push(participant);
        event.common.summary = Some("brief".into());
        event.common.hashtags.push("ethereum".into());
        event.common.locations.push("online".into());
        let signed = EventBuilder::calendar_time_event(&event)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = TimeCalendarEvent::from_event(&signed).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn time_event_day_floors_cover_range() {
        let start = Timestamp::from_secs(86_400 * 10);
        let end = Timestamp::from_secs(86_400 * 12);
        let event = TimeCalendarEvent::new("multi", "Multi", start).end(end);
        assert_eq!(event.day_floors(), vec![10, 11, 12]);
    }

    #[test]
    fn calendar_round_trip() {
        let coord = Coordinate::new(KIND_TIME_EVENT, *keys().public_key(), "meet");
        let calendar =
            Calendar::new("cal-1", "Work")
                .content("description")
                .event(CalendarRequest {
                    calendar: coord,
                    relay_hint: Some(RelayUrl::parse("wss://relay.example/").unwrap()),
                });
        let signed = EventBuilder::calendar(&calendar)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = Calendar::from_event(&signed).unwrap();
        assert_eq!(parsed, calendar);
    }

    #[test]
    fn rsvp_round_trip() {
        let coord = Coordinate::new(KIND_TIME_EVENT, *keys().public_key(), "meet");
        let rsvp = Rsvp::new("rsvp-1", coord, RsvpStatus::Accepted)
            .free_busy(FreeBusy::Busy)
            .event_author(*keys().public_key())
            .event_id(EventId::from_byte_array([0xcc; 32]))
            .content("see you");
        let signed = EventBuilder::calendar_rsvp(&rsvp)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = Rsvp::from_event(&signed).unwrap();
        assert_eq!(parsed, rsvp);
    }

    #[test]
    fn declined_rsvp_omits_fb() {
        let coord = Coordinate::new(KIND_TIME_EVENT, *keys().public_key(), "meet");
        let rsvp = Rsvp::new("rsvp-2", coord, RsvpStatus::Declined).free_busy(FreeBusy::Free);
        let signed = EventBuilder::calendar_rsvp(&rsvp)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = Rsvp::from_event(&signed).unwrap();
        // Builder drops the incompatible `fb` tag.
        assert!(parsed.free_busy.is_none());
        assert_eq!(parsed.status, RsvpStatus::Declined);
    }

    #[test]
    fn wrong_kind_is_rejected() {
        let event = EventBuilder::text_note("nope")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            DateCalendarEvent::from_event(&event),
            Err(CalendarError::WrongKind(_))
        ));
        assert!(matches!(
            TimeCalendarEvent::from_event(&event),
            Err(CalendarError::WrongKind(_))
        ));
        assert!(matches!(
            Calendar::from_event(&event),
            Err(CalendarError::WrongKind(_))
        ));
        assert!(matches!(
            Rsvp::from_event(&event),
            Err(CalendarError::WrongKind(_))
        ));
    }

    #[test]
    fn missing_title_rejected() {
        let event = EventBuilder::new(KIND_DATE_EVENT, "")
            .tag(Tag::d("x"))
            .tag(Tag::with(&TagKind::from_wire(START_TAG), ["2025-01-01"]))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            DateCalendarEvent::from_event(&event),
            Err(CalendarError::MissingTitle)
        ));
    }
}
