//! [NIP-65] Relay List Metadata.
//!
//! NIP-65 lets a user advertise the relays they use by publishing a `kind:
//! 10002` event whose only meaningful payload is a list of `r` tags:
//!
//! ```json
//! ["r", "wss://relay.example"]
//! ["r", "wss://read.example", "read"]
//! ["r", "wss://write.example", "write"]
//! ```
//!
//! - No marker (third element absent) means the relay is used for both
//!   reading and writing.
//! - `read` means the user *consumes* events from this relay.
//! - `write` means the user *publishes* events to this relay.
//!
//! [NIP-65]: https://github.com/nostr-protocol/nips/blob/master/65.md
//!
//! # Example
//!
//! ```
//! use nula_core::nip65::{RelayList, RelayMarker};
//! use nula_core::{Keys, RelayUrl};
//!
//! let mut list = RelayList::new();
//! list.insert(RelayUrl::parse("wss://read.example").unwrap(), RelayMarker::Read);
//! list.insert(
//!     RelayUrl::parse("wss://write.example").unwrap(),
//!     RelayMarker::Write,
//! );
//!
//! let keys = Keys::generate().unwrap();
//! let event = list.to_event_builder().sign_with_keys(&keys).unwrap();
//! event.verify().unwrap();
//! ```

use core::fmt;
use core::str::FromStr;
use std::collections::BTreeMap;

use thiserror::Error;

use crate::event::{Event, EventBuilder, Kind, Tag, TagKind, Tags};
use crate::types::{RelayUrl, RelayUrlError};

/// Whether a NIP-65 relay entry is intended for reading, writing, or both.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RelayMarker {
    /// The relay is used for both reading and writing (default; encoded as
    /// the absence of a third tag element).
    #[default]
    ReadWrite,
    /// The user reads events from this relay.
    Read,
    /// The user publishes events to this relay.
    Write,
}

impl RelayMarker {
    /// Return the wire string the marker uses on the third tag element, or
    /// `None` when the marker is [`RelayMarker::ReadWrite`] (which omits the
    /// element entirely).
    #[must_use]
    pub const fn as_wire(self) -> Option<&'static str> {
        match self {
            Self::ReadWrite => None,
            Self::Read => Some("read"),
            Self::Write => Some("write"),
        }
    }

    /// True when the relay should be queried for events.
    #[must_use]
    pub const fn is_read(self) -> bool {
        matches!(self, Self::Read | Self::ReadWrite)
    }

    /// True when the user should publish to this relay.
    #[must_use]
    pub const fn is_write(self) -> bool {
        matches!(self, Self::Write | Self::ReadWrite)
    }
}

impl fmt::Display for RelayMarker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_wire().unwrap_or("read+write"))
    }
}

impl FromStr for RelayMarker {
    type Err = RelayMarkerError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "read" => Ok(Self::Read),
            "write" => Ok(Self::Write),
            other => Err(RelayMarkerError::Unknown(other.to_owned())),
        }
    }
}

/// Errors raised when parsing a NIP-65 marker string.
#[derive(Debug, Clone, Error)]
#[non_exhaustive]
pub enum RelayMarkerError {
    /// The marker string was neither `read` nor `write`.
    #[error("unknown NIP-65 relay marker `{0}`")]
    Unknown(String),
}

/// Errors raised when building a [`RelayList`] from an [`Event`].
#[derive(Debug, Clone, Error)]
#[non_exhaustive]
pub enum Error {
    /// The event's `kind` was not `10002`.
    #[error("expected kind {expected}, got {got}")]
    UnexpectedKind {
        /// `Kind::RELAY_LIST.as_u16()`.
        expected: u16,
        /// What the event actually advertised.
        got: u16,
    },
    /// An `r` tag had no URL.
    #[error("`r` tag is missing the relay URL")]
    MissingRelayUrl,
    /// An `r` tag's URL did not parse.
    #[error(transparent)]
    InvalidRelayUrl(#[from] RelayUrlError),
    /// An `r` tag's marker did not parse.
    #[error(transparent)]
    InvalidMarker(#[from] RelayMarkerError),
}

/// A user's NIP-65 relay list.
///
/// The internal representation is a [`BTreeMap`] keyed by [`RelayUrl`]; each
/// relay appears at most once and the relays iterate in deterministic order.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RelayList {
    relays: BTreeMap<RelayUrl, RelayMarker>,
}

impl RelayList {
    /// Construct an empty list.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace the relay's marker. Returns the previous marker, if
    /// any.
    ///
    /// # Spec recommendation
    ///
    /// NIP-65 §Size says: "Clients SHOULD guide users to keep `kind:10002`
    /// lists small (2-4 relays of each category)." The crate does not
    /// enforce that bound — it would be a breaking surprise — but a
    /// caller building user-facing UX should warn well before the list
    /// crosses, say, 8 read or 8 write relays.
    pub fn insert(&mut self, url: RelayUrl, marker: RelayMarker) -> Option<RelayMarker> {
        self.relays.insert(url, marker)
    }

    /// Remove a relay from the list. Returns the previous marker, if any.
    pub fn remove(&mut self, url: &RelayUrl) -> Option<RelayMarker> {
        self.relays.remove(url)
    }

    /// Lookup a relay's marker.
    #[must_use]
    pub fn get(&self, url: &RelayUrl) -> Option<RelayMarker> {
        self.relays.get(url).copied()
    }

    /// Whether the list contains the given relay.
    #[must_use]
    pub fn contains(&self, url: &RelayUrl) -> bool {
        self.relays.contains_key(url)
    }

    /// Number of relays in the list.
    #[must_use]
    pub fn len(&self) -> usize {
        self.relays.len()
    }

    /// True when the list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.relays.is_empty()
    }

    /// Iterate over `(url, marker)` pairs in deterministic order.
    pub fn iter(&self) -> impl Iterator<Item = (&RelayUrl, RelayMarker)> {
        self.relays.iter().map(|(url, marker)| (url, *marker))
    }

    /// Iterate over relays the user reads from.
    pub fn read_relays(&self) -> impl Iterator<Item = &RelayUrl> {
        self.iter().filter(|(_, m)| m.is_read()).map(|(url, _)| url)
    }

    /// Iterate over relays the user writes to.
    pub fn write_relays(&self) -> impl Iterator<Item = &RelayUrl> {
        self.iter()
            .filter(|(_, m)| m.is_write())
            .map(|(url, _)| url)
    }

    /// Render the list as the [`Tags`] vector the kind-10002 event must
    /// carry.
    #[must_use]
    pub fn to_tags(&self) -> Tags {
        let tags = self
            .relays
            .iter()
            .map(|(url, marker)| build_r_tag(url, *marker))
            .collect::<Vec<_>>();
        Tags::from_vec(tags)
    }

    /// Build an [`EventBuilder`] for the kind-10002 event that publishes the
    /// list.
    ///
    /// The event's `content` is empty per NIP-65; consumers populate the
    /// builder further (e.g. with [`EventBuilder::created_at`]) before
    /// signing.
    #[must_use]
    pub fn to_event_builder(&self) -> EventBuilder {
        EventBuilder::new(Kind::RELAY_LIST, "").tags(self.to_tags())
    }

    /// Reconstruct a [`RelayList`] from a kind-10002 [`Event`].
    ///
    /// Tags whose first element is not `r` are silently ignored
    /// (forward-compat).
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedKind`] if the event's kind is not
    /// `10002`, or any of the parsing errors when an `r` tag is malformed.
    pub fn from_event(event: &Event) -> Result<Self, Error> {
        if event.kind != Kind::RELAY_LIST {
            return Err(Error::UnexpectedKind {
                expected: Kind::RELAY_LIST.as_u16(),
                got: event.kind.as_u16(),
            });
        }
        let mut list = Self::new();
        for tag in &event.tags {
            if !is_relay_tag(&tag.kind()) {
                continue;
            }
            let mut args = tag.values().iter().skip(1);
            let url_str = args.next().ok_or(Error::MissingRelayUrl)?;
            let url = RelayUrl::parse(url_str)?;
            let marker = match args.next() {
                Some(s) if !s.is_empty() => s.parse::<RelayMarker>()?,
                _ => RelayMarker::ReadWrite,
            };
            list.insert(url, marker);
        }
        Ok(list)
    }
}

fn build_r_tag(url: &RelayUrl, marker: RelayMarker) -> Tag {
    let kind = TagKind::from_wire("r");
    let mut values = vec![url.as_str().to_owned()];
    if let Some(extra) = marker.as_wire() {
        values.push(extra.to_owned());
    }
    Tag::with(&kind, values)
}

fn is_relay_tag(kind: &TagKind) -> bool {
    kind.as_str() == "r"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;

    fn relay(url: &str) -> RelayUrl {
        RelayUrl::parse(url).unwrap()
    }

    fn keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    #[test]
    fn marker_wire_strings() {
        assert_eq!(RelayMarker::Read.as_wire(), Some("read"));
        assert_eq!(RelayMarker::Write.as_wire(), Some("write"));
        assert_eq!(RelayMarker::ReadWrite.as_wire(), None);
    }

    #[test]
    fn marker_parsing() {
        assert_eq!("read".parse::<RelayMarker>().unwrap(), RelayMarker::Read);
        assert_eq!("write".parse::<RelayMarker>().unwrap(), RelayMarker::Write);
        let err = "both".parse::<RelayMarker>().unwrap_err();
        assert!(err.to_string().contains("unknown"));
    }

    #[test]
    fn marker_predicates() {
        assert!(RelayMarker::ReadWrite.is_read());
        assert!(RelayMarker::ReadWrite.is_write());
        assert!(RelayMarker::Read.is_read());
        assert!(!RelayMarker::Read.is_write());
        assert!(!RelayMarker::Write.is_read());
        assert!(RelayMarker::Write.is_write());
    }

    #[test]
    fn round_trip_through_event() {
        let mut list = RelayList::new();
        list.insert(relay("wss://both.example"), RelayMarker::ReadWrite);
        list.insert(relay("wss://read.example"), RelayMarker::Read);
        list.insert(relay("wss://write.example"), RelayMarker::Write);

        let event = list.to_event_builder().sign_with_keys(&keys()).unwrap();
        event.verify().unwrap();
        assert_eq!(event.kind, Kind::RELAY_LIST);

        let parsed = RelayList::from_event(&event).unwrap();
        assert_eq!(parsed, list);
    }

    #[test]
    fn unknown_tags_are_ignored() {
        let event = EventBuilder::new(Kind::RELAY_LIST, "")
            .tags([
                Tag::new(["r", "wss://relay.example"]).unwrap(),
                Tag::new(["alt", "ignored"]).unwrap(),
            ])
            .sign_with_keys(&keys())
            .unwrap();
        let list = RelayList::from_event(&event).unwrap();
        assert_eq!(list.len(), 1);
        assert!(list.contains(&relay("wss://relay.example")));
    }

    #[test]
    fn missing_url_is_rejected() {
        let event = EventBuilder::new(Kind::RELAY_LIST, "")
            .tag(Tag::new(["r"]).unwrap())
            .sign_with_keys(&keys())
            .unwrap();
        let err = RelayList::from_event(&event).unwrap_err();
        assert!(matches!(err, Error::MissingRelayUrl));
    }

    #[test]
    fn unknown_marker_is_rejected() {
        let event = EventBuilder::new(Kind::RELAY_LIST, "")
            .tag(Tag::new(["r", "wss://relay.example", "duplex"]).unwrap())
            .sign_with_keys(&keys())
            .unwrap();
        let err = RelayList::from_event(&event).unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidMarker(RelayMarkerError::Unknown(_))
        ));
    }

    #[test]
    fn wrong_kind_is_rejected() {
        let event = EventBuilder::text_note("not a relay list")
            .sign_with_keys(&keys())
            .unwrap();
        let err = RelayList::from_event(&event).unwrap_err();
        assert!(matches!(
            err,
            Error::UnexpectedKind {
                expected: 10_002,
                got: 1
            }
        ));
    }

    #[test]
    fn read_and_write_iterators() {
        let mut list = RelayList::new();
        list.insert(relay("wss://both.example"), RelayMarker::ReadWrite);
        list.insert(relay("wss://read.example"), RelayMarker::Read);
        list.insert(relay("wss://write.example"), RelayMarker::Write);

        let read: Vec<_> = list.read_relays().collect();
        let write: Vec<_> = list.write_relays().collect();
        assert_eq!(read.len(), 2);
        assert_eq!(write.len(), 2);
        assert!(read.contains(&&relay("wss://both.example")));
        assert!(read.contains(&&relay("wss://read.example")));
        assert!(write.contains(&&relay("wss://both.example")));
        assert!(write.contains(&&relay("wss://write.example")));
    }
}
