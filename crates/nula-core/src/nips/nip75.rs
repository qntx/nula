//! [NIP-75] Zap Goals.
//!
//! `kind: 9041` is a fundraising-goal event. The bundle pins the
//! mandatory `amount` (in millisats) and `relays` columns, plus the
//! optional `closed_at` deadline, `image`, `summary`, and reference
//! tags (`r`/`a`). The spec also lets a goal embed NIP-57 `zap`
//! tags to declare beneficiary pubkeys with split weights — we
//! reuse [`crate::nips::nip57::ZapSplitTarget`] verbatim.
//!
//! On the consumer side, an addressable event can link back to a
//! goal with a `goal` tag (`["goal", "<event-id>", "<relay>?"]`)
//! that we model as [`GoalLink`].
//!
//! # Forward compatibility
//!
//! - Unknown tags survive a round-trip through [`ZapGoal::extra_tags`].
//! - The `closed_at` timestamp uses [`Timestamp`], which already
//!   tolerates negative deltas / future values.
//! - Multiple `relays` columns are concatenated into a single tag
//!   per spec example.
//!
//! [NIP-75]: https://github.com/nostr-protocol/nips/blob/master/75.md

use thiserror::Error;

use crate::event::{
    Alphabet, Coordinate, CoordinateError, Event, EventBuilder, EventId, EventIdError, Kind,
    SingleLetterTag, Tag, TagKind,
};
use crate::nips::nip57::{ZapError, ZapSplitTarget};
use crate::types::{RelayUrl, RelayUrlError, Timestamp, TimestampError, Url, UrlError};

/// `kind: 9041` — zap goal.
pub const KIND_ZAP_GOAL: Kind = Kind::ZAP_GOAL;

const AMOUNT_TAG: &str = "amount";
const RELAYS_TAG: &str = "relays";
const CLOSED_AT_TAG: &str = "closed_at";
const IMAGE_TAG: &str = "image";
const SUMMARY_TAG: &str = "summary";
const GOAL_TAG: &str = "goal";

/// Typed bundle for a `kind: 9041` zap goal event.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ZapGoal {
    /// Target amount in millisats (`amount` tag — required).
    pub amount_msats: u64,
    /// Tally relays (`relays` tag — required). Spec mandates at
    /// least one entry.
    pub relays: Vec<RelayUrl>,
    /// Human-readable description from `.content`.
    pub content: String,
    /// Optional deadline (`closed_at` tag).
    pub closed_at: Option<Timestamp>,
    /// Optional poster image (`image` tag).
    pub image: Option<Url>,
    /// Optional brief description (`summary` tag).
    pub summary: Option<String>,
    /// Optional `r` link (free-form URL).
    pub url_link: Option<Url>,
    /// Optional `a` link (addressable event).
    pub address_link: Option<Coordinate>,
    /// Beneficiary split targets (NIP-57 `zap` tags).
    pub split_targets: Vec<ZapSplitTarget>,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

impl ZapGoal {
    /// Construct a goal with the spec-required fields.
    #[must_use]
    pub fn new(amount_msats: u64, relays: Vec<RelayUrl>) -> Self {
        Self {
            amount_msats,
            relays,
            ..Self::default()
        }
    }

    /// Set the human-readable description from `.content`.
    #[must_use]
    pub fn content(mut self, content: impl Into<String>) -> Self {
        self.content = content.into();
        self
    }

    /// Set [`Self::closed_at`].
    #[must_use]
    pub const fn closed_at(mut self, closed_at: Timestamp) -> Self {
        self.closed_at = Some(closed_at);
        self
    }

    /// Set [`Self::image`].
    #[must_use]
    pub fn image(mut self, url: Url) -> Self {
        self.image = Some(url);
        self
    }

    /// Set [`Self::summary`].
    #[must_use]
    pub fn summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = Some(summary.into());
        self
    }

    /// Set [`Self::url_link`].
    #[must_use]
    pub fn url_link(mut self, url: Url) -> Self {
        self.url_link = Some(url);
        self
    }

    /// Set [`Self::address_link`].
    #[must_use]
    pub fn address_link(mut self, coordinate: Coordinate) -> Self {
        self.address_link = Some(coordinate);
        self
    }

    /// Append a NIP-57 split-target beneficiary.
    #[must_use]
    pub fn split_target(mut self, target: ZapSplitTarget) -> Self {
        self.split_targets.push(target);
        self
    }

    /// Parse a `kind: 9041` event into a typed bundle.
    ///
    /// # Errors
    ///
    /// - [`ZapGoalError::WrongKind`] for non-9041 events.
    /// - [`ZapGoalError::MissingAmount`] / `MissingRelays` when a
    ///   required tag is absent.
    /// - Field-specific errors for malformed columns.
    pub fn from_event(event: &Event) -> Result<Self, ZapGoalError> {
        if event.kind != KIND_ZAP_GOAL {
            return Err(ZapGoalError::WrongKind(event.kind));
        }
        let mut goal = Self {
            content: event.content.clone(),
            ..Self::default()
        };
        let mut saw_amount = false;
        let mut saw_relays = false;
        for tag in &event.tags {
            match tag.kind() {
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::R => {
                    let url_str = tag.get(1).ok_or(ZapGoalError::MalformedUrlLink)?;
                    goal.url_link = Some(Url::parse(url_str)?);
                }
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::A => {
                    let coord_str = tag.get(1).ok_or(ZapGoalError::MalformedAddressLink)?;
                    goal.address_link = Some(Coordinate::parse(coord_str)?);
                }
                _ if tag.name() == AMOUNT_TAG => {
                    let raw = tag.get(1).ok_or(ZapGoalError::MalformedAmount)?;
                    goal.amount_msats = raw
                        .parse::<u64>()
                        .map_err(|_| ZapGoalError::InvalidAmount(raw.to_owned()))?;
                    saw_amount = true;
                }
                _ if tag.name() == RELAYS_TAG => {
                    parse_relays_tag(tag, &mut goal.relays)?;
                    saw_relays = true;
                }
                _ if tag.name() == CLOSED_AT_TAG => {
                    let raw = tag.get(1).ok_or(ZapGoalError::MalformedClosedAt)?;
                    goal.closed_at = Some(raw.parse::<Timestamp>()?);
                }
                _ if tag.name() == IMAGE_TAG => {
                    let raw = tag.get(1).ok_or(ZapGoalError::MalformedImage)?;
                    goal.image = Some(Url::parse(raw)?);
                }
                _ if tag.name() == SUMMARY_TAG => {
                    goal.summary = tag.get(1).map(str::to_owned);
                }
                _ if tag.name() == "zap" => {
                    goal.split_targets
                        .push(ZapSplitTarget::from_tag(tag).map_err(ZapGoalError::Zap)?);
                }
                _ => goal.extra_tags.push(tag.clone()),
            }
        }
        if !saw_amount {
            return Err(ZapGoalError::MissingAmount);
        }
        if !saw_relays {
            return Err(ZapGoalError::MissingRelays);
        }
        Ok(goal)
    }
}

/// `goal` tag — embedded in addressable events to point back at a
/// zap goal (spec §"Client behavior", second-to-last paragraph).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoalLink {
    /// Goal event id.
    pub goal_event: EventId,
    /// Optional relay hint.
    pub relay_hint: Option<RelayUrl>,
}

impl GoalLink {
    /// Construct a goal link without a relay hint.
    #[must_use]
    pub const fn new(goal_event: EventId) -> Self {
        Self {
            goal_event,
            relay_hint: None,
        }
    }

    /// Attach a relay hint.
    #[must_use]
    pub fn relay_hint(mut self, relay: RelayUrl) -> Self {
        self.relay_hint = Some(relay);
        self
    }

    /// Render as a [`Tag`].
    #[must_use]
    pub fn to_tag(&self) -> Tag {
        let head = TagKind::from_wire(GOAL_TAG);
        self.relay_hint.as_ref().map_or_else(
            || Tag::with(&head, [self.goal_event.to_hex()]),
            |relay| Tag::with(&head, [self.goal_event.to_hex(), relay.as_str().to_owned()]),
        )
    }

    /// Parse a `goal` tag back into a typed value.
    ///
    /// # Errors
    ///
    /// - [`ZapGoalError::WrongGoalTag`] when the tag's head is not
    ///   `goal`.
    /// - [`ZapGoalError::MalformedGoalTag`] when the event id is
    ///   absent.
    /// - [`ZapGoalError::InvalidEventId`] /
    ///   [`ZapGoalError::InvalidRelayUrl`] for malformed columns.
    pub fn from_tag(tag: &Tag) -> Result<Self, ZapGoalError> {
        if tag.name() != GOAL_TAG {
            return Err(ZapGoalError::WrongGoalTag);
        }
        let id_hex = tag.get(1).ok_or(ZapGoalError::MalformedGoalTag)?;
        let goal_event = EventId::parse(id_hex)?;
        let relay_hint = match tag.get(2) {
            Some(s) if !s.is_empty() => Some(RelayUrl::parse(s)?),
            _ => None,
        };
        Ok(Self {
            goal_event,
            relay_hint,
        })
    }
}

impl Tag {
    /// Build a NIP-75 `goal` tag.
    #[must_use]
    pub fn goal(link: &GoalLink) -> Self {
        link.to_tag()
    }
}

/// Errors raised by NIP-75 parsers.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ZapGoalError {
    /// The event was not `kind: 9041`.
    #[error("expected kind 9041 (zap goal), got kind {}", .0.as_u16())]
    WrongKind(Kind),
    /// `amount` tag is absent.
    #[error("zap goal missing `amount` tag")]
    MissingAmount,
    /// `relays` tag is absent.
    #[error("zap goal missing `relays` tag")]
    MissingRelays,
    /// `amount` tag is missing its value column.
    #[error("`amount` tag missing value")]
    MalformedAmount,
    /// `closed_at` tag is missing its value column.
    #[error("`closed_at` tag missing value")]
    MalformedClosedAt,
    /// `image` tag is missing its URL column.
    #[error("`image` tag missing URL")]
    MalformedImage,
    /// `r` link tag is missing its URL column.
    #[error("`r` link tag missing URL")]
    MalformedUrlLink,
    /// `a` link tag is missing its coordinate column.
    #[error("`a` link tag missing coordinate")]
    MalformedAddressLink,
    /// `amount` value is not a `u64`.
    #[error("invalid amount value: `{0}`")]
    InvalidAmount(String),
    /// `closed_at` value is not a valid timestamp.
    #[error(transparent)]
    InvalidTimestamp(#[from] TimestampError),
    /// Wrapped relay-url parser error.
    #[error(transparent)]
    InvalidRelayUrl(#[from] RelayUrlError),
    /// Wrapped URL parser error.
    #[error(transparent)]
    InvalidUrl(#[from] UrlError),
    /// Wrapped event-id parser error.
    #[error(transparent)]
    InvalidEventId(#[from] EventIdError),
    /// Wrapped coordinate parser error.
    #[error(transparent)]
    InvalidCoordinate(#[from] CoordinateError),
    /// NIP-57 split-target parsing failed.
    #[error("zap split parse error: {0}")]
    Zap(#[source] ZapError),
    /// `goal` tag head was not `goal`.
    #[error("expected `goal` tag")]
    WrongGoalTag,
    /// `goal` tag is missing the event-id column.
    #[error("`goal` tag missing event id")]
    MalformedGoalTag,
}

fn parse_relays_tag(tag: &Tag, relays: &mut Vec<RelayUrl>) -> Result<(), ZapGoalError> {
    for v in tag.values().iter().skip(1) {
        relays.push(RelayUrl::parse(v)?);
    }
    Ok(())
}

impl EventBuilder {
    /// Author a NIP-75 `kind: 9041` zap goal event.
    ///
    /// # Panics
    ///
    /// Cannot panic in practice: the assembled `relays` tag always
    /// includes its head before the relay URLs, so [`Tag::new`]'s
    /// non-empty invariant always holds.
    #[must_use]
    pub fn zap_goal(goal: &ZapGoal) -> Self {
        let mut builder = Self::new(KIND_ZAP_GOAL, goal.content.clone());
        let mut relays_values: Vec<String> = Vec::with_capacity(goal.relays.len() + 1);
        relays_values.push(RELAYS_TAG.to_owned());
        for relay in &goal.relays {
            relays_values.push(relay.as_str().to_owned());
        }
        let relays_tag = Tag::new(relays_values)
            .unwrap_or_else(|_| unreachable!("`relays_values` always includes the tag head"));
        builder = builder.tag(relays_tag);
        builder = builder.tag(Tag::with(
            &TagKind::from_wire(AMOUNT_TAG),
            [goal.amount_msats.to_string()],
        ));
        if let Some(ts) = goal.closed_at {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(CLOSED_AT_TAG),
                [ts.as_secs().to_string()],
            ));
        }
        if let Some(url) = &goal.image {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(IMAGE_TAG),
                [url.as_str().to_owned()],
            ));
        }
        if let Some(summary) = &goal.summary {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(SUMMARY_TAG),
                [summary.clone()],
            ));
        }
        if let Some(url) = &goal.url_link {
            let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::R));
            builder = builder.tag(Tag::with(&head, [url.as_str().to_owned()]));
        }
        if let Some(coord) = &goal.address_link {
            builder = builder.tag(Tag::a(coord));
        }
        for target in &goal.split_targets {
            builder = builder.tag(target.to_tag());
        }
        for tag in &goal.extra_tags {
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

    fn other_pubkey() -> crate::PublicKey {
        *Keys::parse("0000000000000000000000000000000000000000000000000000000000000004")
            .unwrap()
            .public_key()
    }

    fn relay() -> RelayUrl {
        RelayUrl::parse("wss://alice.example/").unwrap()
    }

    fn relay_other() -> RelayUrl {
        RelayUrl::parse("wss://bob.example/").unwrap()
    }

    #[test]
    fn round_trip_minimal_goal() {
        let goal = ZapGoal::new(210_000, vec![relay()]).content("Nostrasia travel");
        let event = EventBuilder::zap_goal(&goal)
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, KIND_ZAP_GOAL);
        let parsed = ZapGoal::from_event(&event).unwrap();
        assert_eq!(parsed, goal);
    }

    #[test]
    fn round_trip_full_goal() {
        let coord = Coordinate::new(Kind::new(30_023), *keys().public_key(), "post".to_owned());
        let goal = ZapGoal::new(500_000, vec![relay(), relay_other()])
            .content("Help me reach the goal")
            .closed_at(Timestamp::from_secs(1_700_000_000))
            .image(Url::parse("https://example.com/poster.png").unwrap())
            .summary("Short description")
            .url_link(Url::parse("https://example.com/").unwrap())
            .address_link(coord)
            .split_target(ZapSplitTarget::new(other_pubkey()).weight(1));
        let event = EventBuilder::zap_goal(&goal)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = ZapGoal::from_event(&event).unwrap();
        assert_eq!(parsed, goal);
    }

    #[test]
    fn wrong_kind_is_rejected() {
        let event = EventBuilder::text_note("nope")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            ZapGoal::from_event(&event),
            Err(ZapGoalError::WrongKind(_))
        ));
    }

    #[test]
    fn missing_amount_is_rejected() {
        let event = EventBuilder::new(KIND_ZAP_GOAL, "")
            .tag(Tag::new(vec![RELAYS_TAG.to_owned(), relay().as_str().to_owned()]).unwrap())
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            ZapGoal::from_event(&event),
            Err(ZapGoalError::MissingAmount)
        ));
    }

    #[test]
    fn missing_relays_is_rejected() {
        let event = EventBuilder::new(KIND_ZAP_GOAL, "")
            .tag(Tag::with(&TagKind::from_wire(AMOUNT_TAG), ["100"]))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            ZapGoal::from_event(&event),
            Err(ZapGoalError::MissingRelays)
        ));
    }

    #[test]
    fn goal_link_round_trip() {
        let link = GoalLink::new(EventId::from_byte_array([0xaa; 32])).relay_hint(relay());
        let tag = link.to_tag();
        assert_eq!(tag.name(), GOAL_TAG);
        let parsed = GoalLink::from_tag(&tag).unwrap();
        assert_eq!(parsed, link);
    }

    #[test]
    fn goal_link_without_relay_hint() {
        let link = GoalLink::new(EventId::from_byte_array([0xbb; 32]));
        let tag = link.to_tag();
        let parsed = GoalLink::from_tag(&tag).unwrap();
        assert_eq!(parsed, link);
    }

    #[test]
    fn goal_link_wrong_head_rejected() {
        let tag = Tag::title("not a goal tag");
        assert!(matches!(
            GoalLink::from_tag(&tag),
            Err(ZapGoalError::WrongGoalTag)
        ));
    }
}
