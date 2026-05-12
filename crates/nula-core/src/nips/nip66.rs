//! [NIP-66] Relay Discovery & Liveness Monitoring.
//!
//! Two event kinds:
//!
//! - **`kind: 30166` Relay Discovery** — addressable event a monitor
//!   publishes per relay it surveys. Its `d` tag is the relay's
//!   normalised URL (or a hex pubkey for relays unreachable by URL),
//!   `.content` MAY carry the relay's NIP-11 document, and a rich
//!   tag-set documents network type, supported NIPs, requirements,
//!   topics, accepted kinds, geohash, and round-trip times.
//! - **`kind: 10166` Relay Monitor Announcement** — replaceable
//!   advert from a monitor declaring the cadence and battery of
//!   checks it runs.
//!
//! `R` tag values support the NIP-66 `!` prefix for "false" booleans
//! (`!auth` = `auth == false`); we model them through the typed
//! [`RelayRequirement`] struct. `k` tags follow the same convention
//! via [`AcceptedKind`].
//!
//! Unknown tags survive a round-trip through `extra_tags` on both
//! bundles.
//!
//! [NIP-66]: https://github.com/nostr-protocol/nips/blob/master/66.md

use thiserror::Error;

use crate::event::{Alphabet, Event, EventBuilder, Kind, SingleLetterTag, Tag, TagKind, Tags};

/// `kind: 30166` — relay discovery event.
pub const KIND_RELAY_DISCOVERY: Kind = Kind::RELAY_DISCOVERY;

/// `kind: 10166` — relay monitor announcement.
pub const KIND_RELAY_MONITOR: Kind = Kind::RELAY_MONITOR;

const NETWORK_TAG: &str = "n";
const RELAY_TYPE_TAG: &str = "T";
const NIP_TAG: &str = "N";
const REQUIREMENT_TAG: &str = "R";
const TOPIC_TAG: &str = "t";
const KIND_TAG: &str = "k";
const FREQUENCY_TAG: &str = "frequency";
const TIMEOUT_TAG: &str = "timeout";
const CHECK_TAG: &str = "c";
const RTT_PREFIX: &str = "rtt-";

/// A `R` tag value: the requirement name (`auth`, `writes`, `pow`,
/// `payment`, custom) plus a boolean carrying the NIP-66 `!` prefix
/// convention.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelayRequirement {
    /// Requirement name without the `!` prefix.
    pub name: String,
    /// `true` when the requirement is enforced, `false` when the
    /// relay explicitly disables it (`!name`).
    pub enabled: bool,
}

impl RelayRequirement {
    /// Construct an enforced requirement.
    #[must_use]
    pub fn enabled(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            enabled: true,
        }
    }

    /// Construct an explicitly disabled requirement (`!name`).
    #[must_use]
    pub fn disabled(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            enabled: false,
        }
    }

    /// Render to the wire token (`<name>` or `!<name>`).
    #[must_use]
    pub fn to_token(&self) -> String {
        if self.enabled {
            self.name.clone()
        } else {
            format!("!{}", self.name)
        }
    }

    /// Parse a wire token.
    #[must_use]
    pub fn parse(token: &str) -> Self {
        token.strip_prefix('!').map_or_else(
            || Self {
                name: token.to_owned(),
                enabled: true,
            },
            |name| Self {
                name: name.to_owned(),
                enabled: false,
            },
        )
    }
}

/// An accepted-kind token with the NIP-66 `!` convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AcceptedKind {
    /// Event kind.
    pub kind: Kind,
    /// `true` when accepted, `false` when explicitly rejected.
    pub accepted: bool,
}

impl AcceptedKind {
    /// Construct an accepted kind.
    #[must_use]
    pub const fn accepted(kind: Kind) -> Self {
        Self {
            kind,
            accepted: true,
        }
    }

    /// Construct an explicitly rejected kind.
    #[must_use]
    pub const fn rejected(kind: Kind) -> Self {
        Self {
            kind,
            accepted: false,
        }
    }

    /// Render to the wire token (`<kind>` or `!<kind>`).
    #[must_use]
    pub fn to_token(self) -> String {
        if self.accepted {
            self.kind.as_u16().to_string()
        } else {
            format!("!{}", self.kind.as_u16())
        }
    }

    /// Parse a wire token.
    ///
    /// # Errors
    ///
    /// Returns [`RelayDiscoveryError::InvalidAcceptedKind`] when the
    /// numeric portion does not parse as a `u16`.
    pub fn parse(token: &str) -> Result<Self, RelayDiscoveryError> {
        let (accepted, raw) = token
            .strip_prefix('!')
            .map_or((true, token), |rest| (false, rest));
        let kind = raw
            .parse::<u16>()
            .map(Kind::from)
            .map_err(|_| RelayDiscoveryError::InvalidAcceptedKind(token.to_owned()))?;
        Ok(Self { kind, accepted })
    }
}

/// One `rtt-*` measurement.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RoundTripTime {
    /// Phase the measurement applies to (`open`, `read`, `write`,
    /// custom).
    pub phase: String,
    /// Round-trip time in milliseconds (per spec).
    pub milliseconds: u64,
}

impl RoundTripTime {
    /// Construct a measurement.
    #[must_use]
    pub fn new(phase: impl Into<String>, milliseconds: u64) -> Self {
        Self {
            phase: phase.into(),
            milliseconds,
        }
    }

    /// Wire tag name (`rtt-<phase>`).
    #[must_use]
    pub fn tag_name(&self) -> String {
        format!("{RTT_PREFIX}{}", self.phase)
    }
}

/// What the monitor's `d` tag identifies. The spec lets monitors use
/// either a relay URL or, for relays unreachable by URL, a hex pubkey.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DiscoveryTarget {
    /// Relay URL (normalised per RFC 3986 §6).
    Url(String),
    /// Hex-encoded pubkey for relays unreachable by URL.
    Pubkey(String),
}

impl DiscoveryTarget {
    /// Wire string value.
    #[must_use]
    #[expect(
        clippy::missing_const_for_fn,
        reason = "borrows from an owned `String` inside each variant"
    )]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Url(s) | Self::Pubkey(s) => s.as_str(),
        }
    }
}

/// Typed bundle for a `kind: 30166` relay discovery event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayDiscovery {
    /// `d` tag — the relay being described.
    pub target: DiscoveryTarget,
    /// Optional NIP-11 document carried verbatim in `.content`.
    pub nip11_document: Option<String>,
    /// `n` — network type (`clearnet`, `tor`, `i2p`, `loki`, custom).
    pub network: Option<String>,
    /// `T` — `PascalCase` relay type.
    pub relay_type: Option<String>,
    /// `N` — supported NIP numbers.
    pub supported_nips: Vec<u16>,
    /// `R` — requirements with the `!` boolean convention.
    pub requirements: Vec<RelayRequirement>,
    /// `t` — topics.
    pub topics: Vec<String>,
    /// `k` — accepted/rejected kinds.
    pub accepted_kinds: Vec<AcceptedKind>,
    /// `g` — geohash.
    pub geohash: Option<String>,
    /// `rtt-*` — round-trip measurements.
    pub round_trip_times: Vec<RoundTripTime>,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

impl RelayDiscovery {
    /// Construct an empty discovery row for `target`.
    #[must_use]
    pub const fn new(target: DiscoveryTarget) -> Self {
        Self {
            target,
            nip11_document: None,
            network: None,
            relay_type: None,
            supported_nips: Vec::new(),
            requirements: Vec::new(),
            topics: Vec::new(),
            accepted_kinds: Vec::new(),
            geohash: None,
            round_trip_times: Vec::new(),
            extra_tags: Vec::new(),
        }
    }

    /// Set the NIP-11 document.
    #[must_use]
    pub fn nip11_document(mut self, document: impl Into<String>) -> Self {
        self.nip11_document = Some(document.into());
        self
    }

    /// Set [`Self::network`].
    #[must_use]
    pub fn network(mut self, network: impl Into<String>) -> Self {
        self.network = Some(network.into());
        self
    }

    /// Set [`Self::relay_type`].
    #[must_use]
    pub fn relay_type(mut self, relay_type: impl Into<String>) -> Self {
        self.relay_type = Some(relay_type.into());
        self
    }

    /// Append a supported NIP.
    #[must_use]
    pub fn supported_nip(mut self, nip: u16) -> Self {
        self.supported_nips.push(nip);
        self
    }

    /// Append a requirement.
    #[must_use]
    pub fn requirement(mut self, requirement: RelayRequirement) -> Self {
        self.requirements.push(requirement);
        self
    }

    /// Append a topic.
    #[must_use]
    pub fn topic(mut self, topic: impl Into<String>) -> Self {
        self.topics.push(topic.into());
        self
    }

    /// Append an accepted/rejected kind.
    #[must_use]
    pub fn accepted_kind(mut self, value: AcceptedKind) -> Self {
        self.accepted_kinds.push(value);
        self
    }

    /// Set [`Self::geohash`].
    #[must_use]
    pub fn geohash(mut self, geohash: impl Into<String>) -> Self {
        self.geohash = Some(geohash.into());
        self
    }

    /// Append a round-trip measurement.
    #[must_use]
    pub fn rtt(mut self, rtt: RoundTripTime) -> Self {
        self.round_trip_times.push(rtt);
        self
    }

    /// Parse a `kind: 30166` event into a typed bundle.
    ///
    /// # Errors
    ///
    /// - [`RelayDiscoveryError::WrongKind`] for non-30166 events.
    /// - [`RelayDiscoveryError::MissingIdentifier`] when the `d`
    ///   tag is absent.
    /// - Field-specific errors for malformed columns.
    pub fn from_event(event: &Event) -> Result<Self, RelayDiscoveryError> {
        if event.kind != KIND_RELAY_DISCOVERY {
            return Err(RelayDiscoveryError::WrongKind(event.kind));
        }
        let d = d_value(&event.tags)
            .ok_or(RelayDiscoveryError::MissingIdentifier)?
            .to_owned();
        let target = if is_hex_pubkey(&d) {
            DiscoveryTarget::Pubkey(d)
        } else {
            DiscoveryTarget::Url(d)
        };
        let nip11_document = if event.content.is_empty() {
            None
        } else {
            Some(event.content.clone())
        };
        let mut out = Self::new(target);
        out.nip11_document = nip11_document;
        for tag in &event.tags {
            absorb_discovery_tag(tag, &mut out)?;
        }
        Ok(out)
    }
}

fn absorb_discovery_tag(tag: &Tag, out: &mut RelayDiscovery) -> Result<(), RelayDiscoveryError> {
    match tag.kind() {
        TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::D => {}
        TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::G => {
            out.geohash = tag.get(1).map(str::to_owned);
        }
        _ if tag.name() == NETWORK_TAG => out.network = tag.get(1).map(str::to_owned),
        _ if tag.name() == RELAY_TYPE_TAG => out.relay_type = tag.get(1).map(str::to_owned),
        _ if tag.name() == NIP_TAG => absorb_nip_tag(tag, &mut out.supported_nips)?,
        _ if tag.name() == REQUIREMENT_TAG => {
            if let Some(raw) = tag.get(1) {
                out.requirements.push(RelayRequirement::parse(raw));
            }
        }
        _ if tag.name() == TOPIC_TAG => {
            if let Some(raw) = tag.get(1) {
                out.topics.push(raw.to_owned());
            }
        }
        _ if tag.name() == KIND_TAG => {
            if let Some(raw) = tag.get(1) {
                out.accepted_kinds.push(AcceptedKind::parse(raw)?);
            }
        }
        _ if tag.name().starts_with(RTT_PREFIX) => {
            absorb_rtt_tag(tag, &mut out.round_trip_times)?;
        }
        _ => out.extra_tags.push(tag.clone()),
    }
    Ok(())
}

fn absorb_nip_tag(tag: &Tag, out: &mut Vec<u16>) -> Result<(), RelayDiscoveryError> {
    let Some(raw) = tag.get(1) else {
        return Ok(());
    };
    let parsed = raw
        .parse::<u16>()
        .map_err(|_| RelayDiscoveryError::InvalidNip(raw.to_owned()))?;
    out.push(parsed);
    Ok(())
}

fn absorb_rtt_tag(tag: &Tag, out: &mut Vec<RoundTripTime>) -> Result<(), RelayDiscoveryError> {
    let Some(raw) = tag.get(1) else {
        return Ok(());
    };
    let ms = raw
        .parse::<u64>()
        .map_err(|_| RelayDiscoveryError::InvalidRtt(raw.to_owned()))?;
    let phase = tag.name()[RTT_PREFIX.len()..].to_owned();
    out.push(RoundTripTime {
        phase,
        milliseconds: ms,
    });
    Ok(())
}

fn is_hex_pubkey(input: &str) -> bool {
    input.len() == 64 && input.chars().all(|c| c.is_ascii_hexdigit())
}

/// One row inside a `kind: 10166` monitor's `timeout` matrix.
///
/// The spec leaves the column ordering slightly ambiguous: index 1
/// MAY be the milliseconds value, and index 2 MAY be the check name
/// the timeout applies to — or it MAY be reversed. The parser sniffs
/// the numeric column so either ordering decodes cleanly.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MonitorTimeout {
    /// Optional check name the timeout applies to. `None` means the
    /// timeout applies to every check the monitor performs (spec
    /// §"Tags").
    pub check: Option<String>,
    /// Timeout in milliseconds.
    pub milliseconds: u64,
}

impl MonitorTimeout {
    /// Construct a global timeout (no check scope).
    #[must_use]
    pub const fn new(milliseconds: u64) -> Self {
        Self {
            check: None,
            milliseconds,
        }
    }

    /// Attach a check-name scope.
    #[must_use]
    pub fn for_check(mut self, check: impl Into<String>) -> Self {
        self.check = Some(check.into());
        self
    }
}

/// Typed bundle for a `kind: 10166` relay monitor announcement.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RelayMonitor {
    /// `frequency` — seconds between successive 30166 publications.
    pub frequency_seconds: Option<u64>,
    /// `timeout` rows.
    pub timeouts: Vec<MonitorTimeout>,
    /// `c` — lowercase check names (`open`, `read`, `write`, …).
    pub checks: Vec<String>,
    /// `g` — geohash.
    pub geohash: Option<String>,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

impl RelayMonitor {
    /// Construct an empty monitor announcement.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set [`Self::frequency_seconds`].
    #[must_use]
    pub const fn frequency_seconds(mut self, seconds: u64) -> Self {
        self.frequency_seconds = Some(seconds);
        self
    }

    /// Append a timeout row.
    #[must_use]
    pub fn timeout(mut self, timeout: MonitorTimeout) -> Self {
        self.timeouts.push(timeout);
        self
    }

    /// Append a check name.
    #[must_use]
    pub fn check(mut self, name: impl Into<String>) -> Self {
        self.checks.push(name.into());
        self
    }

    /// Set [`Self::geohash`].
    #[must_use]
    pub fn geohash(mut self, geohash: impl Into<String>) -> Self {
        self.geohash = Some(geohash.into());
        self
    }

    /// Parse a `kind: 10166` event into a typed bundle.
    ///
    /// # Errors
    ///
    /// - [`RelayDiscoveryError::WrongKind`] for non-10166 events.
    /// - Field-specific errors for malformed columns.
    pub fn from_event(event: &Event) -> Result<Self, RelayDiscoveryError> {
        if event.kind != KIND_RELAY_MONITOR {
            return Err(RelayDiscoveryError::WrongKind(event.kind));
        }
        let mut out = Self::new();
        for tag in &event.tags {
            absorb_monitor_tag(tag, &mut out)?;
        }
        Ok(out)
    }
}

fn absorb_monitor_tag(tag: &Tag, out: &mut RelayMonitor) -> Result<(), RelayDiscoveryError> {
    match tag.kind() {
        TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::G => {
            out.geohash = tag.get(1).map(str::to_owned);
        }
        _ if tag.name() == FREQUENCY_TAG => {
            if let Some(raw) = tag.get(1) {
                let seconds = raw
                    .parse::<u64>()
                    .map_err(|_| RelayDiscoveryError::InvalidFrequency(raw.to_owned()))?;
                out.frequency_seconds = Some(seconds);
            }
        }
        _ if tag.name() == TIMEOUT_TAG => out.timeouts.push(parse_timeout(tag)?),
        _ if tag.name() == CHECK_TAG => {
            if let Some(raw) = tag.get(1) {
                out.checks.push(raw.to_owned());
            }
        }
        _ => out.extra_tags.push(tag.clone()),
    }
    Ok(())
}

fn parse_timeout(tag: &Tag) -> Result<MonitorTimeout, RelayDiscoveryError> {
    let col1 = tag.get(1).ok_or(RelayDiscoveryError::MalformedTimeout)?;
    let col2 = tag.get(2);
    if let Ok(ms) = col1.parse::<u64>() {
        let check = col2.filter(|s| !s.is_empty()).map(str::to_owned);
        return Ok(MonitorTimeout {
            check,
            milliseconds: ms,
        });
    }
    // Fall back to the spec-example ordering: `["timeout", "<check>",
    // "<ms>"]`.
    let ms_str = col2.ok_or(RelayDiscoveryError::MalformedTimeout)?;
    let ms = ms_str
        .parse::<u64>()
        .map_err(|_| RelayDiscoveryError::InvalidTimeout(ms_str.to_owned()))?;
    Ok(MonitorTimeout {
        check: Some(col1.to_owned()),
        milliseconds: ms,
    })
}

fn d_value(tags: &Tags) -> Option<&str> {
    let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::D));
    tags.find_first(&head).and_then(|tag| tag.get(1))
}

/// Errors raised by NIP-66 parsers.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RelayDiscoveryError {
    /// The event did not match the expected NIP-66 kind.
    #[error("unexpected kind for NIP-66 event: {}", .0.as_u16())]
    WrongKind(Kind),
    /// `d` tag is absent on a 30166 event.
    #[error("NIP-66 discovery event missing `d` tag")]
    MissingIdentifier,
    /// `N` tag value could not be parsed as a `u16`.
    #[error("invalid supported NIP value: `{0}`")]
    InvalidNip(String),
    /// `k` tag value could not be parsed as a `u16`.
    #[error("invalid accepted-kind value: `{0}`")]
    InvalidAcceptedKind(String),
    /// `rtt-*` value could not be parsed as a `u64`.
    #[error("invalid round-trip value: `{0}`")]
    InvalidRtt(String),
    /// `frequency` value could not be parsed as a `u64`.
    #[error("invalid frequency value: `{0}`")]
    InvalidFrequency(String),
    /// `timeout` tag is missing required columns.
    #[error("`timeout` tag is missing required columns")]
    MalformedTimeout,
    /// `timeout` tag value could not be parsed as a `u64`.
    #[error("invalid timeout value: `{0}`")]
    InvalidTimeout(String),
}

impl EventBuilder {
    /// Author a NIP-66 `kind: 30166` relay discovery event.
    #[must_use]
    pub fn relay_discovery(discovery: &RelayDiscovery) -> Self {
        let content = discovery.nip11_document.clone().unwrap_or_default();
        let mut builder = Self::new(KIND_RELAY_DISCOVERY, content);
        builder = builder.tag(Tag::d(discovery.target.as_str()));
        if let Some(n) = &discovery.network {
            builder = builder.tag(Tag::with(&TagKind::from_wire(NETWORK_TAG), [n.clone()]));
        }
        if let Some(t) = &discovery.relay_type {
            builder = builder.tag(Tag::with(&TagKind::from_wire(RELAY_TYPE_TAG), [t.clone()]));
        }
        for nip in &discovery.supported_nips {
            builder = builder.tag(Tag::with(&TagKind::from_wire(NIP_TAG), [nip.to_string()]));
        }
        for req in &discovery.requirements {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(REQUIREMENT_TAG),
                [req.to_token()],
            ));
        }
        for topic in &discovery.topics {
            builder = builder.tag(Tag::with(&TagKind::from_wire(TOPIC_TAG), [topic.clone()]));
        }
        for k in &discovery.accepted_kinds {
            builder = builder.tag(Tag::with(&TagKind::from_wire(KIND_TAG), [k.to_token()]));
        }
        if let Some(g) = &discovery.geohash {
            let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::G));
            builder = builder.tag(Tag::with(&head, [g.clone()]));
        }
        for rtt in &discovery.round_trip_times {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(&rtt.tag_name()),
                [rtt.milliseconds.to_string()],
            ));
        }
        for tag in &discovery.extra_tags {
            builder = builder.tag(tag.clone());
        }
        builder
    }

    /// Author a NIP-66 `kind: 10166` relay monitor announcement.
    #[must_use]
    pub fn relay_monitor(monitor: &RelayMonitor) -> Self {
        let mut builder = Self::new(KIND_RELAY_MONITOR, "");
        for timeout in &monitor.timeouts {
            let tag = timeout.check.as_ref().map_or_else(
                || {
                    Tag::with(
                        &TagKind::from_wire(TIMEOUT_TAG),
                        [timeout.milliseconds.to_string()],
                    )
                },
                |check| {
                    Tag::with(
                        &TagKind::from_wire(TIMEOUT_TAG),
                        [check.clone(), timeout.milliseconds.to_string()],
                    )
                },
            );
            builder = builder.tag(tag);
        }
        if let Some(freq) = monitor.frequency_seconds {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(FREQUENCY_TAG),
                [freq.to_string()],
            ));
        }
        for check in &monitor.checks {
            builder = builder.tag(Tag::with(&TagKind::from_wire(CHECK_TAG), [check.clone()]));
        }
        if let Some(g) = &monitor.geohash {
            let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::G));
            builder = builder.tag(Tag::with(&head, [g.clone()]));
        }
        for tag in &monitor.extra_tags {
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
    fn requirement_parse_round_trip() {
        let rejected = RelayRequirement::parse("!payment");
        assert!(!rejected.enabled);
        assert_eq!(rejected.name, "payment");
        assert_eq!(rejected.to_token(), "!payment");
        let accepted = RelayRequirement::parse("auth");
        assert!(accepted.enabled);
        assert_eq!(accepted.to_token(), "auth");
    }

    #[test]
    fn accepted_kind_parse_round_trip() {
        let rejected = AcceptedKind::parse("!1").unwrap();
        assert!(!rejected.accepted);
        assert_eq!(rejected.kind, Kind::new(1));
        assert_eq!(rejected.to_token(), "!1");
        let accepted = AcceptedKind::parse("30023").unwrap();
        assert!(accepted.accepted);
        assert_eq!(accepted.kind, Kind::new(30_023));
    }

    #[test]
    fn accepted_kind_rejects_non_numeric() {
        assert!(matches!(
            AcceptedKind::parse("abc"),
            Err(RelayDiscoveryError::InvalidAcceptedKind(_))
        ));
    }

    #[test]
    fn relay_discovery_round_trip() {
        let discovery = RelayDiscovery::new(DiscoveryTarget::Url("wss://some.relay/".into()))
            .nip11_document(r#"{"name":"example"}"#)
            .network("clearnet")
            .relay_type("PrivateInbox")
            .supported_nip(40)
            .supported_nip(33)
            .requirement(RelayRequirement::disabled("payment"))
            .requirement(RelayRequirement::enabled("auth"))
            .topic("nsfw")
            .accepted_kind(AcceptedKind::accepted(Kind::new(1)))
            .accepted_kind(AcceptedKind::rejected(Kind::new(5)))
            .geohash("ww8p1r4t8")
            .rtt(RoundTripTime::new("open", 234));
        let event = EventBuilder::relay_discovery(&discovery)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = RelayDiscovery::from_event(&event).unwrap();
        assert_eq!(parsed, discovery);
    }

    #[test]
    fn relay_discovery_hex_pubkey_target() {
        let hex = "0".repeat(64);
        let discovery = RelayDiscovery::new(DiscoveryTarget::Pubkey(hex.clone()));
        let event = EventBuilder::relay_discovery(&discovery)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = RelayDiscovery::from_event(&event).unwrap();
        assert_eq!(parsed.target, DiscoveryTarget::Pubkey(hex));
    }

    #[test]
    fn relay_discovery_wrong_kind_is_rejected() {
        let event = EventBuilder::text_note("nope")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            RelayDiscovery::from_event(&event),
            Err(RelayDiscoveryError::WrongKind(_))
        ));
    }

    #[test]
    fn relay_discovery_missing_identifier_is_rejected() {
        let event = EventBuilder::new(KIND_RELAY_DISCOVERY, "")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            RelayDiscovery::from_event(&event),
            Err(RelayDiscoveryError::MissingIdentifier)
        ));
    }

    #[test]
    fn relay_monitor_round_trip() {
        let monitor = RelayMonitor::new()
            .frequency_seconds(3600)
            .timeout(MonitorTimeout::new(5000).for_check("open"))
            .timeout(MonitorTimeout::new(3000).for_check("read"))
            .check("ws")
            .check("nip11")
            .geohash("ww8p1r4t8");
        let event = EventBuilder::relay_monitor(&monitor)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = RelayMonitor::from_event(&event).unwrap();
        assert_eq!(parsed, monitor);
    }

    #[test]
    fn relay_monitor_tolerates_alternate_timeout_column_order() {
        // Spec example uses `["timeout", "<check>", "<ms>"]`.
        let event = EventBuilder::new(KIND_RELAY_MONITOR, "")
            .tag(Tag::with(
                &TagKind::from_wire(TIMEOUT_TAG),
                ["open", "5000"],
            ))
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = RelayMonitor::from_event(&event).unwrap();
        assert_eq!(
            parsed.timeouts,
            vec![MonitorTimeout::new(5000).for_check("open")]
        );
    }

    #[test]
    fn monitor_wrong_kind_is_rejected() {
        let event = EventBuilder::text_note("nope")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            RelayMonitor::from_event(&event),
            Err(RelayDiscoveryError::WrongKind(_))
        ));
    }
}
