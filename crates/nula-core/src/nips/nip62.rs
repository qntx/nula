//! [NIP-62] Request to Vanish.
//!
//! `kind: 62` is a relay-side delete-everything request bound to the
//! signer's pubkey. The `relay` tag column either targets a specific
//! relay URL or carries the sentinel [`ALL_RELAYS_SENTINEL`] for a
//! global request.
//!
//! Relays MUST honor the request even against paid / restricted
//! pubkeys; the spec also pins that NIP-09 deletion-request events
//! (`kind: 5`) targeting a request-to-vanish event have no effect.
//!
//! [NIP-62]: https://github.com/nostr-protocol/nips/blob/master/62.md

use thiserror::Error;

use crate::event::{Event, EventBuilder, Kind, Tag, TagKind};
use crate::types::{RelayUrl, RelayUrlError};

/// `kind: 62` — request to vanish.
pub const KIND_REQUEST_TO_VANISH: Kind = Kind::REQUEST_TO_VANISH;

/// Sentinel value the spec reserves for the global request shape.
pub const ALL_RELAYS_SENTINEL: &str = "ALL_RELAYS";

const RELAY_TAG: &str = "relay";

/// Per-target shape of the `relay` tag on a request to vanish.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum VanishTarget {
    /// `["relay", "<relay url>"]` — request bound to a single relay.
    Relay(RelayUrl),
    /// `["relay", "ALL_RELAYS"]` — global request targeted at every
    /// relay the client can reach.
    AllRelays,
}

/// Typed bundle for a `kind: 62` request-to-vanish event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestToVanish {
    /// Optional reason / legal notice mirrored from `.content`.
    pub reason: String,
    /// Targets — at least one is required by spec.
    pub targets: Vec<VanishTarget>,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

/// Errors raised while parsing a NIP-62 event.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VanishError {
    /// Event kind is not `62`.
    #[error("unexpected kind for NIP-62 request to vanish: {}", .0.as_u16())]
    WrongKind(Kind),
    /// At least one `relay` tag is required by spec.
    #[error("NIP-62 event missing required `relay` tag")]
    MissingTarget,
    /// A `relay` tag was malformed (missing column 1).
    #[error("`relay` tag missing target")]
    MalformedTarget,
    /// Wrapped relay-URL parser error.
    #[error(transparent)]
    InvalidRelayUrl(#[from] RelayUrlError),
}

impl VanishTarget {
    fn to_tag(&self) -> Tag {
        let head = TagKind::from_wire(RELAY_TAG);
        match self {
            Self::Relay(url) => Tag::with(&head, [url.as_str().to_owned()]),
            Self::AllRelays => Tag::with(&head, [ALL_RELAYS_SENTINEL.to_owned()]),
        }
    }

    fn from_tag(tag: &Tag) -> Result<Self, VanishError> {
        let raw = tag.get(1).ok_or(VanishError::MalformedTarget)?;
        if raw == ALL_RELAYS_SENTINEL {
            Ok(Self::AllRelays)
        } else {
            Ok(Self::Relay(RelayUrl::parse(raw)?))
        }
    }
}

impl RequestToVanish {
    /// Construct a request bound to one or more relays.
    #[must_use]
    pub fn relay(reason: impl Into<String>, relays: Vec<RelayUrl>) -> Self {
        Self {
            reason: reason.into(),
            targets: relays.into_iter().map(VanishTarget::Relay).collect(),
            extra_tags: Vec::new(),
        }
    }

    /// Construct a global request hitting every reachable relay.
    #[must_use]
    pub fn all_relays(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            targets: vec![VanishTarget::AllRelays],
            extra_tags: Vec::new(),
        }
    }

    /// Parse a `kind: 62` request-to-vanish event.
    ///
    /// # Errors
    ///
    /// See [`VanishError`] for the failure modes.
    pub fn from_event(event: &Event) -> Result<Self, VanishError> {
        if event.kind != KIND_REQUEST_TO_VANISH {
            return Err(VanishError::WrongKind(event.kind));
        }
        let mut targets: Vec<VanishTarget> = Vec::new();
        let mut extra_tags: Vec<Tag> = Vec::new();
        for tag in &event.tags {
            if tag.name() == RELAY_TAG {
                targets.push(VanishTarget::from_tag(tag)?);
            } else {
                extra_tags.push(tag.clone());
            }
        }
        if targets.is_empty() {
            return Err(VanishError::MissingTarget);
        }
        Ok(Self {
            reason: event.content.clone(),
            targets,
            extra_tags,
        })
    }
}

impl EventBuilder {
    /// Author a NIP-62 `kind: 62` request-to-vanish event.
    ///
    /// # Errors
    ///
    /// Returns [`VanishError::MissingTarget`] when
    /// [`RequestToVanish::targets`] is empty.
    pub fn request_to_vanish(req: &RequestToVanish) -> Result<Self, VanishError> {
        if req.targets.is_empty() {
            return Err(VanishError::MissingTarget);
        }
        let mut builder = Self::new(KIND_REQUEST_TO_VANISH, req.reason.clone());
        for target in &req.targets {
            builder = builder.tag(target.to_tag());
        }
        for tag in &req.extra_tags {
            builder = builder.tag(tag.clone());
        }
        Ok(builder)
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
    fn relay_target_round_trip() {
        let req = RequestToVanish::relay(
            "GDPR request",
            vec![RelayUrl::parse("wss://relay.example/").unwrap()],
        );
        let event = EventBuilder::request_to_vanish(&req)
            .unwrap()
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = RequestToVanish::from_event(&event).unwrap();
        assert_eq!(parsed, req);
    }

    #[test]
    fn all_relays_round_trip() {
        let req = RequestToVanish::all_relays("legal");
        let event = EventBuilder::request_to_vanish(&req)
            .unwrap()
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = RequestToVanish::from_event(&event).unwrap();
        assert!(matches!(parsed.targets[0], VanishTarget::AllRelays));
    }

    #[test]
    fn missing_target_is_rejected() {
        let req = RequestToVanish {
            reason: "x".into(),
            targets: Vec::new(),
            extra_tags: Vec::new(),
        };
        assert!(matches!(
            EventBuilder::request_to_vanish(&req),
            Err(VanishError::MissingTarget)
        ));
    }

    #[test]
    fn wrong_kind_is_rejected() {
        // A text note is not a NIP-62 request \u2014 the parser must reject it.
        let event = EventBuilder::text_note("nope")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            RequestToVanish::from_event(&event),
            Err(VanishError::WrongKind(_))
        ));
    }

    #[test]
    fn parse_event_with_no_relay_tags_rejected() {
        // A kind-62 event with zero `relay` tags violates the spec.
        let event = EventBuilder::new(KIND_REQUEST_TO_VANISH, "no relay tag here")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            RequestToVanish::from_event(&event),
            Err(VanishError::MissingTarget)
        ));
    }

    #[test]
    fn malformed_relay_tag_is_rejected() {
        // A `relay` tag with only the head column is structurally
        // malformed; the parser should surface MalformedTarget.
        let event = EventBuilder::new(KIND_REQUEST_TO_VANISH, "")
            .tag(Tag::with(
                &TagKind::from_wire(RELAY_TAG),
                Vec::<String>::new(),
            ))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            RequestToVanish::from_event(&event),
            Err(VanishError::MalformedTarget)
        ));
    }
}
