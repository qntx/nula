//! [NIP-85] Trusted Assertions.
//!
//! Web-of-Trust calculations are too heavy for clients, so users
//! declare trusted service providers who publish signed assertion
//! events for client consumption. Assertions are addressable events
//! whose `d` tag names the subject:
//!
//! | Subject            | Kind    | `d` tag value     |
//! |--------------------|---------|-------------------|
//! | User               | `30382` | `<pubkey>`        |
//! | Event              | `30383` | `<event_id>`      |
//! | Addressable event  | `30384` | `<event_address>` |
//! | NIP-73 identifier  | `30385` | `<i-tag>`         |
//!
//! Result values (rank, follower count, zap totals, …) live in flat
//! tags whose names are agreed between providers and clients;
//! [`TrustedAssertion::attribute`] gives typed access without
//! hardcoding the open-ended vocabulary.
//!
//! `kind: 10040` lists the user's authorized providers per
//! `<kind>:<tag>` result type. Private entries are NIP-44-encrypted
//! JSON in `.content`; decryption is signer territory, so
//! [`ProviderList::from_event`] surfaces only the public tags and
//! leaves `.content` untouched.
//!
//! [NIP-85]: https://github.com/nostr-protocol/nips/blob/master/85.md

use thiserror::Error;

use crate::event::{Coordinate, Event, EventBuilder, EventId, Kind, Tag, TagKind};
use crate::key::PublicKey;
use crate::types::RelayUrl;

/// `kind: 30382` — assertion about a user.
pub const KIND_USER_ASSERTION: Kind = Kind::USER_ASSERTION;
/// `kind: 30383` — assertion about a regular event.
pub const KIND_EVENT_ASSERTION: Kind = Kind::EVENT_ASSERTION;
/// `kind: 30384` — assertion about an addressable event.
pub const KIND_ADDRESS_ASSERTION: Kind = Kind::ADDRESS_ASSERTION;
/// `kind: 30385` — assertion about a NIP-73 external identifier.
pub const KIND_EXTERNAL_ID_ASSERTION: Kind = Kind::EXTERNAL_ID_ASSERTION;
/// `kind: 10040` — trusted-provider list.
pub const KIND_TRUSTED_PROVIDER_LIST: Kind = Kind::TRUSTED_PROVIDER_LIST;

/// Subject of a trusted assertion, decoded from `(kind, d-tag)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AssertionSubject {
    /// `kind: 30382` — a user, `d` = hex pubkey.
    User(PublicKey),
    /// `kind: 30383` — a regular event, `d` = hex event id.
    Event(EventId),
    /// `kind: 30384` — an addressable event, `d` = coordinate.
    Address(Coordinate),
    /// `kind: 30385` — a NIP-73 external identifier, `d` = `i`-tag value.
    ExternalId(String),
}

impl AssertionSubject {
    /// The event kind this subject serialises to.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        match self {
            Self::User(_) => KIND_USER_ASSERTION,
            Self::Event(_) => KIND_EVENT_ASSERTION,
            Self::Address(_) => KIND_ADDRESS_ASSERTION,
            Self::ExternalId(_) => KIND_EXTERNAL_ID_ASSERTION,
        }
    }

    /// The `d` tag value this subject serialises to.
    #[must_use]
    pub fn identifier(&self) -> String {
        match self {
            Self::User(pubkey) => pubkey.to_hex(),
            Self::Event(id) => id.to_hex(),
            Self::Address(coordinate) => coordinate.to_wire(),
            Self::ExternalId(id) => id.clone(),
        }
    }
}

/// Typed bundle for a `kind: 30382..=30385` trusted-assertion event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedAssertion {
    /// Assertion subject decoded from `(kind, d-tag)`.
    pub subject: AssertionSubject,
    /// Flat `(name, value)` result attributes, in tag order. The `d`
    /// tag is excluded; multi-valued names (e.g. `t`) repeat.
    pub attributes: Vec<(String, String)>,
}

/// Errors raised while parsing NIP-85 events.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AssertionError {
    /// Event kind is not in `30382..=30385` (or `10040` for lists).
    #[error("unexpected kind for NIP-85: {}", .0.as_u16())]
    WrongKind(Kind),
    /// The required `d` tag is missing.
    #[error("NIP-85 assertion missing required `d` tag")]
    MissingSubject,
    /// The `d` tag value does not decode as the subject the kind implies.
    #[error("NIP-85 `d` tag does not decode as the expected subject: {0}")]
    InvalidSubject(String),
}

impl TrustedAssertion {
    /// Construct an assertion for `subject` with `attributes`.
    #[must_use]
    pub const fn new(subject: AssertionSubject, attributes: Vec<(String, String)>) -> Self {
        Self {
            subject,
            attributes,
        }
    }

    /// First value of the named attribute, if present.
    #[must_use]
    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    /// The `rank` attribute parsed as an integer (spec: norm 0–100).
    #[must_use]
    pub fn rank(&self) -> Option<u8> {
        self.attribute("rank")?.parse().ok()
    }

    /// Parse a `kind: 30382..=30385` trusted-assertion event.
    ///
    /// # Errors
    ///
    /// See [`AssertionError`] for the failure modes.
    pub fn from_event(event: &Event) -> Result<Self, AssertionError> {
        let raw = event
            .tags
            .identifier()
            .ok_or(AssertionError::MissingSubject)?;
        let invalid = || AssertionError::InvalidSubject(raw.to_owned());
        let subject = match event.kind {
            KIND_USER_ASSERTION => {
                AssertionSubject::User(PublicKey::parse(raw).map_err(|_err| invalid())?)
            }
            KIND_EVENT_ASSERTION => {
                AssertionSubject::Event(EventId::parse(raw).map_err(|_err| invalid())?)
            }
            KIND_ADDRESS_ASSERTION => {
                AssertionSubject::Address(Coordinate::parse(raw).map_err(|_err| invalid())?)
            }
            KIND_EXTERNAL_ID_ASSERTION => AssertionSubject::ExternalId(raw.to_owned()),
            other => return Err(AssertionError::WrongKind(other)),
        };
        let attributes = event
            .tags
            .iter()
            .filter(|tag| tag.name() != "d")
            .filter_map(|tag| Some((tag.name().to_owned(), tag.content()?.to_owned())))
            .collect();
        Ok(Self {
            subject,
            attributes,
        })
    }
}

/// One entry of a `kind: 10040` trusted-provider list:
/// `["<kind>:<tag>", "<service pubkey>", "<relay hint>"]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderEntry {
    /// Result type the provider is trusted for, e.g. `30382:rank`.
    pub result_type: String,
    /// The provider's service pubkey.
    pub service: PublicKey,
    /// Relay where the provider publishes its assertions.
    pub relay: Option<RelayUrl>,
}

/// Typed bundle for the public tags of a `kind: 10040` provider list.
///
/// Private entries live NIP-44-encrypted in `.content`; decrypt them
/// with the user's signer and feed the resulting tag array through
/// [`ProviderList::entries_from_tags`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderList {
    /// Publicly declared provider entries.
    pub entries: Vec<ProviderEntry>,
}

impl ProviderList {
    /// Parse a `kind: 10040` trusted-provider list event.
    ///
    /// # Errors
    ///
    /// Returns [`AssertionError::WrongKind`] for other kinds.
    pub fn from_event(event: &Event) -> Result<Self, AssertionError> {
        if event.kind != KIND_TRUSTED_PROVIDER_LIST {
            return Err(AssertionError::WrongKind(event.kind));
        }
        Ok(Self {
            entries: Self::entries_from_tags(event.tags.iter()),
        })
    }

    /// Decode provider entries from a tag iterator. Tags whose head is
    /// not a `<kind>:<tag>` pair or whose pubkey column is malformed
    /// are skipped (forward compatibility).
    pub fn entries_from_tags<'t, I>(tags: I) -> Vec<ProviderEntry>
    where
        I: IntoIterator<Item = &'t Tag>,
    {
        tags.into_iter()
            .filter_map(|tag| {
                let head = tag.name();
                let (kind_part, _tag_part) = head.split_once(':')?;
                kind_part.parse::<u16>().ok()?;
                let service = PublicKey::parse(tag.content()?).ok()?;
                let relay = tag.get(2).and_then(|raw| RelayUrl::parse(raw).ok());
                Some(ProviderEntry {
                    result_type: head.to_owned(),
                    service,
                    relay,
                })
            })
            .collect()
    }
}

impl EventBuilder {
    /// Author a NIP-85 trusted-assertion event (`kind: 30382..=30385`).
    #[must_use]
    pub fn trusted_assertion(assertion: &TrustedAssertion) -> Self {
        let mut builder =
            Self::new(assertion.subject.kind(), "").tag(Tag::d(assertion.subject.identifier()));
        for (name, value) in &assertion.attributes {
            builder = builder.tag(Tag::with(&TagKind::from_wire(name), [value.clone()]));
        }
        builder
    }

    /// Author a `kind: 10040` trusted-provider list from public entries.
    #[must_use]
    pub fn trusted_provider_list<I>(entries: I) -> Self
    where
        I: IntoIterator<Item = ProviderEntry>,
    {
        Self::new(KIND_TRUSTED_PROVIDER_LIST, "").tags(entries.into_iter().map(|entry| {
            let head = TagKind::from_wire(&entry.result_type);
            let mut args = vec![entry.service.to_hex()];
            if let Some(relay) = &entry.relay {
                args.push(relay.as_str().to_owned());
            }
            Tag::with(&head, args)
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;

    fn keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    fn subject_pubkey() -> PublicKey {
        PublicKey::parse("e88a691e98d9987c964521dff60025f60700378a4879180dcbbb4a5027850411")
            .unwrap()
    }

    #[test]
    fn user_assertion_round_trip() {
        let assertion = TrustedAssertion::new(
            AssertionSubject::User(subject_pubkey()),
            vec![
                ("rank".to_owned(), "89".to_owned()),
                ("followers".to_owned(), "1200".to_owned()),
            ],
        );
        let event = EventBuilder::trusted_assertion(&assertion)
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, KIND_USER_ASSERTION);
        let parsed = TrustedAssertion::from_event(&event).unwrap();
        assert_eq!(parsed, assertion);
        assert_eq!(parsed.rank(), Some(89));
        assert_eq!(parsed.attribute("followers"), Some("1200"));
    }

    #[test]
    fn address_assertion_round_trip() {
        let coordinate =
            Coordinate::parse(format!("30023:{}:my-article", subject_pubkey().to_hex())).unwrap();
        let assertion = TrustedAssertion::new(
            AssertionSubject::Address(coordinate.clone()),
            vec![("rank".to_owned(), "42".to_owned())],
        );
        let event = EventBuilder::trusted_assertion(&assertion)
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, KIND_ADDRESS_ASSERTION);
        let parsed = TrustedAssertion::from_event(&event).unwrap();
        assert_eq!(parsed.subject, AssertionSubject::Address(coordinate));
    }

    #[test]
    fn external_id_assertion_round_trip() {
        let assertion = TrustedAssertion::new(
            AssertionSubject::ExternalId("isbn:9780765382030".to_owned()),
            vec![("rank".to_owned(), "77".to_owned())],
        );
        let event = EventBuilder::trusted_assertion(&assertion)
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, KIND_EXTERNAL_ID_ASSERTION);
        let parsed = TrustedAssertion::from_event(&event).unwrap();
        assert_eq!(parsed, assertion);
    }

    #[test]
    fn invalid_subject_is_rejected() {
        let event = EventBuilder::new(KIND_USER_ASSERTION, "")
            .tag(Tag::d("not-a-pubkey"))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            TrustedAssertion::from_event(&event),
            Err(AssertionError::InvalidSubject(_))
        ));
    }

    #[test]
    fn missing_subject_is_rejected() {
        let event = EventBuilder::new(KIND_USER_ASSERTION, "")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            TrustedAssertion::from_event(&event),
            Err(AssertionError::MissingSubject)
        ));
    }

    #[test]
    fn provider_list_round_trip() {
        let entries = vec![
            ProviderEntry {
                result_type: "30382:rank".to_owned(),
                service: subject_pubkey(),
                relay: Some(RelayUrl::parse("wss://nip85.example/").unwrap()),
            },
            ProviderEntry {
                result_type: "30382:zap_amt_sent".to_owned(),
                service: subject_pubkey(),
                relay: None,
            },
        ];
        let event = EventBuilder::trusted_provider_list(entries.clone())
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = ProviderList::from_event(&event).unwrap();
        assert_eq!(parsed.entries, entries);
    }

    #[test]
    fn non_provider_tags_are_skipped() {
        let event = EventBuilder::new(KIND_TRUSTED_PROVIDER_LIST, "")
            .tag(Tag::alt("provider list"))
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = ProviderList::from_event(&event).unwrap();
        assert!(parsed.entries.is_empty());
    }
}
