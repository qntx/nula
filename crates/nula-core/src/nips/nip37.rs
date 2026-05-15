//! [NIP-37] Draft Wraps.
//!
//! Two kinds:
//!
//! - `kind: 31234` — encrypted draft. The unsigned wrapped event is
//!   JSON-stringified, NIP-44-encrypted to the signer's own pubkey,
//!   and stored in `.content`. The plaintext draft kind is recorded in
//!   a `k` tag.
//! - `kind: 10013` — private storage relay list. Relay URLs are
//!   carried inside NIP-44-encrypted private tags within `.content`,
//!   following the same pattern as NIP-51 lists.
//!
//! All encryption helpers require the `nip44` feature.
//!
//! [NIP-37]: https://github.com/nostr-protocol/nips/blob/master/37.md

use thiserror::Error;

use crate::event::{Event, EventBuilder, Kind, Tag, TagKind};
use crate::key::{PublicKey, SecretKey};
use crate::nips::nip44::{self, Nip44Error};
use crate::types::{RelayUrl, RelayUrlError, Timestamp, TimestampError};

/// `kind: 31234` — draft wrap.
pub const KIND_DRAFT_WRAP: Kind = Kind::DRAFT_WRAP;

/// `kind: 10013` — private storage relay list.
pub const KIND_PRIVATE_STORAGE_RELAYS: Kind = Kind::PRIVATE_STORAGE_RELAYS;

const KIND_TAG: &str = "k";
const EXPIRATION_TAG: &str = "expiration";
const RELAY_TAG: &str = "relay";

/// Typed bundle for a `kind: 31234` draft wrap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftWrap {
    /// `d` identifier.
    pub identifier: String,
    /// Wrapped draft kind (per `k` tag).
    pub draft_kind: Kind,
    /// Optional NIP-40 `expiration` deadline.
    pub expiration: Option<Timestamp>,
    /// NIP-44 ciphertext of the wrapped draft event JSON. An empty
    /// string signals the draft has been deleted (per spec).
    pub ciphertext: String,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

/// Typed bundle for a `kind: 10013` private storage relay list.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PrivateStorageRelays {
    /// NIP-44 ciphertext of the encrypted relay tag list.
    pub ciphertext: String,
    /// Forward-compatible passthrough for unknown public tags.
    pub extra_tags: Vec<Tag>,
}

/// Errors raised by NIP-37 helpers.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DraftError {
    /// Event kind is not `31234` / `10013`.
    #[error("unexpected kind for NIP-37 event: {}", .0.as_u16())]
    WrongKind(Kind),
    /// `d` tag missing on a draft wrap.
    #[error("draft wrap missing `d` identifier")]
    MissingIdentifier,
    /// `k` tag missing on a draft wrap.
    #[error("draft wrap missing `k` tag (wrapped draft kind)")]
    MissingDraftKind,
    /// `k` tag value is not a valid kind integer.
    #[error("draft wrap `k` tag value `{0}` is not a valid kind")]
    InvalidDraftKind(String),
    /// Wrapped timestamp parser error.
    #[error(transparent)]
    InvalidTimestamp(#[from] TimestampError),
    /// Wrapped NIP-44 error.
    #[error(transparent)]
    Encryption(#[from] Nip44Error),
    /// JSON serialisation error.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Wrapped relay-URL parser error (private list).
    #[error(transparent)]
    InvalidRelayUrl(#[from] RelayUrlError),
}

impl DraftWrap {
    /// Construct a draft wrap with the ciphertext seeded.
    #[must_use]
    pub fn new(
        identifier: impl Into<String>,
        draft_kind: Kind,
        ciphertext: impl Into<String>,
    ) -> Self {
        Self {
            identifier: identifier.into(),
            draft_kind,
            expiration: None,
            ciphertext: ciphertext.into(),
            extra_tags: Vec::new(),
        }
    }

    /// Author a fresh draft, encrypting `plaintext_event_json` to the
    /// signer's own pubkey via NIP-44.
    ///
    /// # Errors
    ///
    /// Propagates [`Nip44Error`] when encryption fails.
    pub fn encrypt(
        identifier: impl Into<String>,
        draft_kind: Kind,
        plaintext_event_json: &str,
        secret: &SecretKey,
        public_key: &PublicKey,
    ) -> Result<Self, DraftError> {
        let ciphertext = nip44::encrypt(secret, public_key, plaintext_event_json)?;
        Ok(Self::new(identifier, draft_kind, ciphertext))
    }

    /// Decrypt the wrapped draft JSON with the signer's own keys.
    ///
    /// Returns `None` when [`Self::ciphertext`] is empty (the spec's
    /// "draft deleted" sentinel).
    ///
    /// # Errors
    ///
    /// Propagates [`Nip44Error`] when decryption fails.
    pub fn decrypt(
        &self,
        secret: &SecretKey,
        public_key: &PublicKey,
    ) -> Result<Option<String>, DraftError> {
        if self.ciphertext.is_empty() {
            return Ok(None);
        }
        Ok(Some(nip44::decrypt(secret, public_key, &self.ciphertext)?))
    }

    /// True when [`Self::ciphertext`] is empty (draft tombstone).
    #[must_use]
    pub const fn is_tombstone(&self) -> bool {
        self.ciphertext.is_empty()
    }

    /// Parse a `kind: 31234` draft wrap event.
    ///
    /// # Errors
    ///
    /// See [`DraftError`] for the failure modes.
    pub fn from_event(event: &Event) -> Result<Self, DraftError> {
        if event.kind != KIND_DRAFT_WRAP {
            return Err(DraftError::WrongKind(event.kind));
        }
        let mut identifier: Option<String> = None;
        let mut draft_kind: Option<Kind> = None;
        let mut expiration: Option<Timestamp> = None;
        let mut extra_tags: Vec<Tag> = Vec::new();
        for tag in &event.tags {
            absorb_draft_tag(
                tag,
                &mut identifier,
                &mut draft_kind,
                &mut expiration,
                &mut extra_tags,
            )?;
        }
        Ok(Self {
            identifier: identifier.ok_or(DraftError::MissingIdentifier)?,
            draft_kind: draft_kind.ok_or(DraftError::MissingDraftKind)?,
            expiration,
            ciphertext: event.content.clone(),
            extra_tags,
        })
    }
}

fn absorb_draft_tag(
    tag: &Tag,
    identifier: &mut Option<String>,
    draft_kind: &mut Option<Kind>,
    expiration: &mut Option<Timestamp>,
    extra_tags: &mut Vec<Tag>,
) -> Result<(), DraftError> {
    match tag.kind() {
        TagKind::SingleLetter(s)
            if !s.uppercase && s.character == crate::event::Alphabet::D && identifier.is_none() =>
        {
            *identifier = tag.get(1).map(str::to_owned);
        }
        _ if tag.name() == KIND_TAG && draft_kind.is_none() => {
            let raw = tag.get(1).ok_or(DraftError::MissingDraftKind)?;
            let value = raw
                .parse::<u16>()
                .map_err(|_| DraftError::InvalidDraftKind(raw.to_owned()))?;
            *draft_kind = Some(Kind::new(value));
        }
        _ if tag.name() == EXPIRATION_TAG => {
            if let Some(raw) = tag.get(1) {
                *expiration = Some(raw.parse::<Timestamp>()?);
            }
        }
        _ => extra_tags.push(tag.clone()),
    }
    Ok(())
}

impl PrivateStorageRelays {
    /// Construct a relay list with the ciphertext seeded.
    #[must_use]
    pub fn new(ciphertext: impl Into<String>) -> Self {
        Self {
            ciphertext: ciphertext.into(),
            extra_tags: Vec::new(),
        }
    }

    /// Encrypt the supplied relay list to the signer's own keys.
    ///
    /// # Errors
    ///
    /// Propagates [`Nip44Error`] / [`serde_json::Error`].
    pub fn encrypt(
        relays: &[RelayUrl],
        secret: &SecretKey,
        public_key: &PublicKey,
    ) -> Result<Self, DraftError> {
        let payload: Vec<Vec<String>> = relays
            .iter()
            .map(|relay| vec![RELAY_TAG.to_owned(), relay.as_str().to_owned()])
            .collect();
        let plaintext = serde_json::to_string(&payload)?;
        let ciphertext = nip44::encrypt(secret, public_key, &plaintext)?;
        Ok(Self::new(ciphertext))
    }

    /// Decrypt the wrapped relay list with the signer's own keys.
    ///
    /// # Errors
    ///
    /// Propagates [`Nip44Error`] / [`serde_json::Error`] /
    /// [`RelayUrlError`].
    pub fn decrypt(
        &self,
        secret: &SecretKey,
        public_key: &PublicKey,
    ) -> Result<Vec<RelayUrl>, DraftError> {
        if self.ciphertext.is_empty() {
            return Ok(Vec::new());
        }
        let plaintext = nip44::decrypt(secret, public_key, &self.ciphertext)?;
        let rows: Vec<Vec<String>> = serde_json::from_str(&plaintext)?;
        let mut relays: Vec<RelayUrl> = Vec::new();
        for row in rows {
            let mut iter = row.into_iter();
            let head = iter.next();
            let value = iter.next();
            if head.as_deref() != Some(RELAY_TAG) {
                continue;
            }
            if let Some(raw) = value {
                relays.push(RelayUrl::parse(&raw)?);
            }
        }
        Ok(relays)
    }

    /// Parse a `kind: 10013` private-storage relay list event.
    ///
    /// # Errors
    ///
    /// See [`DraftError`] for the failure modes.
    pub fn from_event(event: &Event) -> Result<Self, DraftError> {
        if event.kind != KIND_PRIVATE_STORAGE_RELAYS {
            return Err(DraftError::WrongKind(event.kind));
        }
        Ok(Self {
            ciphertext: event.content.clone(),
            extra_tags: event.tags.iter().cloned().collect(),
        })
    }
}

impl EventBuilder {
    /// Author a NIP-37 `kind: 31234` draft wrap.
    #[must_use]
    pub fn draft_wrap(draft: &DraftWrap) -> Self {
        let mut builder = Self::new(KIND_DRAFT_WRAP, draft.ciphertext.clone());
        builder = builder.tag(Tag::d(&draft.identifier)).tag(Tag::with(
            &TagKind::from_wire(KIND_TAG),
            [draft.draft_kind.as_u16().to_string()],
        ));
        if let Some(ts) = draft.expiration {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(EXPIRATION_TAG),
                [ts.as_secs().to_string()],
            ));
        }
        for tag in &draft.extra_tags {
            builder = builder.tag(tag.clone());
        }
        builder
    }

    /// Author a NIP-37 `kind: 10013` private storage relay list.
    #[must_use]
    pub fn private_storage_relays(list: &PrivateStorageRelays) -> Self {
        let mut builder = Self::new(KIND_PRIVATE_STORAGE_RELAYS, list.ciphertext.clone());
        for tag in &list.extra_tags {
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
    fn draft_round_trip() {
        let plaintext = r#"{"kind":1,"content":"hi"}"#;
        let draft = DraftWrap::encrypt(
            "draft-1",
            Kind::TEXT_NOTE,
            plaintext,
            keys().secret_key(),
            keys().public_key(),
        )
        .unwrap();
        let event = EventBuilder::draft_wrap(&draft)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = DraftWrap::from_event(&event).unwrap();
        assert_eq!(parsed.identifier, draft.identifier);
        assert_eq!(parsed.draft_kind, Kind::TEXT_NOTE);
        let decrypted = parsed
            .decrypt(keys().secret_key(), keys().public_key())
            .unwrap();
        assert_eq!(decrypted.as_deref(), Some(plaintext));
    }

    #[test]
    fn tombstone_decrypts_as_none() {
        let draft = DraftWrap::new("d", Kind::TEXT_NOTE, "");
        assert!(draft.is_tombstone());
        let decrypted = draft
            .decrypt(keys().secret_key(), keys().public_key())
            .unwrap();
        assert!(decrypted.is_none());
    }

    #[test]
    fn private_storage_relays_round_trip() {
        let relays = vec![
            RelayUrl::parse("wss://private.example/").unwrap(),
            RelayUrl::parse("wss://other.example/").unwrap(),
        ];
        let list = PrivateStorageRelays::encrypt(&relays, keys().secret_key(), keys().public_key())
            .unwrap();
        let event = EventBuilder::private_storage_relays(&list)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = PrivateStorageRelays::from_event(&event).unwrap();
        let decrypted = parsed
            .decrypt(keys().secret_key(), keys().public_key())
            .unwrap();
        assert_eq!(decrypted, relays);
    }

    #[test]
    fn missing_kind_is_rejected() {
        let event = EventBuilder::new(KIND_DRAFT_WRAP, "ct")
            .tag(Tag::d("foo"))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            DraftWrap::from_event(&event),
            Err(DraftError::MissingDraftKind)
        ));
    }

    #[test]
    fn wrong_kind_is_rejected() {
        // A text note is the canonical \"not a draft wrap\" sample.
        let event = EventBuilder::text_note("not a draft")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            DraftWrap::from_event(&event),
            Err(DraftError::WrongKind(_))
        ));
        // PrivateStorageRelays parser also rejects mismatched kinds.
        assert!(matches!(
            PrivateStorageRelays::from_event(&event),
            Err(DraftError::WrongKind(_))
        ));
    }

    #[test]
    fn invalid_k_tag_is_rejected() {
        // `k` tag value must be a valid `u16` kind \u2014 anything else is a
        // wire-level error per the typed `Kind` invariants.
        let event = EventBuilder::new(KIND_DRAFT_WRAP, "")
            .tag(Tag::d("foo"))
            .tag(Tag::with(
                &TagKind::from_wire(KIND_TAG),
                ["not-a-number".to_owned()],
            ))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            DraftWrap::from_event(&event),
            Err(DraftError::InvalidDraftKind(raw)) if raw == "not-a-number"
        ));
    }
}
