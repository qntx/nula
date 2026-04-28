// Copyright (c) 2026 QNTX <https://qntx.fun>
// Distributed under the MIT or Apache-2.0 license.

//! [NIP-02] Follow List.
//!
//! NIP-02 publishes the author's follow set as a `kind: 3` event whose `p`
//! tags name the followed pubkeys. The full tag form is:
//!
//! ```text
//! ["p", "<pubkey hex>", "<relay-hint>?", "<petname>?"]
//! ```
//!
//! Empty optional fields are encoded as `""` to preserve column position.
//! The event's `content` historically stored a JSON-encoded relay list
//! (now superseded by NIP-65); the modern crate ignores that field.
//!
//! [NIP-02]: https://github.com/nostr-protocol/nips/blob/master/02.md

use thiserror::Error;

use crate::event::{Alphabet, Event, EventBuilder, Kind, SingleLetterTag, Tag, TagKind};
use crate::key::{PublicKey, PublicKeyError};
use crate::types::{RelayUrl, RelayUrlError};

/// A single follow entry inside a NIP-02 contact list.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Contact {
    /// Followed pubkey.
    pub pubkey: PublicKey,
    /// Optional relay hint where the followee posts.
    pub relay_hint: Option<RelayUrl>,
    /// Optional human-readable petname.
    pub petname: Option<String>,
}

impl Contact {
    /// Construct a bare follow entry (no hint, no petname).
    #[must_use]
    pub const fn new(pubkey: PublicKey) -> Self {
        Self {
            pubkey,
            relay_hint: None,
            petname: None,
        }
    }

    /// Set the relay hint.
    #[must_use]
    pub fn with_relay_hint(mut self, hint: RelayUrl) -> Self {
        self.relay_hint = Some(hint);
        self
    }

    /// Set the petname.
    #[must_use]
    pub fn with_petname(mut self, petname: impl Into<String>) -> Self {
        self.petname = Some(petname.into());
        self
    }
}

/// Ordered NIP-02 contact list.
///
/// The order is preserved: it is meaningful for clients that render
/// follow lists, and for "I just followed X" diffs against the previous
/// contact list event.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ContactList {
    /// Contacts in insertion order.
    pub contacts: Vec<Contact>,
}

impl ContactList {
    /// Construct an empty contact list.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a contact and return `self` for chaining.
    #[must_use]
    pub fn follow(mut self, contact: Contact) -> Self {
        self.contacts.push(contact);
        self
    }

    /// Number of follows.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.contacts.len()
    }

    /// True if the list has no follows.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.contacts.is_empty()
    }

    /// Render the list as the [`Tag`]s that go into a `kind: 3` event.
    #[must_use]
    pub fn to_tags(&self) -> Vec<Tag> {
        let p_kind = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::P));
        self.contacts
            .iter()
            .map(|c| build_p_tag(&p_kind, c))
            .collect()
    }

    /// Reconstruct a [`ContactList`] from a `kind: 3` [`Event`].
    ///
    /// Tags whose head is not `p` are silently ignored (forward-compat).
    ///
    /// # Errors
    ///
    /// Returns [`ContactListError::UnexpectedKind`] if the event's kind is
    /// not `3`, plus the matching parse error if any `p` tag is malformed.
    pub fn from_event(event: &Event) -> Result<Self, ContactListError> {
        if event.kind != Kind::CONTACTS {
            return Err(ContactListError::UnexpectedKind(event.kind.as_u16()));
        }
        let p_kind = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::P));
        let mut contacts = Vec::with_capacity(event.tags.as_slice().len());
        for tag in &event.tags {
            if tag.kind() != p_kind {
                continue;
            }
            let mut values = tag.values().iter().skip(1);
            let pubkey = values
                .next()
                .ok_or(ContactListError::MissingPubkey)?
                .parse::<PublicKey>()?;
            let relay_hint = match values.next() {
                Some(s) if !s.is_empty() => Some(RelayUrl::parse(s)?),
                _ => None,
            };
            let petname = match values.next() {
                Some(s) if !s.is_empty() => Some(s.clone()),
                _ => None,
            };
            contacts.push(Contact {
                pubkey,
                relay_hint,
                petname,
            });
        }
        Ok(Self { contacts })
    }
}

impl EventBuilder {
    /// Build a `kind: 3` contact list event from `list`.
    ///
    /// The event's `content` is empty per the modern interpretation of
    /// NIP-02 (the legacy relay JSON is replaced by NIP-65).
    #[must_use]
    pub fn contact_list(list: &ContactList) -> Self {
        Self::new(Kind::CONTACTS, "").tags(list.to_tags())
    }
}

fn build_p_tag(p_kind: &TagKind, contact: &Contact) -> Tag {
    let pubkey = contact.pubkey.to_hex();
    let relay = contact
        .relay_hint
        .as_ref()
        .map(|r| r.as_str().to_owned())
        .unwrap_or_default();
    let petname = contact.petname.clone().unwrap_or_default();

    if !petname.is_empty() {
        Tag::with(p_kind, [pubkey, relay, petname])
    } else if !relay.is_empty() {
        Tag::with(p_kind, [pubkey, relay])
    } else {
        Tag::with(p_kind, [pubkey])
    }
}

/// Errors raised when parsing a NIP-02 contact list event.
#[derive(Debug, Clone, Error)]
pub enum ContactListError {
    /// The event's kind was not `3`.
    #[error("expected kind 3, got {0}")]
    UnexpectedKind(u16),
    /// A `p` tag was missing the pubkey value.
    #[error("`p` tag is missing the pubkey value")]
    MissingPubkey,
    /// A `p` tag's pubkey did not parse.
    #[error(transparent)]
    InvalidPubkey(#[from] PublicKeyError),
    /// A `p` tag's relay hint did not parse.
    #[error(transparent)]
    InvalidRelay(#[from] RelayUrlError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;
    use crate::types::Timestamp;

    fn keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003")
            .unwrap()
    }

    fn pk(seed: u8) -> PublicKey {
        let mut bytes = [0u8; 32];
        bytes[31] = seed;
        let sk = crate::SecretKey::from_byte_array(bytes).unwrap();
        *Keys::from_secret_key(sk).public_key()
    }

    #[test]
    fn empty_round_trip() {
        let list = ContactList::new();
        let event = EventBuilder::contact_list(&list)
            .created_at(Timestamp::from_secs(1))
            .sign_with_keys(&keys())
            .unwrap();
        event.verify().unwrap();
        assert_eq!(event.kind, Kind::CONTACTS);
        let parsed = ContactList::from_event(&event).unwrap();
        assert_eq!(parsed, list);
    }

    #[test]
    fn round_trip_with_full_metadata() {
        let list = ContactList::new()
            .follow(
                Contact::new(pk(1))
                    .with_relay_hint(RelayUrl::parse("wss://relay.example/").unwrap())
                    .with_petname("alice"),
            )
            .follow(Contact::new(pk(2)))
            .follow(Contact::new(pk(3)).with_relay_hint(RelayUrl::parse("wss://r.x.com/").unwrap()));
        let event = EventBuilder::contact_list(&list)
            .created_at(Timestamp::from_secs(2))
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = ContactList::from_event(&event).unwrap();
        assert_eq!(parsed, list);
    }

    #[test]
    fn order_is_preserved() {
        let list = ContactList::new()
            .follow(Contact::new(pk(3)))
            .follow(Contact::new(pk(1)))
            .follow(Contact::new(pk(2)));
        let event = EventBuilder::contact_list(&list)
            .created_at(Timestamp::from_secs(3))
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = ContactList::from_event(&event).unwrap();
        assert_eq!(
            parsed.contacts.iter().map(|c| c.pubkey).collect::<Vec<_>>(),
            list.contacts.iter().map(|c| c.pubkey).collect::<Vec<_>>(),
        );
    }

    #[test]
    fn unknown_tags_are_ignored() {
        let event = EventBuilder::new(Kind::CONTACTS, "")
            .created_at(Timestamp::from_secs(4))
            .tags([
                Tag::new(["p", &pk(1).to_hex()]).unwrap(),
                Tag::new(["alt", "ignored"]).unwrap(),
            ])
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = ContactList::from_event(&event).unwrap();
        assert_eq!(parsed.len(), 1);
    }

    #[test]
    fn rejects_wrong_kind() {
        let event = EventBuilder::text_note("not contacts")
            .created_at(Timestamp::from_secs(5))
            .sign_with_keys(&keys())
            .unwrap();
        let err = ContactList::from_event(&event).unwrap_err();
        assert!(matches!(err, ContactListError::UnexpectedKind(1)));
    }

    #[test]
    fn rejects_missing_pubkey() {
        let event = EventBuilder::new(Kind::CONTACTS, "")
            .created_at(Timestamp::from_secs(6))
            .tag(Tag::new(["p"]).unwrap())
            .sign_with_keys(&keys())
            .unwrap();
        let err = ContactList::from_event(&event).unwrap_err();
        assert!(matches!(err, ContactListError::MissingPubkey));
    }
}
