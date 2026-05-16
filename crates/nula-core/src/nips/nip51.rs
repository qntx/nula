//! [NIP-51] Lists.
//!
//! Curated lists of "things" — pubkeys, events, hashtags, relays,
//! emojis, addressable coordinates, … — under specific kind numbers.
//! Two flavours:
//!
//! - **Standard lists** — replaceable kinds in `10000..=10999`,
//!   exactly one per (pubkey, kind);
//! - **Sets** — addressable kinds in `30000..=39999`, indexed by an
//!   additional `d` tag so a user can keep many.
//!
//! NIP-51 is also the only list spec that adds **per-item privacy**:
//! each list event SHOULD be allowed to carry both a public tag set
//! and an encrypted JSON-of-tags blob in `.content`. The encrypted
//! payload uses the author's *own* keys for both ECDH halves
//! (NIP-44 v2 default; NIP-04 legacy fallback recognised on
//! reading).
//!
//! # Why a typed module
//!
//! Upstream `rust-nostr` ships a thin `From<List> for Vec<Tag>` for
//! a handful of list kinds and **leaves the encryption out
//! entirely**. We model:
//!
//! 1. **Every spec'd kind** as a typed constant on [`Kind`]
//!    ([`crate::Kind::MUTE_LIST`], `BOOKMARK_SET`, …).
//! 2. A typed [`ListItem`] enum that maps the eight item shapes
//!    NIP-51 uses (pubkey, event, address, hashtag, word, relay,
//!    server, emoji, group). Forward-compat passthrough lives at
//!    [`ListItem::Other`].
//! 3. A unified [`List`] bundle with set metadata
//!    (`title` / `description` / `image`), public items, and a
//!    private item list that goes through NIP-44 / NIP-04 as
//!    needed.
//! 4. End-to-end builders / readers via [`EventBuilder::list`] and
//!    [`List::from_event`] (encrypted contents stay sealed unless
//!    the caller hands in the secret key — at which point
//!    [`List::decrypt_private`] populates `private_items`).
//!
//! # Encryption discipline
//!
//! NIP-51 §"Encryption process pseudocode" hands the author's own
//! secret key to *both* sides of the ECDH so a list owner can
//! always decrypt their own private items without involving a peer.
//! On reading we follow spec §"For backward compatibility":
//! NIP-04's tell-tale `?iv=` separator → NIP-04, otherwise NIP-44
//! v2.
//!
//! [NIP-51]: https://github.com/nostr-protocol/nips/blob/master/51.md

use thiserror::Error;

use crate::event::{
    Alphabet, Coordinate, CoordinateError, Event, EventBuilder, EventId, EventIdError, Kind,
    SingleLetterTag, Tag, TagError, TagKind, Tags,
};
#[cfg(feature = "nip44")]
use crate::key::SecretKey;
use crate::key::{PublicKey, PublicKeyError};
use crate::types::{RelayUrl, RelayUrlError};

/// One typed item that lives on a NIP-51 list or set.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ListItem {
    /// `p` tag — pubkey, with optional relay hint and petname.
    Pubkey {
        /// Pubkey.
        pubkey: PublicKey,
        /// Optional relay hint.
        relay_hint: Option<RelayUrl>,
        /// Optional petname.
        petname: Option<String>,
    },
    /// `e` tag — event id, with optional relay hint.
    Event {
        /// Event id.
        id: EventId,
        /// Optional relay hint.
        relay_hint: Option<RelayUrl>,
    },
    /// `a` tag — addressable event coordinate.
    Address {
        /// Coordinate.
        coordinate: Coordinate,
        /// Optional relay hint.
        relay_hint: Option<RelayUrl>,
    },
    /// `t` tag — hashtag (lowercased per NIP-24).
    Hashtag(String),
    /// `word` tag — muted word (NIP-51 §"Mute list").
    Word(String),
    /// `relay` tag — generic relay URL.
    Relay(RelayUrl),
    /// `server` tag — Blossom blob server URL.
    Server(String),
    /// `emoji` tag — NIP-30 custom-emoji entry.
    Emoji {
        /// Shortcode.
        shortcode: String,
        /// Image URL.
        url: String,
    },
    /// `group` tag — NIP-29 group reference.
    Group {
        /// Group id.
        id: String,
        /// Relay URL.
        relay: RelayUrl,
        /// Optional group name.
        name: Option<String>,
    },
    /// Forward-compatible passthrough: any other tag.
    Other(Tag),
}

impl ListItem {
    /// Convert to the wire `Tag`.
    #[must_use]
    pub fn to_tag(&self) -> Tag {
        match self {
            Self::Pubkey {
                pubkey,
                relay_hint,
                petname,
            } => {
                let mut values: Vec<String> = Vec::with_capacity(3);
                values.push(pubkey.to_hex());
                values.push(relay_hint_value(relay_hint.as_ref()));
                if let Some(name) = petname {
                    values.push(name.clone());
                }
                letter_tag(Alphabet::P, values)
            }
            Self::Event { id, relay_hint } => {
                let mut values: Vec<String> = Vec::with_capacity(2);
                values.push(id.to_hex());
                if let Some(r) = relay_hint {
                    values.push(r.as_str().to_owned());
                }
                letter_tag(Alphabet::E, values)
            }
            Self::Address {
                coordinate,
                relay_hint,
            } => {
                let mut values: Vec<String> = Vec::with_capacity(2);
                values.push(coordinate.to_wire());
                if let Some(r) = relay_hint {
                    values.push(r.as_str().to_owned());
                }
                letter_tag(Alphabet::A, values)
            }
            Self::Hashtag(t) => letter_tag(Alphabet::T, [t.clone()]),
            Self::Word(w) => custom_tag("word", [w.clone()]),
            Self::Relay(url) => custom_tag("relay", [url.as_str().to_owned()]),
            Self::Server(url) => custom_tag("server", [url.clone()]),
            Self::Emoji { shortcode, url } => custom_tag("emoji", [shortcode.clone(), url.clone()]),
            Self::Group { id, relay, name } => {
                let mut values: Vec<String> = Vec::with_capacity(3);
                values.push(id.clone());
                values.push(relay.as_str().to_owned());
                if let Some(n) = name {
                    values.push(n.clone());
                }
                custom_tag("group", values)
            }
            Self::Other(tag) => tag.clone(),
        }
    }

    /// Parse a wire tag into a typed item.
    ///
    /// Unknown tag kinds round-trip through [`Self::Other`] so a
    /// list event never silently drops data.
    ///
    /// # Errors
    ///
    /// Forwarded from [`PublicKey::parse`] / [`EventId::parse`] /
    /// [`Coordinate::parse`] / [`RelayUrl::parse`] for the typed
    /// shapes.
    pub fn from_tag(tag: &Tag) -> Result<Self, ListItemError> {
        match tag.kind() {
            TagKind::SingleLetter(s) if !s.uppercase => match s.character {
                Alphabet::P => parse_pubkey(tag),
                Alphabet::E => parse_event(tag),
                Alphabet::A => parse_address(tag),
                Alphabet::T => parse_hashtag(tag),
                _ => Ok(Self::Other(tag.clone())),
            },
            TagKind::Custom(name) if name == "word" => parse_word(tag),
            TagKind::Custom(name) if name == "relay" => parse_relay(tag),
            TagKind::Custom(name) if name == "server" => parse_server(tag),
            TagKind::Custom(name) if name == "emoji" => parse_emoji(tag),
            TagKind::Custom(name) if name == "group" => parse_group(tag),
            _ => Ok(Self::Other(tag.clone())),
        }
    }
}

fn relay_hint_value(hint: Option<&RelayUrl>) -> String {
    hint.map(|r| r.as_str().to_owned()).unwrap_or_default()
}

fn parse_pubkey(tag: &Tag) -> Result<ListItem, ListItemError> {
    let pk_hex = tag.get(1).ok_or(ListItemError::MissingValue("p"))?;
    let pubkey = PublicKey::parse(pk_hex).map_err(ListItemError::InvalidPublicKey)?;
    let relay_hint = match tag.get(2) {
        Some(s) if !s.is_empty() => {
            Some(RelayUrl::parse(s).map_err(ListItemError::InvalidRelayUrl)?)
        }
        _ => None,
    };
    let petname = tag.get(3).map(str::to_owned);
    Ok(ListItem::Pubkey {
        pubkey,
        relay_hint,
        petname,
    })
}

fn parse_event(tag: &Tag) -> Result<ListItem, ListItemError> {
    let id_hex = tag.get(1).ok_or(ListItemError::MissingValue("e"))?;
    let id = EventId::parse(id_hex).map_err(ListItemError::InvalidEventId)?;
    let relay_hint = match tag.get(2) {
        Some(s) if !s.is_empty() => {
            Some(RelayUrl::parse(s).map_err(ListItemError::InvalidRelayUrl)?)
        }
        _ => None,
    };
    Ok(ListItem::Event { id, relay_hint })
}

fn parse_address(tag: &Tag) -> Result<ListItem, ListItemError> {
    let coord_str = tag.get(1).ok_or(ListItemError::MissingValue("a"))?;
    let coordinate = Coordinate::parse(coord_str).map_err(ListItemError::InvalidCoordinate)?;
    let relay_hint = match tag.get(2) {
        Some(s) if !s.is_empty() => {
            Some(RelayUrl::parse(s).map_err(ListItemError::InvalidRelayUrl)?)
        }
        _ => None,
    };
    Ok(ListItem::Address {
        coordinate,
        relay_hint,
    })
}

fn parse_hashtag(tag: &Tag) -> Result<ListItem, ListItemError> {
    Ok(ListItem::Hashtag(
        tag.get(1)
            .ok_or(ListItemError::MissingValue("t"))?
            .to_owned(),
    ))
}

fn parse_word(tag: &Tag) -> Result<ListItem, ListItemError> {
    Ok(ListItem::Word(
        tag.get(1)
            .ok_or(ListItemError::MissingValue("word"))?
            .to_owned(),
    ))
}

fn parse_relay(tag: &Tag) -> Result<ListItem, ListItemError> {
    let url_str = tag.get(1).ok_or(ListItemError::MissingValue("relay"))?;
    let url = RelayUrl::parse(url_str).map_err(ListItemError::InvalidRelayUrl)?;
    Ok(ListItem::Relay(url))
}

fn parse_server(tag: &Tag) -> Result<ListItem, ListItemError> {
    Ok(ListItem::Server(
        tag.get(1)
            .ok_or(ListItemError::MissingValue("server"))?
            .to_owned(),
    ))
}

fn parse_emoji(tag: &Tag) -> Result<ListItem, ListItemError> {
    Ok(ListItem::Emoji {
        shortcode: tag
            .get(1)
            .ok_or(ListItemError::MissingValue("emoji"))?
            .to_owned(),
        url: tag
            .get(2)
            .ok_or(ListItemError::MissingValue("emoji"))?
            .to_owned(),
    })
}

fn parse_group(tag: &Tag) -> Result<ListItem, ListItemError> {
    let id = tag
        .get(1)
        .ok_or(ListItemError::MissingValue("group"))?
        .to_owned();
    let relay_str = tag.get(2).ok_or(ListItemError::MissingValue("group"))?;
    let relay = RelayUrl::parse(relay_str).map_err(ListItemError::InvalidRelayUrl)?;
    let name = tag.get(3).map(str::to_owned);
    Ok(ListItem::Group { id, relay, name })
}

fn letter_tag<I, S>(alphabet: Alphabet, args: I) -> Tag
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let head = TagKind::single_letter(SingleLetterTag::lowercase(alphabet));
    Tag::with(&head, args)
}

fn custom_tag<I, S>(name: &str, args: I) -> Tag
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    Tag::with(&TagKind::Custom(name.to_owned()), args)
}

/// Errors raised while parsing one [`ListItem`] from a tag.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ListItemError {
    /// A required column was missing.
    #[error("`{0}` tag missing value")]
    MissingValue(&'static str),
    /// Pubkey hex did not parse.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(#[source] PublicKeyError),
    /// Event id hex did not parse.
    #[error("invalid event id: {0}")]
    InvalidEventId(#[source] EventIdError),
    /// Coordinate string did not parse.
    #[error("invalid coordinate: {0}")]
    InvalidCoordinate(#[source] CoordinateError),
    /// Relay URL did not parse.
    #[error("invalid relay URL: {0}")]
    InvalidRelayUrl(#[source] RelayUrlError),
}

/// Typed bundle covering every NIP-51 list / set kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct List {
    /// Event kind — pick from the spec'd `Kind::*` constants
    /// ([`crate::Kind::MUTE_LIST`], `BOOKMARK_SET`, …).
    pub kind: Kind,
    /// `d` tag for sets in `30000..=39999`. Spec mandates exactly
    /// one `d` tag per set; standard lists in `10000..=10999` SHOULD
    /// leave this `None`.
    pub identifier: Option<String>,
    /// `title` tag (sets only — spec §"Sets").
    pub title: Option<String>,
    /// `description` tag (sets only).
    pub description: Option<String>,
    /// `image` tag (sets only).
    pub image: Option<String>,
    /// Public items — one per spec'd item tag.
    pub public_items: Vec<ListItem>,
    /// Encrypted-on-the-wire items. Unset for unencrypted lists, or
    /// after a successful [`Self::decrypt_private`].
    pub private_items: Vec<ListItem>,
    /// Raw encrypted blob from `.content` when the list shipped one
    /// but the caller has not yet decrypted it.
    pub encrypted_payload: Option<String>,
}

impl List {
    /// Construct an empty list at the given kind.
    #[must_use]
    pub const fn new(kind: Kind) -> Self {
        Self {
            kind,
            identifier: None,
            title: None,
            description: None,
            image: None,
            public_items: Vec::new(),
            private_items: Vec::new(),
            encrypted_payload: None,
        }
    }

    /// Set the `d`-tag identifier (required for sets).
    #[must_use]
    pub fn identifier(mut self, identifier: impl Into<String>) -> Self {
        self.identifier = Some(identifier.into());
        self
    }

    /// Set the `title` tag.
    #[must_use]
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Set the `description` tag.
    #[must_use]
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Set the `image` tag.
    #[must_use]
    pub fn image(mut self, image: impl Into<String>) -> Self {
        self.image = Some(image.into());
        self
    }

    /// Append a public item.
    #[must_use]
    pub fn public_item(mut self, item: ListItem) -> Self {
        self.public_items.push(item);
        self
    }

    /// Append a private item. These are encrypted into the
    /// `.content` blob at build time via [`Self::encrypt_private`].
    #[must_use]
    pub fn private_item(mut self, item: ListItem) -> Self {
        self.private_items.push(item);
        self
    }

    /// Render the public tags (everything that goes into
    /// `event.tags`, in spec order: identifier → title → image →
    /// description → items).
    #[must_use]
    pub fn to_public_tags(&self) -> Vec<Tag> {
        let mut tags: Vec<Tag> = Vec::with_capacity(4 + self.public_items.len());
        if let Some(id) = &self.identifier {
            tags.push(Tag::d(id));
        }
        if let Some(title) = &self.title {
            tags.push(Tag::title(title));
        }
        if let Some(image) = &self.image {
            tags.push(custom_tag("image", [image.clone()]));
        }
        if let Some(desc) = &self.description {
            tags.push(custom_tag("description", [desc.clone()]));
        }
        for item in &self.public_items {
            tags.push(item.to_tag());
        }
        tags
    }

    /// Encrypt [`Self::private_items`] (if any) into a NIP-44 v2
    /// payload bound to the *author's own* keys per NIP-51
    /// §"Encryption process pseudocode".
    ///
    /// Returns `Ok(Some(payload))` when there were items to
    /// encrypt, `Ok(None)` when the private list was empty.
    ///
    /// # Errors
    ///
    /// Forwarded from [`crate::nips::nip44::encrypt`].
    #[cfg(feature = "nip44")]
    #[cfg_attr(docsrs, doc(cfg(feature = "nip44")))]
    pub fn encrypt_private(
        &self,
        owner_secret: &SecretKey,
        owner_public: &PublicKey,
    ) -> Result<Option<String>, ListEncryptionError> {
        if self.private_items.is_empty() {
            return Ok(None);
        }
        let json =
            serialize_items(&self.private_items).map_err(ListEncryptionError::InvalidJson)?;
        let payload = crate::nips::nip44::encrypt(owner_secret, owner_public, &json)
            .map_err(ListEncryptionError::Encrypt)?;
        Ok(Some(payload))
    }

    /// Decrypt the previously-stored [`Self::encrypted_payload`]
    /// into [`Self::private_items`]. The payload is auto-detected
    /// as NIP-04 (legacy `?iv=` form) or NIP-44 v2.
    ///
    /// Idempotent: the payload is consumed only on success.
    ///
    /// # Errors
    ///
    /// - [`ListEncryptionError::NoPayload`] when nothing has been
    ///   stashed.
    /// - [`ListEncryptionError::Decrypt`] from the underlying
    ///   primitive.
    /// - [`ListEncryptionError::InvalidJson`] when the decrypted
    ///   plaintext is not a JSON array of tag arrays.
    #[cfg(feature = "nip44")]
    #[cfg_attr(docsrs, doc(cfg(feature = "nip44")))]
    pub fn decrypt_private(
        &mut self,
        owner_secret: &SecretKey,
        owner_public: &PublicKey,
    ) -> Result<(), ListEncryptionError> {
        let Some(payload) = self.encrypted_payload.take() else {
            return Err(ListEncryptionError::NoPayload);
        };
        let json = if payload.contains("?iv=") {
            decrypt_nip04(owner_secret, owner_public, &payload)?
        } else {
            crate::nips::nip44::decrypt(owner_secret, owner_public, &payload)
                .map_err(ListEncryptionError::Decrypt)?
        };
        self.private_items = deserialize_items(&json).map_err(ListEncryptionError::InvalidJson)?;
        Ok(())
    }

    /// Parse a NIP-51 list event back into a typed bundle.
    ///
    /// Encrypted private payloads stay as `Some(...)` in
    /// [`Self::encrypted_payload`]; call [`Self::decrypt_private`]
    /// to surface them.
    ///
    /// # Errors
    ///
    /// - [`ListError::InvalidItem`] if any tag is shaped wrong.
    pub fn from_event(event: &Event) -> Result<Self, ListError> {
        Self::from_tags_and_content(event.kind, &event.tags, &event.content)
    }

    fn from_tags_and_content(kind: Kind, tags: &Tags, content: &str) -> Result<Self, ListError> {
        let mut list = Self::new(kind);
        for tag in tags {
            match tag.kind() {
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::D => {
                    list.identifier = tag.get(1).map(str::to_owned);
                }
                TagKind::Custom(name) if name == "title" => {
                    list.title = tag.get(1).map(str::to_owned);
                }
                TagKind::Custom(name) if name == "description" => {
                    list.description = tag.get(1).map(str::to_owned);
                }
                TagKind::Custom(name) if name == "image" => {
                    list.image = tag.get(1).map(str::to_owned);
                }
                _ => {
                    let item = ListItem::from_tag(tag).map_err(ListError::InvalidItem)?;
                    list.public_items.push(item);
                }
            }
        }
        if !content.is_empty() {
            list.encrypted_payload = Some(content.to_owned());
        }
        Ok(list)
    }
}

#[cfg(feature = "nip44")]
fn serialize_items(items: &[ListItem]) -> Result<String, serde_json::Error> {
    let raw: Vec<Vec<String>> = items.iter().map(|i| i.to_tag().values().to_vec()).collect();
    serde_json::to_string(&raw)
}

#[cfg(feature = "nip44")]
fn deserialize_items(json: &str) -> Result<Vec<ListItem>, serde_json::Error> {
    let raw: Vec<Vec<String>> = serde_json::from_str(json)?;
    raw.into_iter()
        .map(|values| {
            let tag = Tag::new(values).map_err(serde_json::Error::custom)?;
            let item = ListItem::from_tag(&tag).map_err(serde_json::Error::custom)?;
            Ok(item)
        })
        .collect()
}

#[cfg(feature = "nip44")]
trait CustomError {
    fn custom<E: std::fmt::Display>(err: E) -> Self;
}

#[cfg(feature = "nip44")]
impl CustomError for serde_json::Error {
    fn custom<E: std::fmt::Display>(err: E) -> Self {
        <Self as serde::de::Error>::custom(err.to_string())
    }
}

#[cfg(all(feature = "nip44", feature = "nip04"))]
fn decrypt_nip04(
    owner_secret: &SecretKey,
    owner_public: &PublicKey,
    payload: &str,
) -> Result<String, ListEncryptionError> {
    crate::nips::nip04::decrypt(owner_secret, owner_public, payload)
        .map_err(ListEncryptionError::Nip04)
}

#[cfg(all(feature = "nip44", not(feature = "nip04")))]
const fn decrypt_nip04(
    _owner_secret: &SecretKey,
    _owner_public: &PublicKey,
    _payload: &str,
) -> Result<String, ListEncryptionError> {
    Err(ListEncryptionError::Nip04Unavailable)
}

/// Errors raised while parsing or building a [`List`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ListError {
    /// One of the tags carried a malformed item value.
    #[error("invalid list item: {0}")]
    InvalidItem(#[source] ListItemError),
    /// A built-in tag value (`Tag::new`) was malformed.
    #[error("invalid tag: {0}")]
    InvalidTag(#[from] TagError),
}

/// Errors raised by the encryption helpers.
#[derive(Debug, Error)]
#[non_exhaustive]
#[cfg(feature = "nip44")]
#[cfg_attr(docsrs, doc(cfg(feature = "nip44")))]
pub enum ListEncryptionError {
    /// No payload was stashed in [`List::encrypted_payload`].
    #[error("no encrypted payload available; call from_event first")]
    NoPayload,
    /// NIP-44 encryption failed.
    #[error("NIP-44 encrypt failed: {0}")]
    Encrypt(#[source] crate::nips::nip44::Nip44Error),
    /// NIP-44 decryption failed.
    #[error("NIP-44 decrypt failed: {0}")]
    Decrypt(#[source] crate::nips::nip44::Nip44Error),
    /// JSON encode/decode failed.
    #[error("invalid JSON inside encrypted payload: {0}")]
    InvalidJson(#[source] serde_json::Error),
    /// NIP-04 fallback was needed but the feature is disabled.
    #[cfg(not(feature = "nip04"))]
    #[error("NIP-04 fallback required but the `nip04` feature is disabled")]
    Nip04Unavailable,
    /// NIP-04 decryption failed.
    #[cfg(feature = "nip04")]
    #[error("NIP-04 decrypt failed: {0}")]
    Nip04(#[source] crate::nips::nip04::Nip04Error),
}

impl EventBuilder {
    /// Author a NIP-51 list event from a [`List`] bundle (no
    /// encryption applied).
    ///
    /// The resulting event has empty `.content`. Use
    /// [`Self::list_with_private_items`] to encrypt private items
    /// in one shot.
    #[must_use]
    pub fn list(list: &List) -> Self {
        let mut builder = Self::new(list.kind, "");
        for tag in list.to_public_tags() {
            builder = builder.tag(tag);
        }
        builder
    }

    /// Author a NIP-51 list event with encrypted private items.
    ///
    /// `owner_secret` / `owner_public` MUST belong to the same
    /// keypair (NIP-51 §"Encryption process pseudocode").
    ///
    /// # Errors
    ///
    /// Forwarded from [`List::encrypt_private`].
    #[cfg(feature = "nip44")]
    #[cfg_attr(docsrs, doc(cfg(feature = "nip44")))]
    pub fn list_with_private_items(
        list: &List,
        owner_secret: &SecretKey,
        owner_public: &PublicKey,
    ) -> Result<Self, ListEncryptionError> {
        let payload = list
            .encrypt_private(owner_secret, owner_public)?
            .unwrap_or_default();
        let mut builder = Self::new(list.kind, payload);
        for tag in list.to_public_tags() {
            builder = builder.tag(tag);
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
    fn mute_list_round_trips_public_items() {
        let pk = *keys().public_key();
        let list = List::new(Kind::MUTE_LIST)
            .public_item(ListItem::Pubkey {
                pubkey: pk,
                relay_hint: None,
                petname: None,
            })
            .public_item(ListItem::Hashtag("spam".to_owned()))
            .public_item(ListItem::Word("crypto".to_owned()))
            .public_item(ListItem::Event {
                id: EventId::from_byte_array([0xab; 32]),
                relay_hint: None,
            });
        let event = EventBuilder::list(&list).sign_with_keys(&keys()).unwrap();
        assert_eq!(event.kind, Kind::MUTE_LIST);
        let parsed = List::from_event(&event).unwrap();
        assert_eq!(parsed.public_items, list.public_items);
        assert!(parsed.encrypted_payload.is_none());
    }

    #[test]
    fn bookmark_set_round_trips_metadata() {
        let list = List::new(Kind::BOOKMARK_SET)
            .identifier("yaks")
            .title("Yaks")
            .description("articles about yaks")
            .image("https://example.com/yak.png")
            .public_item(ListItem::Address {
                coordinate: Coordinate::new(
                    Kind::LONG_FORM_TEXT_NOTE,
                    *keys().public_key(),
                    "yak-1",
                ),
                relay_hint: None,
            });
        let event = EventBuilder::list(&list).sign_with_keys(&keys()).unwrap();
        let parsed = List::from_event(&event).unwrap();
        assert_eq!(parsed.identifier.as_deref(), Some("yaks"));
        assert_eq!(parsed.title.as_deref(), Some("Yaks"));
        assert_eq!(parsed.description.as_deref(), Some("articles about yaks"));
        assert_eq!(parsed.image.as_deref(), Some("https://example.com/yak.png"));
        assert_eq!(parsed.public_items.len(), 1);
    }

    #[test]
    fn relay_set_round_trips_relays() {
        let list = List::new(Kind::RELAY_SET)
            .identifier("default")
            .public_item(ListItem::Relay(
                RelayUrl::parse("wss://relay.example/").unwrap(),
            ));
        let event = EventBuilder::list(&list).sign_with_keys(&keys()).unwrap();
        let parsed = List::from_event(&event).unwrap();
        assert_eq!(parsed.public_items.len(), 1);
        assert!(matches!(&parsed.public_items[0], ListItem::Relay(_)));
    }

    #[test]
    fn unknown_tags_round_trip_as_other() {
        let list = List::new(Kind::INTEREST_SET)
            .identifier("cust")
            .public_item(ListItem::Other(Tag::with(
                &TagKind::Custom("vendor".to_owned()),
                ["xyz"],
            )));
        let event = EventBuilder::list(&list).sign_with_keys(&keys()).unwrap();
        let parsed = List::from_event(&event).unwrap();
        assert_eq!(parsed.public_items.len(), 1);
        match &parsed.public_items[0] {
            ListItem::Other(tag) => assert_eq!(tag.name(), "vendor"),
            other => panic!("expected Other, got {other:?}"),
        }
    }

    #[cfg(feature = "nip44")]
    #[test]
    fn private_items_round_trip_through_nip44() {
        let owner = keys();
        let list = List::new(Kind::MUTE_LIST)
            .public_item(ListItem::Hashtag("public".to_owned()))
            .private_item(ListItem::Hashtag("secret".to_owned()))
            .private_item(ListItem::Pubkey {
                pubkey: *owner.public_key(),
                relay_hint: None,
                petname: None,
            });
        let event =
            EventBuilder::list_with_private_items(&list, owner.secret_key(), owner.public_key())
                .unwrap()
                .sign_with_keys(&owner)
                .unwrap();

        // Public side parsing.
        let mut parsed = List::from_event(&event).unwrap();
        assert_eq!(parsed.public_items.len(), 1);
        assert!(parsed.encrypted_payload.is_some());

        // Private side decrypts cleanly.
        parsed
            .decrypt_private(owner.secret_key(), owner.public_key())
            .unwrap();
        assert_eq!(parsed.private_items.len(), 2);
        assert!(parsed.encrypted_payload.is_none());
    }

    #[test]
    fn pubkey_with_petname_round_trips() {
        let pk = *keys().public_key();
        let list = List::new(Kind::FOLLOW_SET)
            .identifier("close-friends")
            .public_item(ListItem::Pubkey {
                pubkey: pk,
                relay_hint: Some(RelayUrl::parse("wss://relay.example/").unwrap()),
                petname: Some("alice".to_owned()),
            });
        let event = EventBuilder::list(&list).sign_with_keys(&keys()).unwrap();
        let parsed = List::from_event(&event).unwrap();
        match &parsed.public_items[0] {
            ListItem::Pubkey {
                pubkey,
                relay_hint,
                petname,
            } => {
                assert_eq!(*pubkey, pk);
                assert!(relay_hint.is_some());
                assert_eq!(petname.as_deref(), Some("alice"));
            }
            other => panic!("expected Pubkey, got {other:?}"),
        }
    }
}
