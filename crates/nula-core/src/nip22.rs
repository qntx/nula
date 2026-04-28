//! [NIP-22] Comments.
//!
//! NIP-22 introduces `kind: 1111` events that comment on **any** other
//! Nostr or external identifier (URL, podcast item, …). The tag scheme
//! distinguishes *root* scope (uppercase) from *parent* scope (lowercase):
//!
//! | tag | scope  | content                                            |
//! |-----|--------|----------------------------------------------------|
//! | `E` | root   | regular event id                                   |
//! | `A` | root   | replaceable coordinate (`<kind>:<pubkey>:<id>`)    |
//! | `I` | root   | external identifier (NIP-73)                       |
//! | `K` | root   | event kind                                         |
//! | `P` | root   | author pubkey                                      |
//! | `e` | parent | regular event id                                   |
//! | `a` | parent | replaceable coordinate                             |
//! | `i` | parent | external identifier                                |
//! | `k` | parent | event kind                                         |
//! | `p` | parent | author pubkey                                      |
//!
//! The crate models the three scope flavours through [`CommentScope`] and
//! exposes [`Comment`] as the authoring/parsing struct.
//!
//! [NIP-22]: https://github.com/nostr-protocol/nips/blob/master/22.md

use thiserror::Error;

use crate::event::{
    Coordinate, CoordinateError, Event, EventBuilder, EventId, EventIdError, Kind, Tag, TagKind,
};
use crate::key::{PublicKey, PublicKeyError};
use crate::types::{RelayUrl, RelayUrlError};

/// What a comment is rooted at or replying to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CommentScope {
    /// A regular event id.
    Event {
        /// Target event id.
        id: EventId,
        /// Optional relay hint.
        relay_hint: Option<RelayUrl>,
    },
    /// A parameterized replaceable event coordinate.
    Address {
        /// `(kind, author, identifier)` of the addressable event.
        coordinate: Coordinate,
        /// Optional relay hint.
        relay_hint: Option<RelayUrl>,
    },
    /// An external identifier (NIP-73), e.g. a URL.
    External {
        /// Free-form identifier value.
        value: String,
        /// Optional relay or context hint.
        context: Option<String>,
    },
}

impl CommentScope {
    /// Construct an [`CommentScope::Event`] without a relay hint.
    #[must_use]
    pub const fn event(id: EventId) -> Self {
        Self::Event {
            id,
            relay_hint: None,
        }
    }

    /// Construct an [`CommentScope::Address`] without a relay hint.
    #[must_use]
    pub const fn address(coordinate: Coordinate) -> Self {
        Self::Address {
            coordinate,
            relay_hint: None,
        }
    }

    /// Construct an [`CommentScope::External`] from an identifier.
    #[must_use]
    pub fn external(value: impl Into<String>) -> Self {
        Self::External {
            value: value.into(),
            context: None,
        }
    }
}

/// A NIP-22 `kind: 1111` comment ready to be turned into an [`Event`].
///
/// Both `root` and `parent` are mandatory; if the comment replies directly
/// to the root, set both fields to the same scope.
///
/// # Spec note on `K` / `P` tags
///
/// NIP-22 declares that the `K` (root kind) and `P` (root pubkey) tags
/// "MUST be" present alongside an `E`/`A` root scope. The crate stores
/// them as `Option`s for two practical reasons:
///
/// - the [`CommentScope::External`] flavour has no inherent kind or
///   author (the comment targets a URL, podcast, or NIP-73 identifier),
/// - real-world events from Coracle, Damus and others sometimes ship a
///   comment without the K/P columns, and the lenient parser would
///   otherwise reject them.
///
/// Authors writing new NIP-22 events targeting [`CommentScope::Event`] /
/// [`CommentScope::Address`] roots SHOULD set [`Self::root_kind`] (and
/// the matching parent kind / author hints) so downstream relays can
/// index the comment correctly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comment {
    /// Top of the conversation.
    pub root: CommentScope,
    /// Optional kind hint for the root.
    pub root_kind: Option<Kind>,
    /// Optional author hint for the root.
    pub root_author: Option<PublicKey>,
    /// Direct parent (the message being replied to).
    pub parent: CommentScope,
    /// Optional kind hint for the parent.
    pub parent_kind: Option<Kind>,
    /// Optional author hint for the parent.
    pub parent_author: Option<PublicKey>,
    /// Free-form comment text.
    pub content: String,
}

impl Comment {
    /// Construct a comment whose `parent` equals its `root`.
    #[must_use]
    pub fn top_level(root: CommentScope, content: impl Into<String>) -> Self {
        Self {
            parent: root.clone(),
            parent_kind: None,
            parent_author: None,
            root,
            root_kind: None,
            root_author: None,
            content: content.into(),
        }
    }

    /// Set the root kind hint.
    #[must_use]
    pub const fn with_root_kind(mut self, kind: Kind) -> Self {
        self.root_kind = Some(kind);
        self
    }

    /// Set the root author hint.
    #[must_use]
    pub const fn with_root_author(mut self, author: PublicKey) -> Self {
        self.root_author = Some(author);
        self
    }

    /// Set the parent kind hint.
    #[must_use]
    pub const fn with_parent_kind(mut self, kind: Kind) -> Self {
        self.parent_kind = Some(kind);
        self
    }

    /// Set the parent author hint.
    #[must_use]
    pub const fn with_parent_author(mut self, author: PublicKey) -> Self {
        self.parent_author = Some(author);
        self
    }

    /// Override the parent scope (use when the parent differs from the
    /// root).
    #[must_use]
    pub fn with_parent(mut self, parent: CommentScope) -> Self {
        self.parent = parent;
        self
    }

    /// Render the comment as the [`Tag`]s that go into its `kind: 1111`
    /// event.
    #[must_use]
    pub fn to_tags(&self) -> Vec<Tag> {
        let mut tags = Vec::new();
        push_scope_tags(&mut tags, &self.root, /*root=*/ true);
        if let Some(k) = self.root_kind {
            tags.push(Tag::with(
                &TagKind::from_wire("K"),
                [k.as_u16().to_string()],
            ));
        }
        if let Some(p) = self.root_author {
            tags.push(Tag::with(&TagKind::from_wire("P"), [p.to_hex()]));
        }
        push_scope_tags(&mut tags, &self.parent, /*root=*/ false);
        if let Some(k) = self.parent_kind {
            tags.push(Tag::with(
                &TagKind::from_wire("k"),
                [k.as_u16().to_string()],
            ));
        }
        if let Some(p) = self.parent_author {
            tags.push(Tag::with(&TagKind::from_wire("p"), [p.to_hex()]));
        }
        tags
    }

    /// Reconstruct a [`Comment`] from a `kind: 1111` [`Event`].
    ///
    /// # Errors
    ///
    /// Returns the matching [`Error`] when the event is the wrong
    /// kind, missing one of the required scope tags, or carries malformed
    /// values.
    pub fn from_event(event: &Event) -> Result<Self, Error> {
        if event.kind != Kind::from(1111_u16) {
            return Err(Error::UnexpectedKind(event.kind.as_u16()));
        }

        let mut root: Option<CommentScope> = None;
        let mut parent: Option<CommentScope> = None;
        let mut root_kind: Option<Kind> = None;
        let mut parent_kind: Option<Kind> = None;
        let mut root_author: Option<PublicKey> = None;
        let mut parent_author: Option<PublicKey> = None;

        for tag in &event.tags {
            let head = tag.kind().as_str().to_owned();
            match head.as_str() {
                "E" => root = Some(parse_event_scope(tag)?),
                "A" => root = Some(parse_address_scope(tag)?),
                "I" => root = Some(parse_external_scope(tag)?),
                "K" => root_kind = Some(parse_kind(tag, "K")?),
                "P" => root_author = Some(parse_pubkey(tag, "P")?),
                "e" => parent = Some(parse_event_scope(tag)?),
                "a" => parent = Some(parse_address_scope(tag)?),
                "i" => parent = Some(parse_external_scope(tag)?),
                "k" => parent_kind = Some(parse_kind(tag, "k")?),
                "p" => parent_author = Some(parse_pubkey(tag, "p")?),
                _ => {} // forward-compat
            }
        }

        Ok(Self {
            root: root.ok_or(Error::MissingRoot)?,
            root_kind,
            root_author,
            parent: parent.ok_or(Error::MissingParent)?,
            parent_kind,
            parent_author,
            content: event.content.clone(),
        })
    }
}

impl EventBuilder {
    /// Build a `kind: 1111` event from `comment`.
    #[must_use]
    pub fn comment(comment: &Comment) -> Self {
        Self::new(Kind::from(1111_u16), comment.content.clone()).tags(comment.to_tags())
    }
}

fn push_scope_tags(out: &mut Vec<Tag>, scope: &CommentScope, root: bool) {
    let event_head = if root { "E" } else { "e" };
    let addr_head = if root { "A" } else { "a" };
    let ext_head = if root { "I" } else { "i" };

    match scope {
        CommentScope::Event { id, relay_hint } => {
            let mut values = vec![id.to_hex()];
            if let Some(r) = relay_hint {
                values.push(r.as_str().to_owned());
            }
            out.push(Tag::with(&TagKind::from_wire(event_head), values));
        }
        CommentScope::Address {
            coordinate,
            relay_hint,
        } => {
            let mut values = vec![coordinate.to_wire()];
            if let Some(r) = relay_hint {
                values.push(r.as_str().to_owned());
            }
            out.push(Tag::with(&TagKind::from_wire(addr_head), values));
        }
        CommentScope::External { value, context } => {
            let mut values = vec![value.clone()];
            if let Some(c) = context {
                values.push(c.clone());
            }
            out.push(Tag::with(&TagKind::from_wire(ext_head), values));
        }
    }
}

fn parse_event_scope(tag: &Tag) -> Result<CommentScope, Error> {
    let mut args = tag.values().iter().skip(1);
    let id = args
        .next()
        .ok_or(Error::MissingValue { tag: "E/e" })?
        .parse::<EventId>()?;
    let relay_hint = match args.next() {
        Some(s) if !s.is_empty() => Some(RelayUrl::parse(s)?),
        _ => None,
    };
    Ok(CommentScope::Event { id, relay_hint })
}

fn parse_address_scope(tag: &Tag) -> Result<CommentScope, Error> {
    let mut args = tag.values().iter().skip(1);
    let coordinate = args
        .next()
        .ok_or(Error::MissingValue { tag: "A/a" })?
        .parse::<Coordinate>()?;
    let relay_hint = match args.next() {
        Some(s) if !s.is_empty() => Some(RelayUrl::parse(s)?),
        _ => None,
    };
    Ok(CommentScope::Address {
        coordinate,
        relay_hint,
    })
}

fn parse_external_scope(tag: &Tag) -> Result<CommentScope, Error> {
    let mut args = tag.values().iter().skip(1);
    let value = args
        .next()
        .ok_or(Error::MissingValue { tag: "I/i" })?
        .clone();
    let context = match args.next() {
        Some(s) if !s.is_empty() => Some(s.clone()),
        _ => None,
    };
    Ok(CommentScope::External { value, context })
}

fn parse_kind(tag: &Tag, name: &'static str) -> Result<Kind, Error> {
    let value = tag
        .values()
        .get(1)
        .ok_or(Error::MissingValue { tag: name })?;
    let raw: u16 = value
        .parse()
        .map_err(|_| Error::InvalidKind(value.clone()))?;
    Ok(Kind::from(raw))
}

fn parse_pubkey(tag: &Tag, name: &'static str) -> Result<PublicKey, Error> {
    let value = tag
        .values()
        .get(1)
        .ok_or(Error::MissingValue { tag: name })?;
    Ok(value.parse::<PublicKey>()?)
}

/// Errors raised when parsing a NIP-22 comment event.
#[derive(Debug, Clone, Error)]
#[non_exhaustive]
pub enum Error {
    /// The event's kind was not `1111`.
    #[error("expected kind 1111, got {0}")]
    UnexpectedKind(u16),
    /// The event was missing a root scope tag (`E`/`A`/`I`).
    #[error("comment is missing the root scope tag (E/A/I)")]
    MissingRoot,
    /// The event was missing a parent scope tag (`e`/`a`/`i`).
    #[error("comment is missing the parent scope tag (e/a/i)")]
    MissingParent,
    /// A recognised tag was missing its value.
    #[error("`{tag}` tag is missing its value")]
    MissingValue {
        /// Wire name of the offending tag head.
        tag: &'static str,
    },
    /// A `K`/`k` value did not parse as `u16`.
    #[error("invalid kind value `{0}`")]
    InvalidKind(String),
    /// An `E`/`e` tag's id did not parse.
    #[error(transparent)]
    InvalidEventId(#[from] EventIdError),
    /// An `A`/`a` tag's coordinate did not parse.
    #[error(transparent)]
    InvalidCoordinate(#[from] CoordinateError),
    /// A relay hint did not parse.
    #[error(transparent)]
    InvalidRelay(#[from] RelayUrlError),
    /// A `P`/`p` tag's pubkey did not parse.
    #[error(transparent)]
    InvalidPubkey(#[from] PublicKeyError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;
    use crate::types::Timestamp;

    fn keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    fn pk(seed: u8) -> PublicKey {
        let mut bytes = [0u8; 32];
        bytes[31] = seed;
        let sk = crate::SecretKey::from_byte_array(bytes).unwrap();
        *Keys::from_secret_key(sk).public_key()
    }

    #[test]
    fn top_level_event_round_trip() {
        let id = EventId::from_byte_array([0xaa; 32]);
        let comment = Comment::top_level(CommentScope::event(id), "hello!")
            .with_root_kind(Kind::TEXT_NOTE)
            .with_root_author(pk(1))
            .with_parent_kind(Kind::TEXT_NOTE)
            .with_parent_author(pk(1));
        let event = EventBuilder::comment(&comment)
            .created_at(Timestamp::from_secs(1))
            .sign_with_keys(&keys())
            .unwrap();
        event.verify().unwrap();
        assert_eq!(event.kind, Kind::from(1111_u16));
        let parsed = Comment::from_event(&event).unwrap();
        assert_eq!(parsed, comment);
    }

    #[test]
    fn nested_reply_round_trip() {
        let root_id = EventId::from_byte_array([0x10; 32]);
        let parent_id = EventId::from_byte_array([0x20; 32]);
        let comment = Comment::top_level(CommentScope::event(root_id), "ack")
            .with_parent(CommentScope::event(parent_id))
            .with_root_kind(Kind::TEXT_NOTE)
            .with_root_author(pk(2))
            .with_parent_kind(Kind::TEXT_NOTE)
            .with_parent_author(pk(3));
        let event = EventBuilder::comment(&comment)
            .created_at(Timestamp::from_secs(2))
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = Comment::from_event(&event).unwrap();
        assert_eq!(parsed, comment);
    }

    #[test]
    fn address_scope_round_trip() {
        let coord = Coordinate::new(Kind::from(30_023_u16), pk(4), "long-form-1");
        let comment =
            Comment::top_level(CommentScope::address(coord), "first comment on the article");
        let event = EventBuilder::comment(&comment)
            .created_at(Timestamp::from_secs(3))
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = Comment::from_event(&event).unwrap();
        assert_eq!(parsed, comment);
    }

    #[test]
    fn external_scope_round_trip() {
        let comment = Comment::top_level(
            CommentScope::external("https://example.com/article"),
            "external pointer",
        );
        let event = EventBuilder::comment(&comment)
            .created_at(Timestamp::from_secs(4))
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = Comment::from_event(&event).unwrap();
        assert_eq!(parsed, comment);
    }

    #[test]
    fn rejects_wrong_kind() {
        let event = EventBuilder::text_note("not a comment")
            .created_at(Timestamp::from_secs(5))
            .sign_with_keys(&keys())
            .unwrap();
        let err = Comment::from_event(&event).unwrap_err();
        assert!(matches!(err, Error::UnexpectedKind(1)));
    }

    #[test]
    fn rejects_missing_root() {
        let event = EventBuilder::new(Kind::from(1111_u16), "")
            .created_at(Timestamp::from_secs(6))
            .tag(Tag::new(["e", &EventId::from_byte_array([0u8; 32]).to_hex()]).unwrap())
            .sign_with_keys(&keys())
            .unwrap();
        let err = Comment::from_event(&event).unwrap_err();
        assert!(matches!(err, Error::MissingRoot));
    }

    #[test]
    fn rejects_missing_parent() {
        let event = EventBuilder::new(Kind::from(1111_u16), "")
            .created_at(Timestamp::from_secs(7))
            .tag(Tag::new(["E", &EventId::from_byte_array([0u8; 32]).to_hex()]).unwrap())
            .sign_with_keys(&keys())
            .unwrap();
        let err = Comment::from_event(&event).unwrap_err();
        assert!(matches!(err, Error::MissingParent));
    }
}
