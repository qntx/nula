//! [NIP-48] Proxy Tags.
//!
//! Bridge events authored by relays / federations / RSS scrapers can
//! attach a `["proxy", <id>, <protocol>]` tag pointing back at the
//! original object on its native protocol. The protocol token is
//! extensible — the spec lists `activitypub`, `atproto`, `rss`, and
//! `web` but explicitly allows new tokens.
//!
//! [NIP-48]: https://github.com/nostr-protocol/nips/blob/master/48.md

use thiserror::Error;

use crate::event::{Tag, TagKind, Tags};

const PROXY_TAG: &str = "proxy";

/// Spec-listed proxy protocols plus a forward-compatible passthrough.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProxyProtocol {
    /// `activitypub` (Mastodon / Pleroma / Misskey URLs).
    ActivityPub,
    /// `atproto` (Bluesky AT URIs).
    AtProto,
    /// `rss` (URL with `#guid` fragment).
    Rss,
    /// `web` (any HTTP URL).
    Web,
    /// Extensible passthrough for unknown protocol tokens.
    Custom(String),
}

impl ProxyProtocol {
    /// Wire token.
    #[must_use]
    #[expect(
        clippy::missing_const_for_fn,
        reason = "`Self::Custom` borrows from a heap `String`"
    )]
    pub fn as_str(&self) -> &str {
        match self {
            Self::ActivityPub => "activitypub",
            Self::AtProto => "atproto",
            Self::Rss => "rss",
            Self::Web => "web",
            Self::Custom(s) => s.as_str(),
        }
    }

    /// Parse a wire token. Always succeeds: unknown tokens decode
    /// as [`Self::Custom`].
    #[must_use]
    pub fn parse(token: &str) -> Self {
        match token {
            "activitypub" => Self::ActivityPub,
            "atproto" => Self::AtProto,
            "rss" => Self::Rss,
            "web" => Self::Web,
            _ => Self::Custom(token.to_owned()),
        }
    }
}

/// A `proxy` tag value.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProxyTag {
    /// Source object id.
    pub id: String,
    /// Source protocol.
    pub protocol: ProxyProtocol,
}

/// Errors raised while parsing a proxy tag.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProxyTagError {
    /// `proxy` tag missing the id column.
    #[error("`proxy` tag missing source id")]
    MissingId,
    /// `proxy` tag missing the protocol column.
    #[error("`proxy` tag missing source protocol")]
    MissingProtocol,
    /// Tag head is not `proxy`.
    #[error("tag is not `proxy`")]
    WrongTag,
}

impl ProxyTag {
    /// Construct a proxy tag.
    #[must_use]
    pub fn new(id: impl Into<String>, protocol: ProxyProtocol) -> Self {
        Self {
            id: id.into(),
            protocol,
        }
    }

    /// Render as a [`Tag`].
    #[must_use]
    pub fn to_tag(&self) -> Tag {
        Tag::with(
            &TagKind::from_wire(PROXY_TAG),
            [self.id.clone(), self.protocol.as_str().to_owned()],
        )
    }

    /// Parse a `proxy` tag.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyTagError`] when the wire shape is malformed.
    pub fn from_tag(tag: &Tag) -> Result<Self, ProxyTagError> {
        if tag.name() != PROXY_TAG {
            return Err(ProxyTagError::WrongTag);
        }
        let id = tag.get(1).ok_or(ProxyTagError::MissingId)?.to_owned();
        let protocol_token = tag.get(2).ok_or(ProxyTagError::MissingProtocol)?;
        Ok(Self {
            id,
            protocol: ProxyProtocol::parse(protocol_token),
        })
    }
}

/// Walk all `proxy` tags on an event.
///
/// # Errors
///
/// Returns the first malformed tag's [`ProxyTagError`].
pub fn proxies_from_tags(tags: &Tags) -> Result<Vec<ProxyTag>, ProxyTagError> {
    let mut out: Vec<ProxyTag> = Vec::new();
    for tag in tags {
        if tag.name() == PROXY_TAG {
            out.push(ProxyTag::from_tag(tag)?);
        }
    }
    Ok(out)
}

impl Tag {
    /// Build a [`NIP-48`](crate::nips::nip48) `proxy` tag.
    #[must_use]
    pub fn proxy(id: impl Into<String>, protocol: ProxyProtocol) -> Self {
        ProxyTag::new(id, protocol).to_tag()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_tag_round_trip() {
        let proxy = ProxyTag::new(
            "https://gleasonator.com/objects/9f524868",
            ProxyProtocol::ActivityPub,
        );
        let tag = proxy.to_tag();
        let parsed = ProxyTag::from_tag(&tag).unwrap();
        assert_eq!(parsed, proxy);
    }

    #[test]
    fn protocol_round_trip_custom() {
        let proxy = ProxyTag::new("foo", ProxyProtocol::parse("nostr-bridge"));
        assert_eq!(
            proxy.protocol,
            ProxyProtocol::Custom("nostr-bridge".to_owned())
        );
        let tag = proxy.to_tag();
        let parsed = ProxyTag::from_tag(&tag).unwrap();
        assert_eq!(parsed.protocol.as_str(), "nostr-bridge");
    }

    #[test]
    fn missing_columns_is_rejected() {
        let tag = Tag::with(&TagKind::from_wire(PROXY_TAG), ["only-id"]);
        assert!(matches!(
            ProxyTag::from_tag(&tag),
            Err(ProxyTagError::MissingProtocol)
        ));
    }
}
