//! [NIP-B7] Blossom media — typed event bundle for the user's
//! preferred [Blossom] server list (kind `10063`) plus helpers for
//! the SHA-256-addressed blob URLs Blossom servers expose.
//!
//! # Blossom in one paragraph
//!
//! [Blossom] is a family of HTTP standards ("BUDs") for content-
//! addressed file storage: every blob is uploaded under its
//! SHA-256 digest and fetched back at `<server>/<64-char-hex>`
//! (optionally with a file extension). Nostr clients publish a
//! kind-10063 replaceable event listing the servers they trust;
//! peers fetch that list to discover alternate origins when a
//! quoted blob URL goes 404.
//!
//! # Why a typed module
//!
//! Upstream `rust-nostr` ships nothing for NIP-B7 / BUD-03. We
//! model:
//!
//! 1. [`BlossomServerList`] — the typed `kind:10063` advert with
//!    a `to_event` / `from_event` round trip and an
//!    [`EventBuilder::blossom_servers`] constructor.
//! 2. [`BlossomBlobRef`] — the parsed `<64-hex>[.<ext>]` blob
//!    locator. [`BlossomBlobRef::from_url`] extracts the digest
//!    from any quoted Blossom URL, and [`BlossomBlobRef::to_url`]
//!    rebuilds a URL on a different server so callers can iterate
//!    the user's mirror list when a primary origin disappears.
//!
//! [NIP-B7]: https://github.com/nostr-protocol/nips/blob/master/B7.md
//! [Blossom]: https://github.com/hzrd149/blossom
//! [BUD-03]: https://github.com/hzrd149/blossom/blob/master/buds/03.md

use thiserror::Error;

use crate::event::{Event, EventBuilder, Kind, Tag, TagError, TagKind};
use crate::types::{Url, UrlError};

/// `kind: 10063` — Blossom user-server list (BUD-03).
pub const KIND_BLOSSOM_SERVERS: Kind = Kind::BLOSSOM_SERVERS;

const SERVER_TAG: &str = "server";
const SHA256_HEX_LEN: usize = 64;

/// Errors raised by the NIP-B7 typed bundle / blob-ref helpers.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NipB7Error {
    /// Event kind did not match `10063`.
    #[error("expected kind 10063, got {0}")]
    WrongKind(Kind),
    /// A server URL was malformed.
    #[error(transparent)]
    Url(#[from] UrlError),
    /// A typed [`Tag`] could not be constructed.
    #[error(transparent)]
    Tag(#[from] TagError),
}


/// Typed bundle for the `kind: 10063` Blossom user-server list.
///
/// The list is intentionally ordered: clients SHOULD try the
/// servers in the order the user published them so the head of the
/// list acts as the user's preferred origin and the rest as
/// fallback mirrors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlossomServerList {
    /// Server URLs the user trusts to host their blobs.
    pub servers: Vec<Url>,
}

impl BlossomServerList {
    /// Construct a server list from an iterable of URLs.
    #[must_use]
    pub fn new<I>(servers: I) -> Self
    where
        I: IntoIterator<Item = Url>,
    {
        Self {
            servers: servers.into_iter().collect(),
        }
    }

    /// Render the typed bundle to the public tag list.
    #[must_use]
    pub fn to_tags(&self) -> Vec<Tag> {
        self.servers
            .iter()
            .map(|server| Tag::with(&TagKind::custom(SERVER_TAG), [server.as_str().to_owned()]))
            .collect()
    }

    /// Parse a signed `kind:10063` event into a typed bundle.
    ///
    /// # Errors
    ///
    /// Returns [`NipB7Error::WrongKind`] when the event's kind is
    /// not `10063`; otherwise forwards every per-tag URL parse
    /// error.
    pub fn from_event(event: &Event) -> Result<Self, NipB7Error> {
        if event.kind != KIND_BLOSSOM_SERVERS {
            return Err(NipB7Error::WrongKind(event.kind));
        }
        let mut servers: Vec<Url> = Vec::new();
        for tag in &event.tags {
            if tag.name() != SERVER_TAG {
                continue;
            }
            // `values()` includes the tag head; the URL is at
            // index 1.
            let Some(url) = tag.values().get(1) else {
                continue;
            };
            servers.push(Url::parse(url)?);
        }
        Ok(Self { servers })
    }
}


/// Parsed Blossom blob locator: a 32-byte SHA-256 digest plus an
/// optional file-extension hint preserved verbatim from the source
/// URL.
///
/// The digest is the spec-mandated 64-character lowercase hex of the
/// blob's content; the extension is purely a content-type hint
/// (`png`, `mp4`, …) carried through to the rebuilt URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlossomBlobRef {
    /// Lowercase hex of the blob's SHA-256 digest (64 chars).
    pub hash_hex: String,
    /// Optional file-extension hint (without the leading dot).
    pub extension: Option<String>,
}

impl BlossomBlobRef {
    /// Try to parse a Blossom blob locator out of an arbitrary URL.
    ///
    /// Returns `Some` when the URL's final path segment matches
    /// `<64-hex>` or `<64-hex>.<ext>` and the hex is well-formed;
    /// otherwise returns `None`.
    #[must_use]
    pub fn from_url(url: &Url) -> Option<Self> {
        let path = url.as_url().path();
        // The final path segment carries the digest (the spec only
        // examines the trailing component, not the whole path).
        let segment = path.rsplit('/').find(|s| !s.is_empty())?;
        Self::from_segment(segment)
    }

    /// Try to parse a Blossom blob locator out of a raw path
    /// segment (`<64-hex>` or `<64-hex>.<ext>`).
    #[must_use]
    pub fn from_segment(segment: &str) -> Option<Self> {
        let (hash, extension) = segment.split_once('.').map_or_else(
            || (segment, None),
            |(prefix, ext)| (prefix, Some(ext.to_owned())),
        );
        if hash.len() != SHA256_HEX_LEN {
            return None;
        }
        if !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        Some(Self {
            hash_hex: hash.to_ascii_lowercase(),
            extension,
        })
    }

    /// Build a fully-qualified Blossom URL on `server` for this
    /// blob, preserving the optional extension hint.
    ///
    /// # Errors
    ///
    /// Forwards [`UrlError`] when the resulting URL is malformed
    /// (which should never happen for a well-formed `server` plus a
    /// valid hex digest, but is surfaced for completeness).
    pub fn to_url(&self, server: &Url) -> Result<Url, NipB7Error> {
        let mut raw = server.as_str().trim_end_matches('/').to_owned();
        raw.push('/');
        raw.push_str(&self.hash_hex);
        if let Some(ext) = &self.extension {
            raw.push('.');
            raw.push_str(ext);
        }
        Ok(Url::parse(&raw)?)
    }
}


impl EventBuilder {
    /// Author a NIP-B7 / BUD-03 `kind: 10063` user-server list event
    /// from a typed [`BlossomServerList`].
    #[must_use]
    pub fn blossom_servers(list: &BlossomServerList) -> Self {
        let mut builder = Self::new(KIND_BLOSSOM_SERVERS, "");
        for tag in list.to_tags() {
            builder = builder.tag(tag);
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

    fn primary() -> Url {
        Url::parse("https://blossom.self.hosted").unwrap()
    }

    fn fallback() -> Url {
        Url::parse("https://cdn.blossom.cloud").unwrap()
    }

    fn sample_hash_hex() -> &'static str {
        "e4bee088334cb5d38cff1616e964369c37b6081be997962ab289d6c671975d71"
    }

    #[test]
    fn server_list_round_trips_through_event() {
        let list = BlossomServerList::new([primary(), fallback()]);
        let event = EventBuilder::blossom_servers(&list)
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, KIND_BLOSSOM_SERVERS);
        let recovered = BlossomServerList::from_event(&event).unwrap();
        assert_eq!(recovered, list);
    }

    #[test]
    fn server_list_from_event_rejects_wrong_kind() {
        let event = EventBuilder::text_note("not a server list")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            BlossomServerList::from_event(&event),
            Err(NipB7Error::WrongKind(_)),
        ));
    }

    #[test]
    fn blob_ref_parses_64_hex_with_and_without_extension() {
        let no_ext =
            Url::parse(format!("https://blossom.self.hosted/{}", sample_hash_hex())).unwrap();
        let with_ext = Url::parse(format!(
            "https://blossom.self.hosted/{}.png",
            sample_hash_hex()
        ))
        .unwrap();

        let parsed_no_ext = BlossomBlobRef::from_url(&no_ext).unwrap();
        assert_eq!(parsed_no_ext.hash_hex, sample_hash_hex());
        assert_eq!(parsed_no_ext.extension, None);

        let parsed_with_ext = BlossomBlobRef::from_url(&with_ext).unwrap();
        assert_eq!(parsed_with_ext.hash_hex, sample_hash_hex());
        assert_eq!(parsed_with_ext.extension.as_deref(), Some("png"));
    }

    #[test]
    fn blob_ref_rejects_non_64_hex_paths() {
        let too_short = Url::parse("https://blossom.self.hosted/deadbeef").unwrap();
        let non_hex = Url::parse(
            "https://blossom.self.hosted/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        )
        .unwrap();
        assert!(BlossomBlobRef::from_url(&too_short).is_none());
        assert!(BlossomBlobRef::from_url(&non_hex).is_none());
    }

    #[test]
    fn blob_ref_to_url_preserves_extension() {
        let blob = BlossomBlobRef {
            hash_hex: sample_hash_hex().to_owned(),
            extension: Some("png".to_owned()),
        };
        let url = blob.to_url(&fallback()).unwrap();
        assert_eq!(
            url.as_str(),
            "https://cdn.blossom.cloud/e4bee088334cb5d38cff1616e964369c37b6081be997962ab289d6c671975d71.png",
        );
    }

    #[test]
    fn blob_ref_to_url_with_no_extension_omits_dot() {
        let blob = BlossomBlobRef {
            hash_hex: sample_hash_hex().to_owned(),
            extension: None,
        };
        let url = blob.to_url(&primary()).unwrap();
        assert_eq!(
            url.as_str(),
            "https://blossom.self.hosted/e4bee088334cb5d38cff1616e964369c37b6081be997962ab289d6c671975d71",
        );
    }

    #[test]
    fn blob_ref_to_url_strips_trailing_slash_on_server() {
        let blob = BlossomBlobRef {
            hash_hex: sample_hash_hex().to_owned(),
            extension: None,
        };
        let server = Url::parse("https://blossom.self.hosted/").unwrap();
        let url = blob.to_url(&server).unwrap();
        assert_eq!(
            url.as_str(),
            "https://blossom.self.hosted/e4bee088334cb5d38cff1616e964369c37b6081be997962ab289d6c671975d71",
        );
    }
}
