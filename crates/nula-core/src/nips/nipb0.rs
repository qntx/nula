//! [NIP-B0] Web Bookmarks.
//!
//! `kind: 39701` is an addressable web-bookmark event. The `d` tag
//! holds the bookmarked URL **without** the scheme (always assumed to
//! be `https://` or `http://`), enabling clients to query bookmarks by
//! `d` value. Optional metadata mirrors common bookmarking apps:
//! `title`, `published_at` (unix-seconds string), and `t` hashtags.
//!
//! [NIP-B0]: https://github.com/nostr-protocol/nips/blob/master/B0.md

use thiserror::Error;

use crate::event::{Alphabet, Coordinate, Event, EventBuilder, Kind, Tag, TagKind};
use crate::key::PublicKey;
use crate::types::{Timestamp, TimestampError};

/// `kind: 39701` — web bookmark.
pub const KIND_WEB_BOOKMARK: Kind = Kind::WEB_BOOKMARK;

const TITLE_TAG: &str = "title";
const PUBLISHED_AT_TAG: &str = "published_at";

/// Typed bundle for a `kind: 39701` web-bookmark event.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WebBookmark {
    /// `d`-identifier — the URL without the scheme.
    pub identifier: String,
    /// Free-form description body.
    pub content: String,
    /// Optional `title` (HTML link title attribute).
    pub title: Option<String>,
    /// Optional `published_at` Unix timestamp (first publication).
    pub published_at: Option<Timestamp>,
    /// `t` hashtags (lower-cased).
    pub hashtags: Vec<String>,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

/// Errors raised while parsing a NIP-B0 event.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WebBookmarkError {
    /// Event kind is not `39701`.
    #[error("unexpected kind for NIP-B0 web bookmark: {}", .0.as_u16())]
    WrongKind(Kind),
    /// `d` tag missing.
    #[error("NIP-B0 web bookmark missing `d` identifier")]
    MissingIdentifier,
    /// Wrapped timestamp parser error.
    #[error(transparent)]
    InvalidTimestamp(#[from] TimestampError),
}

impl WebBookmark {
    /// Construct a bookmark with the URL identifier seeded.
    #[must_use]
    pub fn new(identifier: impl Into<String>) -> Self {
        Self {
            identifier: identifier.into(),
            ..Self::default()
        }
    }

    /// Build the bookmark's addressable coordinate.
    #[must_use]
    pub fn coordinate(&self, author: PublicKey) -> Coordinate {
        Coordinate::new(KIND_WEB_BOOKMARK, author, self.identifier.clone())
    }

    /// Parse a `kind: 39701` web-bookmark event.
    ///
    /// # Errors
    ///
    /// See [`WebBookmarkError`] for the failure modes.
    pub fn from_event(event: &Event) -> Result<Self, WebBookmarkError> {
        if event.kind != KIND_WEB_BOOKMARK {
            return Err(WebBookmarkError::WrongKind(event.kind));
        }
        let mut identifier: Option<String> = None;
        let mut title: Option<String> = None;
        let mut published_at: Option<Timestamp> = None;
        let mut hashtags: Vec<String> = Vec::new();
        let mut extra_tags: Vec<Tag> = Vec::new();
        for tag in &event.tags {
            absorb_tag(
                tag,
                &mut identifier,
                &mut title,
                &mut published_at,
                &mut hashtags,
                &mut extra_tags,
            )?;
        }
        Ok(Self {
            identifier: identifier.ok_or(WebBookmarkError::MissingIdentifier)?,
            content: event.content.clone(),
            title,
            published_at,
            hashtags,
            extra_tags,
        })
    }
}

fn absorb_tag(
    tag: &Tag,
    identifier: &mut Option<String>,
    title: &mut Option<String>,
    published_at: &mut Option<Timestamp>,
    hashtags: &mut Vec<String>,
    extra_tags: &mut Vec<Tag>,
) -> Result<(), WebBookmarkError> {
    match tag.kind() {
        TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::D => {
            *identifier = tag.get(1).map(str::to_owned);
        }
        TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::T => {
            if let Some(raw) = tag.get(1) {
                hashtags.push(raw.to_ascii_lowercase());
            }
        }
        _ if tag.name() == TITLE_TAG => *title = tag.get(1).map(str::to_owned),
        _ if tag.name() == PUBLISHED_AT_TAG => {
            if let Some(raw) = tag.get(1) {
                *published_at = Some(raw.parse::<Timestamp>()?);
            }
        }
        _ => extra_tags.push(tag.clone()),
    }
    Ok(())
}

impl EventBuilder {
    /// Author a NIP-B0 `kind: 39701` web-bookmark event.
    #[must_use]
    pub fn web_bookmark(bookmark: &WebBookmark) -> Self {
        let mut builder = Self::new(KIND_WEB_BOOKMARK, bookmark.content.clone());
        builder = builder.tag(Tag::d(&bookmark.identifier));
        if let Some(title) = &bookmark.title {
            builder = builder.tag(Tag::with(&TagKind::from_wire(TITLE_TAG), [title.clone()]));
        }
        if let Some(ts) = bookmark.published_at {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(PUBLISHED_AT_TAG),
                [ts.as_secs().to_string()],
            ));
        }
        for hashtag in &bookmark.hashtags {
            builder = builder.tag(Tag::t(hashtag));
        }
        for tag in &bookmark.extra_tags {
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
    fn web_bookmark_round_trip() {
        let bookmark = WebBookmark {
            identifier: "alice.blog/post".into(),
            content: "A marvelous insight".into(),
            title: Some("Blog insights by Alice".into()),
            published_at: Some(Timestamp::from_secs(1_738_863_000)),
            hashtags: vec!["post".into(), "insight".into()],
            extra_tags: Vec::new(),
        };
        let event = EventBuilder::web_bookmark(&bookmark)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = WebBookmark::from_event(&event).unwrap();
        assert_eq!(parsed, bookmark);
    }

    #[test]
    fn missing_d_is_rejected() {
        let event = EventBuilder::new(KIND_WEB_BOOKMARK, "content")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            WebBookmark::from_event(&event),
            Err(WebBookmarkError::MissingIdentifier)
        ));
    }
}
