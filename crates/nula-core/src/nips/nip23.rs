//! [NIP-23] Long-form Content.
//!
//! Defines `kind: 30023` — an **addressable** Markdown article,
//! identified by the tuple `(pubkey, 30023, d)` — and its draft
//! sibling `kind: 30024`. Four optional metadata pieces are pinned
//! by the spec (everything else travels as ad-hoc tags or inline
//! Markdown):
//!
//! - `title` — article title;
//! - `image` — hero-image URL;
//! - `summary` — short description;
//! - `published_at` — stringified unix seconds of the first publish.
//!
//! Hashtags flow through repeated `t` tags, exactly like short
//! text notes.
//!
//! # Authoring vs reading
//!
//! - Author with [`EventBuilder::long_form_article`] /
//!   [`EventBuilder::long_form_draft`]. Both consume an
//!   [`Article`], which groups the spec-standard fields in one
//!   place and emits exactly one `d`, `title`, `image`, `summary`,
//!   and `published_at` tag.
//! - Read with [`Article::from_event`], which reverses the mapping,
//!   tolerates missing optional fields. The draft-vs-published
//!   distinction lives on the containing event's [`Kind`]
//!   ([`KIND_LONG_FORM_ARTICLE`] vs [`KIND_LONG_FORM_DRAFT`]) rather
//!   than the bundle itself.
//!
//! # Spec fidelity
//!
//! - Markdown content is left untouched: the spec forbids embedded
//!   HTML and hard-wrapped paragraphs but does not mandate a
//!   canonicalizer, so we decline to invent one.
//! - `published_at` is serialised as **seconds as a stringified
//!   `u64`** per the spec ("stringified unix seconds"), even though
//!   that is awkwardly different from most other timestamp tags.
//!
//! [NIP-23]: https://github.com/nostr-protocol/nips/blob/master/23.md

use thiserror::Error;

use crate::event::{Alphabet, Event, EventBuilder, Kind, SingleLetterTag, Tag, TagKind, Tags};
use crate::types::Timestamp;

/// `kind: 30023` — published long-form article.
pub const KIND_LONG_FORM_ARTICLE: Kind = Kind::LONG_FORM_TEXT_NOTE;

/// `kind: 30024` — long-form draft. Same shape as 30023 but relays
/// and clients treat it as work-in-progress.
pub const KIND_LONG_FORM_DRAFT: Kind = Kind::new(30_024);

/// Wire head of the `title` metadata tag.
pub const TITLE_TAG: &str = "title";
/// Wire head of the `image` metadata tag.
pub const IMAGE_TAG: &str = "image";
/// Wire head of the `summary` metadata tag.
pub const SUMMARY_TAG: &str = "summary";
/// Wire head of the `published_at` metadata tag.
pub const PUBLISHED_AT_TAG: &str = "published_at";

/// Typed NIP-23 article bundle.
///
/// Only [`Self::identifier`] and [`Self::content`] are required.
/// Every other field is optional and round-trips through the
/// builder + [`Self::from_event`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Article {
    /// `d`-tag identifier (addressable coordinate `d` segment).
    pub identifier: String,
    /// Markdown content. Must NOT contain HTML and SHOULD NOT hard
    /// wrap paragraphs — both are spec requirements on authors, not
    /// gates enforced here.
    pub content: String,
    /// `title` tag. `None` omits the tag.
    pub title: Option<String>,
    /// `image` tag (hero image URL). NIP-23 does not pin a URL
    /// format, so we accept any string (matches the looseness of
    /// NIP-38 `r` links).
    pub image: Option<String>,
    /// `summary` tag (short description).
    pub summary: Option<String>,
    /// `published_at` tag (first-publish unix seconds).
    pub published_at: Option<Timestamp>,
    /// Hashtags, each producing one `t` tag.
    pub hashtags: Vec<String>,
}

impl Article {
    /// Construct an article with only the required fields.
    #[must_use]
    pub fn new(identifier: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            identifier: identifier.into(),
            content: content.into(),
            ..Self::default()
        }
    }

    /// Chainable title setter.
    #[must_use]
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Chainable image setter.
    #[must_use]
    pub fn image(mut self, image: impl Into<String>) -> Self {
        self.image = Some(image.into());
        self
    }

    /// Chainable summary setter.
    #[must_use]
    pub fn summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = Some(summary.into());
        self
    }

    /// Chainable `published_at` setter.
    #[must_use]
    pub const fn published_at(mut self, ts: Timestamp) -> Self {
        self.published_at = Some(ts);
        self
    }

    /// Push one hashtag (emits a single `t` tag on build).
    #[must_use]
    pub fn hashtag(mut self, tag: impl Into<String>) -> Self {
        self.hashtags.push(tag.into());
        self
    }

    /// `true` when the event was authored as `kind: 30024`.
    ///
    /// Only meaningful on a value returned by [`Self::from_event`];
    /// a freshly-constructed [`Article`] reports `false` because
    /// the draft-ness lives on the containing event, not the
    /// bundle.
    #[must_use]
    pub const fn is_draft_marker() -> Kind {
        KIND_LONG_FORM_DRAFT
    }

    /// Parse a `kind: 30023` or `kind: 30024` event back into an
    /// [`Article`].
    ///
    /// # Errors
    ///
    /// - [`ArticleError::WrongKind`] for any other kind.
    /// - [`ArticleError::MissingIdentifier`] when the `d` tag is
    ///   absent (the event would not be addressable without it).
    /// - [`ArticleError::InvalidPublishedAt`] when `published_at`
    ///   is present but does not parse as unix seconds.
    pub fn from_event(event: &Event) -> Result<Self, ArticleError> {
        if event.kind != KIND_LONG_FORM_ARTICLE && event.kind != KIND_LONG_FORM_DRAFT {
            return Err(ArticleError::WrongKind(event.kind));
        }
        let identifier = d_tag(&event.tags)
            .ok_or(ArticleError::MissingIdentifier)?
            .to_owned();

        let mut article = Self::new(identifier, event.content.clone());
        article.title = custom_tag(&event.tags, TITLE_TAG).map(str::to_owned);
        article.image = custom_tag(&event.tags, IMAGE_TAG).map(str::to_owned);
        article.summary = custom_tag(&event.tags, SUMMARY_TAG).map(str::to_owned);
        if let Some(raw) = custom_tag(&event.tags, PUBLISHED_AT_TAG) {
            let n: u64 = raw
                .parse()
                .map_err(|_| ArticleError::InvalidPublishedAt(raw.to_owned()))?;
            article.published_at = Some(Timestamp::from_secs(n));
        }
        article.hashtags = event
            .tags
            .iter()
            .filter_map(|tag| match tag.kind() {
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::T => {
                    tag.get(1).map(str::to_owned)
                }
                _ => None,
            })
            .collect();

        Ok(article)
    }
}

/// Errors raised by [`Article::from_event`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ArticleError {
    /// The event was not `kind: 30023` / `30024`.
    #[error("expected kind 30023 / 30024 (long-form), got kind {}", .0.as_u16())]
    WrongKind(Kind),
    /// No `d` tag was present.
    #[error("NIP-23 event must carry exactly one `d` tag")]
    MissingIdentifier,
    /// `published_at` was present but malformed.
    #[error("`published_at` must be stringified unix seconds; got `{0}`")]
    InvalidPublishedAt(String),
}

fn d_tag(tags: &Tags) -> Option<&str> {
    let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::D));
    tags.find_first(&head).and_then(|t| t.get(1))
}

fn custom_tag<'a>(tags: &'a Tags, name: &str) -> Option<&'a str> {
    let head = TagKind::Custom(name.to_owned());
    tags.find_first(&head).and_then(|t| t.get(1))
}

fn build_article_event(article: Article, kind: Kind) -> EventBuilder {
    let mut builder = EventBuilder::new(kind, article.content).tag(Tag::d(article.identifier));
    if let Some(title) = article.title {
        builder = builder.tag(Tag::title(title));
    }
    if let Some(image) = article.image {
        let head = TagKind::Custom(IMAGE_TAG.to_owned());
        builder = builder.tag(Tag::with(&head, [image]));
    }
    if let Some(summary) = article.summary {
        let head = TagKind::Custom(SUMMARY_TAG.to_owned());
        builder = builder.tag(Tag::with(&head, [summary]));
    }
    if let Some(ts) = article.published_at {
        let head = TagKind::Custom(PUBLISHED_AT_TAG.to_owned());
        builder = builder.tag(Tag::with(&head, [ts.as_secs().to_string()]));
    }
    for hashtag in article.hashtags {
        let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::T));
        builder = builder.tag(Tag::with(&head, [hashtag]));
    }
    builder
}

impl EventBuilder {
    /// Author a published NIP-23 `kind: 30023` article.
    #[must_use]
    pub fn long_form_article(article: Article) -> Self {
        build_article_event(article, KIND_LONG_FORM_ARTICLE)
    }

    /// Author a NIP-23 `kind: 30024` draft.
    #[must_use]
    pub fn long_form_draft(article: Article) -> Self {
        build_article_event(article, KIND_LONG_FORM_DRAFT)
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
    fn article_round_trips_all_metadata_fields() {
        let article = Article::new("lorem-ipsum", "body")
            .title("Lorem Ipsum")
            .image("https://example.com/i.png")
            .summary("a short note")
            .published_at(Timestamp::from_secs(1_296_962_229))
            .hashtag("placeholder")
            .hashtag("test");

        let event = EventBuilder::long_form_article(article.clone())
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, KIND_LONG_FORM_ARTICLE);

        let parsed = Article::from_event(&event).unwrap();
        assert_eq!(parsed, article);
    }

    #[test]
    fn drafts_use_kind_30024() {
        let article = Article::new("draft-1", "wip");
        let event = EventBuilder::long_form_draft(article)
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, KIND_LONG_FORM_DRAFT);
    }

    #[test]
    fn missing_d_tag_is_rejected_when_parsing() {
        // Hand-build an event without a d tag.
        let event = EventBuilder::new(KIND_LONG_FORM_ARTICLE, "x")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            Article::from_event(&event),
            Err(ArticleError::MissingIdentifier)
        ));
    }

    #[test]
    fn wrong_kind_is_rejected_when_parsing() {
        let event = EventBuilder::text_note("nope")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            Article::from_event(&event),
            Err(ArticleError::WrongKind(_))
        ));
    }

    #[test]
    fn published_at_must_parse_as_unix_seconds() {
        let event = EventBuilder::new(KIND_LONG_FORM_ARTICLE, "x")
            .tag(Tag::d("slug"))
            .tag(Tag::with(
                &TagKind::Custom(PUBLISHED_AT_TAG.to_owned()),
                ["not-a-number"],
            ))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            Article::from_event(&event),
            Err(ArticleError::InvalidPublishedAt(s)) if s == "not-a-number"
        ));
    }

    #[test]
    fn minimal_article_has_only_d_tag() {
        let article = Article::new("slug", "just content");
        let event = EventBuilder::long_form_article(article.clone())
            .sign_with_keys(&keys())
            .unwrap();
        // exactly one tag: the d tag.
        assert_eq!(event.tags.len(), 1);
        let parsed = Article::from_event(&event).unwrap();
        assert_eq!(parsed, article);
    }
}
