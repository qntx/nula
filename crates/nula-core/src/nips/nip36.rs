//! [NIP-36] Sensitive Content / Content Warning.
//!
//! `content-warning` is a single optional tag any kind of event MAY
//! carry to signal that the body should be hidden behind a click /
//! tap gate. The spec also lets producers attach NIP-32 `L`/`l`
//! tags under the [`CONTENT_WARNING_NAMESPACE`] (or any other
//! ontology such as `social.nos.ontology`) to qualify the reason.
//!
//! This module is intentionally tiny:
//!
//! - [`ContentWarning`] models the tag's optional reason column.
//! - [`content_warning_from_tags`] reads the first warning off any
//!   event so clients do not have to walk the tag list themselves.
//! - [`Tag::content_warning`](crate::event::Tag::content_warning)
//!   lives on [`Tag`] and is the canonical builder.
//!
//! For richer classification, pair this with NIP-32:
//! [`crate::nips::nip32::Label`] handles the full `L`/`l` reader and
//! builder surface.
//!
//! [NIP-36]: https://github.com/nostr-protocol/nips/blob/master/36.md

use thiserror::Error;

use crate::event::{Tag, TagKind, Tags};

/// Wire name of the content-warning tag.
pub const CONTENT_WARNING_TAG: &str = "content-warning";

/// Reserved NIP-32 namespace used to qualify content warnings
/// (spec §"Example": `["L", "content-warning"]`).
pub const CONTENT_WARNING_NAMESPACE: &str = "content-warning";

/// Typed view of a `content-warning` tag.
///
/// Per spec the reason column is optional — producers MAY publish a
/// bare `["content-warning"]` tag when the reason is implicit.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ContentWarning {
    /// Human-readable reason (spec §"options.reason").
    pub reason: Option<String>,
}

impl ContentWarning {
    /// Construct a warning without a reason. Equivalent to the bare
    /// `["content-warning"]` tag.
    #[must_use]
    pub const fn unspecified() -> Self {
        Self { reason: None }
    }

    /// Construct a warning carrying a free-form reason.
    #[must_use]
    pub fn with_reason(reason: impl Into<String>) -> Self {
        Self {
            reason: Some(reason.into()),
        }
    }

    /// Render as a [`Tag`].
    #[must_use]
    pub fn to_tag(&self) -> Tag {
        let head = TagKind::from_wire(CONTENT_WARNING_TAG);
        self.reason.as_ref().map_or_else(
            || Tag::with(&head, std::iter::empty::<String>()),
            |reason| Tag::with(&head, [reason.clone()]),
        )
    }

    /// Parse a single `content-warning` [`Tag`]. The tag head must be
    /// `content-warning`; column 1 (if present) becomes
    /// [`Self::reason`].
    ///
    /// # Errors
    ///
    /// Returns [`ContentWarningError::WrongTag`] when the tag is not
    /// a `content-warning` tag.
    pub fn from_tag(tag: &Tag) -> Result<Self, ContentWarningError> {
        if tag.name() != CONTENT_WARNING_TAG {
            return Err(ContentWarningError::WrongTag);
        }
        let reason = tag.get(1).filter(|s| !s.is_empty()).map(str::to_owned);
        Ok(Self { reason })
    }
}

/// Look up the first `content-warning` tag in `tags`.
///
/// Returns `None` when no tag is present. Multiple warnings on a
/// single event are not defined by spec; only the first one wins.
#[must_use]
pub fn content_warning_from_tags(tags: &Tags) -> Option<ContentWarning> {
    let head = TagKind::from_wire(CONTENT_WARNING_TAG);
    tags.find_first(&head)
        .and_then(|tag| ContentWarning::from_tag(tag).ok())
}

/// Errors raised by [`ContentWarning::from_tag`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ContentWarningError {
    /// The tag's head was not `content-warning`.
    #[error("expected `content-warning` tag")]
    WrongTag,
}

impl Tag {
    /// Spec-compliant `content-warning` tag.
    ///
    /// Pass `None` for the bare `["content-warning"]` form, or a
    /// string for `["content-warning", "<reason>"]`.
    #[must_use]
    pub fn content_warning(reason: Option<impl Into<String>>) -> Self {
        let head = TagKind::from_wire(CONTENT_WARNING_TAG);
        reason.map_or_else(
            || Self::with(&head, std::iter::empty::<String>()),
            |r| Self::with(&head, [r.into()]),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EventBuilder;
    use crate::Keys;

    fn keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    #[test]
    fn round_trip_with_reason() {
        let warning = ContentWarning::with_reason("violent imagery");
        let tag = warning.to_tag();
        assert_eq!(tag.name(), CONTENT_WARNING_TAG);
        assert_eq!(tag.get(1), Some("violent imagery"));
        let parsed = ContentWarning::from_tag(&tag).unwrap();
        assert_eq!(parsed, warning);
    }

    #[test]
    fn round_trip_without_reason() {
        let warning = ContentWarning::unspecified();
        let tag = warning.to_tag();
        assert_eq!(tag.name(), CONTENT_WARNING_TAG);
        assert_eq!(tag.get(1), None);
        let parsed = ContentWarning::from_tag(&tag).unwrap();
        assert_eq!(parsed, warning);
    }

    #[test]
    fn empty_reason_string_is_treated_as_none() {
        let tag = Tag::with(&TagKind::from_wire(CONTENT_WARNING_TAG), [""]);
        let parsed = ContentWarning::from_tag(&tag).unwrap();
        assert_eq!(parsed.reason, None);
    }

    #[test]
    fn wrong_tag_is_rejected() {
        let tag = Tag::title("not a warning");
        assert!(matches!(
            ContentWarning::from_tag(&tag),
            Err(ContentWarningError::WrongTag),
        ));
    }

    #[test]
    fn tag_builder_round_trips_through_event() {
        let event = EventBuilder::text_note("sensitive")
            .tag(Tag::content_warning(Some("nsfw")))
            .sign_with_keys(&keys())
            .unwrap();
        let warning = content_warning_from_tags(&event.tags).unwrap();
        assert_eq!(warning.reason.as_deref(), Some("nsfw"));
    }

    #[test]
    fn content_warning_from_tags_returns_none_when_absent() {
        let event = EventBuilder::text_note("clean")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(content_warning_from_tags(&event.tags).is_none());
    }

    #[test]
    fn bare_tag_builder() {
        let tag = Tag::content_warning(None::<String>);
        assert_eq!(tag.name(), CONTENT_WARNING_TAG);
        assert_eq!(tag.values().len(), 1, "only the tag head, no reason");
    }
}
