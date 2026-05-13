//! [NIP-78] Arbitrary Custom App Data.
//!
//! `kind: 30078` is the catch-all *addressable* event for
//! application-specific blobs. The wire format is intentionally
//! tiny: a `d` tag carries some reference to the app + context (the
//! addressable identifier), and `.content` plus any extra tags hold
//! whatever payload the app wants. Nostr serves as a "bring your own
//! database" key/value store.
//!
//! # Why a typed wrapper at all
//!
//! Even though the spec leaves the body free-form, two patterns
//! recur:
//!
//! 1. **App namespacing** — clients prefix the `d` tag with a
//!    reverse-DNS or vendor identifier (`com.example.todoapp`,
//!    `nostr-tools/v0`) so two unrelated apps never collide on the
//!    same `(pubkey, 30078, d)` coordinate. The
//!    [`ApplicationData`] builder accepts any string and does not
//!    invent a format, but documents the convention.
//! 2. **Forward-compatible extra tags** — apps frequently attach
//!    bespoke tags they invent for their own bookkeeping. We
//!    expose them through [`ApplicationData::extra_tags`] so
//!    [`ApplicationData::from_event`] never silently drops anything.
//!
//! # Usage sketch
//!
//! ```no_run
//! use nula_core::{EventBuilder, Keys};
//! use nula_core::nips::nip78::ApplicationData;
//!
//! let keys = Keys::generate().unwrap();
//! let app_data = ApplicationData::new("com.example.todoapp")
//!     .content(r#"{"theme":"dark"}"#);
//! let event = EventBuilder::application_data(&app_data)
//!     .sign_with_keys(&keys)
//!     .unwrap();
//! ```
//!
//! [NIP-78]: https://github.com/nostr-protocol/nips/blob/master/78.md

use thiserror::Error;

use crate::event::{Alphabet, Event, EventBuilder, Kind, SingleLetterTag, Tag, TagKind, Tags};

/// `kind: 30078` — application-specific addressable event.
pub const KIND_APPLICATION_DATA: Kind = Kind::new(30_078);

/// Typed bundle for a NIP-78 `kind: 30078` event.
///
/// The `d` tag (= [`Self::identifier`]) is the only required wire
/// element; everything else is opaque payload that the producing
/// app interprets however it likes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ApplicationData {
    /// `d`-tag value. Spec recommends a reverse-DNS or vendor-prefixed
    /// identifier such as `com.example.todoapp` so unrelated apps do
    /// not collide on the same `(pubkey, 30078, d)` coordinate.
    pub identifier: String,
    /// Free-form `.content`. Often JSON, but any string works.
    pub content: String,
    /// Any additional tags the app stamped on the event. They are
    /// preserved on a [`Self::from_event`] round-trip so consumers
    /// never silently lose data.
    pub extra_tags: Vec<Tag>,
}

impl ApplicationData {
    /// Construct an empty bundle bound to `identifier`.
    #[must_use]
    pub fn new(identifier: impl Into<String>) -> Self {
        Self {
            identifier: identifier.into(),
            content: String::new(),
            extra_tags: Vec::new(),
        }
    }

    /// Replace the content blob.
    #[must_use]
    pub fn content(mut self, content: impl Into<String>) -> Self {
        self.content = content.into();
        self
    }

    /// Append an app-defined tag.
    ///
    /// `d`-tags submitted here are silently dropped — the addressable
    /// identifier is owned by [`Self::identifier`] and the builder
    /// pins exactly one `d` tag at the head of the event.
    #[must_use]
    pub fn tag(mut self, tag: Tag) -> Self {
        if !is_d_tag(&tag) {
            self.extra_tags.push(tag);
        }
        self
    }

    /// Append several app-defined tags.
    #[must_use]
    pub fn tags<I>(mut self, tags: I) -> Self
    where
        I: IntoIterator<Item = Tag>,
    {
        for tag in tags {
            if !is_d_tag(&tag) {
                self.extra_tags.push(tag);
            }
        }
        self
    }

    /// Parse a `kind: 30078` event back into a typed bundle.
    ///
    /// # Errors
    ///
    /// - [`ApplicationDataError::WrongKind`] for any other kind.
    /// - [`ApplicationDataError::MissingIdentifier`] when no `d` tag
    ///   is present (the event would not be addressable without one).
    pub fn from_event(event: &Event) -> Result<Self, ApplicationDataError> {
        if event.kind != KIND_APPLICATION_DATA {
            return Err(ApplicationDataError::WrongKind(event.kind));
        }
        let identifier = d_value(&event.tags)
            .ok_or(ApplicationDataError::MissingIdentifier)?
            .to_owned();
        let extra_tags: Vec<Tag> = event
            .tags
            .iter()
            .filter(|tag| !is_d_tag(tag))
            .cloned()
            .collect();
        Ok(Self {
            identifier,
            content: event.content.clone(),
            extra_tags,
        })
    }
}

/// Errors raised by [`ApplicationData::from_event`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ApplicationDataError {
    /// The event was not `kind: 30078`.
    #[error("expected kind 30078 (application data), got kind {}", .0.as_u16())]
    WrongKind(Kind),
    /// The `d` tag is absent.
    #[error("NIP-78 event must carry a `d` tag")]
    MissingIdentifier,
}

fn is_d_tag(tag: &Tag) -> bool {
    matches!(
        tag.kind(),
        TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::D
    )
}

fn d_value(tags: &Tags) -> Option<&str> {
    let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::D));
    tags.find_first(&head).and_then(|tag| tag.get(1))
}

impl EventBuilder {
    /// Author a NIP-78 `kind: 30078` application-data event.
    ///
    /// The `d` tag is pinned at the head of the tag list; any extra
    /// tags follow in the order they were attached to the bundle.
    #[must_use]
    pub fn application_data(data: &ApplicationData) -> Self {
        let mut builder =
            Self::new(KIND_APPLICATION_DATA, data.content.clone()).tag(Tag::d(&data.identifier));
        for tag in &data.extra_tags {
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
    fn round_trip_with_only_required_fields() {
        let data = ApplicationData::new("com.example.app");
        let event = EventBuilder::application_data(&data)
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, KIND_APPLICATION_DATA);
        assert_eq!(event.tags.len(), 1, "exactly one tag: the d tag");
        let parsed = ApplicationData::from_event(&event).unwrap();
        assert_eq!(parsed, data);
    }

    #[test]
    fn round_trip_preserves_content_and_extra_tags_in_order() {
        let data = ApplicationData::new("vendor/v1")
            .content(r#"{"theme":"dark"}"#)
            .tag(Tag::with(&TagKind::Custom("color".to_owned()), ["blue"]))
            .tag(Tag::with(&TagKind::Custom("color".to_owned()), ["red"]))
            .tag(Tag::title("preferences"));
        let event = EventBuilder::application_data(&data)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = ApplicationData::from_event(&event).unwrap();
        assert_eq!(parsed, data);
        // Extra tags retain insertion order.
        let names: Vec<&str> = parsed.extra_tags.iter().map(Tag::name).collect();
        assert_eq!(names, ["color", "color", "title"]);
    }

    #[test]
    fn user_supplied_d_tags_are_silently_dropped() {
        let data = ApplicationData::new("vendor/v1")
            .tag(Tag::d("not-the-real-id"))
            .tag(Tag::title("ok"));
        // Builder still pins the `vendor/v1` d-tag.
        assert_eq!(data.extra_tags.len(), 1);
        assert_eq!(data.extra_tags[0].name(), "title");
    }

    #[test]
    fn missing_d_tag_is_rejected_when_parsing() {
        let event = EventBuilder::new(KIND_APPLICATION_DATA, "")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            ApplicationData::from_event(&event),
            Err(ApplicationDataError::MissingIdentifier)
        ));
    }

    #[test]
    fn wrong_kind_is_rejected_when_parsing() {
        let event = EventBuilder::text_note("nope")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            ApplicationData::from_event(&event),
            Err(ApplicationDataError::WrongKind(_))
        ));
    }

    #[test]
    fn empty_identifier_is_allowed_per_spec() {
        // The spec says "any other arbitrary string" — including empty.
        let data = ApplicationData::new("");
        let event = EventBuilder::application_data(&data)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = ApplicationData::from_event(&event).unwrap();
        assert_eq!(parsed.identifier, "");
    }
}
