//! [NIP-7D] Threads.
//!
//! `kind: 11` carries a thread-root post. The spec recommends a `title`
//! tag but neither requires it nor caps the body length. Replies MUST
//! use NIP-22 `kind: 1111` comments scoped at the root `kind: 11`.
//!
//! [NIP-7D]: https://github.com/nostr-protocol/nips/blob/master/7D.md

use thiserror::Error;

use crate::event::{Event, EventBuilder, Kind, Tag, TagKind};

/// `kind: 11` — thread root.
pub const KIND_THREAD: Kind = Kind::THREAD;

const TITLE_TAG: &str = "title";

/// Typed bundle for a `kind: 11` thread-root event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Thread {
    /// Free-form body of the thread root.
    pub content: String,
    /// Optional `title` (recommended by spec).
    pub title: Option<String>,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

/// Errors raised while parsing a NIP-7D event.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ThreadError {
    /// Event kind is not `11`.
    #[error("unexpected kind for NIP-7D thread: {}", .0.as_u16())]
    WrongKind(Kind),
}

impl Thread {
    /// Construct a thread-root with no title.
    #[must_use]
    pub fn new(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            title: None,
            extra_tags: Vec::new(),
        }
    }

    /// Attach a title.
    #[must_use]
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Parse a `kind: 11` thread event.
    ///
    /// # Errors
    ///
    /// Returns [`ThreadError::WrongKind`] when `event.kind != 11`.
    pub fn from_event(event: &Event) -> Result<Self, ThreadError> {
        if event.kind != KIND_THREAD {
            return Err(ThreadError::WrongKind(event.kind));
        }
        let mut title: Option<String> = None;
        let mut extra_tags: Vec<Tag> = Vec::new();
        for tag in &event.tags {
            if tag.name() == TITLE_TAG && title.is_none() {
                title = tag.get(1).map(str::to_owned);
            } else {
                extra_tags.push(tag.clone());
            }
        }
        Ok(Self {
            content: event.content.clone(),
            title,
            extra_tags,
        })
    }
}

impl EventBuilder {
    /// Author a NIP-7D `kind: 11` thread root.
    #[must_use]
    pub fn thread(thread: &Thread) -> Self {
        let mut builder = Self::new(KIND_THREAD, thread.content.clone());
        if let Some(title) = &thread.title {
            builder = builder.tag(Tag::with(&TagKind::from_wire(TITLE_TAG), [title.clone()]));
        }
        for tag in &thread.extra_tags {
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
    fn thread_round_trip() {
        let thread = Thread::new("Good morning").title("GM");
        let event = EventBuilder::thread(&thread)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = Thread::from_event(&event).unwrap();
        assert_eq!(parsed, thread);
    }

    #[test]
    fn thread_without_title() {
        let thread = Thread::new("orphan");
        let event = EventBuilder::thread(&thread)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = Thread::from_event(&event).unwrap();
        assert!(parsed.title.is_none());
    }

    #[test]
    fn wrong_kind_is_rejected() {
        let event = EventBuilder::text_note("nope")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            Thread::from_event(&event),
            Err(ThreadError::WrongKind(_))
        ));
    }
}
