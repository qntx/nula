//! [NIP-31] Dealing with unknown event kinds.
//!
//! A custom event kind that is **not** meant to be rendered as plain
//! text (i.e. not a `kind: 1` note) SHOULD ship an `["alt", <summary>]`
//! tag carrying a short human-readable description. The goal is that a
//! `kind: 1`-centric client — used to only display text notes —
//! still has something meaningful to show when a user references an
//! unknown kind from their timeline.
//!
//! This module is both an *index* and a read-side helper:
//!
//! - [`ALT_TAG_KEY`] pins the literal key (`"alt"`) so every read /
//!   write path shares the same string constant.
//! - [`alt_description`] returns the first `alt` value in a [`Tags`]
//!   list, which is how the spec instructs consumers to read the
//!   fallback.
//!
//! The *write* side is handled by the typed constructor
//! [`crate::Tag::alt`], so that all NIP-24 / NIP-31 tag authoring
//! stays inside the single `event::tag` surface rather than
//! ping-ponging between modules.
//!
//! # Usage
//!
//! ```
//! use nula_core::nips::nip31;
//! use nula_core::{EventBuilder, Keys, Kind, Tag};
//!
//! let keys = Keys::generate().unwrap();
//! // A pretend "custom forum post" kind: a `kind: 1`-only client will
//! // show the alt text instead of an opaque JSON blob.
//! let event = EventBuilder::new(Kind::from(30023), "# hello")
//!     .tag(Tag::alt("blog post titled ‘hello’"))
//!     .sign_with_keys(&keys)
//!     .unwrap();
//!
//! assert_eq!(
//!     nip31::alt_description(&event.tags),
//!     Some("blog post titled ‘hello’"),
//! );
//! ```
//!
//! [NIP-31]: https://github.com/nostr-protocol/nips/blob/master/31.md

use crate::event::{TagKind, Tags};

/// Literal tag key used by NIP-31 fallback descriptions.
pub const ALT_TAG_KEY: &str = "alt";

/// Return the first `alt` tag's description, if any.
///
/// NIP-31 does not forbid multiple `alt` tags on the same event but
/// only the first one has a defined meaning; later duplicates are
/// ignored here. Tags whose head is not exactly `"alt"` are skipped;
/// tags with the right head but no argument value (a stray `["alt"]`
/// on the wire) return [`None`].
#[must_use]
pub fn alt_description(tags: &Tags) -> Option<&str> {
    for tag in tags {
        if !is_alt_tag(&tag.kind()) {
            continue;
        }
        if let Some(description) = tag.values().get(1) {
            return Some(description.as_str());
        }
    }
    None
}

fn is_alt_tag(kind: &TagKind) -> bool {
    matches!(kind, TagKind::Custom(s) if s == ALT_TAG_KEY)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Kind, Tag};
    use crate::{EventBuilder, Keys};

    fn fixture_keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    #[test]
    fn tag_constructor_shape_matches_spec() {
        let tag = Tag::alt("short summary");
        assert_eq!(tag.values(), &["alt".to_owned(), "short summary".into()]);
    }

    #[test]
    fn reads_back_first_alt_description_from_event() {
        let keys = fixture_keys();
        let event = EventBuilder::new(Kind::from(30023), "{body}")
            .tag(Tag::alt("a blog post"))
            .sign_with_keys(&keys)
            .unwrap();

        assert_eq!(alt_description(&event.tags), Some("a blog post"));
    }

    #[test]
    fn returns_none_when_no_alt_tag_is_present() {
        let keys = fixture_keys();
        let event = EventBuilder::new(Kind::from(30023), "{body}")
            .sign_with_keys(&keys)
            .unwrap();
        assert_eq!(alt_description(&event.tags), None);
    }

    #[test]
    fn duplicate_alt_tags_prefer_the_first_occurrence() {
        let mut tags = Tags::new();
        tags.push(Tag::alt("primary"));
        tags.push(Tag::alt("secondary"));
        assert_eq!(alt_description(&tags), Some("primary"));
    }

    #[test]
    fn bare_alt_head_without_value_returns_none() {
        let mut tags = Tags::new();
        // A malformed `["alt"]` with no description argument.
        tags.push(Tag::new(["alt"]).unwrap());
        assert_eq!(alt_description(&tags), None);
    }
}
