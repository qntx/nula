//! [NIP-14] `subject` tag for text events.
//!
//! NIP-14 attaches a single short summary to a `kind: 1` text note via
//! the `["subject", "<text>"]` tag. The intent mirrors email subject
//! lines: clients that render threaded views can use the subject as
//! the row title instead of inferring one from the first few words of
//! the body.
//!
//! Spec recommendations this module surfaces but does not enforce:
//!
//! - Subjects MAY be reused on replies, optionally with a `Re: ` prefix
//!   to mark them as such.
//! - Subjects SHOULD be shorter than 80 characters; longer ones risk
//!   client-side trimming.
//!
//! Authors: use [`crate::Tag::subject`] to attach a subject to an
//! [`crate::EventBuilder`]. Readers: use [`subject_of`] to recover the
//! first subject tag's text. To craft a reply that mirrors the parent
//! subject (with or without a `Re: ` prefix), use [`reply_subject`].
//!
//! # Usage
//!
//! ```
//! use nula_core::nips::nip14;
//! use nula_core::{EventBuilder, Keys, Kind, Tag};
//!
//! let keys = Keys::generate().unwrap();
//! let post = EventBuilder::text_note("hello, threadable nostr")
//!     .tag(Tag::subject("hello"))
//!     .sign_with_keys(&keys)
//!     .unwrap();
//!
//! assert_eq!(nip14::subject_of(&post.tags), Some("hello"));
//!
//! // A reply that mirrors the parent subject with a `Re:` prefix.
//! let reply_subject = nip14::reply_subject(&post.tags, true).unwrap();
//! assert_eq!(reply_subject, "Re: hello");
//! ```
//!
//! [NIP-14]: https://github.com/nostr-protocol/nips/blob/master/14.md

use crate::event::{TagKind, Tags};

/// Literal tag key (`"subject"`).
pub const SUBJECT_TAG_KEY: &str = "subject";

/// `Re: ` prefix idiomatically used by clients that want to mark a
/// reply's subject the way email user agents do. Authors are free to
/// pick a different prefix; this constant is a hint, not a requirement.
pub const REPLY_PREFIX: &str = "Re: ";

/// Return the first `subject` tag's text in `tags`, if any.
///
/// NIP-14 does not forbid multiple `subject` tags but only the first
/// one has a defined meaning; later duplicates are ignored.
/// Tags with the right head but no argument value (a stray
/// `["subject"]` on the wire) yield [`None`].
#[must_use]
pub fn subject_of(tags: &Tags) -> Option<&str> {
    for tag in tags {
        if !is_subject_tag(&tag.kind()) {
            continue;
        }
        if let Some(text) = tag.values().get(1) {
            return Some(text.as_str());
        }
    }
    None
}

/// Compute the subject string a reply SHOULD copy from the parent's
/// `tags`.
///
/// Returns the parent subject verbatim when `add_reply_prefix` is
/// `false`, or with [`REPLY_PREFIX`] prepended when `true`. The prefix
/// is **not** added if the existing subject already starts with it
/// (case-insensitive on the leading `Re:`), so threading a deep reply
/// chain doesn't pile up `Re: Re: Re:` walls — clients that genuinely
/// want that effect can call [`subject_of`] directly and concatenate
/// themselves.
///
/// Returns [`None`] when the parent has no subject tag.
#[must_use]
pub fn reply_subject(parent_tags: &Tags, add_reply_prefix: bool) -> Option<String> {
    let parent = subject_of(parent_tags)?;
    if !add_reply_prefix || starts_with_reply_prefix(parent) {
        return Some(parent.to_owned());
    }
    let mut out = String::with_capacity(REPLY_PREFIX.len() + parent.len());
    out.push_str(REPLY_PREFIX);
    out.push_str(parent);
    Some(out)
}

fn is_subject_tag(kind: &TagKind) -> bool {
    matches!(kind, TagKind::Custom(s) if s == SUBJECT_TAG_KEY)
}

fn starts_with_reply_prefix(s: &str) -> bool {
    // Recognise `Re:` / `RE:` / `re:` (case-insensitive) regardless of
    // whether a space follows. Some real-world clients ship
    // `Re:hello` without the space; users still read it as a reply, so
    // we treat both spellings as already-prefixed and avoid stacking
    // `Re: Re:hello`. `Reaction:` and similar three-letter prefixes do
    // not match because their fourth byte is not `:`.
    matches!(
        s.as_bytes(),
        [b0, b1, b':', ..]
            if b0.eq_ignore_ascii_case(&b'R') && b1.eq_ignore_ascii_case(&b'E')
    )
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
        let tag = Tag::subject("greetings");
        assert_eq!(tag.values(), &["subject".to_owned(), "greetings".into()]);
    }

    #[test]
    fn reads_back_first_subject_from_event() {
        let keys = fixture_keys();
        let event = EventBuilder::new(Kind::TEXT_NOTE, "hi")
            .tag(Tag::subject("greetings"))
            .sign_with_keys(&keys)
            .unwrap();
        assert_eq!(subject_of(&event.tags), Some("greetings"));
    }

    #[test]
    fn returns_none_when_no_subject_is_present() {
        let keys = fixture_keys();
        let event = EventBuilder::new(Kind::TEXT_NOTE, "hi")
            .sign_with_keys(&keys)
            .unwrap();
        assert_eq!(subject_of(&event.tags), None);
    }

    #[test]
    fn duplicate_subject_tags_prefer_the_first_occurrence() {
        let mut tags = Tags::new();
        tags.push(Tag::subject("primary"));
        tags.push(Tag::subject("secondary"));
        assert_eq!(subject_of(&tags), Some("primary"));
    }

    #[test]
    fn bare_subject_head_without_value_returns_none() {
        let mut tags = Tags::new();
        tags.push(Tag::new(["subject"]).unwrap());
        assert_eq!(subject_of(&tags), None);
    }

    #[test]
    fn reply_subject_without_prefix_is_verbatim() {
        let mut parent_tags = Tags::new();
        parent_tags.push(Tag::subject("daily standup"));
        assert_eq!(
            reply_subject(&parent_tags, false),
            Some("daily standup".to_owned())
        );
    }

    #[test]
    fn reply_subject_with_prefix_prepends_re_colon_space() {
        let mut parent_tags = Tags::new();
        parent_tags.push(Tag::subject("daily standup"));
        assert_eq!(
            reply_subject(&parent_tags, true),
            Some("Re: daily standup".to_owned())
        );
    }

    #[test]
    fn reply_subject_does_not_double_re_prefix() {
        for already in [
            "Re: greetings",
            "RE: greetings",
            "re: greetings",
            "Re:greetings",
        ] {
            let mut parent_tags = Tags::new();
            parent_tags.push(Tag::subject(already));
            let out = reply_subject(&parent_tags, true).unwrap();
            assert_eq!(out, already, "must not stack `Re:` for {already:?}");
        }
    }

    #[test]
    fn reply_subject_returns_none_when_parent_has_no_subject() {
        let parent_tags = Tags::new();
        assert!(reply_subject(&parent_tags, true).is_none());
    }

    #[test]
    fn re_prefix_detection_is_strict_about_word_boundary() {
        // `Reaction:` shares the first three bytes but is *not* a NIP-14
        // reply prefix; we must not mis-classify it.
        let mut parent_tags = Tags::new();
        parent_tags.push(Tag::subject("Reaction: dispatch"));
        assert_eq!(
            reply_subject(&parent_tags, true),
            Some("Re: Reaction: dispatch".to_owned()),
            "non-NIP-14 prefixes must still get a Re: prefix",
        );
    }
}
