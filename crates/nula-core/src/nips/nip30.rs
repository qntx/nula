//! [NIP-30] Custom emoji.
//!
//! NIP-30 piggybacks on `kind: 0` / `1` / `7` / `30315` events by
//! declaring `emoji` tags that map a `:shortcode:` token in the
//! body (or in a `kind: 0` `name`/`about` field) to a hosted image
//! URL. The tag shape is:
//!
//! ```text
//! ["emoji", "<shortcode>", "<image-url>", "<optional NIP-51 kind:30030 emoji-set address>"]
//! ```
//!
//! where `<shortcode>` MUST consist of alphanumerics, hyphens, and
//! underscores only.
//!
//! This module provides:
//!
//! - [`Emoji`] — typed bundle of the three wire columns;
//! - [`Tag::emoji`] — builder for the `emoji` tag;
//! - [`validate_shortcode`] — strict charset gate reused by both the
//!   builder and the reader;
//! - [`emojis_from_tags`] — forward-compatible reader that tolerates
//!   future extra tag columns;
//! - [`shortcodes_in`] — content scanner that yields every
//!   `:shortcode:` span in a text body. The scanner produces
//!   byte-offset ranges so callers can perform in-place substitution
//!   without re-parsing.
//!
//! [NIP-30]: https://github.com/nostr-protocol/nips/blob/master/30.md

use std::ops::Range;

use thiserror::Error;

use crate::event::{Coordinate, Tag, TagKind, Tags};

/// Wire head of the NIP-30 tag.
pub const EMOJI_TAG_KEY: &str = "emoji";

/// Errors raised by the NIP-30 helpers.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum Nip30Error {
    /// The shortcode was empty.
    #[error("emoji shortcode must not be empty")]
    EmptyShortcode,
    /// The shortcode contained a character outside `[A-Za-z0-9_-]`.
    #[error("emoji shortcode `{0}` contains invalid characters (allowed: `a-z A-Z 0-9 _ -`)")]
    InvalidShortcode(String),
    /// The image URL was empty.
    #[error("emoji image URL must not be empty")]
    EmptyUrl,
    /// The optional emoji-set address was malformed.
    #[error("emoji-set address must be a NIP-51 kind:30030 coordinate: {0}")]
    InvalidSet(String),
}

/// Validate a `<shortcode>` per NIP-30 §"shortcode MUST be comprised
/// of only alphanumeric characters, hyphens, and underscores".
///
/// Note: NIP-30 does not mandate lowercase, so we preserve case.
///
/// # Errors
///
/// - [`Nip30Error::EmptyShortcode`] for `""`.
/// - [`Nip30Error::InvalidShortcode`] for any disallowed char.
pub fn validate_shortcode(s: &str) -> Result<(), Nip30Error> {
    if s.is_empty() {
        return Err(Nip30Error::EmptyShortcode);
    }
    if !s
        .bytes()
        .all(|b| matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_'))
    {
        return Err(Nip30Error::InvalidShortcode(s.to_owned()));
    }
    Ok(())
}

/// A custom emoji declaration.
///
/// Construct with [`Self::new`] to get charset validation up front,
/// then optionally attach an NIP-51 `kind: 30030` emoji-set address
/// via [`Self::with_set`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Emoji {
    /// The `:<shortcode>:` token (bare, no colons).
    pub shortcode: String,
    /// HTTPS URL of the image.
    pub url: String,
    /// Optional NIP-51 `kind:30030:<pubkey>:<d>` emoji-set address.
    pub set: Option<Coordinate>,
}

impl Emoji {
    /// Construct with charset validation.
    ///
    /// # Errors
    ///
    /// - [`Nip30Error::EmptyShortcode`] / [`Nip30Error::InvalidShortcode`]
    ///   on a bad shortcode.
    /// - [`Nip30Error::EmptyUrl`] on an empty URL.
    pub fn new(shortcode: impl Into<String>, url: impl Into<String>) -> Result<Self, Nip30Error> {
        let shortcode = shortcode.into();
        validate_shortcode(&shortcode)?;
        let url = url.into();
        if url.is_empty() {
            return Err(Nip30Error::EmptyUrl);
        }
        Ok(Self {
            shortcode,
            url,
            set: None,
        })
    }

    /// Attach an NIP-51 emoji-set address.
    #[must_use]
    pub fn with_set(mut self, set: Coordinate) -> Self {
        self.set = Some(set);
        self
    }

    /// Render the `:<shortcode>:` token used inside event content.
    #[must_use]
    pub fn token(&self) -> String {
        format!(":{}:", self.shortcode)
    }
}

impl Tag {
    /// Build a NIP-30 `emoji` tag.
    ///
    /// Wire form: `["emoji", shortcode, url]` or
    /// `["emoji", shortcode, url, "<kind>:<pubkey>:<d>"]` when an
    /// emoji-set address is attached.
    #[must_use]
    pub fn emoji(emoji: &Emoji) -> Self {
        let head = TagKind::Custom(EMOJI_TAG_KEY.to_owned());
        let mut values: Vec<String> = Vec::with_capacity(3);
        values.push(emoji.shortcode.clone());
        values.push(emoji.url.clone());
        if let Some(set) = &emoji.set {
            values.push(set.to_wire());
        }
        Self::with(&head, values)
    }
}

/// Iterate every well-formed NIP-30 `emoji` tag in `tags`.
///
/// Malformed entries (empty shortcode, invalid charset, empty URL,
/// malformed set address) are silently skipped so a single bad tag
/// does not break rendering of the rest of an event.
pub fn emojis_from_tags(tags: &Tags) -> impl Iterator<Item = Emoji> + use<'_> {
    tags.iter().filter_map(|tag| {
        if !matches!(tag.kind(), TagKind::Custom(s) if s == EMOJI_TAG_KEY) {
            return None;
        }
        let values = tag.values();
        let shortcode = values.get(1)?.clone();
        let url = values.get(2)?.clone();
        if validate_shortcode(&shortcode).is_err() || url.is_empty() {
            return None;
        }
        let set = values.get(3).and_then(|raw| Coordinate::parse(raw).ok());
        Some(Emoji {
            shortcode,
            url,
            set,
        })
    })
}

/// Scan `content` for `:<shortcode>:` tokens and yield their byte
/// offsets.
///
/// Matching is deliberately conservative: both delimiting colons
/// must be present, the body must satisfy [`validate_shortcode`],
/// and adjacency to another alphanumeric character is *not*
/// rejected (so `prefix:code:` yields the `:code:` span starting
/// after `prefix`).
///
/// Returns [`Range<usize>`](std::ops::Range) of byte offsets plus
/// a borrowed slice of the shortcode body (no colons).
pub fn shortcodes_in(content: &str) -> impl Iterator<Item = (Range<usize>, &str)> + '_ {
    ShortcodeScanner::new(content)
}

struct ShortcodeScanner<'a> {
    content: &'a str,
    cursor: usize,
}

impl<'a> ShortcodeScanner<'a> {
    const fn new(content: &'a str) -> Self {
        Self { content, cursor: 0 }
    }
}

impl<'a> Iterator for ShortcodeScanner<'a> {
    type Item = (Range<usize>, &'a str);

    fn next(&mut self) -> Option<Self::Item> {
        let bytes = self.content.as_bytes();
        loop {
            let &first = bytes.get(self.cursor)?;
            if first != b':' {
                self.cursor = self.cursor.saturating_add(1);
                continue;
            }
            let start = self.cursor;
            let body_start = start + 1;
            let body_len = bytes.get(body_start..).map_or(0, count_shortcode_bytes);
            let end = body_start + body_len;
            if body_len == 0 || bytes.get(end) != Some(&b':') {
                // Not a valid shortcode span; advance past the opener.
                self.cursor = start + 1;
                continue;
            }
            let full_end = end + 1;
            let span = start..full_end;
            let body = self.content.get(body_start..end)?;
            self.cursor = full_end;
            return Some((span, body));
        }
    }
}

fn count_shortcode_bytes(slice: &[u8]) -> usize {
    slice
        .iter()
        .take_while(|&&b| matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_'))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_shortcode_accepts_allowed_charset() {
        for s in ["a", "abc", "A_B-C", "123", "X-9_z"] {
            validate_shortcode(s).unwrap_or_else(|e| panic!("{s:?}: {e}"));
        }
    }

    #[test]
    fn validate_shortcode_rejects_invalid_characters_and_empty() {
        assert!(matches!(
            validate_shortcode(""),
            Err(Nip30Error::EmptyShortcode)
        ));
        for s in ["a:b", "a b", "a.b", "a!b", "π"] {
            assert!(
                matches!(validate_shortcode(s), Err(Nip30Error::InvalidShortcode(_))),
                "should reject {s:?}"
            );
        }
    }

    #[test]
    fn emoji_new_validates_and_produces_colon_token() {
        let e = Emoji::new("soapbox", "https://example.com/s.png").unwrap();
        assert_eq!(e.shortcode, "soapbox");
        assert_eq!(e.token(), ":soapbox:");
    }

    #[test]
    fn emoji_new_rejects_bad_shortcode_and_empty_url() {
        assert!(matches!(
            Emoji::new("bad:code", "https://x"),
            Err(Nip30Error::InvalidShortcode(_))
        ));
        assert!(matches!(Emoji::new("ok", ""), Err(Nip30Error::EmptyUrl)));
    }

    #[test]
    fn tag_emoji_without_set_emits_three_values() {
        let e = Emoji::new("soapbox", "https://example.com/s.png").unwrap();
        let tag = Tag::emoji(&e);
        assert_eq!(tag.values().len(), 3);
        assert_eq!(tag.get(0), Some("emoji"));
        assert_eq!(tag.get(1), Some("soapbox"));
        assert_eq!(tag.get(2), Some("https://example.com/s.png"));
    }

    #[test]
    fn tag_emoji_with_set_emits_four_values_and_coordinate() {
        use crate::PublicKey;
        let pk =
            PublicKey::parse("79c2cae114ea28a981e7559b4fe7854a473521a8d22a66bbab9fa248eb820ff6")
                .unwrap();
        let set = Coordinate::new(crate::Kind::new(30030), pk, "blobcats");
        let e = Emoji::new("ablobcatrainbow", "https://example.com/a.png")
            .unwrap()
            .with_set(set.clone());
        let tag = Tag::emoji(&e);
        assert_eq!(tag.values().len(), 4);
        assert_eq!(tag.get(3), Some(set.to_wire().as_str()));
    }

    #[test]
    fn emojis_from_tags_skips_malformed_entries() {
        let mut tags = Tags::new();
        tags.push(Tag::emoji(
            &Emoji::new("ok", "https://example.com/o.png").unwrap(),
        ));
        // Malformed: invalid shortcode.
        tags.push(Tag::new(["emoji", "has:colon", "https://x"]).unwrap());
        // Malformed: empty URL.
        tags.push(Tag::new(["emoji", "validbody", ""]).unwrap());
        // Not an emoji tag.
        tags.push(Tag::new(["alt", "something"]).unwrap());

        let parsed: Vec<_> = emojis_from_tags(&tags).collect();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].shortcode, "ok");
    }

    #[test]
    fn shortcodes_in_detects_multiple_occurrences() {
        let content = "Hello :gleasonator: 😂 :ablobcatrainbow: :disputed: yolo";
        let spans: Vec<_> = shortcodes_in(content).collect();
        assert_eq!(spans.len(), 3);
        let bodies: Vec<&str> = spans.iter().map(|(_, s)| *s).collect();
        assert_eq!(bodies, ["gleasonator", "ablobcatrainbow", "disputed"]);
        // Byte offsets round-trip back to the original slices.
        let (r0, _) = &spans[0];
        assert_eq!(&content[r0.clone()], ":gleasonator:");
    }

    #[test]
    fn shortcodes_in_ignores_malformed_or_empty_spans() {
        // `::` (empty body), unclosed `:foo`, invalid chars inside.
        let content = ":: :foo :bar! :ok:";
        let spans: Vec<_> = shortcodes_in(content).collect();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].1, "ok");
    }

    #[test]
    fn shortcodes_in_handles_adjacent_colons_without_overlap() {
        // `:a::b:` — after consuming `:a:`, the cursor lands on the
        // second `:`, which begins `:b:` → two spans, non-overlapping.
        let content = ":a::b:";
        let spans: Vec<_> = shortcodes_in(content).collect();
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].1, "a");
        assert_eq!(spans[1].1, "b");
        assert!(spans[0].0.end <= spans[1].0.start);
    }
}
