//! [NIP-27] Text note references.
//!
//! NIP-27 standardises the practice of embedding NIP-21 `nostr:`
//! URIs inside the `.content` of text-bearing events (kinds 1, 30023,
//! …). Clients scan the body at render time, decode the URI, and
//! augment the UI (hyperlink, inline preview, mention tag).
//!
//! # Why this is a differentiation vs upstream
//!
//! `rust-nostr/nostr@master` does not ship a NIP-27 module; callers
//! have to scan with a hand-rolled regex. Reading the spec properly
//! means juggling three layers:
//!
//! 1. finding every `nostr:<bech32>` span in the content,
//! 2. decoding each span as a [`Nip21`] entity (which already refuses
//!    `nsec` bodies via [`crate::nips::nip21`]),
//! 3. optionally producing `p` / `e` / `a` / `q` tags for the
//!    referenced entities per NIP-27 + NIP-18.
//!
//! This module wraps all three:
//!
//! - [`references_in`] — byte-range scanner that yields
//!   `(range, Nip21)` tuples in content order, skipping malformed
//!   spans without erroring out.
//! - [`tags_from_content`] — producer of the tag bundle recommended
//!   by NIP-27 (`p` for profile/pubkey mentions; `q` for event /
//!   coordinate quotes per NIP-18). Deduplicates identical tags so
//!   a content that mentions the same pubkey three times only
//!   carries one `p` tag.
//!
//! Spans are matched conservatively: the scanner only consumes
//! ASCII lowercase alphanumerics after the `nostr:` head, which is
//! exactly the bech32 character set used by every NIP-19 HRP (`npub`
//! / `nsec` / `note` / `nprofile` / `nevent` / `naddr`). Anything
//! else simply fails the downstream [`Nip21::parse`] and is
//! dropped.
//!
//! [NIP-27]: https://github.com/nostr-protocol/nips/blob/master/27.md

use core::ops::Range;
use std::collections::BTreeSet;

use crate::event::{Alphabet, SingleLetterTag, Tag, TagKind};
use crate::nips::nip21::Nip21;

/// Scheme prefix for NIP-21 URIs.
const SCHEME: &str = "nostr:";

/// One decoded NIP-21 reference inside an event's content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    /// Byte-offset span into the source content string.
    ///
    /// `&content[range]` yields the full `nostr:<bech32>`
    /// substring — useful for in-place substitution (e.g. rendering
    /// `@mattn` over the top of a `nostr:nprofile1…`).
    pub range: Range<usize>,
    /// The parsed NIP-21 entity.
    pub entity: Nip21,
}

/// Iterate every successfully-parsed NIP-21 reference in `content`.
///
/// The scanner is zero-allocation: it only allocates inside
/// [`Nip21::parse`] for the successfully-decoded entities.
/// Malformed spans (wrong HRP, truncated body, bad checksum, or the
/// forbidden `nsec` body) are silently skipped.
pub fn references_in(content: &str) -> impl Iterator<Item = Reference> + '_ {
    NostrUriScanner::new(content)
}

/// Produce the NIP-27 + NIP-18 implicit tag bundle from `content`.
///
/// Mapping:
///
/// | `Nip21` variant                | Tag(s) emitted                                |
/// |--------------------------------|-----------------------------------------------|
/// | `Pubkey` / `Profile`           | `p` (with relay hints when `Profile`)         |
/// | `EventId` / `Event`            | `q` (NIP-18, with relay + author when known)  |
/// | `Coordinate`                   | `q` addressable (`["q", <coord>, <relay>]`)   |
///
/// Deduplication is by *content-equal* tag value: a note that
/// mentions the same pubkey twice only emits one `p` tag.
///
/// This function is intentionally side-effect-free; higher-level
/// builders can layer it on top of a pre-populated tag list by
/// filtering out duplicates of their own choosing.
#[must_use]
pub fn tags_from_content(content: &str) -> Vec<Tag> {
    let mut seen: BTreeSet<Vec<String>> = BTreeSet::new();
    let mut out: Vec<Tag> = Vec::new();

    for r in references_in(content) {
        for tag in entity_to_tags(&r.entity) {
            if seen.insert(tag.values().to_vec()) {
                out.push(tag);
            }
        }
    }
    out
}

fn entity_to_tags(entity: &Nip21) -> Vec<Tag> {
    match entity {
        Nip21::Pubkey(pk) => vec![Tag::p(*pk)],
        Nip21::Profile(p) => {
            let mut values: Vec<String> = Vec::with_capacity(2);
            values.push(p.public_key.to_hex());
            if let Some(first) = p.relays.first() {
                values.push(first.as_str().to_owned());
            }
            vec![make_tag(Alphabet::P, values)]
        }
        Nip21::EventId(id) => vec![make_tag(Alphabet::Q, [id.to_hex()])],
        Nip21::Event(e) => {
            let mut values: Vec<String> = Vec::with_capacity(3);
            values.push(e.event_id.to_hex());
            values.push(
                e.relays
                    .first()
                    .map(|r| r.as_str().to_owned())
                    .unwrap_or_default(),
            );
            if let Some(author) = e.author {
                values.push(author.to_hex());
            }
            vec![make_tag(Alphabet::Q, values)]
        }
        Nip21::Coordinate(c) => {
            let mut values: Vec<String> = Vec::with_capacity(2);
            values.push(c.coordinate.to_wire());
            if let Some(first) = c.relays.first() {
                values.push(first.as_str().to_owned());
            }
            vec![make_tag(Alphabet::Q, values)]
        }
    }
}

fn make_tag<I, S>(letter: Alphabet, args: I) -> Tag
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let head = TagKind::single_letter(SingleLetterTag::lowercase(letter));
    Tag::with(&head, args)
}

struct NostrUriScanner<'a> {
    content: &'a str,
    cursor: usize,
}

impl<'a> NostrUriScanner<'a> {
    const fn new(content: &'a str) -> Self {
        Self { content, cursor: 0 }
    }
}

impl Iterator for NostrUriScanner<'_> {
    type Item = Reference;

    fn next(&mut self) -> Option<Self::Item> {
        let haystack = self.content.as_bytes();
        loop {
            let rest = haystack.get(self.cursor..)?;
            let rel = find_scheme(rest)?;
            let start = self.cursor + rel;
            let body_start = start + SCHEME.len();
            let body_slice = haystack.get(body_start..).unwrap_or(&[]);
            let body_end = scan_bech32_body(body_slice) + body_start;
            if body_end == body_start {
                self.cursor = body_start;
                continue;
            }
            let full = start..body_end;
            // `content[full.clone()]` is safe: we only consumed ASCII.
            let uri = self.content.get(full.clone())?;
            self.cursor = body_end;
            if let Ok(entity) = Nip21::parse(uri) {
                return Some(Reference {
                    range: full,
                    entity,
                });
            }
            // Unparseable (wrong HRP, bad checksum, nsec refused, …);
            // loop and keep scanning.
        }
    }
}

fn find_scheme(haystack: &[u8]) -> Option<usize> {
    haystack
        .windows(SCHEME.len())
        .position(|w| w == SCHEME.as_bytes())
}

fn scan_bech32_body(bytes: &[u8]) -> usize {
    // Bech32 HRP + separator `1` + data is entirely lowercase
    // alphanumerics. Uppercase is *syntactically* allowed by bech32
    // but not used by any NIP-19 HRP; we therefore restrict the
    // scanner to lowercase so adjacency to a capital letter breaks
    // cleanly (e.g. `nostr:npub1…AND` yields `nostr:npub1…` without
    // swallowing `AND`).
    bytes
        .iter()
        .take_while(|&&b| matches!(b, b'a'..=b'z' | b'0'..=b'9'))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;
    use crate::event::Kind;
    use crate::key::PublicKey;
    use crate::nips::nip19::{Nip19Profile, ToBech32};

    fn profile_uri() -> (String, PublicKey) {
        let keys = Keys::parse("0000000000000000000000000000000000000000000000000000000000000003")
            .unwrap();
        let profile = Nip19Profile::new(*keys.public_key(), core::iter::empty());
        let bech32 = profile.to_bech32().unwrap();
        (format!("nostr:{bech32}"), *keys.public_key())
    }

    fn npub_uri() -> (String, PublicKey) {
        let keys = Keys::parse("0000000000000000000000000000000000000000000000000000000000000005")
            .unwrap();
        let bech32 = keys.public_key().to_bech32().unwrap();
        (format!("nostr:{bech32}"), *keys.public_key())
    }

    #[test]
    fn scanner_yields_every_valid_reference_in_order() {
        let (u1, pk1) = profile_uri();
        let (u2, pk2) = npub_uri();
        let content = format!("hi {u1} and also {u2}!");
        let refs: Vec<_> = references_in(&content).collect();
        assert_eq!(refs.len(), 2);
        // First should be the profile.
        assert!(matches!(&refs[0].entity, Nip21::Profile(p) if p.public_key == pk1));
        assert!(matches!(refs[1].entity, Nip21::Pubkey(pk) if pk == pk2));
        // Byte ranges round-trip.
        assert_eq!(&content[refs[0].range.clone()], u1.as_str());
        assert_eq!(&content[refs[1].range.clone()], u2.as_str());
    }

    #[test]
    fn scanner_skips_malformed_spans() {
        let content = "nope nostr: bar nostr:not-bech32 nostr:nsec1abc baz";
        assert!(references_in(content).next().is_none());
    }

    #[test]
    fn scanner_skips_disallowed_nsec_bodies() {
        // nsec is syntactically valid bech32 but NIP-21 refuses it.
        let keys = Keys::parse("0000000000000000000000000000000000000000000000000000000000000007")
            .unwrap();
        let bech32 = keys.secret_key().to_bech32().unwrap();
        let content = format!("secret leak: nostr:{bech32}");
        assert!(references_in(&content).next().is_none());
    }

    #[test]
    fn tags_from_content_emits_p_for_pubkey_mentions() {
        let (uri, pk) = npub_uri();
        let content = format!("cc {uri}");
        let tags = tags_from_content(&content);
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].get(0), Some("p"));
        assert_eq!(tags[0].get(1), Some(pk.to_hex().as_str()));
    }

    #[test]
    fn tags_from_content_deduplicates_repeated_mentions() {
        let (uri, _) = npub_uri();
        let content = format!("{uri} {uri} {uri}");
        let tags = tags_from_content(&content);
        assert_eq!(tags.len(), 1);
    }

    #[test]
    fn tags_from_content_uses_q_for_event_references() {
        use crate::event::EventId;
        use crate::nips::nip19::Nip19Event;
        let id = EventId::parse("0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap();
        let ev = Nip19Event::new(id);
        let bech = ev.to_bech32().unwrap();
        let content = format!("see nostr:{bech}");
        let tags = tags_from_content(&content);
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].get(0), Some("q"));
        assert_eq!(tags[0].get(1), Some(id.to_hex().as_str()));
    }

    #[test]
    fn scanner_tolerates_adjacent_punctuation_and_emoji() {
        let (uri, _) = profile_uri();
        let content = format!("look: {uri}. Also emoji 🚀 then {uri}, end.");
        assert_eq!(references_in(&content).count(), 2);
    }

    #[test]
    fn scanner_does_not_cross_whitespace_into_next_token() {
        let (uri_a, _) = profile_uri();
        let (uri_b, _) = npub_uri();
        let content = format!("{uri_a} not-a-uri {uri_b}");
        let refs: Vec<_> = references_in(&content).collect();
        assert_eq!(refs.len(), 2);
        // Between them lives `" not-a-uri "`: scanner must not
        // collapse that into a single URI.
        assert!(refs[0].range.end < refs[1].range.start);
    }

    #[test]
    fn tags_from_content_emits_q_with_coordinate_and_relay_hint() {
        use crate::event::Coordinate;
        use crate::nips::nip19::Nip19Coordinate;
        use crate::types::RelayUrl;

        let keys = Keys::parse("0000000000000000000000000000000000000000000000000000000000000009")
            .unwrap();
        let coord = Coordinate::new(Kind::new(30_023), *keys.public_key(), "slug");
        let nip19_coord = Nip19Coordinate::from_coordinate(
            coord.clone(),
            [RelayUrl::parse("wss://relay.example/").unwrap()],
        );
        let bech = nip19_coord.to_bech32().unwrap();
        let content = format!("see also nostr:{bech}");
        let tags = tags_from_content(&content);
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].get(0), Some("q"));
        assert_eq!(tags[0].get(1), Some(coord.to_wire().as_str()));
        assert_eq!(tags[0].get(2), Some("wss://relay.example/"));
    }
}
