//! Single-pass content parser for Nostr text-bearing events.
//!
//! Nostr clients render `kind:1` notes (and a long tail of similar
//! kinds) by walking the `.content` string and recognising four
//! syntactic affordances:
//!
//! - **NIP-21 `nostr:` URIs** ([NIP-21]) — embedded references to
//!   profiles, events, addressable coordinates, …;
//! - **HTTP(S) and other scheme URLs** — to be rendered as
//!   hyperlinks;
//! - **`#hashtags`** ([NIP-12]) — folksonomy markers that the
//!   `t` filter key indexes;
//! - **`\n` line breaks** — for layout.
//!
//! [`NostrParser`] is a single-pass tokeniser that yields the
//! [`Token`] stream representing those affordances plus the
//! interspersed plain-text spans. Callers configure which affordances
//! to recognise via [`NostrParserOptions`]; a disabled affordance
//! falls through to plain text untouched.
//!
//! # Why this exists
//!
//! Earlier nula releases shipped two narrowly-scoped scanners:
//! [`crate::nips::nip27::references_in`] (NIP-21 only) and
//! [`crate::nips::nip27::tags_from_content`] (tag harvester).
//! Renderers had to layer their own URL / hashtag detection on top.
//! This module unifies those concerns behind a single iterator so a
//! UI layer can drive its rendering loop with one walk over the
//! source string.
//!
//! # Token kinds
//!
//! | Variant         | Borrow scope | Spec |
//! |-----------------|--------------|------|
//! | [`Token::Text`] | `&'a str`    | n/a  |
//! | [`Token::Nostr`]| owned [`Nip21`] | NIP-21 |
//! | [`Token::Url`]  | owned [`Url`]   | n/a (RFC-3986) |
//! | [`Token::Hashtag`] | `&'a str` (without leading `#`) | NIP-12 |
//! | [`Token::LineBreak`] | n/a    | n/a |
//!
//! # Example
//!
//! ```
//! use nula_core::parser::{NostrParser, NostrParserOptions, Token};
//!
//! let parser = NostrParser::new();
//! let opts = NostrParserOptions::default();
//! let mut tokens = parser.parse("Visit https://example.com #rust", opts);
//! assert!(matches!(tokens.next(), Some(Token::Text(_))));
//! assert!(matches!(tokens.next(), Some(Token::Url(_))));
//! ```
//!
//! [NIP-12]: https://github.com/nostr-protocol/nips/blob/master/12.md
//! [NIP-21]: https://github.com/nostr-protocol/nips/blob/master/21.md

use bech32::Fe32;

use crate::nips::nip21::{self, Nip21};
use crate::types::Url;

/// One unit produced by [`NostrParser::parse`].
///
/// Lifetimes:
///
/// - `Text` and `Hashtag` borrow directly from the input string so
///   the parser can operate without copying.
/// - `Nostr` and `Url` are owned because their parsed form requires
///   an allocation (`Nip21`'s relay-hint vectors, `Url`'s normalised
///   string).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Token<'a> {
    /// Plain text run that did not match any other token. Empty
    /// strings are never emitted; the parser collapses zero-length
    /// gaps between adjacent matches.
    Text(&'a str),
    /// A successfully-decoded [NIP-21] `nostr:` URI.
    ///
    /// [NIP-21]: https://github.com/nostr-protocol/nips/blob/master/21.md
    Nostr(Nip21),
    /// A successfully-parsed URL.
    Url(Url),
    /// A `#hashtag` whose body is the slice **without** the leading
    /// `#`. Empty hashtags (a bare `#`) fall through as text.
    Hashtag(&'a str),
    /// A `\n` byte at the current position.
    LineBreak,
}

/// Knobs that control which affordances [`NostrParser`] recognises.
///
/// Disabled affordances are treated as plain text — the parser still
/// makes forward progress and never errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[allow(
    clippy::struct_excessive_bools,
    reason = "each toggle maps 1:1 to a distinct NIP affordance; collapsing them into a bitflags enum would obscure the doc-friendly per-field comments"
)]
pub struct NostrParserOptions {
    /// Recognise `nostr:<bech32>` URIs.
    pub parse_nostr_uris: bool,
    /// Recognise scheme URLs (`http://`, `https://`, `ftp://`, …).
    pub parse_urls: bool,
    /// Recognise `#hashtags` per NIP-12.
    pub parse_hashtags: bool,
    /// Emit dedicated [`Token::LineBreak`] for `\n` bytes; when
    /// `false`, line breaks are folded into the surrounding
    /// [`Token::Text`] runs.
    pub emit_line_breaks: bool,
}

impl Default for NostrParserOptions {
    fn default() -> Self {
        Self::all_enabled()
    }
}

impl NostrParserOptions {
    /// Every affordance enabled (the most common configuration).
    #[must_use]
    pub const fn all_enabled() -> Self {
        Self {
            parse_nostr_uris: true,
            parse_urls: true,
            parse_hashtags: true,
            emit_line_breaks: true,
        }
    }

    /// No affordance enabled — the parser yields one
    /// [`Token::Text`] covering the whole input.
    #[must_use]
    pub const fn all_disabled() -> Self {
        Self {
            parse_nostr_uris: false,
            parse_urls: false,
            parse_hashtags: false,
            emit_line_breaks: false,
        }
    }

    /// Builder helper toggling [`Self::parse_nostr_uris`].
    #[must_use]
    pub const fn nostr_uris(mut self, enabled: bool) -> Self {
        self.parse_nostr_uris = enabled;
        self
    }

    /// Builder helper toggling [`Self::parse_urls`].
    #[must_use]
    pub const fn urls(mut self, enabled: bool) -> Self {
        self.parse_urls = enabled;
        self
    }

    /// Builder helper toggling [`Self::parse_hashtags`].
    #[must_use]
    pub const fn hashtags(mut self, enabled: bool) -> Self {
        self.parse_hashtags = enabled;
        self
    }

    /// Builder helper toggling [`Self::emit_line_breaks`].
    #[must_use]
    pub const fn line_breaks(mut self, enabled: bool) -> Self {
        self.emit_line_breaks = enabled;
        self
    }
}

/// Stateless factory that turns a `&str` into a [`NostrParserIter`].
///
/// The parser holds no state itself; it exists so callers can
/// configure module-wide defaults (currently none) without rebuilding
/// the iterator at every call site.
#[derive(Debug, Clone, Copy, Default)]
pub struct NostrParser;

impl NostrParser {
    /// Construct a new parser.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Parse `text` into a token stream using `opts`.
    ///
    /// The returned iterator borrows from `text` and lives for as
    /// long as `text` does.
    #[must_use]
    #[allow(
        clippy::unused_self,
        reason = "kept as a method so a future stateful parser variant can land without breaking callers"
    )]
    pub const fn parse(self, text: &str, opts: NostrParserOptions) -> NostrParserIter<'_> {
        NostrParserIter::new(text, opts)
    }
}

/// Iterator yielded by [`NostrParser::parse`].
#[derive(Debug)]
pub struct NostrParserIter<'a> {
    text: &'a str,
    bytes: &'a [u8],
    pos: usize,
    opts: NostrParserOptions,
    /// A pre-computed match the iterator will emit on the *next*
    /// `next()` call after first flushing the leading text gap.
    pending: Option<Match>,
}

impl<'a> NostrParserIter<'a> {
    const fn new(text: &'a str, opts: NostrParserOptions) -> Self {
        Self {
            text,
            bytes: text.as_bytes(),
            pos: 0,
            opts,
            pending: None,
        }
    }
}

impl<'a> Iterator for NostrParserIter<'a> {
    type Item = Token<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        // 1) Drain any pending typed match queued by the previous
        //    iteration after we emitted its leading text gap.
        if let Some(mat) = self.pending.take() {
            self.pos = mat.end;
            return Some(self.materialise(mat));
        }

        // 2) Walk forward looking for the next affordance.
        if self.pos >= self.bytes.len() {
            return None;
        }
        if let Some(mat) = self.next_match() {
            if mat.start > self.pos {
                // Emit the leading text gap; queue the typed
                // match for the next call.
                let gap = self.text.get(self.pos..mat.start)?;
                self.pos = mat.start;
                self.pending = Some(mat);
                return Some(Token::Text(gap));
            }
            // Match starts here; emit it directly.
            self.pos = mat.end;
            return Some(self.materialise(mat));
        }
        // No more matches; emit the remainder as one Text run.
        let rest = self.text.get(self.pos..)?;
        self.pos = self.bytes.len();
        Some(Token::Text(rest))
    }
}

impl<'a> NostrParserIter<'a> {
    /// Locate the *first* affordance at or after `self.pos`.
    fn next_match(&self) -> Option<Match> {
        let mut search = self.pos;
        while search < self.bytes.len() {
            if self.opts.emit_line_breaks && self.bytes.get(search) == Some(&b'\n') {
                return Some(Match::line_break(search));
            }
            if self.opts.parse_hashtags
                && let Some(mat) = self.try_hashtag(search)
            {
                return Some(mat);
            }
            if self.opts.parse_nostr_uris
                && let Some(mat) = self.try_nostr_uri(search)
            {
                return Some(mat);
            }
            if self.opts.parse_urls
                && let Some(mat) = self.try_url(search)
            {
                return Some(mat);
            }
            search += utf8_step(self.text, search);
        }
        None
    }

    fn try_hashtag(&self, start: usize) -> Option<Match> {
        if self.bytes.get(start)? != &b'#' {
            return None;
        }
        // A hashtag is anchored at start-of-string or directly after
        // a whitespace byte. Anything else (e.g. `foo#bar`) is text.
        if start > 0
            && let Some(prev) = self.bytes.get(start - 1)
            && !prev.is_ascii_whitespace()
        {
            return None;
        }
        let mut end = start + 1;
        while end < self.bytes.len() {
            let ch = self.text.get(end..)?.chars().next()?;
            if is_forbidden_hashtag_char(ch) {
                break;
            }
            end += ch.len_utf8();
        }
        if end == start + 1 {
            return None;
        }
        Some(Match::hashtag(start, end))
    }

    fn try_nostr_uri(&self, start: usize) -> Option<Match> {
        let prefix = nip21::SCHEME_PREFIX.as_bytes(); // "nostr:"
        if self.bytes.get(start..start + prefix.len()) != Some(prefix) {
            return None;
        }
        let body_start = start + prefix.len();
        let mut end = body_start;
        // Greedy bech32 consumption: `Nip21::parse` validates the
        // checksum so trailing garbage falls back through `Text`.
        while let Some(&b) = self.bytes.get(end) {
            if b.is_ascii_lowercase() || b == b'1' || Fe32::from_char(b as char).is_ok() {
                end += 1;
            } else {
                break;
            }
        }
        if end == body_start {
            return None;
        }
        Some(Match::nostr(start, end))
    }

    fn try_url(&self, start: usize) -> Option<Match> {
        if !self.bytes.get(start)?.is_ascii_alphabetic() {
            return None;
        }
        let mut after_scheme = start + 1;
        while let Some(&b) = self.bytes.get(after_scheme) {
            if b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.') {
                after_scheme += 1;
            } else {
                break;
            }
        }
        let separator = b"://";
        if self.bytes.get(after_scheme..after_scheme + separator.len()) != Some(separator) {
            return None;
        }
        let mut end = after_scheme + separator.len();
        while let Some(&b) = self.bytes.get(end) {
            if b.is_ascii_whitespace() || !is_allowed_url_byte(b) {
                break;
            }
            end += 1;
        }
        if end <= after_scheme + separator.len() {
            return None;
        }
        // Trim sentence-terminating punctuation.
        while end > after_scheme + separator.len()
            && self
                .bytes
                .get(end - 1)
                .copied()
                .is_some_and(is_url_trailing_punct)
        {
            end -= 1;
        }
        // Balance an unmatched closing paren.
        if end > start
            && self.bytes.get(end - 1) == Some(&b')')
            && let Some(url_bytes) = self.bytes.get(start..end)
        {
            #[allow(
                clippy::naive_bytecount,
                reason = "avoid pulling in `bytecount` for two scans of a tiny URL slice"
            )]
            let opens = url_bytes.iter().filter(|&&b| b == b'(').count();
            #[allow(
                clippy::naive_bytecount,
                reason = "avoid pulling in `bytecount` for two scans of a tiny URL slice"
            )]
            let closes = url_bytes.iter().filter(|&&b| b == b')').count();
            if closes > opens {
                end -= 1;
            }
        }
        Some(Match::url(start, end))
    }

    fn materialise(&self, mat: Match) -> Token<'a> {
        let Some(slice) = self.text.get(mat.start..mat.end) else {
            return Token::Text("");
        };
        match mat.kind {
            MatchKind::LineBreak => Token::LineBreak,
            MatchKind::Hashtag => slice.get(1..).map_or(Token::Text(slice), Token::Hashtag),
            MatchKind::NostrUri => Nip21::parse(slice).map_or(Token::Text(slice), Token::Nostr),
            MatchKind::Url => Url::parse(slice).map_or(Token::Text(slice), Token::Url),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Match {
    kind: MatchKind,
    start: usize,
    end: usize,
}

impl Match {
    const fn line_break(at: usize) -> Self {
        Self {
            kind: MatchKind::LineBreak,
            start: at,
            end: at + 1,
        }
    }
    const fn hashtag(start: usize, end: usize) -> Self {
        Self {
            kind: MatchKind::Hashtag,
            start,
            end,
        }
    }
    const fn nostr(start: usize, end: usize) -> Self {
        Self {
            kind: MatchKind::NostrUri,
            start,
            end,
        }
    }
    const fn url(start: usize, end: usize) -> Self {
        Self {
            kind: MatchKind::Url,
            start,
            end,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum MatchKind {
    LineBreak,
    Hashtag,
    NostrUri,
    Url,
}

/// True when `ch` is a byte the NIP-12 hashtag body cannot include.
fn is_forbidden_hashtag_char(ch: char) -> bool {
    if ch.is_whitespace() || ch.is_control() {
        return true;
    }
    matches!(
        ch,
        '.' | ','
            | '!'
            | '?'
            | '('
            | ')'
            | '['
            | ']'
            | '{'
            | '}'
            | '"'
            | '\''
            | '@'
            | '#'
            | ';'
            | ':'
            | '&'
            | '*'
            | '+'
            | '='
            | '<'
            | '>'
            | '/'
            | '\\'
            | '|'
            | '^'
            | '~'
            | '%'
            | '$'
            | '`'
    )
}

/// True when `byte` may legitimately appear inside a URL body. Based
/// on RFC-3986 §unreserved + §sub-delims + a few common reserved
/// chars (`/?#[]@`) that real-world URLs use.
const fn is_allowed_url_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b':'
                | b'/'
                | b'?'
                | b'#'
                | b'['
                | b']'
                | b'@'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b'%'
        )
}

/// Punctuation that should be stripped from the tail of a URL when it
/// is more likely sentence-terminator than URL data.
const fn is_url_trailing_punct(byte: u8) -> bool {
    matches!(byte, b'.' | b',' | b';' | b':' | b'!' | b'?' | b']' | b'}')
}

/// Length of the UTF-8 codepoint at `byte_index` inside `text`.
///
/// Falls back to `1` when the index is on a continuation byte (which
/// is invariant-broken and only reachable in malformed inputs); the
/// fallback keeps the parser making forward progress instead of
/// looping.
fn utf8_step(text: &str, byte_index: usize) -> usize {
    text[byte_index..].chars().next().map_or(1, char::len_utf8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;
    use crate::nips::nip19::{Nip19Profile, ToBech32};

    fn parse(text: &str) -> Vec<Token<'_>> {
        NostrParser::new()
            .parse(text, NostrParserOptions::default())
            .collect()
    }

    fn parse_with(text: &str, opts: NostrParserOptions) -> Vec<Token<'_>> {
        NostrParser::new().parse(text, opts).collect()
    }

    fn npub_uri(seed: u8) -> (String, crate::PublicKey) {
        let raw = format!("{seed:0>64}");
        let keys = Keys::parse(&raw).unwrap();
        let bech = keys.public_key().to_bech32().unwrap();
        (format!("nostr:{bech}"), *keys.public_key())
    }

    #[test]
    fn empty_input_yields_no_tokens() {
        assert_eq!(parse(""), Vec::<Token<'_>>::new());
    }

    #[test]
    fn pure_text_passthrough() {
        assert_eq!(parse("hello world"), vec![Token::Text("hello world")]);
    }

    #[test]
    fn single_url() {
        let tokens = parse("https://example.com");
        assert_eq!(tokens.len(), 1);
        assert!(matches!(tokens[0], Token::Url(_)));
    }

    #[test]
    fn url_in_sentence_with_trailing_dot() {
        let tokens = parse("Visit https://example.com.");
        assert_eq!(
            tokens,
            vec![
                Token::Text("Visit "),
                Token::Url(Url::parse("https://example.com").unwrap()),
                Token::Text("."),
            ],
        );
    }

    #[test]
    fn url_with_path_and_query() {
        let tokens = parse("https://example.com/foo?bar=baz#frag");
        assert!(matches!(&tokens[..], [Token::Url(_)]));
    }

    #[test]
    fn url_strips_trailing_comma_then_emits_text() {
        let tokens = parse("see https://example.com, then leave");
        assert_eq!(tokens.len(), 3);
        assert!(matches!(tokens[1], Token::Url(_)));
        assert!(matches!(tokens[2], Token::Text(", then leave")));
    }

    #[test]
    fn url_balances_unmatched_parenthesis() {
        let tokens = parse("(https://example.com)");
        assert_eq!(
            tokens,
            vec![
                Token::Text("("),
                Token::Url(Url::parse("https://example.com").unwrap()),
                Token::Text(")"),
            ],
        );
    }

    #[test]
    fn url_keeps_balanced_parentheses() {
        let tokens = parse("https://en.wikipedia.org/wiki/Rust_(programming_language)");
        assert!(matches!(&tokens[..], [Token::Url(_)]));
    }

    #[test]
    fn ftp_scheme_recognised() {
        let tokens = parse("ftp://files.example.com/x");
        assert!(matches!(&tokens[..], [Token::Url(_)]));
    }

    #[test]
    fn hashtag_at_start() {
        let tokens = parse("#rust is fun");
        assert_eq!(tokens, vec![Token::Hashtag("rust"), Token::Text(" is fun")],);
    }

    #[test]
    fn hashtag_after_whitespace() {
        let tokens = parse("hello #nostr");
        assert_eq!(tokens, vec![Token::Text("hello "), Token::Hashtag("nostr")],);
    }

    #[test]
    fn hashtag_after_letter_is_text() {
        let tokens = parse("foo#bar");
        assert_eq!(tokens, vec![Token::Text("foo#bar")]);
    }

    #[test]
    fn bare_hash_is_text() {
        let tokens = parse("just a # symbol");
        assert_eq!(tokens, vec![Token::Text("just a # symbol")]);
    }

    #[test]
    fn hashtag_terminates_at_punctuation() {
        let tokens = parse("#tag, more");
        assert_eq!(tokens, vec![Token::Hashtag("tag"), Token::Text(", more")],);
    }

    #[test]
    fn hashtag_with_unicode_body() {
        let tokens = parse("#日本語ok");
        assert_eq!(tokens, vec![Token::Hashtag("日本語ok")]);
    }

    #[test]
    fn nostr_npub_uri() {
        let (uri, pk) = npub_uri(3);
        let tokens = parse(&uri);
        assert_eq!(tokens.len(), 1);
        match &tokens[0] {
            Token::Nostr(Nip21::Pubkey(p)) => assert_eq!(*p, pk),
            other => panic!("expected Token::Nostr(Pubkey), got {other:?}"),
        }
    }

    #[test]
    fn nostr_uri_inside_sentence() {
        let (uri, _) = npub_uri(5);
        let text = format!("hi {uri}, ok?");
        let tokens = parse(&text);
        assert_eq!(tokens.len(), 3);
        assert!(matches!(tokens[0], Token::Text("hi ")));
        assert!(matches!(tokens[1], Token::Nostr(Nip21::Pubkey(_))));
        assert!(matches!(tokens[2], Token::Text(", ok?")));
    }

    #[test]
    fn nsec_uri_falls_through_as_text() {
        // NIP-21 forbids `nsec` URIs; the parser refuses to surface
        // them as Token::Nostr but must not panic — they fall back to
        // a plain Text run.
        let keys = Keys::parse("0000000000000000000000000000000000000000000000000000000000000007")
            .unwrap();
        let bech = keys.secret_key().to_bech32().unwrap();
        let text = format!("leak: nostr:{bech}");
        let tokens = parse(&text);
        assert!(
            tokens.iter().all(|t| !matches!(t, Token::Nostr(_))),
            "nsec must NOT be surfaced as a Nostr token: {tokens:?}"
        );
    }

    #[test]
    fn line_break_emitted_when_enabled() {
        let tokens = parse("a\nb");
        assert_eq!(
            tokens,
            vec![Token::Text("a"), Token::LineBreak, Token::Text("b")],
        );
    }

    #[test]
    fn line_break_can_be_disabled() {
        let opts = NostrParserOptions::default().line_breaks(false);
        let tokens = parse_with("a\nb", opts);
        assert_eq!(tokens, vec![Token::Text("a\nb")]);
    }

    #[test]
    fn hashtag_disabled_falls_through() {
        let opts = NostrParserOptions::default().hashtags(false);
        let tokens = parse_with("#rust", opts);
        assert_eq!(tokens, vec![Token::Text("#rust")]);
    }

    #[test]
    fn url_disabled_falls_through() {
        let opts = NostrParserOptions::default().urls(false);
        let tokens = parse_with("see https://example.com.", opts);
        assert_eq!(tokens, vec![Token::Text("see https://example.com.")]);
    }

    #[test]
    fn nostr_uri_disabled_falls_through() {
        let (uri, _) = npub_uri(11);
        let opts = NostrParserOptions::default().nostr_uris(false);
        let tokens = parse_with(&uri, opts);
        assert_eq!(tokens.len(), 1);
        assert!(matches!(tokens[0], Token::Text(_)));
    }

    #[test]
    fn all_disabled_emits_one_text_run() {
        let tokens = parse_with(
            "Hello https://example.com #rust nostr:npub1abc",
            NostrParserOptions::all_disabled(),
        );
        assert_eq!(tokens.len(), 1);
        assert!(matches!(tokens[0], Token::Text(_)));
    }

    #[test]
    fn mixed_url_hashtag_and_nostr_uri() {
        let (uri, _) = npub_uri(9);
        let text = format!("Check {uri} via https://relay.example #intro");
        let tokens = parse(&text);
        assert!(tokens.len() >= 4);
        // First non-text token should be the nostr URI.
        let nostr_idx = tokens
            .iter()
            .position(|t| matches!(t, Token::Nostr(_)))
            .unwrap();
        let url_idx = tokens
            .iter()
            .position(|t| matches!(t, Token::Url(_)))
            .unwrap();
        let hash_idx = tokens
            .iter()
            .position(|t| matches!(t, Token::Hashtag(_)))
            .unwrap();
        assert!(nostr_idx < url_idx && url_idx < hash_idx);
    }

    #[test]
    fn multiline_input_yields_line_breaks_between_runs() {
        let tokens = parse("first\n#tag\nlast");
        assert_eq!(
            tokens,
            vec![
                Token::Text("first"),
                Token::LineBreak,
                Token::Hashtag("tag"),
                Token::LineBreak,
                Token::Text("last"),
            ],
        );
    }

    #[test]
    fn emoji_inside_text_does_not_break_parser() {
        let tokens = parse("hello 🚀 world");
        assert_eq!(tokens, vec![Token::Text("hello 🚀 world")]);
    }

    #[test]
    fn emoji_directly_before_hashtag() {
        let tokens = parse("🚀 #moon");
        assert_eq!(tokens, vec![Token::Text("🚀 "), Token::Hashtag("moon")],);
    }

    #[test]
    fn nostr_uri_at_end_of_input() {
        let (uri, _) = npub_uri(13);
        let text = format!("ping {uri}");
        let tokens = parse(&text);
        assert_eq!(tokens.len(), 2);
        assert!(matches!(tokens[1], Token::Nostr(_)));
    }

    #[test]
    fn malformed_nostr_uri_falls_through() {
        let tokens = parse("nostr:notbech32 abc");
        assert!(
            tokens.iter().all(|t| !matches!(t, Token::Nostr(_))),
            "garbage bech32 must not produce a Nostr token: {tokens:?}",
        );
    }

    #[test]
    fn many_repeated_hashtags() {
        let tokens = parse("#a #b #c");
        let hashtags: Vec<_> = tokens
            .iter()
            .filter_map(|t| match t {
                Token::Hashtag(s) => Some(*s),
                _ => None,
            })
            .collect();
        assert_eq!(hashtags, vec!["a", "b", "c"]);
    }

    #[test]
    fn nprofile_uri_is_recognised() {
        let keys = Keys::parse("0000000000000000000000000000000000000000000000000000000000000017")
            .unwrap();
        let profile = Nip19Profile::new(*keys.public_key(), std::iter::empty());
        let bech = profile.to_bech32().unwrap();
        let uri = format!("nostr:{bech}");
        let tokens = parse(&uri);
        assert_eq!(tokens.len(), 1);
        assert!(matches!(tokens[0], Token::Nostr(Nip21::Profile(_))));
    }

    #[test]
    fn iterator_is_lazy() {
        // The parser must not materialise the whole stream eagerly.
        let mut iter = NostrParser::new().parse("alpha #beta gamma", NostrParserOptions::default());
        // Pull one token, then drop the iterator implicitly at end
        // of scope. The smoke check ensures partial consumption is
        // safe and the iterator does not allocate eagerly.
        let _first = iter.next();
    }

    #[test]
    fn url_followed_by_newline_is_split() {
        let tokens = parse("https://example.com\nnext");
        assert!(matches!(tokens[0], Token::Url(_)));
        assert!(matches!(tokens[1], Token::LineBreak));
        assert!(matches!(tokens[2], Token::Text("next")));
    }

    #[test]
    fn hashtag_at_end_of_input() {
        let tokens = parse("ending with #tag");
        assert_eq!(tokens.len(), 2);
        assert!(matches!(tokens[1], Token::Hashtag("tag")));
    }

    #[test]
    fn forbidden_hashtag_chars_terminate_body() {
        for forbidden in &[".", ",", "!", "?", "(", ")", "/", ";", ":"] {
            let text = format!("#abc{forbidden}rest");
            let tokens = parse(&text);
            let body = tokens
                .iter()
                .find_map(|t| match t {
                    Token::Hashtag(s) => Some(*s),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("hashtag must split at {forbidden}: {tokens:?}"));
            assert_eq!(body, "abc", "split-on `{forbidden}` failed");
        }
    }

    #[test]
    fn newline_before_hashtag() {
        let tokens = parse("\n#start");
        assert_eq!(tokens, vec![Token::LineBreak, Token::Hashtag("start")],);
    }

    #[test]
    fn double_newline_emits_two_line_breaks() {
        let tokens = parse("a\n\nb");
        assert_eq!(
            tokens,
            vec![
                Token::Text("a"),
                Token::LineBreak,
                Token::LineBreak,
                Token::Text("b"),
            ],
        );
    }
}
