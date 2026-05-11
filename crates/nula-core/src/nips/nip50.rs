//! [NIP-50] Search Capability.
//!
//! NIP-50 specifies a `search` field on `REQ` filters, plus a tiny
//! query-string DSL for constrained extensions:
//!
//! ```text
//! best nostr clients language:en nsfw:false sentiment:positive
//! ```
//!
//! The free-text portion is whatever the relay's search backend
//! understands; the extensions are well-defined `key:value` pairs.
//!
//! # Why a typed wrapper
//!
//! [`crate::Filter::search`] already accepts an arbitrary string —
//! that satisfies the wire format. NIP-50's value lies in:
//!
//! 1. *Building* such queries safely so a typo in
//!    `sentiment:positiv` does not silently mean "match everything";
//! 2. *Parsing* relay-supplied queries to discover which extensions
//!    are in use without rolling per-call regex;
//! 3. *Forward compatibility* — relays MAY add their own extensions
//!    (NIP-50 §"Extensions" line about ignoring unknown keys), so
//!    [`SearchExtension::Other`] keeps unknown pairs round-tripping.
//!
//! # Wire shape
//!
//! Free-text and extensions live in the same string. Extensions are
//! `key:value` tokens (no whitespace inside the value). Both halves
//! are joined with single spaces. The parser tolerates extra
//! whitespace and is order-insensitive: a relay can quote any
//! extension before, after, or amongst the free text.
//!
//! # Usage
//!
//! ```
//! use nula_core::nips::nip50::{SearchExtension, SearchQuery, Sentiment};
//!
//! let q = SearchQuery::new("best nostr apps")
//!     .with_extension(SearchExtension::Language("en".to_owned()))
//!     .with_extension(SearchExtension::Nsfw(false))
//!     .with_extension(SearchExtension::Sentiment(Sentiment::Positive));
//! let rendered = q.render();
//! let parsed = SearchQuery::parse(&rendered);
//! assert_eq!(parsed.free_text, "best nostr apps");
//! ```
//!
//! [NIP-50]: https://github.com/nostr-protocol/nips/blob/master/50.md

use thiserror::Error;

use crate::filter::Filter;

/// One spec-named NIP-50 extension or a forward-compatible
/// passthrough for unknown ones.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SearchExtension {
    /// `include:spam` — disable the relay's spam filter for this query.
    IncludeSpam,
    /// `domain:<domain>` — restrict to authors whose NIP-05 domain matches.
    Domain(String),
    /// `language:<iso-639-1>` — restrict to events of the given language
    /// (lowercase two-letter code).
    Language(String),
    /// `sentiment:<negative|neutral|positive>` — filter by sentiment.
    Sentiment(Sentiment),
    /// `nsfw:<true|false>` — include or exclude NSFW.
    Nsfw(bool),
    /// Any other `key:value` extension. The `key` is normalised to
    /// lowercase by the parser; case-sensitive values are
    /// preserved as-is.
    Other {
        /// Extension key (lowercase).
        key: String,
        /// Extension value (verbatim).
        value: String,
    },
}

/// Sentiment classification spec'd by NIP-50.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Sentiment {
    /// `negative`.
    Negative,
    /// `neutral`.
    Neutral,
    /// `positive`.
    Positive,
    /// Unknown sentiment string. Forward-compatible.
    Other(String),
}

impl Sentiment {
    /// Render to wire form.
    ///
    /// Returns the spec-defined lowercase token or, for [`Self::Other`],
    /// the borrowed inner string — which precludes a `const fn`.
    #[must_use]
    #[expect(
        clippy::missing_const_for_fn,
        reason = "`Self::Other` borrows from a heap `String`"
    )]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Negative => "negative",
            Self::Neutral => "neutral",
            Self::Positive => "positive",
            Self::Other(s) => s.as_str(),
        }
    }

    /// Parse a wire token. Always succeeds: unknown values become
    /// [`Self::Other`] for forward compatibility.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s {
            "negative" => Self::Negative,
            "neutral" => Self::Neutral,
            "positive" => Self::Positive,
            other => Self::Other(other.to_owned()),
        }
    }
}

impl SearchExtension {
    /// Render the extension as one wire token (`key:value`).
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Self::IncludeSpam => "include:spam".to_owned(),
            Self::Domain(d) => format!("domain:{d}"),
            Self::Language(l) => format!("language:{l}"),
            Self::Sentiment(s) => format!("sentiment:{}", s.as_str()),
            Self::Nsfw(b) => format!("nsfw:{b}"),
            Self::Other { key, value } => format!("{key}:{value}"),
        }
    }

    /// Parse a single `key:value` token.
    ///
    /// Returns `None` if the token has no colon (i.e. it's free
    /// text, not an extension). Returns `Some(Other { ... })` for
    /// any unknown key. Returns
    /// `Some(InvalidExtensionValue)` only when a *known* key
    /// receives a value the spec forbids (`nsfw:bogus`).
    ///
    /// # Errors
    ///
    /// - [`SearchExtensionError::EmptyKey`] when the token starts
    ///   with `:`.
    /// - [`SearchExtensionError::InvalidNsfwValue`] when `nsfw:` is
    ///   followed by anything other than `true`/`false`.
    pub fn parse_token(token: &str) -> Result<Option<Self>, SearchExtensionError> {
        let Some((key, value)) = token.split_once(':') else {
            return Ok(None);
        };
        if key.is_empty() {
            return Err(SearchExtensionError::EmptyKey);
        }
        let key_lc = key.to_ascii_lowercase();
        let parsed = match key_lc.as_str() {
            "include" if value == "spam" => Self::IncludeSpam,
            "domain" => Self::Domain(value.to_owned()),
            "language" => Self::Language(value.to_owned()),
            "sentiment" => Self::Sentiment(Sentiment::parse(value)),
            "nsfw" => Self::Nsfw(parse_bool(value)?),
            _ => Self::Other {
                key: key_lc,
                value: value.to_owned(),
            },
        };
        Ok(Some(parsed))
    }
}

/// Errors raised when parsing a single NIP-50 extension token.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SearchExtensionError {
    /// The token started with `:`, leaving the key empty.
    #[error("extension token has empty key")]
    EmptyKey,
    /// `nsfw:` saw a value that wasn't `true` or `false`.
    #[error("`nsfw:` value must be `true` or `false`, got `{0}`")]
    InvalidNsfwValue(String),
}

fn parse_bool(s: &str) -> Result<bool, SearchExtensionError> {
    match s {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(SearchExtensionError::InvalidNsfwValue(other.to_owned())),
    }
}

/// Typed NIP-50 query: free text + zero or more extension tokens.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SearchQuery {
    /// Whatever the relay's search backend interprets as a natural
    /// language query. Whitespace is preserved as-is (the wire
    /// format does the same).
    pub free_text: String,
    /// Spec-named or forward-compatible extension tokens, in the
    /// order they were inserted / parsed.
    pub extensions: Vec<SearchExtension>,
}

impl SearchQuery {
    /// Build a query with only free text.
    #[must_use]
    pub fn new(free_text: impl Into<String>) -> Self {
        Self {
            free_text: free_text.into(),
            extensions: Vec::new(),
        }
    }

    /// Append one extension. Order is preserved on render.
    #[must_use]
    pub fn with_extension(mut self, ext: SearchExtension) -> Self {
        self.extensions.push(ext);
        self
    }

    /// Render to the NIP-50 wire form. Extensions follow the free
    /// text, single-spaced.
    #[must_use]
    pub fn render(&self) -> String {
        if self.extensions.is_empty() {
            return self.free_text.clone();
        }
        let mut out = self.free_text.trim().to_owned();
        for ext in &self.extensions {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(&ext.render());
        }
        out
    }

    /// Parse a NIP-50 wire string into a typed query.
    ///
    /// The parser is **lenient**: tokens that do not look like
    /// extensions flow into `free_text`, and unknown extension keys
    /// surface as [`SearchExtension::Other`] so a relay's bespoke
    /// extension never lands in the free-text bucket by accident.
    /// The only token-level error is a malformed *known* extension
    /// (currently only `nsfw:`), which is silently dropped after
    /// emitting a `tracing` event so callers cannot lose the
    /// surrounding query.
    #[must_use]
    pub fn parse(query: &str) -> Self {
        let mut extensions: Vec<SearchExtension> = Vec::new();
        let mut free_parts: Vec<&str> = Vec::new();
        for token in query.split_whitespace() {
            match SearchExtension::parse_token(token) {
                Ok(Some(ext)) => extensions.push(ext),
                Ok(None) => free_parts.push(token),
                Err(_) => {
                    // Malformed known extension — keep it as free
                    // text rather than dropping data. The relay
                    // will reject at parse time anyway.
                    free_parts.push(token);
                }
            }
        }
        Self {
            free_text: free_parts.join(" "),
            extensions,
        }
    }
}

impl Filter {
    /// Apply a typed [`SearchQuery`] to this filter.
    ///
    /// Equivalent to `filter.search(query.render())` but spelled out
    /// so call sites stay self-documenting.
    #[must_use]
    pub fn search_query(self, query: &SearchQuery) -> Self {
        self.search(query.render())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_extracts_known_extensions_in_order() {
        let q = SearchQuery::parse("best apps language:en sentiment:positive nsfw:false");
        assert_eq!(q.free_text, "best apps");
        assert_eq!(
            q.extensions,
            vec![
                SearchExtension::Language("en".to_owned()),
                SearchExtension::Sentiment(Sentiment::Positive),
                SearchExtension::Nsfw(false),
            ]
        );
    }

    #[test]
    fn parse_handles_include_spam() {
        let q = SearchQuery::parse("include:spam orange");
        assert_eq!(q.free_text, "orange");
        assert_eq!(q.extensions, vec![SearchExtension::IncludeSpam]);
    }

    #[test]
    fn parse_preserves_unknown_extensions_as_other() {
        let q = SearchQuery::parse("foo BAR:baz another:thing");
        assert_eq!(q.free_text, "foo");
        assert_eq!(
            q.extensions,
            vec![
                SearchExtension::Other {
                    key: "bar".to_owned(),
                    value: "baz".to_owned(),
                },
                SearchExtension::Other {
                    key: "another".to_owned(),
                    value: "thing".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn parse_keeps_malformed_known_ext_in_free_text() {
        let q = SearchQuery::parse("orange nsfw:bogus");
        assert_eq!(q.free_text, "orange nsfw:bogus");
        assert!(q.extensions.is_empty());
    }

    #[test]
    fn render_round_trips() {
        let original = SearchQuery::new("rust nostr")
            .with_extension(SearchExtension::Domain("nostr.example".to_owned()))
            .with_extension(SearchExtension::Nsfw(true));
        let rendered = original.render();
        assert_eq!(rendered, "rust nostr domain:nostr.example nsfw:true");
        assert_eq!(SearchQuery::parse(&rendered), original);
    }

    #[test]
    fn empty_query_renders_empty() {
        assert_eq!(SearchQuery::default().render(), "");
        assert_eq!(SearchQuery::new("").render(), "");
    }

    #[test]
    fn extensions_only_drops_leading_whitespace() {
        let q = SearchQuery::default().with_extension(SearchExtension::IncludeSpam);
        assert_eq!(q.render(), "include:spam");
    }

    #[test]
    fn sentiment_round_trips_unknown() {
        let s = Sentiment::parse("euphoric");
        assert_eq!(s, Sentiment::Other("euphoric".to_owned()));
        assert_eq!(s.as_str(), "euphoric");
    }

    #[test]
    fn empty_key_token_errors() {
        let err = SearchExtension::parse_token(":value").unwrap_err();
        assert_eq!(err, SearchExtensionError::EmptyKey);
    }

    #[test]
    fn token_without_colon_is_free_text() {
        assert!(SearchExtension::parse_token("plain").unwrap().is_none());
    }

    #[test]
    fn filter_search_query_helper_round_trips() {
        let q = SearchQuery::new("rust").with_extension(SearchExtension::Language("en".to_owned()));
        let filter = Filter::new().search_query(&q);
        assert_eq!(filter.search.as_deref(), Some("rust language:en"));
    }
}
