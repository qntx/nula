//! [NIP-C0] Code Snippets.
//!
//! `kind: 1337` carries a code snippet body in `.content` plus an
//! extensible metadata surface (language, file extension, runtime,
//! license, dependencies, repository pointer). The repository tag may
//! reference a NIP-34 git repository announcement coordinate or any
//! `https://`-style URL.
//!
//! [NIP-C0]: https://github.com/nostr-protocol/nips/blob/master/C0.md

use thiserror::Error;

use crate::event::{Coordinate, CoordinateError, Event, EventBuilder, Kind, Tag, TagKind};
use crate::types::{RelayUrl, RelayUrlError, Url, UrlError};

/// `kind: 1337` — code snippet.
pub const KIND_CODE_SNIPPET: Kind = Kind::CODE_SNIPPET;

const LANGUAGE_TAG: &str = "l";
const NAME_TAG: &str = "name";
const EXTENSION_TAG: &str = "extension";
const DESCRIPTION_TAG: &str = "description";
const RUNTIME_TAG: &str = "runtime";
const LICENSE_TAG: &str = "license";
const DEPENDENCY_TAG: &str = "dep";
const REPO_TAG: &str = "repo";

/// `repo` reference flavours: a plain URL or a NIP-34 repository
/// addressable coordinate (with optional relay hint).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeRepo {
    /// Plain HTTP URL pointing at a public repo browser page.
    Url(Url),
    /// NIP-34 `kind: 30617` repository announcement coordinate.
    Repository {
        /// Repo coordinate.
        coordinate: Coordinate,
        /// Optional relay hint.
        relay_hint: Option<RelayUrl>,
    },
}

/// Typed bundle for a `kind: 1337` code-snippet event.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CodeSnippet {
    /// The actual code body.
    pub content: String,
    /// `l` programming language token (lower-case per spec).
    pub language: Option<String>,
    /// `name` (commonly a filename).
    pub name: Option<String>,
    /// `extension` (without the leading dot).
    pub extension: Option<String>,
    /// `description` line.
    pub description: Option<String>,
    /// `runtime` specifier.
    pub runtime: Option<String>,
    /// `license` SPDX identifiers (multi-licensing supported).
    pub licenses: Vec<String>,
    /// `dep` dependency lines (repeatable).
    pub dependencies: Vec<String>,
    /// `repo` references (URL or NIP-34 coordinate).
    pub repos: Vec<CodeRepo>,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

/// Errors raised while parsing a NIP-C0 event.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CodeSnippetError {
    /// Event kind is not `1337`.
    #[error("unexpected kind for NIP-C0 code snippet: {}", .0.as_u16())]
    WrongKind(Kind),
    /// `repo` tag has no value column.
    #[error("`repo` tag missing value")]
    MalformedRepo,
    /// Wrapped URL parser error.
    #[error(transparent)]
    InvalidUrl(#[from] UrlError),
    /// Wrapped coordinate parser error.
    #[error(transparent)]
    InvalidCoordinate(#[from] CoordinateError),
    /// Wrapped relay-URL parser error.
    #[error(transparent)]
    InvalidRelayUrl(#[from] RelayUrlError),
}

impl CodeSnippet {
    /// Construct a code snippet with the body seeded.
    #[must_use]
    pub fn new(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            ..Self::default()
        }
    }

    /// Parse a `kind: 1337` code-snippet event.
    ///
    /// # Errors
    ///
    /// See [`CodeSnippetError`] for the failure modes.
    pub fn from_event(event: &Event) -> Result<Self, CodeSnippetError> {
        if event.kind != KIND_CODE_SNIPPET {
            return Err(CodeSnippetError::WrongKind(event.kind));
        }
        let mut out = Self::new(event.content.clone());
        for tag in &event.tags {
            absorb_tag(tag, &mut out)?;
        }
        Ok(out)
    }
}

fn absorb_tag(tag: &Tag, out: &mut CodeSnippet) -> Result<(), CodeSnippetError> {
    let col1 = tag.get(1);
    match tag.name() {
        LANGUAGE_TAG => out.language = col1.map(str::to_owned),
        NAME_TAG => out.name = col1.map(str::to_owned),
        EXTENSION_TAG => out.extension = col1.map(str::to_owned),
        DESCRIPTION_TAG => out.description = col1.map(str::to_owned),
        RUNTIME_TAG => out.runtime = col1.map(str::to_owned),
        LICENSE_TAG => {
            if let Some(raw) = col1 {
                out.licenses.push(raw.to_owned());
            }
        }
        DEPENDENCY_TAG => {
            if let Some(raw) = col1 {
                out.dependencies.push(raw.to_owned());
            }
        }
        REPO_TAG => out.repos.push(parse_repo(tag)?),
        _ => out.extra_tags.push(tag.clone()),
    }
    Ok(())
}

fn parse_repo(tag: &Tag) -> Result<CodeRepo, CodeSnippetError> {
    let raw = tag.get(1).ok_or(CodeSnippetError::MalformedRepo)?;
    if let Ok(coord) = Coordinate::parse(raw) {
        let relay_hint = match tag.get(2) {
            Some(s) if !s.is_empty() => Some(RelayUrl::parse(s)?),
            _ => None,
        };
        Ok(CodeRepo::Repository {
            coordinate: coord,
            relay_hint,
        })
    } else {
        Ok(CodeRepo::Url(Url::parse(raw)?))
    }
}

fn repo_tag(repo: &CodeRepo) -> Tag {
    let head = TagKind::from_wire(REPO_TAG);
    match repo {
        CodeRepo::Url(url) => Tag::with(&head, [url.as_str().to_owned()]),
        CodeRepo::Repository {
            coordinate,
            relay_hint,
        } => relay_hint.as_ref().map_or_else(
            || Tag::with(&head, [coordinate.to_wire()]),
            |relay| Tag::with(&head, [coordinate.to_wire(), relay.as_str().to_owned()]),
        ),
    }
}

impl EventBuilder {
    /// Author a NIP-C0 `kind: 1337` code-snippet event.
    #[must_use]
    pub fn code_snippet(snippet: &CodeSnippet) -> Self {
        let mut builder = Self::new(KIND_CODE_SNIPPET, snippet.content.clone());
        let single_value = [
            (LANGUAGE_TAG, snippet.language.as_deref()),
            (NAME_TAG, snippet.name.as_deref()),
            (EXTENSION_TAG, snippet.extension.as_deref()),
            (DESCRIPTION_TAG, snippet.description.as_deref()),
            (RUNTIME_TAG, snippet.runtime.as_deref()),
        ];
        for (name, value) in single_value {
            if let Some(v) = value {
                builder = builder.tag(Tag::with(&TagKind::from_wire(name), [v.to_owned()]));
            }
        }
        for license in &snippet.licenses {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(LICENSE_TAG),
                [license.clone()],
            ));
        }
        for dep in &snippet.dependencies {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(DEPENDENCY_TAG),
                [dep.clone()],
            ));
        }
        for repo in &snippet.repos {
            builder = builder.tag(repo_tag(repo));
        }
        for tag in &snippet.extra_tags {
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
    fn code_snippet_round_trip() {
        let snippet = CodeSnippet {
            content: "fn hello() { println!(\"hi\"); }".into(),
            language: Some("rust".into()),
            name: Some("hello.rs".into()),
            extension: Some("rs".into()),
            description: Some("Demo".into()),
            runtime: Some("rustc 1.79".into()),
            licenses: vec!["MIT".into(), "Apache-2.0".into()],
            dependencies: vec!["serde = \"1\"".into()],
            repos: vec![
                CodeRepo::Url(Url::parse("https://github.com/example/hello").unwrap()),
                CodeRepo::Repository {
                    coordinate: Coordinate::new(
                        Kind::GIT_REPOSITORY,
                        *keys().public_key(),
                        "hello".to_owned(),
                    ),
                    relay_hint: Some(RelayUrl::parse("wss://relay.example/").unwrap()),
                },
            ],
            extra_tags: Vec::new(),
        };
        let event = EventBuilder::code_snippet(&snippet)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = CodeSnippet::from_event(&event).unwrap();
        assert_eq!(parsed, snippet);
    }

    #[test]
    fn wrong_kind_is_rejected() {
        let event = EventBuilder::text_note("nope")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            CodeSnippet::from_event(&event),
            Err(CodeSnippetError::WrongKind(_))
        ));
    }

    #[test]
    fn minimal_snippet_with_only_language_round_trips() {
        // Smallest valid snippet: body + language label only.
        let snippet = CodeSnippet::new("print('hi')");
        let mut snippet = snippet;
        snippet.language = Some("python".into());
        let event = EventBuilder::code_snippet(&snippet)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = CodeSnippet::from_event(&event).unwrap();
        assert_eq!(parsed.language.as_deref(), Some("python"));
        assert_eq!(parsed.content, "print('hi')");
        assert!(parsed.licenses.is_empty());
        assert!(parsed.repos.is_empty());
    }

    #[test]
    fn url_only_repo_reference_round_trips() {
        // A snippet may attach a plain URL repo \u2014 the parser preserves
        // the `CodeRepo::Url` shape rather than upgrading to `Repository`.
        let mut snippet = CodeSnippet::new("body");
        snippet.repos.push(CodeRepo::Url(
            Url::parse("https://github.com/example/proj").unwrap(),
        ));
        let event = EventBuilder::code_snippet(&snippet)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = CodeSnippet::from_event(&event).unwrap();
        assert_eq!(parsed.repos.len(), 1);
        match &parsed.repos[0] {
            CodeRepo::Url(url) => assert_eq!(url.as_str(), "https://github.com/example/proj"),
            other @ CodeRepo::Repository { .. } => panic!("expected URL repo, got {other:?}"),
        }
    }

    #[test]
    fn malformed_repo_tag_is_rejected() {
        // A `repo` tag with only the head column is malformed.
        let event = EventBuilder::new(KIND_CODE_SNIPPET, "body")
            .tag(Tag::with(
                &TagKind::from_wire(REPO_TAG),
                Vec::<String>::new(),
            ))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            CodeSnippet::from_event(&event),
            Err(CodeSnippetError::MalformedRepo)
        ));
    }
}
