//! [NIP-5A] Static Websites (nsites).
//!
//! Hosts static websites from Blossom assets. Two manifest shapes:
//!
//! - **Root site** — `kind: 15128`, replaceable, no `d` tag; one root
//!   site per pubkey.
//! - **Named site** — `kind: 35128`, addressable, `d` tag carries the
//!   site identifier (think sub-domains under a pubkey).
//!
//! The manifest maps absolute paths to sha256 hashes via `path` tags
//! (`["path", "/absolute/path", "<sha256>"]`), optionally hints at
//! Blossom servers via `server` tags, and may carry `title` /
//! `description` / `source` metadata.
//!
//! [`SiteManifest::resolve`] implements the spec's path-resolution
//! rule: paths not ending in a filename fall back to `index.html`
//! (`/` → `/index.html`, `/blog/` → `/blog/index.html`).
//!
//! The legacy per-file `kind: 34128` shape is deprecated upstream and
//! deliberately not implemented.
//!
//! [NIP-5A]: https://github.com/nostr-protocol/nips/blob/master/5A.md

use thiserror::Error;

use crate::event::{Event, EventBuilder, Kind, Tag, TagKind};
use crate::types::Url;

/// `kind: 15128` — root site manifest.
pub const KIND_NSITE_ROOT: Kind = Kind::NSITE_ROOT;
/// `kind: 35128` — named site manifest.
pub const KIND_NSITE_NAMED: Kind = Kind::NSITE_NAMED;

const PATH_TAG: &str = "path";
const SERVER_TAG: &str = "server";
const TITLE_TAG: &str = "title";
const DESCRIPTION_TAG: &str = "description";
const SOURCE_TAG: &str = "source";

/// A single `path` tag mapping an absolute path to a sha256 hash.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PathMapping {
    /// Absolute path ending with a filename and extension.
    pub path: String,
    /// Lowercase hex sha256 of the file served under this path.
    pub sha256: String,
}

impl PathMapping {
    /// Construct a validated path mapping.
    ///
    /// # Errors
    ///
    /// See [`SiteManifestError`] for the failure modes.
    pub fn new(
        path: impl Into<String>,
        sha256: impl Into<String>,
    ) -> Result<Self, SiteManifestError> {
        let path = path.into();
        let sha256 = sha256.into();
        if !path.starts_with('/') {
            return Err(SiteManifestError::RelativePath(path));
        }
        if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(SiteManifestError::InvalidHash(sha256));
        }
        Ok(Self { path, sha256 })
    }
}

/// Typed bundle for a `kind: 15128` / `kind: 35128` site manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteManifest {
    /// Site identifier (`d` tag). `None` for the root site
    /// (`kind: 15128`), `Some` for named sites (`kind: 35128`).
    pub identifier: Option<String>,
    /// Path-to-hash mappings (`path` tags). At least one is required.
    pub paths: Vec<PathMapping>,
    /// Blossom server hints (`server` tags).
    pub servers: Vec<Url>,
    /// Optional site title.
    pub title: Option<String>,
    /// Optional site description.
    pub description: Option<String>,
    /// Optional source repository / archive URL.
    pub source: Option<Url>,
}

/// Errors raised while building or parsing a NIP-5A manifest.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SiteManifestError {
    /// Event kind is neither `15128` nor `35128`.
    #[error("unexpected kind for NIP-5A manifest: {}", .0.as_u16())]
    WrongKind(Kind),
    /// A named site (`kind: 35128`) is missing its `d` tag.
    #[error("named site manifest missing required `d` tag")]
    MissingIdentifier,
    /// A root site (`kind: 15128`) must not carry a `d` tag.
    #[error("root site manifest must not carry a `d` tag")]
    UnexpectedIdentifier,
    /// The manifest has no valid `path` tag.
    #[error("site manifest missing required `path` tags")]
    MissingPaths,
    /// A path did not start with `/`.
    #[error("path is not absolute: {0}")]
    RelativePath(String),
    /// A sha256 column was not 64 hex characters.
    #[error("invalid sha256 hash: {0}")]
    InvalidHash(String),
}

impl SiteManifest {
    /// Construct a root-site manifest (`kind: 15128`).
    ///
    /// # Errors
    ///
    /// Returns [`SiteManifestError::MissingPaths`] when `paths` is empty.
    pub fn root(paths: Vec<PathMapping>) -> Result<Self, SiteManifestError> {
        if paths.is_empty() {
            return Err(SiteManifestError::MissingPaths);
        }
        Ok(Self {
            identifier: None,
            paths,
            servers: Vec::new(),
            title: None,
            description: None,
            source: None,
        })
    }

    /// Construct a named-site manifest (`kind: 35128`).
    ///
    /// # Errors
    ///
    /// Returns [`SiteManifestError::MissingPaths`] when `paths` is empty.
    pub fn named(
        identifier: impl Into<String>,
        paths: Vec<PathMapping>,
    ) -> Result<Self, SiteManifestError> {
        if paths.is_empty() {
            return Err(SiteManifestError::MissingPaths);
        }
        Ok(Self {
            identifier: Some(identifier.into()),
            paths,
            servers: Vec::new(),
            title: None,
            description: None,
            source: None,
        })
    }

    /// The event kind this manifest serialises to.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        if self.identifier.is_some() {
            KIND_NSITE_NAMED
        } else {
            KIND_NSITE_ROOT
        }
    }

    /// True when `identifier` fits the canonical single-label
    /// subdomain format: `^[a-z0-9-]{1,13}$`, not ending with `-`.
    ///
    /// Root manifests (no identifier) return `true`.
    #[must_use]
    pub fn has_canonical_identifier(&self) -> bool {
        self.identifier.as_ref().is_none_or(|id| {
            (1..=13).contains(&id.len())
                && !id.ends_with('-')
                && id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
    }

    /// Resolve a request path to its sha256 hash, applying the spec's
    /// `index.html` fallback for directory-style paths.
    #[must_use]
    pub fn resolve(&self, request_path: &str) -> Option<&PathMapping> {
        let needs_index = request_path.ends_with('/');
        let candidate: String;
        let effective = if needs_index {
            candidate = format!("{request_path}index.html");
            candidate.as_str()
        } else {
            request_path
        };
        self.paths.iter().find(|m| m.path == effective)
    }

    /// Parse a `kind: 15128` / `kind: 35128` site-manifest event.
    ///
    /// # Errors
    ///
    /// See [`SiteManifestError`] for the failure modes.
    pub fn from_event(event: &Event) -> Result<Self, SiteManifestError> {
        let identifier = match event.kind {
            KIND_NSITE_ROOT => {
                if event.tags.identifier().is_some() {
                    return Err(SiteManifestError::UnexpectedIdentifier);
                }
                None
            }
            KIND_NSITE_NAMED => Some(
                event
                    .tags
                    .identifier()
                    .ok_or(SiteManifestError::MissingIdentifier)?
                    .to_owned(),
            ),
            other => return Err(SiteManifestError::WrongKind(other)),
        };
        let mut paths: Vec<PathMapping> = Vec::new();
        for tag in event.tags.iter().filter(|tag| tag.name() == PATH_TAG) {
            let (Some(path), Some(hash)) = (tag.get(1), tag.get(2)) else {
                continue;
            };
            paths.push(PathMapping::new(path, hash)?);
        }
        if paths.is_empty() {
            return Err(SiteManifestError::MissingPaths);
        }
        let servers: Vec<Url> = event
            .tags
            .iter()
            .filter(|tag| tag.name() == SERVER_TAG)
            .filter_map(|tag| Url::parse(tag.content()?).ok())
            .collect();
        let text_of = |name: &str| {
            event
                .tags
                .find_first(&TagKind::custom(name))
                .and_then(Tag::content)
        };
        let title = text_of(TITLE_TAG).map(str::to_owned);
        let description = text_of(DESCRIPTION_TAG).map(str::to_owned);
        let source = text_of(SOURCE_TAG).and_then(|raw| Url::parse(raw).ok());
        Ok(Self {
            identifier,
            paths,
            servers,
            title,
            description,
            source,
        })
    }
}

impl EventBuilder {
    /// Author a NIP-5A site-manifest event.
    ///
    /// # Errors
    ///
    /// Returns [`SiteManifestError::MissingPaths`] when
    /// [`SiteManifest::paths`] is empty.
    pub fn site_manifest(manifest: &SiteManifest) -> Result<Self, SiteManifestError> {
        if manifest.paths.is_empty() {
            return Err(SiteManifestError::MissingPaths);
        }
        let mut builder = Self::new(manifest.kind(), "");
        if let Some(id) = &manifest.identifier {
            builder = builder.tag(Tag::d(id.clone()));
        }
        let path_head = TagKind::custom(PATH_TAG);
        for mapping in &manifest.paths {
            builder = builder.tag(Tag::with(
                &path_head,
                [mapping.path.clone(), mapping.sha256.clone()],
            ));
        }
        let server_head = TagKind::custom(SERVER_TAG);
        for server in &manifest.servers {
            builder = builder.tag(Tag::with(&server_head, [server.as_str().to_owned()]));
        }
        if let Some(title) = &manifest.title {
            builder = builder.tag(Tag::title(title.clone()));
        }
        if let Some(description) = &manifest.description {
            builder = builder.tag(Tag::with(
                &TagKind::custom(DESCRIPTION_TAG),
                [description.clone()],
            ));
        }
        if let Some(source) = &manifest.source {
            builder = builder.tag(Tag::with(
                &TagKind::custom(SOURCE_TAG),
                [source.as_str().to_owned()],
            ));
        }
        Ok(builder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;

    const HASH_A: &str = "186ea5fd14e88fd1ac49351759e7ab906fa94892002b60bf7f5a428f28ca1c99";
    const HASH_B: &str = "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456";

    fn keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    fn sample_paths() -> Vec<PathMapping> {
        vec![
            PathMapping::new("/index.html", HASH_A).unwrap(),
            PathMapping::new("/blog/index.html", HASH_B).unwrap(),
        ]
    }

    #[test]
    fn root_manifest_round_trip() {
        let mut manifest = SiteManifest::root(sample_paths()).unwrap();
        manifest.title = Some("My Nostr Site".to_owned());
        manifest.servers = vec![Url::parse("https://blossom.example.com").unwrap()];
        let event = EventBuilder::site_manifest(&manifest)
            .unwrap()
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, KIND_NSITE_ROOT);
        let parsed = SiteManifest::from_event(&event).unwrap();
        assert_eq!(parsed, manifest);
    }

    #[test]
    fn named_manifest_round_trip() {
        let manifest = SiteManifest::named("blog", sample_paths()).unwrap();
        let event = EventBuilder::site_manifest(&manifest)
            .unwrap()
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, KIND_NSITE_NAMED);
        let parsed = SiteManifest::from_event(&event).unwrap();
        assert_eq!(parsed.identifier.as_deref(), Some("blog"));
    }

    #[test]
    fn resolve_applies_index_fallback() {
        let manifest = SiteManifest::root(sample_paths()).unwrap();
        assert_eq!(manifest.resolve("/").unwrap().sha256, HASH_A);
        assert_eq!(manifest.resolve("/blog/").unwrap().sha256, HASH_B);
        assert_eq!(manifest.resolve("/index.html").unwrap().sha256, HASH_A);
        assert!(manifest.resolve("/missing.html").is_none());
    }

    #[test]
    fn canonical_identifier_rules() {
        let paths = sample_paths();
        assert!(
            SiteManifest::root(paths.clone())
                .unwrap()
                .has_canonical_identifier()
        );
        assert!(
            SiteManifest::named("blog", paths.clone())
                .unwrap()
                .has_canonical_identifier()
        );
        // Ends with `-`.
        assert!(
            !SiteManifest::named("blog-", paths.clone())
                .unwrap()
                .has_canonical_identifier()
        );
        // Too long (> 13 chars).
        assert!(
            !SiteManifest::named("abcdefghijklmn", paths.clone())
                .unwrap()
                .has_canonical_identifier()
        );
        // Uppercase not allowed.
        assert!(
            !SiteManifest::named("Blog", paths)
                .unwrap()
                .has_canonical_identifier()
        );
    }

    #[test]
    fn invalid_path_and_hash_are_rejected() {
        assert!(matches!(
            PathMapping::new("index.html", HASH_A),
            Err(SiteManifestError::RelativePath(_))
        ));
        assert!(matches!(
            PathMapping::new("/index.html", "deadbeef"),
            Err(SiteManifestError::InvalidHash(_))
        ));
    }

    #[test]
    fn empty_paths_are_rejected() {
        assert!(matches!(
            SiteManifest::root(Vec::new()),
            Err(SiteManifestError::MissingPaths)
        ));
    }

    #[test]
    fn root_with_d_tag_is_rejected() {
        let event = EventBuilder::new(KIND_NSITE_ROOT, "")
            .tag(Tag::d("oops"))
            .tag(Tag::with(
                &TagKind::custom(PATH_TAG),
                ["/index.html".to_owned(), HASH_A.to_owned()],
            ))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            SiteManifest::from_event(&event),
            Err(SiteManifestError::UnexpectedIdentifier)
        ));
    }

    #[test]
    fn named_without_d_tag_is_rejected() {
        let event = EventBuilder::new(KIND_NSITE_NAMED, "")
            .tag(Tag::with(
                &TagKind::custom(PATH_TAG),
                ["/index.html".to_owned(), HASH_A.to_owned()],
            ))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            SiteManifest::from_event(&event),
            Err(SiteManifestError::MissingIdentifier)
        ));
    }
}
