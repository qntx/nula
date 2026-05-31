//! [NIP-34] `git` stuff — typed bundles for the eleven event
//! kinds NIP-34 reserves for code-collaboration over Nostr.
//!
//! # Kind map
//!
//! | Kind   | Role                                          | Bundle                       |
//! |--------|-----------------------------------------------|------------------------------|
//! | 30617  | Repository announcement (addressable)         | [`Repository`]               |
//! | 30618  | Repository state announcement (addressable)   | [`RepositoryState`]          |
//! | 1617   | Patch                                         | [`Patch`]                    |
//! | 1618   | Pull request                                  | [`PullRequest`]              |
//! | 1619   | Pull request update                           | [`PullRequestUpdate`]        |
//! | 1621   | Issue                                         | [`Issue`]                    |
//! | 1630   | Status: open                                  | [`StatusEvent`] (typed kind) |
//! | 1631   | Status: applied / merged / resolved           | [`StatusEvent`] (typed kind) |
//! | 1632   | Status: closed                                | [`StatusEvent`] (typed kind) |
//! | 1633   | Status: draft                                 | [`StatusEvent`] (typed kind) |
//! | 10317  | User grasp-server list (replaceable)          | [`GraspServerList`]          |
//!
//! [`StatusEvent::status`] is a typed [`GitStatus`] discriminator
//! that picks the right kind constant at build time and rejects
//! anything outside `1630..=1633` at parse time.
//!
//! # Why a typed module
//!
//! Upstream `rust-nostr` does not yet ship NIP-34. We model the
//! complete tag vocabulary the spec defines:
//!
//! - **`a` tag** — addressable pointer to the repository
//!   announcement (`30617:<author>:<d>`). Parsed back into a
//!   [`Coordinate`] so callers can re-resolve the repo.
//! - **`clone` / `web` / `relays` / `maintainers`** — multi-valued
//!   metadata rows on [`Repository`].
//! - **`r ... euc`** — earliest-unique-commit marker, kept as
//!   [`Repository::earliest_unique_commit`].
//! - **`refs/heads/<branch>` / `refs/tags/<tag>` / `HEAD`** — the
//!   typed [`GitRef`] rows on [`RepositoryState`].
//! - **`commit` / `parent-commit` / `commit-pgp-sig` / `committer`**
//!   — the optional reproducibility columns on [`Patch`].
//! - **`E` / `P` uppercase** — NIP-22 root references on
//!   [`PullRequestUpdate`].
//! - **`merge-commit` / `applied-as-commits` / `q`** — applied/merged
//!   status columns on [`StatusEvent`].
//!
//! Every bundle ships a `to_tags` renderer, a `from_event` parser,
//! and an [`EventBuilder`] constructor.
//!
//! [NIP-34]: https://github.com/nostr-protocol/nips/blob/master/34.md

#![allow(
    clippy::excessive_nesting,
    reason = "the per-tag match-on-name dispatch pattern in `from_event` keeps the wire-format-to-field mapping at the surface; flattening obscures it"
)]
#![allow(
    clippy::too_many_lines,
    reason = "NIP-34 fields fan out across 8 typed bundles; splitting renders / parsers further would create indirection without clarity"
)]

use thiserror::Error;

use crate::event::{
    Alphabet, Coordinate, CoordinateError, Event, EventBuilder, EventId, EventIdError, Kind,
    SingleLetterTag, Tag, TagError, TagKind,
};
use crate::key::{PublicKey, PublicKeyError};
use crate::types::{RelayUrl, RelayUrlError};

/// `kind: 30617` — repository announcement.
pub const KIND_REPO: Kind = Kind::GIT_REPOSITORY;
/// `kind: 30618` — repository state announcement.
pub const KIND_REPO_STATE: Kind = Kind::GIT_REPOSITORY_STATE;
/// `kind: 1617` — patch.
pub const KIND_PATCH: Kind = Kind::GIT_PATCH;
/// `kind: 1618` — pull request.
pub const KIND_PULL_REQUEST: Kind = Kind::GIT_PULL_REQUEST;
/// `kind: 1619` — pull request update.
pub const KIND_PULL_REQUEST_UPDATE: Kind = Kind::GIT_PULL_REQUEST_UPDATE;
/// `kind: 1621` — issue.
pub const KIND_ISSUE: Kind = Kind::GIT_ISSUE;
/// `kind: 1630` — status `open`.
pub const KIND_STATUS_OPEN: Kind = Kind::GIT_STATUS_OPEN;
/// `kind: 1631` — status `applied / merged / resolved`.
pub const KIND_STATUS_APPLIED: Kind = Kind::GIT_STATUS_APPLIED;
/// `kind: 1632` — status `closed`.
pub const KIND_STATUS_CLOSED: Kind = Kind::GIT_STATUS_CLOSED;
/// `kind: 1633` — status `draft`.
pub const KIND_STATUS_DRAFT: Kind = Kind::GIT_STATUS_DRAFT;
/// `kind: 10317` — user grasp-server list.
pub const KIND_GRASP_LIST: Kind = Kind::GIT_GRASP_LIST;

/// `personal-fork` reserved hashtag.
pub const PERSONAL_FORK_HASHTAG: &str = "personal-fork";
/// `euc` marker on the earliest-unique-commit `r` tag.
pub const EUC_MARKER: &str = "euc";

mod tag_names {
    pub(super) const D: &str = "d";
    pub(super) const NAME: &str = "name";
    pub(super) const DESCRIPTION: &str = "description";
    pub(super) const WEB: &str = "web";
    pub(super) const CLONE: &str = "clone";
    pub(super) const RELAYS: &str = "relays";
    pub(super) const MAINTAINERS: &str = "maintainers";
    pub(super) const COMMIT: &str = "commit";
    pub(super) const PARENT_COMMIT: &str = "parent-commit";
    pub(super) const COMMIT_PGP_SIG: &str = "commit-pgp-sig";
    pub(super) const COMMITTER: &str = "committer";
    pub(super) const SUBJECT: &str = "subject";
    pub(super) const BRANCH_NAME: &str = "branch-name";
    pub(super) const MERGE_BASE: &str = "merge-base";
    pub(super) const MERGE_COMMIT: &str = "merge-commit";
    pub(super) const APPLIED_AS_COMMITS: &str = "applied-as-commits";
    pub(super) const HEAD: &str = "HEAD";
    pub(super) const REFS_PREFIX: &str = "refs/";
}

/// Errors raised by the NIP-34 typed bundles.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Nip34Error {
    /// Event kind did not match the expected NIP-34 kind.
    #[error("expected kind {expected}, got {got}")]
    WrongKind {
        /// Kind the caller asked for.
        expected: Kind,
        /// Kind the event actually carried.
        got: Kind,
    },
    /// Status kind was outside `1630..=1633`.
    #[error("expected a status kind (1630..=1633), got {0}")]
    InvalidStatusKind(Kind),
    /// Repository announcement / state was missing its `d` tag.
    #[error("NIP-34 {kind} event missing required `d` tag")]
    MissingIdentifier {
        /// Kind of the event missing its identifier.
        kind: Kind,
    },
    /// Patch / PR / issue / status event was missing the required
    /// repository `a` tag.
    #[error("NIP-34 {kind} event missing required `a` repository tag")]
    MissingRepository {
        /// Kind of the event missing its repository pointer.
        kind: Kind,
    },
    /// A coordinate was malformed.
    #[error(transparent)]
    Coordinate(#[from] CoordinateError),
    /// An event id was malformed.
    #[error(transparent)]
    EventId(#[from] EventIdError),
    /// A relay URL was malformed.
    #[error(transparent)]
    RelayUrl(#[from] RelayUrlError),
    /// A pubkey was malformed.
    #[error(transparent)]
    PublicKey(#[from] PublicKeyError),
    /// A typed [`Tag`] could not be constructed.
    #[error(transparent)]
    Tag(#[from] TagError),
}

fn second(values: &[String]) -> Option<&str> {
    values.get(1).map(String::as_str)
}

fn args(values: &[String]) -> &[String] {
    values.get(1..).unwrap_or(&[])
}

fn p_tag(pubkey: PublicKey) -> Tag {
    Tag::with(
        &TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::P)),
        [pubkey.to_hex()],
    )
}

fn e_tag(event_id: EventId, marker: Option<&str>) -> Tag {
    let mut row = vec![event_id.to_hex()];
    row.push(String::new());
    if let Some(marker) = marker {
        row.push(marker.to_owned());
    }
    Tag::with(
        &TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::E)),
        row,
    )
}

fn r_tag(value: impl Into<String>) -> Tag {
    Tag::with(
        &TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::R)),
        [value.into()],
    )
}

fn a_tag(coordinate: &Coordinate) -> Tag {
    Tag::with(
        &TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::A)),
        [coordinate.to_wire()],
    )
}

/// Typed bundle for the `kind: 30617` repository announcement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repository {
    /// `d` tag — addressable identifier, usually kebab-case.
    pub identifier: String,
    /// Human-readable project name.
    pub name: Option<String>,
    /// Short project description.
    pub description: Option<String>,
    /// Web URLs (homepage, browser-side git UI, …).
    pub web: Vec<String>,
    /// `git clone` URLs.
    pub clone: Vec<String>,
    /// Relays the author monitors for patches / issues.
    pub relays: Vec<RelayUrl>,
    /// Earliest unique commit hex (`r` tag with `euc` marker).
    pub earliest_unique_commit: Option<String>,
    /// Maintainer pubkeys.
    pub maintainers: Vec<PublicKey>,
    /// Hashtags labelling the repository.
    pub hashtags: Vec<String>,
    /// True when the spec-reserved `personal-fork` hashtag is set.
    pub personal_fork: bool,
}

impl Repository {
    /// Construct an announcement bound to the addressable `d`
    /// identifier.
    #[must_use]
    pub fn new(identifier: impl Into<String>) -> Self {
        Self {
            identifier: identifier.into(),
            name: None,
            description: None,
            web: Vec::new(),
            clone: Vec::new(),
            relays: Vec::new(),
            earliest_unique_commit: None,
            maintainers: Vec::new(),
            hashtags: Vec::new(),
            personal_fork: false,
        }
    }

    /// Build the addressable coordinate for this announcement under
    /// `author`.
    #[must_use]
    pub fn coordinate(&self, author: PublicKey) -> Coordinate {
        Coordinate::new(KIND_REPO, author, self.identifier.clone())
    }

    /// Render the typed bundle to the public tag list.
    #[must_use]
    pub fn to_tags(&self) -> Vec<Tag> {
        let mut tags: Vec<Tag> = Vec::new();
        tags.push(Tag::with(
            &TagKind::custom(tag_names::D),
            [self.identifier.clone()],
        ));
        if let Some(name) = &self.name {
            tags.push(Tag::with(&TagKind::custom(tag_names::NAME), [name.clone()]));
        }
        if let Some(description) = &self.description {
            tags.push(Tag::with(
                &TagKind::custom(tag_names::DESCRIPTION),
                [description.clone()],
            ));
        }
        if !self.web.is_empty() {
            tags.push(Tag::with(
                &TagKind::custom(tag_names::WEB),
                self.web.clone(),
            ));
        }
        if !self.clone.is_empty() {
            tags.push(Tag::with(
                &TagKind::custom(tag_names::CLONE),
                self.clone.clone(),
            ));
        }
        if !self.relays.is_empty() {
            let row: Vec<String> = self.relays.iter().map(|r| r.as_str().to_owned()).collect();
            tags.push(Tag::with(&TagKind::custom(tag_names::RELAYS), row));
        }
        if let Some(euc) = &self.earliest_unique_commit {
            tags.push(Tag::with(
                &TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::R)),
                [euc.clone(), EUC_MARKER.to_owned()],
            ));
        }
        if !self.maintainers.is_empty() {
            let row: Vec<String> = self.maintainers.iter().map(|pk| pk.to_hex()).collect();
            tags.push(Tag::with(&TagKind::custom(tag_names::MAINTAINERS), row));
        }
        if self.personal_fork {
            tags.push(Tag::with(
                &TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::T)),
                [PERSONAL_FORK_HASHTAG.to_owned()],
            ));
        }
        for hashtag in &self.hashtags {
            tags.push(Tag::with(
                &TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::T)),
                [hashtag.clone()],
            ));
        }
        tags
    }

    /// Parse a signed kind-30617 event into a typed bundle.
    ///
    /// # Errors
    ///
    /// Returns [`Nip34Error::WrongKind`] for the wrong kind and
    /// [`Nip34Error::MissingIdentifier`] when the `d` tag is absent.
    pub fn from_event(event: &Event) -> Result<Self, Nip34Error> {
        if event.kind != KIND_REPO {
            return Err(Nip34Error::WrongKind {
                expected: KIND_REPO,
                got: event.kind,
            });
        }
        let mut identifier: Option<String> = None;
        let mut repo = Self::new(String::new());
        for tag in &event.tags {
            let values = tag.values();
            let args = args(values);
            match tag.name() {
                tag_names::D => identifier = second(values).map(String::from),
                tag_names::NAME => repo.name = second(values).map(String::from),
                tag_names::DESCRIPTION => repo.description = second(values).map(String::from),
                tag_names::WEB => {
                    for v in args {
                        repo.web.push(v.clone());
                    }
                }
                tag_names::CLONE => {
                    for v in args {
                        repo.clone.push(v.clone());
                    }
                }
                tag_names::RELAYS => {
                    for v in args {
                        repo.relays.push(RelayUrl::parse(v)?);
                    }
                }
                tag_names::MAINTAINERS => {
                    for v in args {
                        repo.maintainers.push(PublicKey::parse(v)?);
                    }
                }
                "r" => {
                    let marker = args.get(1).map(String::as_str);
                    if marker == Some(EUC_MARKER) {
                        repo.earliest_unique_commit = args.first().cloned();
                    }
                }
                "t" => {
                    if let Some(value) = args.first() {
                        if value == PERSONAL_FORK_HASHTAG {
                            repo.personal_fork = true;
                        } else {
                            repo.hashtags.push(value.clone());
                        }
                    }
                }
                _ => {}
            }
        }
        repo.identifier = identifier.ok_or(Nip34Error::MissingIdentifier { kind: KIND_REPO })?;
        Ok(repo)
    }
}

/// One `refs/<heads|tags>/<name>` row on a [`RepositoryState`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitRef {
    /// Full ref path (`refs/heads/main` / `refs/tags/v1.0.0`).
    pub ref_path: String,
    /// Object id (lowercase hex of the SHA-1 or SHA-256 oid).
    pub oid: String,
}

impl GitRef {
    /// Construct a ref row.
    #[must_use]
    pub fn new(ref_path: impl Into<String>, oid: impl Into<String>) -> Self {
        Self {
            ref_path: ref_path.into(),
            oid: oid.into(),
        }
    }
}

/// Typed bundle for the `kind: 30618` repository state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryState {
    /// `d` tag — matches the [`Repository::identifier`].
    pub identifier: String,
    /// `refs/...` rows.
    pub refs: Vec<GitRef>,
    /// `HEAD` symbolic ref (e.g. `ref: refs/heads/main`).
    pub head: Option<String>,
}

impl RepositoryState {
    /// Construct a state bundle bound to the addressable `d`
    /// identifier.
    #[must_use]
    pub fn new(identifier: impl Into<String>) -> Self {
        Self {
            identifier: identifier.into(),
            refs: Vec::new(),
            head: None,
        }
    }

    /// Render the typed bundle to the public tag list.
    #[must_use]
    pub fn to_tags(&self) -> Vec<Tag> {
        let mut tags: Vec<Tag> = Vec::new();
        tags.push(Tag::with(
            &TagKind::custom(tag_names::D),
            [self.identifier.clone()],
        ));
        for git_ref in &self.refs {
            tags.push(Tag::with(
                &TagKind::custom(&git_ref.ref_path),
                [git_ref.oid.clone()],
            ));
        }
        if let Some(head) = &self.head {
            tags.push(Tag::with(&TagKind::custom(tag_names::HEAD), [head.clone()]));
        }
        tags
    }

    /// Parse a signed kind-30618 event into a typed bundle.
    ///
    /// # Errors
    ///
    /// Returns [`Nip34Error::WrongKind`] for the wrong kind and
    /// [`Nip34Error::MissingIdentifier`] when the `d` tag is absent.
    pub fn from_event(event: &Event) -> Result<Self, Nip34Error> {
        if event.kind != KIND_REPO_STATE {
            return Err(Nip34Error::WrongKind {
                expected: KIND_REPO_STATE,
                got: event.kind,
            });
        }
        let mut identifier: Option<String> = None;
        let mut state = Self::new(String::new());
        for tag in &event.tags {
            let values = tag.values();
            let name = tag.name();
            if name == tag_names::D {
                identifier = second(values).map(String::from);
                continue;
            }
            if name == tag_names::HEAD {
                state.head = second(values).map(String::from);
                continue;
            }
            if name.starts_with(tag_names::REFS_PREFIX)
                && let Some(oid) = second(values)
            {
                state.refs.push(GitRef::new(name, oid));
            }
        }
        state.identifier = identifier.ok_or(Nip34Error::MissingIdentifier {
            kind: KIND_REPO_STATE,
        })?;
        Ok(state)
    }
}

/// Typed bundle for the `kind: 1617` patch event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Patch {
    /// `.content` — full `git format-patch` output.
    pub content: String,
    /// Repository pointer.
    pub repo: Coordinate,
    /// Earliest-unique-commit hex of the target repo (mirrors
    /// [`Repository::earliest_unique_commit`]).
    pub repo_euc: Option<String>,
    /// People to notify (maintainers + ad-hoc reviewers).
    pub mentions: Vec<PublicKey>,
    /// `t:root` on the first patch in a series.
    pub root: bool,
    /// `t:root-revision` on the first patch in a revision.
    pub root_revision: bool,
    /// Optional commit hex (for stable-id replay).
    pub commit: Option<String>,
    /// Optional parent-commit hex.
    pub parent_commit: Option<String>,
    /// Optional PGP signature blob.
    pub commit_pgp_sig: Option<String>,
    /// Optional `["committer", name, email, timestamp, offset]` row.
    pub committer: Option<Committer>,
}

/// Typed `committer` row on a [`Patch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Committer {
    /// Committer name.
    pub name: String,
    /// Committer email.
    pub email: String,
    /// Unix-seconds timestamp.
    pub timestamp: String,
    /// Time-zone offset string (e.g. `"+0000"`, `"-0700"`).
    pub offset: String,
}

impl Patch {
    /// Construct a patch bundle.
    #[must_use]
    pub fn new(repo: Coordinate, content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            repo,
            repo_euc: None,
            mentions: Vec::new(),
            root: false,
            root_revision: false,
            commit: None,
            parent_commit: None,
            commit_pgp_sig: None,
            committer: None,
        }
    }

    /// Render the typed bundle to the public tag list.
    #[must_use]
    pub fn to_tags(&self) -> Vec<Tag> {
        let mut tags: Vec<Tag> = Vec::new();
        tags.push(a_tag(&self.repo));
        if let Some(euc) = &self.repo_euc {
            tags.push(r_tag(euc.clone()));
        }
        for mention in &self.mentions {
            tags.push(p_tag(*mention));
        }
        if self.root {
            tags.push(Tag::with(
                &TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::T)),
                ["root".to_owned()],
            ));
        }
        if self.root_revision {
            tags.push(Tag::with(
                &TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::T)),
                ["root-revision".to_owned()],
            ));
        }
        if let Some(commit) = &self.commit {
            tags.push(Tag::with(
                &TagKind::custom(tag_names::COMMIT),
                [commit.clone()],
            ));
            tags.push(r_tag(commit.clone()));
        }
        if let Some(parent_commit) = &self.parent_commit {
            tags.push(Tag::with(
                &TagKind::custom(tag_names::PARENT_COMMIT),
                [parent_commit.clone()],
            ));
        }
        if let Some(sig) = &self.commit_pgp_sig {
            tags.push(Tag::with(
                &TagKind::custom(tag_names::COMMIT_PGP_SIG),
                [sig.clone()],
            ));
        }
        if let Some(committer) = &self.committer {
            tags.push(Tag::with(
                &TagKind::custom(tag_names::COMMITTER),
                [
                    committer.name.clone(),
                    committer.email.clone(),
                    committer.timestamp.clone(),
                    committer.offset.clone(),
                ],
            ));
        }
        tags
    }

    /// Parse a signed kind-1617 event into a typed bundle.
    ///
    /// # Errors
    ///
    /// Returns [`Nip34Error::WrongKind`] for the wrong kind;
    /// returns [`Nip34Error::MissingRepository`] when the `a` tag
    /// is absent; forwards every coordinate / pubkey parse error.
    pub fn from_event(event: &Event) -> Result<Self, Nip34Error> {
        if event.kind != KIND_PATCH {
            return Err(Nip34Error::WrongKind {
                expected: KIND_PATCH,
                got: event.kind,
            });
        }
        let mut repo: Option<Coordinate> = None;
        let mut mentions: Vec<PublicKey> = Vec::new();
        let mut root = false;
        let mut root_revision = false;
        let mut commit: Option<String> = None;
        let mut parent_commit: Option<String> = None;
        let mut commit_pgp_sig: Option<String> = None;
        let mut committer: Option<Committer> = None;
        let mut repo_euc: Option<String> = None;
        for tag in &event.tags {
            let values = tag.values();
            let args = args(values);
            match tag.name() {
                "a" => {
                    if let Some(value) = args.first() {
                        repo = Some(Coordinate::parse(value)?);
                    }
                }
                "r" => {
                    if let Some(value) = args.first() {
                        repo_euc.get_or_insert_with(|| value.clone());
                    }
                }
                "p" => {
                    if let Some(value) = args.first() {
                        mentions.push(PublicKey::parse(value)?);
                    }
                }
                "t" => match args.first().map(String::as_str) {
                    Some("root") => root = true,
                    Some("root-revision") => root_revision = true,
                    _ => {}
                },
                tag_names::COMMIT => commit = args.first().cloned(),
                tag_names::PARENT_COMMIT => parent_commit = args.first().cloned(),
                tag_names::COMMIT_PGP_SIG => commit_pgp_sig = args.first().cloned(),
                tag_names::COMMITTER => {
                    if let [name, email, timestamp, offset, ..] = args {
                        committer = Some(Committer {
                            name: name.clone(),
                            email: email.clone(),
                            timestamp: timestamp.clone(),
                            offset: offset.clone(),
                        });
                    }
                }
                _ => {}
            }
        }
        let repo = repo.ok_or(Nip34Error::MissingRepository { kind: KIND_PATCH })?;
        Ok(Self {
            content: event.content.clone(),
            repo,
            repo_euc,
            mentions,
            root,
            root_revision,
            commit,
            parent_commit,
            commit_pgp_sig,
            committer,
        })
    }
}

/// Typed bundle for the `kind: 1618` pull request event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullRequest {
    /// `.content` — free-form description.
    pub content: String,
    /// Repository pointer.
    pub repo: Coordinate,
    /// Earliest-unique-commit hex of the target repo.
    pub repo_euc: Option<String>,
    /// People to notify.
    pub mentions: Vec<PublicKey>,
    /// `subject` tag.
    pub subject: Option<String>,
    /// Hashtags.
    pub hashtags: Vec<String>,
    /// `c` tag — tip of the PR branch.
    pub tip_commit: Option<String>,
    /// `clone` URLs where the commit can be downloaded.
    pub clone: Vec<String>,
    /// Optional recommended branch name.
    pub branch_name: Option<String>,
    /// Optional `e` tag — existing PR/patch being revised.
    pub revises_event: Option<EventId>,
    /// `merge-base` tag — most recent common ancestor with the
    /// target branch.
    pub merge_base: Option<String>,
}

impl PullRequest {
    /// Construct a pull request bundle.
    #[must_use]
    pub fn new(repo: Coordinate, content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            repo,
            repo_euc: None,
            mentions: Vec::new(),
            subject: None,
            hashtags: Vec::new(),
            tip_commit: None,
            clone: Vec::new(),
            branch_name: None,
            revises_event: None,
            merge_base: None,
        }
    }

    /// Render the typed bundle to the public tag list.
    #[must_use]
    pub fn to_tags(&self) -> Vec<Tag> {
        let mut tags: Vec<Tag> = Vec::new();
        tags.push(a_tag(&self.repo));
        if let Some(euc) = &self.repo_euc {
            tags.push(r_tag(euc.clone()));
        }
        for mention in &self.mentions {
            tags.push(p_tag(*mention));
        }
        if let Some(subject) = &self.subject {
            tags.push(Tag::with(
                &TagKind::custom(tag_names::SUBJECT),
                [subject.clone()],
            ));
        }
        for hashtag in &self.hashtags {
            tags.push(Tag::with(
                &TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::T)),
                [hashtag.clone()],
            ));
        }
        if let Some(c) = &self.tip_commit {
            tags.push(Tag::with(
                &TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::C)),
                [c.clone()],
            ));
        }
        if !self.clone.is_empty() {
            tags.push(Tag::with(
                &TagKind::custom(tag_names::CLONE),
                self.clone.clone(),
            ));
        }
        if let Some(branch) = &self.branch_name {
            tags.push(Tag::with(
                &TagKind::custom(tag_names::BRANCH_NAME),
                [branch.clone()],
            ));
        }
        if let Some(event_id) = self.revises_event {
            tags.push(e_tag(event_id, None));
        }
        if let Some(merge_base) = &self.merge_base {
            tags.push(Tag::with(
                &TagKind::custom(tag_names::MERGE_BASE),
                [merge_base.clone()],
            ));
        }
        tags
    }

    /// Parse a signed kind-1618 event into a typed bundle.
    ///
    /// # Errors
    ///
    /// Returns [`Nip34Error::WrongKind`] for the wrong kind and
    /// [`Nip34Error::MissingRepository`] when the `a` tag is
    /// absent; forwards every parse error.
    pub fn from_event(event: &Event) -> Result<Self, Nip34Error> {
        if event.kind != KIND_PULL_REQUEST {
            return Err(Nip34Error::WrongKind {
                expected: KIND_PULL_REQUEST,
                got: event.kind,
            });
        }
        let mut repo: Option<Coordinate> = None;
        let mut repo_euc: Option<String> = None;
        let mut mentions: Vec<PublicKey> = Vec::new();
        let mut subject: Option<String> = None;
        let mut hashtags: Vec<String> = Vec::new();
        let mut tip_commit: Option<String> = None;
        let mut clone: Vec<String> = Vec::new();
        let mut branch_name: Option<String> = None;
        let mut revises_event: Option<EventId> = None;
        let mut merge_base: Option<String> = None;
        for tag in &event.tags {
            let values = tag.values();
            let args = args(values);
            match tag.name() {
                "a" => {
                    if let Some(value) = args.first() {
                        repo = Some(Coordinate::parse(value)?);
                    }
                }
                "r" => {
                    if let Some(value) = args.first() {
                        repo_euc.get_or_insert_with(|| value.clone());
                    }
                }
                "p" => {
                    if let Some(value) = args.first() {
                        mentions.push(PublicKey::parse(value)?);
                    }
                }
                tag_names::SUBJECT => subject = args.first().cloned(),
                "t" => {
                    if let Some(value) = args.first() {
                        hashtags.push(value.clone());
                    }
                }
                "c" => tip_commit = args.first().cloned(),
                tag_names::CLONE => {
                    for v in args {
                        clone.push(v.clone());
                    }
                }
                tag_names::BRANCH_NAME => branch_name = args.first().cloned(),
                "e" => {
                    if let Some(value) = args.first() {
                        revises_event = Some(EventId::parse(value)?);
                    }
                }
                tag_names::MERGE_BASE => merge_base = args.first().cloned(),
                _ => {}
            }
        }
        let repo = repo.ok_or(Nip34Error::MissingRepository {
            kind: KIND_PULL_REQUEST,
        })?;
        Ok(Self {
            content: event.content.clone(),
            repo,
            repo_euc,
            mentions,
            subject,
            hashtags,
            tip_commit,
            clone,
            branch_name,
            revises_event,
            merge_base,
        })
    }
}

/// Typed bundle for the `kind: 1619` pull request update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PullRequestUpdate {
    /// `.content` — free-form description.
    pub content: String,
    /// Repository pointer.
    pub repo: Coordinate,
    /// Earliest-unique-commit hex of the target repo.
    pub repo_euc: Option<String>,
    /// People to notify.
    pub mentions: Vec<PublicKey>,
    /// `E` (uppercase) — root PR event id (NIP-22).
    pub root_event: EventId,
    /// `P` (uppercase) — root PR author pubkey (NIP-22).
    pub root_pubkey: PublicKey,
    /// `c` tag — updated tip commit.
    pub tip_commit: Option<String>,
    /// `clone` URLs.
    pub clone: Vec<String>,
    /// `merge-base` tag.
    pub merge_base: Option<String>,
}

impl PullRequestUpdate {
    /// Construct a PR-update bundle.
    #[must_use]
    pub fn new(
        repo: Coordinate,
        root_event: EventId,
        root_pubkey: PublicKey,
        content: impl Into<String>,
    ) -> Self {
        Self {
            content: content.into(),
            repo,
            repo_euc: None,
            mentions: Vec::new(),
            root_event,
            root_pubkey,
            tip_commit: None,
            clone: Vec::new(),
            merge_base: None,
        }
    }

    /// Render the typed bundle to the public tag list.
    #[must_use]
    pub fn to_tags(&self) -> Vec<Tag> {
        let mut tags: Vec<Tag> = Vec::new();
        tags.push(a_tag(&self.repo));
        if let Some(euc) = &self.repo_euc {
            tags.push(r_tag(euc.clone()));
        }
        for mention in &self.mentions {
            tags.push(p_tag(*mention));
        }
        tags.push(Tag::with(
            &TagKind::single_letter(SingleLetterTag::uppercase(Alphabet::E)),
            [self.root_event.to_hex()],
        ));
        tags.push(Tag::with(
            &TagKind::single_letter(SingleLetterTag::uppercase(Alphabet::P)),
            [self.root_pubkey.to_hex()],
        ));
        if let Some(c) = &self.tip_commit {
            tags.push(Tag::with(
                &TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::C)),
                [c.clone()],
            ));
        }
        if !self.clone.is_empty() {
            tags.push(Tag::with(
                &TagKind::custom(tag_names::CLONE),
                self.clone.clone(),
            ));
        }
        if let Some(merge_base) = &self.merge_base {
            tags.push(Tag::with(
                &TagKind::custom(tag_names::MERGE_BASE),
                [merge_base.clone()],
            ));
        }
        tags
    }

    /// Parse a signed kind-1619 event into a typed bundle.
    ///
    /// # Errors
    ///
    /// Returns [`Nip34Error::WrongKind`] for the wrong kind,
    /// [`Nip34Error::MissingRepository`] when the `a` tag is
    /// absent, and forwards every parse error. The uppercase `E`
    /// and `P` tags MUST both be present per NIP-22.
    pub fn from_event(event: &Event) -> Result<Self, Nip34Error> {
        if event.kind != KIND_PULL_REQUEST_UPDATE {
            return Err(Nip34Error::WrongKind {
                expected: KIND_PULL_REQUEST_UPDATE,
                got: event.kind,
            });
        }
        let mut repo: Option<Coordinate> = None;
        let mut repo_euc: Option<String> = None;
        let mut mentions: Vec<PublicKey> = Vec::new();
        let mut root_event: Option<EventId> = None;
        let mut root_pubkey: Option<PublicKey> = None;
        let mut tip_commit: Option<String> = None;
        let mut clone: Vec<String> = Vec::new();
        let mut merge_base: Option<String> = None;
        for tag in &event.tags {
            let values = tag.values();
            let args = args(values);
            match tag.name() {
                "a" => {
                    if let Some(value) = args.first() {
                        repo = Some(Coordinate::parse(value)?);
                    }
                }
                "r" => {
                    if let Some(value) = args.first() {
                        repo_euc.get_or_insert_with(|| value.clone());
                    }
                }
                "p" => {
                    if let Some(value) = args.first() {
                        mentions.push(PublicKey::parse(value)?);
                    }
                }
                "E" => {
                    if let Some(value) = args.first() {
                        root_event = Some(EventId::parse(value)?);
                    }
                }
                "P" => {
                    if let Some(value) = args.first() {
                        root_pubkey = Some(PublicKey::parse(value)?);
                    }
                }
                "c" => tip_commit = args.first().cloned(),
                tag_names::CLONE => {
                    for v in args {
                        clone.push(v.clone());
                    }
                }
                tag_names::MERGE_BASE => merge_base = args.first().cloned(),
                _ => {}
            }
        }
        let repo = repo.ok_or(Nip34Error::MissingRepository {
            kind: KIND_PULL_REQUEST_UPDATE,
        })?;
        let root_event = root_event.ok_or(Nip34Error::MissingRepository {
            kind: KIND_PULL_REQUEST_UPDATE,
        })?;
        let root_pubkey = root_pubkey.ok_or(Nip34Error::MissingRepository {
            kind: KIND_PULL_REQUEST_UPDATE,
        })?;
        Ok(Self {
            content: event.content.clone(),
            repo,
            repo_euc,
            mentions,
            root_event,
            root_pubkey,
            tip_commit,
            clone,
            merge_base,
        })
    }
}

/// Typed bundle for the `kind: 1621` issue event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    /// `.content` — Markdown issue body.
    pub content: String,
    /// Repository pointer.
    pub repo: Coordinate,
    /// People to notify.
    pub mentions: Vec<PublicKey>,
    /// Optional `subject` tag.
    pub subject: Option<String>,
    /// Issue labels.
    pub hashtags: Vec<String>,
}

impl Issue {
    /// Construct an issue bundle.
    #[must_use]
    pub fn new(repo: Coordinate, content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            repo,
            mentions: Vec::new(),
            subject: None,
            hashtags: Vec::new(),
        }
    }

    /// Render the typed bundle to the public tag list.
    #[must_use]
    pub fn to_tags(&self) -> Vec<Tag> {
        let mut tags: Vec<Tag> = Vec::new();
        tags.push(a_tag(&self.repo));
        for mention in &self.mentions {
            tags.push(p_tag(*mention));
        }
        if let Some(subject) = &self.subject {
            tags.push(Tag::with(
                &TagKind::custom(tag_names::SUBJECT),
                [subject.clone()],
            ));
        }
        for hashtag in &self.hashtags {
            tags.push(Tag::with(
                &TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::T)),
                [hashtag.clone()],
            ));
        }
        tags
    }

    /// Parse a signed kind-1621 event into a typed bundle.
    ///
    /// # Errors
    ///
    /// Returns [`Nip34Error::WrongKind`] for the wrong kind and
    /// [`Nip34Error::MissingRepository`] when the `a` tag is
    /// absent.
    pub fn from_event(event: &Event) -> Result<Self, Nip34Error> {
        if event.kind != KIND_ISSUE {
            return Err(Nip34Error::WrongKind {
                expected: KIND_ISSUE,
                got: event.kind,
            });
        }
        let mut repo: Option<Coordinate> = None;
        let mut mentions: Vec<PublicKey> = Vec::new();
        let mut subject: Option<String> = None;
        let mut hashtags: Vec<String> = Vec::new();
        for tag in &event.tags {
            let values = tag.values();
            let args = args(values);
            match tag.name() {
                "a" => {
                    if let Some(value) = args.first() {
                        repo = Some(Coordinate::parse(value)?);
                    }
                }
                "p" => {
                    if let Some(value) = args.first() {
                        mentions.push(PublicKey::parse(value)?);
                    }
                }
                tag_names::SUBJECT => subject = args.first().cloned(),
                "t" => {
                    if let Some(value) = args.first() {
                        hashtags.push(value.clone());
                    }
                }
                _ => {}
            }
        }
        let repo = repo.ok_or(Nip34Error::MissingRepository { kind: KIND_ISSUE })?;
        Ok(Self {
            content: event.content.clone(),
            repo,
            mentions,
            subject,
            hashtags,
        })
    }
}

/// Typed status discriminator covering kinds `1630..=1633`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum GitStatus {
    /// `1630` — open.
    Open,
    /// `1631` — applied / merged for patches & PRs, resolved for issues.
    Applied,
    /// `1632` — closed.
    Closed,
    /// `1633` — draft.
    Draft,
}

impl GitStatus {
    /// Map the discriminator to its on-the-wire kind.
    #[must_use]
    pub const fn to_kind(self) -> Kind {
        match self {
            Self::Open => KIND_STATUS_OPEN,
            Self::Applied => KIND_STATUS_APPLIED,
            Self::Closed => KIND_STATUS_CLOSED,
            Self::Draft => KIND_STATUS_DRAFT,
        }
    }

    /// Try to recover a discriminator from a status kind.
    ///
    /// # Errors
    ///
    /// Returns [`Nip34Error::InvalidStatusKind`] when `kind` is
    /// outside `1630..=1633`.
    pub const fn from_kind(kind: Kind) -> Result<Self, Nip34Error> {
        match kind.as_u16() {
            1_630 => Ok(Self::Open),
            1_631 => Ok(Self::Applied),
            1_632 => Ok(Self::Closed),
            1_633 => Ok(Self::Draft),
            _ => Err(Nip34Error::InvalidStatusKind(kind)),
        }
    }
}

/// `e` tag reference on a [`StatusEvent`] (target event id + marker).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusReference {
    /// Target event id.
    pub event_id: EventId,
    /// `root` / `reply` marker per NIP-10.
    pub marker: Option<String>,
}

/// Typed bundle for the `kind: 1630..=1633` status events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusEvent {
    /// `.content` — free-form explanation.
    pub content: String,
    /// Typed status discriminator (controls the rendered kind).
    pub status: GitStatus,
    /// `e` tag references (root + reply revisions).
    pub references: Vec<StatusReference>,
    /// People to notify.
    pub mentions: Vec<PublicKey>,
    /// Optional repository pointer.
    pub repo: Option<Coordinate>,
    /// Optional earliest-unique-commit hex.
    pub repo_euc: Option<String>,
    /// Optional `q` tag — quoted patch references on `1631` events.
    pub quoted_patches: Vec<EventId>,
    /// Optional `merge-commit` hex (only on `1631`).
    pub merge_commit: Option<String>,
    /// Optional `applied-as-commits` list (only on `1631`).
    pub applied_as_commits: Vec<String>,
}

impl StatusEvent {
    /// Construct a status bundle.
    #[must_use]
    pub const fn new(status: GitStatus) -> Self {
        Self {
            content: String::new(),
            status,
            references: Vec::new(),
            mentions: Vec::new(),
            repo: None,
            repo_euc: None,
            quoted_patches: Vec::new(),
            merge_commit: None,
            applied_as_commits: Vec::new(),
        }
    }

    /// Render the typed bundle to the public tag list.
    #[must_use]
    pub fn to_tags(&self) -> Vec<Tag> {
        let mut tags: Vec<Tag> = Vec::new();
        for reference in &self.references {
            tags.push(e_tag(reference.event_id, reference.marker.as_deref()));
        }
        for mention in &self.mentions {
            tags.push(p_tag(*mention));
        }
        if let Some(repo) = &self.repo {
            tags.push(a_tag(repo));
        }
        if let Some(euc) = &self.repo_euc {
            tags.push(r_tag(euc.clone()));
        }
        for q in &self.quoted_patches {
            tags.push(Tag::with(
                &TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::Q)),
                [q.to_hex(), String::new(), String::new()],
            ));
        }
        if let Some(merge_commit) = &self.merge_commit {
            tags.push(Tag::with(
                &TagKind::custom(tag_names::MERGE_COMMIT),
                [merge_commit.clone()],
            ));
            tags.push(r_tag(merge_commit.clone()));
        }
        if !self.applied_as_commits.is_empty() {
            tags.push(Tag::with(
                &TagKind::custom(tag_names::APPLIED_AS_COMMITS),
                self.applied_as_commits.clone(),
            ));
            for commit in &self.applied_as_commits {
                tags.push(r_tag(commit.clone()));
            }
        }
        tags
    }

    /// Parse a signed kind-`1630..=1633` event into a typed bundle.
    ///
    /// # Errors
    ///
    /// Returns [`Nip34Error::InvalidStatusKind`] when the event's
    /// kind is outside `1630..=1633`; forwards every parse error.
    pub fn from_event(event: &Event) -> Result<Self, Nip34Error> {
        let status = GitStatus::from_kind(event.kind)?;
        let mut bundle = Self::new(status);
        bundle.content.clone_from(&event.content);
        for tag in &event.tags {
            let values = tag.values();
            let args = args(values);
            match tag.name() {
                "e" => {
                    let Some(id_hex) = args.first() else {
                        continue;
                    };
                    let event_id = EventId::parse(id_hex)?;
                    let marker = args.get(2).cloned().filter(|s| !s.is_empty());
                    bundle.references.push(StatusReference { event_id, marker });
                }
                "p" => {
                    if let Some(value) = args.first() {
                        bundle.mentions.push(PublicKey::parse(value)?);
                    }
                }
                "a" => {
                    if let Some(value) = args.first() {
                        bundle.repo = Some(Coordinate::parse(value)?);
                    }
                }
                "r" => {
                    if let Some(value) = args.first() {
                        bundle.repo_euc.get_or_insert_with(|| value.clone());
                    }
                }
                "q" => {
                    if let Some(value) = args.first() {
                        bundle.quoted_patches.push(EventId::parse(value)?);
                    }
                }
                tag_names::MERGE_COMMIT => bundle.merge_commit = args.first().cloned(),
                tag_names::APPLIED_AS_COMMITS => {
                    for v in args {
                        bundle.applied_as_commits.push(v.clone());
                    }
                }
                _ => {}
            }
        }
        Ok(bundle)
    }
}

/// Typed bundle for the `kind: 10317` user grasp-server list.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GraspServerList {
    /// Grasp service WebSocket URLs in preference order.
    pub servers: Vec<RelayUrl>,
}

impl GraspServerList {
    /// Construct a grasp-server list.
    #[must_use]
    pub fn new<I>(servers: I) -> Self
    where
        I: IntoIterator<Item = RelayUrl>,
    {
        Self {
            servers: servers.into_iter().collect(),
        }
    }

    /// Render the typed bundle to the public tag list.
    #[must_use]
    pub fn to_tags(&self) -> Vec<Tag> {
        self.servers
            .iter()
            .map(|server| {
                Tag::with(
                    &TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::G)),
                    [server.as_str().to_owned()],
                )
            })
            .collect()
    }

    /// Parse a signed kind-10317 event into a typed bundle.
    ///
    /// # Errors
    ///
    /// Returns [`Nip34Error::WrongKind`] for the wrong kind.
    pub fn from_event(event: &Event) -> Result<Self, Nip34Error> {
        if event.kind != KIND_GRASP_LIST {
            return Err(Nip34Error::WrongKind {
                expected: KIND_GRASP_LIST,
                got: event.kind,
            });
        }
        let mut servers: Vec<RelayUrl> = Vec::new();
        for tag in &event.tags {
            if tag.name() != "g" {
                continue;
            }
            if let Some(value) = tag.values().get(1) {
                servers.push(RelayUrl::parse(value)?);
            }
        }
        Ok(Self { servers })
    }
}

impl EventBuilder {
    /// Author a NIP-34 repository announcement (`kind: 30617`).
    #[must_use]
    pub fn git_repository(repo: &Repository) -> Self {
        let mut builder = Self::new(KIND_REPO, "");
        for tag in repo.to_tags() {
            builder = builder.tag(tag);
        }
        builder
    }

    /// Author a NIP-34 repository state event (`kind: 30618`).
    #[must_use]
    pub fn git_repository_state(state: &RepositoryState) -> Self {
        let mut builder = Self::new(KIND_REPO_STATE, "");
        for tag in state.to_tags() {
            builder = builder.tag(tag);
        }
        builder
    }

    /// Author a NIP-34 patch event (`kind: 1617`).
    #[must_use]
    pub fn git_patch(patch: &Patch) -> Self {
        let mut builder = Self::new(KIND_PATCH, patch.content.clone());
        for tag in patch.to_tags() {
            builder = builder.tag(tag);
        }
        builder
    }

    /// Author a NIP-34 pull request event (`kind: 1618`).
    #[must_use]
    pub fn git_pull_request(pr: &PullRequest) -> Self {
        let mut builder = Self::new(KIND_PULL_REQUEST, pr.content.clone());
        for tag in pr.to_tags() {
            builder = builder.tag(tag);
        }
        builder
    }

    /// Author a NIP-34 pull request update event (`kind: 1619`).
    #[must_use]
    pub fn git_pull_request_update(update: &PullRequestUpdate) -> Self {
        let mut builder = Self::new(KIND_PULL_REQUEST_UPDATE, update.content.clone());
        for tag in update.to_tags() {
            builder = builder.tag(tag);
        }
        builder
    }

    /// Author a NIP-34 issue event (`kind: 1621`).
    #[must_use]
    pub fn git_issue(issue: &Issue) -> Self {
        let mut builder = Self::new(KIND_ISSUE, issue.content.clone());
        for tag in issue.to_tags() {
            builder = builder.tag(tag);
        }
        builder
    }

    /// Author a NIP-34 status event (`kind: 1630..=1633`).
    #[must_use]
    pub fn git_status(event: &StatusEvent) -> Self {
        let mut builder = Self::new(event.status.to_kind(), event.content.clone());
        for tag in event.to_tags() {
            builder = builder.tag(tag);
        }
        builder
    }

    /// Author a NIP-34 grasp-server list event (`kind: 10317`).
    #[must_use]
    pub fn git_grasp_servers(list: &GraspServerList) -> Self {
        let mut builder = Self::new(KIND_GRASP_LIST, "");
        for tag in list.to_tags() {
            builder = builder.tag(tag);
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

    fn other_keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000005").unwrap()
    }

    fn repo_coord() -> Coordinate {
        Coordinate::new(KIND_REPO, *keys().public_key(), "ngit".to_owned())
    }

    #[test]
    fn repository_round_trips_through_event() {
        let repo = Repository {
            identifier: "ngit".to_owned(),
            name: Some("ngit".to_owned()),
            description: Some("Nostr git-helper".to_owned()),
            web: vec!["https://ngit.dev".to_owned()],
            clone: vec!["https://github.com/x/ngit.git".to_owned()],
            relays: vec![RelayUrl::parse("wss://relay.ngit.dev").unwrap()],
            earliest_unique_commit: Some("deadbeef".to_owned()),
            maintainers: vec![*other_keys().public_key()],
            hashtags: vec!["git".to_owned(), "tooling".to_owned()],
            personal_fork: false,
        };
        let event = EventBuilder::git_repository(&repo)
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, KIND_REPO);
        let recovered = Repository::from_event(&event).unwrap();
        assert_eq!(recovered, repo);
    }

    #[test]
    fn repository_personal_fork_flag_round_trips() {
        let repo = Repository {
            personal_fork: true,
            ..Repository::new("fork".to_owned())
        };
        let event = EventBuilder::git_repository(&repo)
            .sign_with_keys(&keys())
            .unwrap();
        let recovered = Repository::from_event(&event).unwrap();
        assert!(recovered.personal_fork);
    }

    #[test]
    fn repository_from_event_requires_identifier() {
        let event = EventBuilder::new(KIND_REPO, "")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            Repository::from_event(&event),
            Err(Nip34Error::MissingIdentifier { .. }),
        ));
    }

    #[test]
    fn repository_state_round_trips_through_event() {
        let state = RepositoryState {
            identifier: "ngit".to_owned(),
            refs: vec![
                GitRef::new("refs/heads/main", "aabb"),
                GitRef::new("refs/tags/v1.0.0", "ccdd"),
            ],
            head: Some("ref: refs/heads/main".to_owned()),
        };
        let event = EventBuilder::git_repository_state(&state)
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, KIND_REPO_STATE);
        let recovered = RepositoryState::from_event(&event).unwrap();
        assert_eq!(recovered, state);
    }

    #[test]
    fn patch_round_trips_through_event() {
        let patch = Patch {
            content: "From <git format-patch output>\n".to_owned(),
            repo: repo_coord(),
            repo_euc: Some("deadbeef".to_owned()),
            mentions: vec![*other_keys().public_key()],
            root: true,
            root_revision: false,
            commit: Some("abc123".to_owned()),
            parent_commit: Some("def456".to_owned()),
            commit_pgp_sig: Some("-----BEGIN PGP SIGNATURE-----\n...".to_owned()),
            committer: Some(Committer {
                name: "Satoshi".to_owned(),
                email: "satoshi@example".to_owned(),
                timestamp: "1700000000".to_owned(),
                offset: "+0000".to_owned(),
            }),
        };
        let event = EventBuilder::git_patch(&patch)
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, KIND_PATCH);
        let recovered = Patch::from_event(&event).unwrap();
        assert_eq!(recovered, patch);
    }

    #[test]
    fn patch_from_event_requires_repository() {
        let event = EventBuilder::new(KIND_PATCH, "")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            Patch::from_event(&event),
            Err(Nip34Error::MissingRepository { .. }),
        ));
    }

    #[test]
    fn pull_request_round_trips_through_event() {
        let pr = PullRequest {
            content: "Adds awesome feature".to_owned(),
            repo: repo_coord(),
            repo_euc: Some("deadbeef".to_owned()),
            mentions: vec![*other_keys().public_key()],
            subject: Some("feat: awesome".to_owned()),
            hashtags: vec!["feature".to_owned()],
            tip_commit: Some("abc123".to_owned()),
            clone: vec!["https://github.com/x/ngit.git".to_owned()],
            branch_name: Some("feat/awesome".to_owned()),
            revises_event: Some(EventId::from_byte_array([0xaa; 32])),
            merge_base: Some("base999".to_owned()),
        };
        let event = EventBuilder::git_pull_request(&pr)
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, KIND_PULL_REQUEST);
        let recovered = PullRequest::from_event(&event).unwrap();
        assert_eq!(recovered, pr);
    }

    #[test]
    fn pull_request_update_round_trips_through_event() {
        let update = PullRequestUpdate {
            content: "Updated tip".to_owned(),
            repo: repo_coord(),
            repo_euc: None,
            mentions: vec![],
            root_event: EventId::from_byte_array([0xbb; 32]),
            root_pubkey: *other_keys().public_key(),
            tip_commit: Some("def456".to_owned()),
            clone: vec!["https://github.com/x/ngit.git".to_owned()],
            merge_base: Some("base000".to_owned()),
        };
        let event = EventBuilder::git_pull_request_update(&update)
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, KIND_PULL_REQUEST_UPDATE);
        let recovered = PullRequestUpdate::from_event(&event).unwrap();
        assert_eq!(recovered, update);
    }

    #[test]
    fn issue_round_trips_through_event() {
        let issue = Issue {
            content: "Bug body in Markdown".to_owned(),
            repo: repo_coord(),
            mentions: vec![*other_keys().public_key()],
            subject: Some("Crash on startup".to_owned()),
            hashtags: vec!["bug".to_owned(), "priority-high".to_owned()],
        };
        let event = EventBuilder::git_issue(&issue)
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, KIND_ISSUE);
        let recovered = Issue::from_event(&event).unwrap();
        assert_eq!(recovered, issue);
    }

    #[test]
    fn status_round_trips_for_each_kind() {
        for status in [
            GitStatus::Open,
            GitStatus::Applied,
            GitStatus::Closed,
            GitStatus::Draft,
        ] {
            let event = StatusEvent {
                content: format!("status: {status:?}"),
                status,
                references: vec![StatusReference {
                    event_id: EventId::from_byte_array([0xcc; 32]),
                    marker: Some("root".to_owned()),
                }],
                mentions: vec![*other_keys().public_key()],
                repo: Some(repo_coord()),
                repo_euc: Some("deadbeef".to_owned()),
                quoted_patches: vec![],
                merge_commit: None,
                applied_as_commits: vec![],
            };
            let signed = EventBuilder::git_status(&event)
                .sign_with_keys(&keys())
                .unwrap();
            assert_eq!(signed.kind, status.to_kind());
            let recovered = StatusEvent::from_event(&signed).unwrap();
            assert_eq!(recovered, event);
        }
    }

    #[test]
    fn status_applied_carries_merge_metadata() {
        let event = StatusEvent {
            content: String::new(),
            status: GitStatus::Applied,
            references: vec![],
            mentions: vec![],
            repo: None,
            repo_euc: None,
            quoted_patches: vec![EventId::from_byte_array([0xdd; 32])],
            merge_commit: Some("mergecommithex".to_owned()),
            applied_as_commits: vec!["a1".to_owned(), "a2".to_owned()],
        };
        let signed = EventBuilder::git_status(&event)
            .sign_with_keys(&keys())
            .unwrap();
        let recovered = StatusEvent::from_event(&signed).unwrap();
        assert_eq!(recovered.merge_commit.as_deref(), Some("mergecommithex"));
        assert_eq!(recovered.applied_as_commits, event.applied_as_commits);
        assert_eq!(recovered.quoted_patches, event.quoted_patches);
    }

    #[test]
    fn status_from_event_rejects_kind_outside_range() {
        let event = EventBuilder::text_note("not a status")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            StatusEvent::from_event(&event),
            Err(Nip34Error::InvalidStatusKind(_)),
        ));
    }

    #[test]
    fn git_status_kind_helpers_round_trip() {
        for status in [
            GitStatus::Open,
            GitStatus::Applied,
            GitStatus::Closed,
            GitStatus::Draft,
        ] {
            assert_eq!(GitStatus::from_kind(status.to_kind()).unwrap(), status);
        }
        assert!(matches!(
            GitStatus::from_kind(Kind::TEXT_NOTE),
            Err(Nip34Error::InvalidStatusKind(_)),
        ));
    }

    #[test]
    fn grasp_server_list_round_trips_through_event() {
        let list = GraspServerList::new([
            RelayUrl::parse("wss://grasp.one.example").unwrap(),
            RelayUrl::parse("wss://grasp.two.example").unwrap(),
        ]);
        let event = EventBuilder::git_grasp_servers(&list)
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, KIND_GRASP_LIST);
        let recovered = GraspServerList::from_event(&event).unwrap();
        assert_eq!(recovered, list);
    }

    #[test]
    fn grasp_server_list_from_event_rejects_wrong_kind() {
        let event = EventBuilder::text_note("nope")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            GraspServerList::from_event(&event),
            Err(Nip34Error::WrongKind { .. }),
        ));
    }
}
