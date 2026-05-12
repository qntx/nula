//! [NIP-56] Reporting.
//!
//! A `kind: 1984` event signals that some referenced content is
//! objectionable. The spec requires:
//!
//! - one `p` tag identifying the user being reported, and
//! - optionally an `e` tag pointing at a specific note when the
//!   report concerns that note, plus an `x` tag for blob hashes,
//! - a *report type* token as the 3rd column of the `p` / `e` / `x`
//!   target tag (one of the documented strings: `nudity`, `malware`,
//!   `profanity`, `illegal`, `spam`, `impersonation`, `other`).
//!
//! NIP-32 `L`/`l` tags MAY co-exist; we expose them through
//! [`crate::nips::nip32::labels_from_tags`].
//!
//! # Forward compatibility
//!
//! - [`ReportType`] keeps a [`ReportType::Custom`] variant so future
//!   tokens decode cleanly.
//! - Unknown tags survive a round-trip through [`Report::extra_tags`].
//! - `x` blob reports may pin both an `e` host event and one or more
//!   `server` URLs, matching the spec §"Tags".
//!
//! [NIP-56]: https://github.com/nostr-protocol/nips/blob/master/56.md

use thiserror::Error;

use crate::event::{
    Alphabet, Event, EventBuilder, EventId, EventIdError, Kind, SingleLetterTag, Tag, TagKind,
};
use crate::key::{PublicKey, PublicKeyError};
use crate::types::{Url, UrlError};

/// `kind: 1984` — reporting event.
pub const KIND_REPORT: Kind = Kind::REPORTING;

/// Wire-defined report types (spec §"Tags").
///
/// Unknown tokens decode as [`Self::Custom`] so the parser tolerates
/// new categories introduced by future spec revisions.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ReportType {
    /// `nudity` — depictions of nudity, porn, etc.
    Nudity,
    /// `malware` — virus, worm, ransomware, spyware, etc.
    Malware,
    /// `profanity` — hateful speech.
    Profanity,
    /// `illegal` — content that may be illegal in some jurisdiction.
    Illegal,
    /// `spam`.
    Spam,
    /// `impersonation` — pretending to be someone else (profile-only).
    Impersonation,
    /// `other` — generic catch-all defined by the spec.
    Other,
    /// Forward-compatible passthrough for unrecognised tokens.
    Custom(String),
}

impl ReportType {
    /// Wire token.
    ///
    /// Returns the spec-defined lowercase string or, for
    /// [`Self::Custom`], the inner string slice. The borrow on the
    /// inner string prevents this from being `const`.
    #[must_use]
    #[expect(
        clippy::missing_const_for_fn,
        reason = "`Self::Custom` borrows from a heap `String`"
    )]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Nudity => "nudity",
            Self::Malware => "malware",
            Self::Profanity => "profanity",
            Self::Illegal => "illegal",
            Self::Spam => "spam",
            Self::Impersonation => "impersonation",
            Self::Other => "other",
            Self::Custom(s) => s.as_str(),
        }
    }

    /// Parse a wire token. Always succeeds: unknown tokens decode as
    /// [`Self::Custom`].
    #[must_use]
    pub fn parse(token: &str) -> Self {
        match token {
            "nudity" => Self::Nudity,
            "malware" => Self::Malware,
            "profanity" => Self::Profanity,
            "illegal" => Self::Illegal,
            "spam" => Self::Spam,
            "impersonation" => Self::Impersonation,
            "other" => Self::Other,
            _ => Self::Custom(token.to_owned()),
        }
    }
}

/// What is being reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportTarget {
    /// `e` tag — reports a specific event. The `p` tag still
    /// identifies the event's author per spec.
    Event {
        /// Note id being reported.
        id: EventId,
        /// Note author. The `p` tag is required by spec even when an
        /// `e` tag is present.
        author: PublicKey,
        /// Optional `ReportType` carried on the `e` tag.
        report_type: Option<ReportType>,
    },
    /// `p`-only tag — reports a profile.
    Profile {
        /// Pubkey being reported.
        pubkey: PublicKey,
        /// `ReportType` token. `impersonation` is only meaningful on
        /// profile reports per spec.
        report_type: Option<ReportType>,
    },
    /// `x` tag — reports a blob by hash. Per spec, an `e` tag with
    /// the host event id MUST accompany the blob report; `servers`
    /// are optional URL hints pointing at media stores.
    Blob {
        /// Blob hash (typically SHA-256 hex).
        hash: String,
        /// Type token associated with the blob.
        report_type: Option<ReportType>,
        /// Host event id (`e` tag), required by spec.
        host_event: EventId,
        /// Host event's report type token (may differ from
        /// [`Self::Blob::report_type`]).
        host_report_type: Option<ReportType>,
        /// `server` URL hints pointing at media stores.
        servers: Vec<Url>,
    },
}

/// Typed bundle for a NIP-56 `kind: 1984` event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// What is being reported.
    pub target: ReportTarget,
    /// `.content` — free-form rationale from the reporter.
    pub content: String,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

impl Report {
    /// Construct a profile-only report.
    #[must_use]
    pub const fn profile(pubkey: PublicKey, report_type: Option<ReportType>) -> Self {
        Self {
            target: ReportTarget::Profile {
                pubkey,
                report_type,
            },
            content: String::new(),
            extra_tags: Vec::new(),
        }
    }

    /// Construct an event report. `author` must be the note's pubkey.
    #[must_use]
    pub const fn event(id: EventId, author: PublicKey, report_type: Option<ReportType>) -> Self {
        Self {
            target: ReportTarget::Event {
                id,
                author,
                report_type,
            },
            content: String::new(),
            extra_tags: Vec::new(),
        }
    }

    /// Construct a blob-hash report.
    #[must_use]
    pub fn blob(
        hash: impl Into<String>,
        host_event: EventId,
        report_type: Option<ReportType>,
    ) -> Self {
        Self {
            target: ReportTarget::Blob {
                hash: hash.into(),
                report_type: report_type.clone(),
                host_event,
                host_report_type: report_type,
                servers: Vec::new(),
            },
            content: String::new(),
            extra_tags: Vec::new(),
        }
    }

    /// Attach a free-form rationale.
    #[must_use]
    pub fn content(mut self, content: impl Into<String>) -> Self {
        self.content = content.into();
        self
    }

    /// Append a `server` URL hint to a blob report.
    ///
    /// Has no effect for non-blob targets.
    #[must_use]
    pub fn server(mut self, url: Url) -> Self {
        if let ReportTarget::Blob { servers, .. } = &mut self.target {
            servers.push(url);
        }
        self
    }

    /// Parse a `kind: 1984` event into a typed bundle.
    ///
    /// # Errors
    ///
    /// - [`ReportError::WrongKind`] when the event is not
    ///   `kind: 1984`.
    /// - [`ReportError::MissingTarget`] when no target tag is
    ///   present.
    /// - [`ReportError::MissingHostEvent`] when an `x` tag has no
    ///   matching `e` host tag.
    /// - [`ReportError::InvalidPublicKey`] /
    ///   [`ReportError::InvalidEventId`] /
    ///   [`ReportError::InvalidUrl`] when fields fail to parse.
    pub fn from_event(event: &Event) -> Result<Self, ReportError> {
        if event.kind != KIND_REPORT {
            return Err(ReportError::WrongKind(event.kind));
        }

        let mut p_tag: Option<(PublicKey, Option<ReportType>)> = None;
        let mut e_tag: Option<(EventId, Option<ReportType>)> = None;
        let mut x_tag: Option<(String, Option<ReportType>)> = None;
        let mut servers: Vec<Url> = Vec::new();
        let mut extra_tags: Vec<Tag> = Vec::new();

        for tag in &event.tags {
            match tag.kind() {
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::P => {
                    p_tag = Some(parse_p_tag(tag)?);
                }
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::E => {
                    e_tag = Some(parse_e_tag(tag)?);
                }
                TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::X => {
                    x_tag = Some(parse_x_tag(tag));
                }
                _ if tag.name() == "server" => {
                    let url_str = tag.get(1).ok_or(ReportError::MalformedServer)?;
                    servers.push(Url::parse(url_str)?);
                }
                _ => extra_tags.push(tag.clone()),
            }
        }

        let target = build_target(p_tag, e_tag, x_tag, servers)?;
        Ok(Self {
            target,
            content: event.content.clone(),
            extra_tags,
        })
    }
}

fn build_target(
    p_tag: Option<(PublicKey, Option<ReportType>)>,
    e_tag: Option<(EventId, Option<ReportType>)>,
    x_tag: Option<(String, Option<ReportType>)>,
    servers: Vec<Url>,
) -> Result<ReportTarget, ReportError> {
    match (x_tag, e_tag, p_tag) {
        (Some((hash, x_type)), Some((host_event, e_type)), _) => Ok(ReportTarget::Blob {
            hash,
            report_type: x_type,
            host_event,
            host_report_type: e_type,
            servers,
        }),
        (Some(_), None, _) => Err(ReportError::MissingHostEvent),
        (None, Some((id, e_type)), Some((author, _))) => Ok(ReportTarget::Event {
            id,
            author,
            report_type: e_type,
        }),
        (None, None, Some((pubkey, p_type))) => Ok(ReportTarget::Profile {
            pubkey,
            report_type: p_type,
        }),
        _ => Err(ReportError::MissingTarget),
    }
}

fn parse_p_tag(tag: &Tag) -> Result<(PublicKey, Option<ReportType>), ReportError> {
    let pk_hex = tag.get(1).ok_or(ReportError::MalformedPubkey)?;
    let pubkey = PublicKey::parse(pk_hex)?;
    let report_type = tag.get(2).filter(|s| !s.is_empty()).map(ReportType::parse);
    Ok((pubkey, report_type))
}

fn parse_e_tag(tag: &Tag) -> Result<(EventId, Option<ReportType>), ReportError> {
    let id_hex = tag.get(1).ok_or(ReportError::MalformedEvent)?;
    let id = EventId::parse(id_hex)?;
    let report_type = tag.get(2).filter(|s| !s.is_empty()).map(ReportType::parse);
    Ok((id, report_type))
}

fn parse_x_tag(tag: &Tag) -> (String, Option<ReportType>) {
    let hash = tag.get(1).unwrap_or_default().to_owned();
    let report_type = tag.get(2).filter(|s| !s.is_empty()).map(ReportType::parse);
    (hash, report_type)
}

/// Errors raised by [`Report::from_event`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ReportError {
    /// The event was not `kind: 1984`.
    #[error("expected kind 1984 (report), got kind {}", .0.as_u16())]
    WrongKind(Kind),
    /// No target tag was present.
    #[error("report must include at least one of `p`, `e`, or `x` tags")]
    MissingTarget,
    /// An `x` tag was present without a host `e` tag.
    #[error("`x` blob report must accompany an `e` host event tag")]
    MissingHostEvent,
    /// `p` tag is missing the pubkey column.
    #[error("`p` tag missing pubkey")]
    MalformedPubkey,
    /// `e` tag is missing the event id column.
    #[error("`e` tag missing event id")]
    MalformedEvent,
    /// `server` tag is missing the URL column.
    #[error("`server` tag missing URL")]
    MalformedServer,
    /// `p` pubkey is malformed.
    #[error(transparent)]
    InvalidPublicKey(#[from] PublicKeyError),
    /// `e` event id is malformed.
    #[error(transparent)]
    InvalidEventId(#[from] EventIdError),
    /// `server` URL is malformed.
    #[error(transparent)]
    InvalidUrl(#[from] UrlError),
}

fn p_target(pubkey: PublicKey, report_type: Option<&ReportType>) -> Tag {
    let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::P));
    report_type.map_or_else(
        || Tag::with(&head, [pubkey.to_hex()]),
        |rt| Tag::with(&head, [pubkey.to_hex(), rt.as_str().to_owned()]),
    )
}

fn e_target(id: EventId, report_type: Option<&ReportType>) -> Tag {
    let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::E));
    report_type.map_or_else(
        || Tag::with(&head, [id.to_hex()]),
        |rt| Tag::with(&head, [id.to_hex(), rt.as_str().to_owned()]),
    )
}

fn x_target(hash: &str, report_type: Option<&ReportType>) -> Tag {
    let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::X));
    report_type.map_or_else(
        || Tag::with(&head, [hash.to_owned()]),
        |rt| Tag::with(&head, [hash.to_owned(), rt.as_str().to_owned()]),
    )
}

impl EventBuilder {
    /// Author a NIP-56 `kind: 1984` report event.
    ///
    /// Tag order matches the spec examples:
    ///
    /// 1. Primary target tag (`p`, `e`, or `x`).
    /// 2. Secondary tags (the `p` author for an `e` report or the
    ///    host `e` for an `x` report).
    /// 3. `server` URL hints, if any.
    /// 4. Caller-supplied [`Report::extra_tags`].
    #[must_use]
    pub fn report(report: &Report) -> Self {
        let mut builder = Self::new(KIND_REPORT, report.content.clone());
        match &report.target {
            ReportTarget::Profile {
                pubkey,
                report_type,
            } => {
                builder = builder.tag(p_target(*pubkey, report_type.as_ref()));
            }
            ReportTarget::Event {
                id,
                author,
                report_type,
            } => {
                builder = builder.tag(e_target(*id, report_type.as_ref()));
                builder = builder.tag(p_target(*author, None));
            }
            ReportTarget::Blob {
                hash,
                report_type,
                host_event,
                host_report_type,
                servers,
            } => {
                builder = builder.tag(x_target(hash, report_type.as_ref()));
                builder = builder.tag(e_target(*host_event, host_report_type.as_ref()));
                for server in servers {
                    builder = builder.tag(Tag::with(
                        &TagKind::from_wire("server"),
                        [server.as_str().to_owned()],
                    ));
                }
            }
        }
        for tag in &report.extra_tags {
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

    fn other_pubkey() -> PublicKey {
        *Keys::parse("0000000000000000000000000000000000000000000000000000000000000004")
            .unwrap()
            .public_key()
    }

    #[test]
    fn report_type_wire_tokens_round_trip() {
        for token in [
            "nudity",
            "malware",
            "profanity",
            "illegal",
            "spam",
            "impersonation",
            "other",
        ] {
            assert_eq!(ReportType::parse(token).as_str(), token);
        }
        assert_eq!(ReportType::parse("new-category").as_str(), "new-category",);
    }

    #[test]
    fn profile_report_round_trip() {
        let report = Report::profile(other_pubkey(), Some(ReportType::Impersonation))
            .content("not the king");
        let event = EventBuilder::report(&report)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = Report::from_event(&event).unwrap();
        assert_eq!(parsed, report);
    }

    #[test]
    fn event_report_round_trip() {
        let id = EventId::from_byte_array([0x07; 32]);
        let report = Report::event(id, other_pubkey(), Some(ReportType::Illegal))
            .content("contains illegal speech");
        let event = EventBuilder::report(&report)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = Report::from_event(&event).unwrap();
        assert_eq!(parsed, report);
    }

    #[test]
    fn blob_report_round_trip_with_server_hints() {
        let host = EventId::from_byte_array([0x09; 32]);
        let report = Report::blob("abc123def", host, Some(ReportType::Malware))
            .server(Url::parse("https://media.example.com/blob.bin").unwrap())
            .content("contains malware");
        let event = EventBuilder::report(&report)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = Report::from_event(&event).unwrap();
        assert_eq!(parsed, report);
    }

    #[test]
    fn wrong_kind_is_rejected() {
        let event = EventBuilder::text_note("nope")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            Report::from_event(&event),
            Err(ReportError::WrongKind(_)),
        ));
    }

    #[test]
    fn missing_target_is_rejected() {
        let event = EventBuilder::new(KIND_REPORT, "")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            Report::from_event(&event),
            Err(ReportError::MissingTarget),
        ));
    }

    #[test]
    fn blob_without_host_event_is_rejected() {
        let event = EventBuilder::new(KIND_REPORT, "")
            .tag(Tag::with(
                &TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::X)),
                ["abc", "malware"],
            ))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            Report::from_event(&event),
            Err(ReportError::MissingHostEvent),
        ));
    }

    #[test]
    fn unknown_report_type_decodes_as_custom() {
        let report = Report::profile(other_pubkey(), Some(ReportType::Custom("doxx".into())));
        let event = EventBuilder::report(&report)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = Report::from_event(&event).unwrap();
        assert_eq!(parsed, report);
    }

    #[test]
    fn extra_tags_are_preserved_on_round_trip() {
        let custom = Tag::with(&TagKind::Custom("note".to_owned()), ["context"]);
        let report = Report::profile(other_pubkey(), None);
        let mut builder = EventBuilder::report(&report);
        builder = builder.tag(custom.clone());
        let event = builder.sign_with_keys(&keys()).unwrap();
        let parsed = Report::from_event(&event).unwrap();
        assert_eq!(parsed.extra_tags, vec![custom]);
    }
}
