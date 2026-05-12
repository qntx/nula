//! [NIP-71] Video Events.
//!
//! Four kinds model the same content shape:
//!
//! | Kind   | Form         | Target use                           |
//! |--------|--------------|--------------------------------------|
//! | `21`   | regular      | long-form / landscape videos         |
//! | `22`   | regular      | short-form / portrait videos         |
//! | `34235`| addressable  | long-form videos with a `d` identifier |
//! | `34236`| addressable  | short-form videos with a `d` identifier |
//!
//! # Modelled fields
//!
//! - **Required**: `title`, plus at least one `imeta` tag carrying
//!   the variant's URL and extra metadata. Addressable variants also
//!   require a `d` identifier.
//! - **`imeta` tags** reuse [`MediaAttachment`](crate::nips::nip92::MediaAttachment)
//!   from NIP-92, which already rounds-trips every NIP-94 field and
//!   preserves unknown keys. NIP-71's two extra fields (`duration`,
//!   `bitrate`) ride inside that struct's
//!   [`extra_fields`](crate::nips::nip92::MediaAttachment::extra_fields)
//!   passthrough, so producers that set them round-trip cleanly.
//! - **Top-level**: `published_at`, `alt`, `content-warning` (spec
//!   cross-ref to NIP-36), `duration`, `t` hashtags, `p`
//!   participants (optional relay hint), `r` URLs, `text-track`
//!   entries, `segment` chapters, and `origin` imported-content
//!   metadata.
//!
//! Unknown tags survive a round-trip through [`Video::extra_tags`].
//!
//! [NIP-71]: https://github.com/nostr-protocol/nips/blob/master/71.md

use thiserror::Error;

use crate::event::{
    Alphabet, Coordinate, Event, EventBuilder, Kind, SingleLetterTag, Tag, TagKind, Tags,
};
use crate::key::{PublicKey, PublicKeyError};
use crate::nips::nip92::{IMETA_TAG, MediaAttachment, MediaAttachmentError};
use crate::types::{RelayUrl, RelayUrlError, Timestamp, TimestampError, Url, UrlError};

/// `kind: 21` — normal (long-form) video.
pub const KIND_VIDEO_NORMAL: Kind = Kind::VIDEO_NORMAL;

/// `kind: 22` — short-form video.
pub const KIND_VIDEO_SHORT: Kind = Kind::VIDEO_SHORT;

/// `kind: 34235` — addressable normal video.
pub const KIND_VIDEO_NORMAL_ADDRESSABLE: Kind = Kind::VIDEO_NORMAL_ADDRESSABLE;

/// `kind: 34236` — addressable short video.
pub const KIND_VIDEO_SHORT_ADDRESSABLE: Kind = Kind::VIDEO_SHORT_ADDRESSABLE;

const TITLE_TAG: &str = "title";
const PUBLISHED_AT_TAG: &str = "published_at";
const ALT_TAG: &str = "alt";
const CONTENT_WARNING_TAG: &str = "content-warning";
const DURATION_TAG: &str = "duration";
const TEXT_TRACK_TAG: &str = "text-track";
const SEGMENT_TAG: &str = "segment";
const ORIGIN_TAG: &str = "origin";

/// Semantic identifier for one of the four NIP-71 kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VideoKind {
    /// `kind: 21` — long-form regular event.
    Normal,
    /// `kind: 22` — short-form regular event.
    Short,
    /// `kind: 34235` — long-form addressable event.
    NormalAddressable,
    /// `kind: 34236` — short-form addressable event.
    ShortAddressable,
}

impl VideoKind {
    /// Wire kind for this variant.
    #[must_use]
    pub const fn to_kind(self) -> Kind {
        match self {
            Self::Normal => KIND_VIDEO_NORMAL,
            Self::Short => KIND_VIDEO_SHORT,
            Self::NormalAddressable => KIND_VIDEO_NORMAL_ADDRESSABLE,
            Self::ShortAddressable => KIND_VIDEO_SHORT_ADDRESSABLE,
        }
    }

    /// Map a wire kind back to the semantic identifier.
    #[must_use]
    pub const fn from_kind(kind: Kind) -> Option<Self> {
        match kind.as_u16() {
            21 => Some(Self::Normal),
            22 => Some(Self::Short),
            34_235 => Some(Self::NormalAddressable),
            34_236 => Some(Self::ShortAddressable),
            _ => None,
        }
    }

    /// `true` when the variant is addressable and therefore
    /// requires a `d` identifier.
    #[must_use]
    pub const fn is_addressable(self) -> bool {
        matches!(self, Self::NormalAddressable | Self::ShortAddressable)
    }
}

/// A `text-track` tag (captions / subtitles / chapters / metadata).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextTrack {
    /// Spec column 1: value (URL, NIP-19 entity, or opaque
    /// identifier). Left as `String` because the spec's example
    /// uses "`<encoded kind 6000 event>`".
    pub value: String,
    /// Optional recommended relay URL.
    pub relay_hint: Option<RelayUrl>,
}

/// A `segment` tag chapter entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// Start timestamp (`HH:MM:SS.sss`).
    pub start: String,
    /// End timestamp (`HH:MM:SS.sss`).
    pub end: String,
    /// Chapter title.
    pub title: String,
    /// Thumbnail URL.
    pub thumbnail: Option<Url>,
}

/// A `p` participant tag on a video event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VideoParticipant {
    /// Participant pubkey.
    pub pubkey: PublicKey,
    /// Optional recommended relay URL.
    pub relay_hint: Option<RelayUrl>,
}

/// An `origin` tag for imported content (spec §"Optional tags for
/// imported content").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VideoOrigin {
    /// Platform identifier (`youtube`, `tiktok`, custom).
    pub platform: String,
    /// Platform-external ID.
    pub external_id: String,
    /// Optional original URL.
    pub original_url: Option<Url>,
    /// Optional extra metadata (free-form).
    pub metadata: Option<String>,
}

/// Typed bundle for a NIP-71 video event (any of the four kinds).
#[derive(Debug, Clone, PartialEq)]
pub struct Video {
    /// Semantic kind.
    pub kind: VideoKind,
    /// `d` identifier (required for addressable variants).
    pub identifier: Option<String>,
    /// `.content` — summary / description.
    pub content: String,
    /// `title` tag (required).
    pub title: String,
    /// Media variants (at least one `imeta` tag).
    pub media: Vec<MediaAttachment>,
    /// `published_at` Unix timestamp.
    pub published_at: Option<Timestamp>,
    /// `alt` accessibility description.
    pub alt: Option<String>,
    /// `content-warning` reason.
    pub content_warning: Option<String>,
    /// Top-level `duration` in seconds (used by the spec's
    /// addressable example; the same value MAY also ride inside
    /// `imeta`).
    pub duration_seconds: Option<f64>,
    /// `text-track` rows.
    pub text_tracks: Vec<TextTrack>,
    /// `segment` chapters.
    pub segments: Vec<Segment>,
    /// `t` hashtags (lower-cased).
    pub hashtags: Vec<String>,
    /// `p` participants.
    pub participants: Vec<VideoParticipant>,
    /// `r` URL references.
    pub references: Vec<Url>,
    /// `origin` import metadata.
    pub origin: Option<VideoOrigin>,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

impl Video {
    /// Construct a regular (non-addressable) video.
    #[must_use]
    pub fn new(kind: VideoKind, title: impl Into<String>, media: MediaAttachment) -> Self {
        Self {
            kind,
            identifier: if kind.is_addressable() {
                Some(String::new())
            } else {
                None
            },
            content: String::new(),
            title: title.into(),
            media: vec![media],
            published_at: None,
            alt: None,
            content_warning: None,
            duration_seconds: None,
            text_tracks: Vec::new(),
            segments: Vec::new(),
            hashtags: Vec::new(),
            participants: Vec::new(),
            references: Vec::new(),
            origin: None,
            extra_tags: Vec::new(),
        }
    }

    /// Set the `d` identifier (required for addressable kinds).
    #[must_use]
    pub fn identifier(mut self, identifier: impl Into<String>) -> Self {
        self.identifier = Some(identifier.into());
        self
    }

    /// Set the `.content` body.
    #[must_use]
    pub fn content(mut self, content: impl Into<String>) -> Self {
        self.content = content.into();
        self
    }

    /// Append another media variant.
    #[must_use]
    pub fn media(mut self, media: MediaAttachment) -> Self {
        self.media.push(media);
        self
    }

    /// Set [`Self::published_at`].
    #[must_use]
    pub const fn published_at(mut self, ts: Timestamp) -> Self {
        self.published_at = Some(ts);
        self
    }

    /// Set [`Self::alt`].
    #[must_use]
    pub fn alt(mut self, alt: impl Into<String>) -> Self {
        self.alt = Some(alt.into());
        self
    }

    /// Set [`Self::content_warning`].
    #[must_use]
    pub fn content_warning(mut self, warning: impl Into<String>) -> Self {
        self.content_warning = Some(warning.into());
        self
    }

    /// Set [`Self::duration_seconds`].
    #[must_use]
    pub const fn duration_seconds(mut self, secs: f64) -> Self {
        self.duration_seconds = Some(secs);
        self
    }

    /// Append a text track.
    #[must_use]
    pub fn text_track(mut self, track: TextTrack) -> Self {
        self.text_tracks.push(track);
        self
    }

    /// Append a segment.
    #[must_use]
    pub fn segment(mut self, seg: Segment) -> Self {
        self.segments.push(seg);
        self
    }

    /// Append a hashtag (lower-cased).
    #[must_use]
    pub fn hashtag(mut self, tag: impl AsRef<str>) -> Self {
        self.hashtags.push(tag.as_ref().to_lowercase());
        self
    }

    /// Append a participant.
    #[must_use]
    pub fn participant(mut self, p: VideoParticipant) -> Self {
        self.participants.push(p);
        self
    }

    /// Append a reference URL.
    #[must_use]
    pub fn reference(mut self, url: Url) -> Self {
        self.references.push(url);
        self
    }

    /// Set the origin metadata.
    #[must_use]
    pub fn origin(mut self, origin: VideoOrigin) -> Self {
        self.origin = Some(origin);
        self
    }

    /// Build the addressable coordinate. Returns `None` for
    /// non-addressable kinds.
    #[must_use]
    pub fn coordinate(&self, author: PublicKey) -> Option<Coordinate> {
        if !self.kind.is_addressable() {
            return None;
        }
        let identifier = self.identifier.clone().unwrap_or_default();
        Some(Coordinate::new(self.kind.to_kind(), author, identifier))
    }

    /// Parse an NIP-71 event into a typed bundle.
    ///
    /// # Errors
    ///
    /// - [`VideoError::WrongKind`] for any non-NIP-71 kind.
    /// - [`VideoError::MissingIdentifier`] on addressable variants
    ///   missing a `d` tag.
    /// - [`VideoError::MissingTitle`] when no `title` tag is present.
    /// - [`VideoError::MissingMedia`] when no `imeta` tags are
    ///   present (the spec says the primary source of video info is
    ///   `imeta`).
    /// - Field-specific errors for malformed columns.
    pub fn from_event(event: &Event) -> Result<Self, VideoError> {
        let kind = VideoKind::from_kind(event.kind).ok_or(VideoError::WrongKind(event.kind))?;
        let identifier = d_value(&event.tags).map(str::to_owned);
        if kind.is_addressable() && identifier.is_none() {
            return Err(VideoError::MissingIdentifier);
        }
        let mut video = Self {
            kind,
            identifier,
            content: event.content.clone(),
            title: String::new(),
            media: Vec::new(),
            published_at: None,
            alt: None,
            content_warning: None,
            duration_seconds: None,
            text_tracks: Vec::new(),
            segments: Vec::new(),
            hashtags: Vec::new(),
            participants: Vec::new(),
            references: Vec::new(),
            origin: None,
            extra_tags: Vec::new(),
        };
        for tag in &event.tags {
            absorb_video_tag(tag, &mut video)?;
        }
        if video.title.is_empty() {
            return Err(VideoError::MissingTitle);
        }
        if video.media.is_empty() {
            return Err(VideoError::MissingMedia);
        }
        Ok(video)
    }
}

fn absorb_video_tag(tag: &Tag, video: &mut Video) -> Result<(), VideoError> {
    match tag.kind() {
        TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::D => {}
        TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::T => {
            if let Some(raw) = tag.get(1) {
                video.hashtags.push(raw.to_ascii_lowercase());
            }
        }
        TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::R => {
            if let Some(raw) = tag.get(1) {
                video.references.push(Url::parse(raw)?);
            }
        }
        TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::P => {
            video.participants.push(parse_participant(tag)?);
        }
        _ if tag.name() == TITLE_TAG => {
            video.title = tag.get(1).map(str::to_owned).unwrap_or_default();
        }
        _ if tag.name() == PUBLISHED_AT_TAG => {
            if let Some(raw) = tag.get(1) {
                video.published_at = Some(raw.parse::<Timestamp>()?);
            }
        }
        _ if tag.name() == ALT_TAG => video.alt = tag.get(1).map(str::to_owned),
        _ if tag.name() == CONTENT_WARNING_TAG => {
            video.content_warning = tag.get(1).map(str::to_owned);
        }
        _ if tag.name() == DURATION_TAG => {
            if let Some(raw) = tag.get(1) {
                video.duration_seconds = Some(
                    raw.parse::<f64>()
                        .map_err(|_| VideoError::InvalidDuration(raw.to_owned()))?,
                );
            }
        }
        _ if tag.name() == TEXT_TRACK_TAG => video.text_tracks.push(parse_text_track(tag)?),
        _ if tag.name() == SEGMENT_TAG => video.segments.push(parse_segment(tag)?),
        _ if tag.name() == ORIGIN_TAG => video.origin = Some(parse_origin(tag)?),
        _ if tag.name() == IMETA_TAG => {
            video.media.push(MediaAttachment::from_tag(tag)?);
        }
        _ => video.extra_tags.push(tag.clone()),
    }
    Ok(())
}

fn parse_participant(tag: &Tag) -> Result<VideoParticipant, VideoError> {
    let pk_hex = tag.get(1).ok_or(VideoError::MalformedParticipant)?;
    let pubkey = PublicKey::parse(pk_hex)?;
    let relay_hint = match tag.get(2) {
        Some(s) if !s.is_empty() => Some(RelayUrl::parse(s)?),
        _ => None,
    };
    Ok(VideoParticipant { pubkey, relay_hint })
}

fn parse_text_track(tag: &Tag) -> Result<TextTrack, VideoError> {
    let value = tag.get(1).ok_or(VideoError::MalformedTextTrack)?.to_owned();
    let relay_hint = match tag.get(2) {
        Some(s) if !s.is_empty() => Some(RelayUrl::parse(s)?),
        _ => None,
    };
    Ok(TextTrack { value, relay_hint })
}

fn parse_segment(tag: &Tag) -> Result<Segment, VideoError> {
    let start = tag.get(1).ok_or(VideoError::MalformedSegment)?.to_owned();
    let end = tag.get(2).ok_or(VideoError::MalformedSegment)?.to_owned();
    let title = tag.get(3).ok_or(VideoError::MalformedSegment)?.to_owned();
    let thumbnail = match tag.get(4) {
        Some(s) if !s.is_empty() => Some(Url::parse(s)?),
        _ => None,
    };
    Ok(Segment {
        start,
        end,
        title,
        thumbnail,
    })
}

fn parse_origin(tag: &Tag) -> Result<VideoOrigin, VideoError> {
    let platform = tag.get(1).ok_or(VideoError::MalformedOrigin)?.to_owned();
    let external_id = tag.get(2).ok_or(VideoError::MalformedOrigin)?.to_owned();
    let original_url = match tag.get(3) {
        Some(s) if !s.is_empty() => Some(Url::parse(s)?),
        _ => None,
    };
    let metadata = tag.get(4).filter(|s| !s.is_empty()).map(str::to_owned);
    Ok(VideoOrigin {
        platform,
        external_id,
        original_url,
        metadata,
    })
}

fn d_value(tags: &Tags) -> Option<&str> {
    let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::D));
    tags.find_first(&head).and_then(|tag| tag.get(1))
}

/// Errors raised by NIP-71 parsers.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VideoError {
    /// Event kind is not one of the four NIP-71 kinds.
    #[error("unexpected kind for NIP-71 event: {}", .0.as_u16())]
    WrongKind(Kind),
    /// Addressable event is missing its `d` tag.
    #[error("addressable NIP-71 video missing `d` identifier")]
    MissingIdentifier,
    /// Required `title` tag is absent.
    #[error("NIP-71 video missing `title` tag")]
    MissingTitle,
    /// Required `imeta` tag(s) are absent.
    #[error("NIP-71 video missing `imeta` tag")]
    MissingMedia,
    /// `p` tag missing pubkey column.
    #[error("`p` participant tag missing pubkey")]
    MalformedParticipant,
    /// `text-track` tag missing value column.
    #[error("`text-track` tag missing value")]
    MalformedTextTrack,
    /// `segment` tag missing one of the required columns.
    #[error("`segment` tag missing required columns")]
    MalformedSegment,
    /// `origin` tag missing one of the required columns.
    #[error("`origin` tag missing required columns")]
    MalformedOrigin,
    /// `duration` tag value could not be parsed as `f64`.
    #[error("invalid `duration` value: `{0}`")]
    InvalidDuration(String),
    /// Wrapped `imeta` parser error.
    #[error(transparent)]
    Media(#[from] MediaAttachmentError),
    /// Wrapped pubkey parser error.
    #[error(transparent)]
    InvalidPublicKey(#[from] PublicKeyError),
    /// Wrapped URL parser error.
    #[error(transparent)]
    InvalidUrl(#[from] UrlError),
    /// Wrapped relay-URL parser error.
    #[error(transparent)]
    InvalidRelayUrl(#[from] RelayUrlError),
    /// Wrapped timestamp parser error.
    #[error(transparent)]
    InvalidTimestamp(#[from] TimestampError),
}

impl EventBuilder {
    /// Author a NIP-71 video event.
    ///
    /// # Errors
    ///
    /// Propagates [`MediaAttachmentError`] when any variant in
    /// [`Video::media`] violates NIP-92 invariants (missing URL or
    /// no other field). Also returns
    /// [`VideoError::MissingIdentifier`] when the variant is
    /// addressable but [`Video::identifier`] is `None`.
    pub fn video(video: &Video) -> Result<Self, VideoError> {
        if video.kind.is_addressable() && video.identifier.is_none() {
            return Err(VideoError::MissingIdentifier);
        }
        let mut builder = Self::new(video.kind.to_kind(), video.content.clone());
        if let Some(identifier) = &video.identifier {
            builder = builder.tag(Tag::d(identifier));
        }
        builder = builder.tag(Tag::with(
            &TagKind::from_wire(TITLE_TAG),
            [video.title.clone()],
        ));
        if let Some(ts) = video.published_at {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(PUBLISHED_AT_TAG),
                [ts.as_secs().to_string()],
            ));
        }
        if let Some(alt) = &video.alt {
            builder = builder.tag(Tag::with(&TagKind::from_wire(ALT_TAG), [alt.clone()]));
        }
        if let Some(cw) = &video.content_warning {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(CONTENT_WARNING_TAG),
                [cw.clone()],
            ));
        }
        if let Some(dur) = video.duration_seconds {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(DURATION_TAG),
                [dur.to_string()],
            ));
        }
        for media in &video.media {
            builder = builder.tag(media.to_tag()?);
        }
        for track in &video.text_tracks {
            builder = builder.tag(text_track_tag(track));
        }
        for seg in &video.segments {
            builder = builder.tag(segment_tag(seg));
        }
        for hashtag in &video.hashtags {
            builder = builder.tag(Tag::t(hashtag));
        }
        for participant in &video.participants {
            builder = builder.tag(participant_tag(participant));
        }
        for url in &video.references {
            let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::R));
            builder = builder.tag(Tag::with(&head, [url.as_str().to_owned()]));
        }
        if let Some(origin) = &video.origin {
            builder = builder.tag(origin_tag(origin));
        }
        for tag in &video.extra_tags {
            builder = builder.tag(tag.clone());
        }
        Ok(builder)
    }
}

fn text_track_tag(track: &TextTrack) -> Tag {
    let head = TagKind::from_wire(TEXT_TRACK_TAG);
    track.relay_hint.as_ref().map_or_else(
        || Tag::with(&head, [track.value.clone()]),
        |relay| Tag::with(&head, [track.value.clone(), relay.as_str().to_owned()]),
    )
}

fn segment_tag(seg: &Segment) -> Tag {
    let head = TagKind::from_wire(SEGMENT_TAG);
    seg.thumbnail.as_ref().map_or_else(
        || {
            Tag::with(
                &head,
                [seg.start.clone(), seg.end.clone(), seg.title.clone()],
            )
        },
        |url| {
            Tag::with(
                &head,
                [
                    seg.start.clone(),
                    seg.end.clone(),
                    seg.title.clone(),
                    url.as_str().to_owned(),
                ],
            )
        },
    )
}

fn participant_tag(p: &VideoParticipant) -> Tag {
    let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::P));
    p.relay_hint.as_ref().map_or_else(
        || Tag::with(&head, [p.pubkey.to_hex()]),
        |relay| Tag::with(&head, [p.pubkey.to_hex(), relay.as_str().to_owned()]),
    )
}

fn origin_tag(origin: &VideoOrigin) -> Tag {
    let head = TagKind::from_wire(ORIGIN_TAG);
    let mut cols: Vec<String> = vec![origin.platform.clone(), origin.external_id.clone()];
    if let Some(url) = &origin.original_url {
        cols.push(url.as_str().to_owned());
    } else if origin.metadata.is_some() {
        cols.push(String::new());
    }
    if let Some(meta) = &origin.metadata {
        cols.push(meta.clone());
    }
    Tag::with(&head, cols)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;

    fn keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    fn sample_media() -> MediaAttachment {
        MediaAttachment::new(Url::parse("https://example.com/v.mp4").unwrap())
            .mime_type("video/mp4")
            .dim("1920x1080".parse().unwrap())
    }

    #[test]
    fn video_kind_round_trip() {
        for k in [
            VideoKind::Normal,
            VideoKind::Short,
            VideoKind::NormalAddressable,
            VideoKind::ShortAddressable,
        ] {
            assert_eq!(VideoKind::from_kind(k.to_kind()), Some(k));
        }
    }

    #[test]
    fn regular_video_round_trip() {
        let video = Video::new(VideoKind::Normal, "Demo Video", sample_media())
            .content("summary")
            .alt("alt text")
            .hashtag("ANIMATION")
            .reference(Url::parse("https://blog.example.com/ep1").unwrap())
            .participant(VideoParticipant {
                pubkey: *keys().public_key(),
                relay_hint: Some(RelayUrl::parse("wss://relay.example/").unwrap()),
            })
            .published_at(Timestamp::from_secs(1_700_000_000));
        let event = EventBuilder::video(&video)
            .unwrap()
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = Video::from_event(&event).unwrap();
        assert_eq!(parsed.hashtags, vec!["animation".to_owned()]);
        assert_eq!(parsed.title, "Demo Video");
        assert_eq!(parsed.media.len(), 1);
        assert_eq!(parsed.kind, VideoKind::Normal);
    }

    #[test]
    fn addressable_video_round_trip() {
        let video = Video::new(VideoKind::NormalAddressable, "Addr Video", sample_media())
            .identifier("ep-1")
            .duration_seconds(120.5)
            .content_warning("loud");
        let event = EventBuilder::video(&video)
            .unwrap()
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = Video::from_event(&event).unwrap();
        assert_eq!(parsed.identifier.as_deref(), Some("ep-1"));
        assert!((parsed.duration_seconds.unwrap() - 120.5).abs() < 1e-6);
        assert_eq!(parsed.content_warning.as_deref(), Some("loud"));
    }

    #[test]
    fn video_missing_media_is_rejected() {
        let event = EventBuilder::new(KIND_VIDEO_NORMAL, "")
            .tag(Tag::with(&TagKind::from_wire(TITLE_TAG), ["no media"]))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            Video::from_event(&event),
            Err(VideoError::MissingMedia)
        ));
    }

    #[test]
    fn addressable_missing_identifier_is_rejected() {
        let event = EventBuilder::new(KIND_VIDEO_NORMAL_ADDRESSABLE, "")
            .tag(Tag::with(&TagKind::from_wire(TITLE_TAG), ["no id"]))
            .tag(sample_media().to_tag().unwrap())
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            Video::from_event(&event),
            Err(VideoError::MissingIdentifier)
        ));
    }

    #[test]
    fn segment_round_trip() {
        let seg = Segment {
            start: "00:00:00.000".into(),
            end: "00:00:10.000".into(),
            title: "Intro".into(),
            thumbnail: Some(Url::parse("https://example.com/t.jpg").unwrap()),
        };
        let video = Video::new(VideoKind::Normal, "seg", sample_media()).segment(seg.clone());
        let event = EventBuilder::video(&video)
            .unwrap()
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = Video::from_event(&event).unwrap();
        assert_eq!(parsed.segments, vec![seg]);
    }

    #[test]
    fn origin_round_trip() {
        let origin = VideoOrigin {
            platform: "youtube".into(),
            external_id: "abc123".into(),
            original_url: Some(Url::parse("https://youtu.be/abc123").unwrap()),
            metadata: Some(r#"{"duration":"120"}"#.into()),
        };
        let video = Video::new(VideoKind::NormalAddressable, "origin", sample_media())
            .identifier("ep-2")
            .origin(origin.clone());
        let event = EventBuilder::video(&video)
            .unwrap()
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = Video::from_event(&event).unwrap();
        assert_eq!(parsed.origin, Some(origin));
    }

    #[test]
    fn wrong_kind_is_rejected() {
        let event = EventBuilder::text_note("nope")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            Video::from_event(&event),
            Err(VideoError::WrongKind(_))
        ));
    }
}
