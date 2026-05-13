//! [NIP-94] File Metadata.
//!
//! `kind: 1063` describes a file: where to fetch it, what type it is,
//! how big it is, what it looks like, and (most importantly) the
//! SHA-256 over the bytes so consumers can verify integrity. The
//! `.content` is the human-readable caption; every interesting fact
//! is a tag.
//!
//! # Spec coverage
//!
//! Upstream `rust-nostr` implements only the four fields it cares
//! about (`url`, `m`, `x`, `dim`, `size`, `magnet`, `blurhash`) and
//! ignores everything else NIP-94 mentions. We model the **complete**
//! set so a NIP-94 event round-trips byte-for-byte:
//!
//! | Tag         | Field                                 | Type            |
//! |-------------|---------------------------------------|-----------------|
//! | `url`       | [`FileMetadata::url`]                 | [`Url`]         |
//! | `m`         | [`FileMetadata::mime_type`]           | `String`        |
//! | `x`         | [`FileMetadata::hash`]                | `[u8; 32]`      |
//! | `ox`        | [`FileMetadata::original_hash`]       | `[u8; 32]`      |
//! | `size`      | [`FileMetadata::size`]                | `u64`           |
//! | `dim`       | [`FileMetadata::dim`]                 | [`ImageDimensions`] |
//! | `magnet`    | [`FileMetadata::magnet`]              | `String`        |
//! | `i`         | [`FileMetadata::torrent_infohash`]    | `String`        |
//! | `blurhash`  | [`FileMetadata::blurhash`]            | `String`        |
//! | `thumb`     | [`FileMetadata::thumb`]               | [`FileVariant`] |
//! | `image`     | [`FileMetadata::preview_image`]       | [`FileVariant`] |
//! | `summary`   | [`FileMetadata::summary`]             | `String`        |
//! | `alt`       | [`FileMetadata::alt`]                 | `String`        |
//! | `fallback`  | [`FileMetadata::fallback_urls`]       | `Vec<Url>`      |
//! | `service`   | [`FileMetadata::service`]             | `String`        |
//!
//! # Authoring vs reading
//!
//! - Author with [`EventBuilder::file_metadata`]; the builder takes
//!   a [`FileMetadata`] bundle plus a caption string and emits one
//!   event with every populated field as a tag.
//! - Read with [`FileMetadata::from_event`], which refuses non-1063
//!   kinds and reports specific errors for the three required tags
//!   (`url` / `m` / `x`). Optional tags that are present but
//!   malformed (bad hex, bad URL, bad dimensions) flow through as
//!   typed errors rather than being silently dropped — this is a
//!   deliberate departure from the "best effort" upstream policy.
//!
//! # Hash representation
//!
//! Hashes are stored as raw `[u8; 32]` so callers can compare them
//! cheaply against [`crate::EventId`] / `Sha256` digests without an
//! intermediate hex parse. The wire format remains lowercase 64-char
//! hex per NIP-94 §"x".
//!
//! [NIP-94]: https://github.com/nostr-protocol/nips/blob/master/94.md

use thiserror::Error;

use crate::event::{Alphabet, Event, EventBuilder, Kind, SingleLetterTag, Tag, TagKind, Tags};
use crate::types::{ImageDimensions, ImageError, Url, UrlError};
use crate::util::hex::{self, HexError};

/// `kind: 1063` — file metadata.
pub const KIND_FILE_METADATA: Kind = Kind::FILE_METADATA;

/// `url` tag wire head.
pub const URL_TAG: &str = "url";
/// `ox` tag wire head (original SHA-256).
pub const OX_TAG: &str = "ox";
/// `size` tag wire head.
pub const SIZE_TAG: &str = "size";
/// `dim` tag wire head.
pub const DIM_TAG: &str = "dim";
/// `magnet` tag wire head.
pub const MAGNET_TAG: &str = "magnet";
/// `blurhash` tag wire head.
pub const BLURHASH_TAG: &str = "blurhash";
/// `thumb` tag wire head.
pub const THUMB_TAG: &str = "thumb";
/// `image` tag wire head (preview, distinct from `m` / `x`).
pub const IMAGE_TAG: &str = "image";
/// `summary` tag wire head.
pub const SUMMARY_TAG: &str = "summary";
/// `alt` tag wire head.
pub const ALT_TAG: &str = "alt";
/// `fallback` tag wire head.
pub const FALLBACK_TAG: &str = "fallback";
/// `service` tag wire head.
pub const SERVICE_TAG: &str = "service";

/// One image / thumbnail variant. Both `thumb` and `image` tags share
/// this shape: a URL, optionally followed by a SHA-256 hash that
/// pins the variant's bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FileVariant {
    /// Variant URL.
    pub url: Url,
    /// Optional SHA-256 over the variant's bytes (raw bytes, NOT
    /// hex). `None` matches the spec's two-column form
    /// `["thumb", "<url>"]`.
    pub hash: Option<[u8; 32]>,
}

impl FileVariant {
    /// Construct a variant with no integrity hash.
    #[must_use]
    pub const fn new(url: Url) -> Self {
        Self { url, hash: None }
    }

    /// Attach a SHA-256 hash.
    #[must_use]
    pub const fn with_hash(mut self, hash: [u8; 32]) -> Self {
        self.hash = Some(hash);
        self
    }
}

/// Typed bundle of every NIP-94 field.
///
/// Build incrementally with [`Self::new`] + the chainable setters,
/// or hydrate from a wire event with [`Self::from_event`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileMetadata {
    /// Download URL (`url` tag — required).
    pub url: Option<Url>,
    /// MIME type (`m` tag — required).
    pub mime_type: Option<String>,
    /// SHA-256 of the served bytes (`x` tag — required).
    pub hash: Option<[u8; 32]>,
    /// SHA-256 of the original bytes before any server-side
    /// transformation (`ox` tag).
    pub original_hash: Option<[u8; 32]>,
    /// File size in bytes (`size` tag).
    pub size: Option<u64>,
    /// Pixel dimensions (`dim` tag).
    pub dim: Option<ImageDimensions>,
    /// Magnet URI (`magnet` tag).
    pub magnet: Option<String>,
    /// Torrent infohash (`i` tag).
    pub torrent_infohash: Option<String>,
    /// Blurhash placeholder (`blurhash` tag).
    pub blurhash: Option<String>,
    /// Thumbnail variant (`thumb` tag).
    pub thumb: Option<FileVariant>,
    /// Preview image variant (`image` tag).
    pub preview_image: Option<FileVariant>,
    /// Text excerpt (`summary` tag).
    pub summary: Option<String>,
    /// Accessibility description (`alt` tag).
    pub alt: Option<String>,
    /// Zero or more fallback download URLs (`fallback` tags).
    pub fallback_urls: Vec<Url>,
    /// Serving-service identifier such as `nip96` (`service` tag).
    pub service: Option<String>,
}

impl FileMetadata {
    /// Construct with the three required fields.
    #[must_use]
    pub fn new(url: Url, mime_type: impl Into<String>, hash: [u8; 32]) -> Self {
        Self {
            url: Some(url),
            mime_type: Some(mime_type.into()),
            hash: Some(hash),
            ..Self::default()
        }
    }

    /// Set [`Self::original_hash`].
    #[must_use]
    pub const fn original_hash(mut self, hash: [u8; 32]) -> Self {
        self.original_hash = Some(hash);
        self
    }

    /// Set [`Self::size`].
    #[must_use]
    pub const fn size(mut self, size: u64) -> Self {
        self.size = Some(size);
        self
    }

    /// Set [`Self::dim`].
    #[must_use]
    pub const fn dim(mut self, dim: ImageDimensions) -> Self {
        self.dim = Some(dim);
        self
    }

    /// Set [`Self::magnet`].
    #[must_use]
    pub fn magnet(mut self, magnet: impl Into<String>) -> Self {
        self.magnet = Some(magnet.into());
        self
    }

    /// Set [`Self::torrent_infohash`].
    #[must_use]
    pub fn torrent_infohash(mut self, infohash: impl Into<String>) -> Self {
        self.torrent_infohash = Some(infohash.into());
        self
    }

    /// Set [`Self::blurhash`].
    #[must_use]
    pub fn blurhash(mut self, blurhash: impl Into<String>) -> Self {
        self.blurhash = Some(blurhash.into());
        self
    }

    /// Set [`Self::thumb`].
    #[must_use]
    pub fn thumb(mut self, thumb: FileVariant) -> Self {
        self.thumb = Some(thumb);
        self
    }

    /// Set [`Self::preview_image`].
    #[must_use]
    pub fn preview_image(mut self, image: FileVariant) -> Self {
        self.preview_image = Some(image);
        self
    }

    /// Set [`Self::summary`].
    #[must_use]
    pub fn summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = Some(summary.into());
        self
    }

    /// Set [`Self::alt`].
    #[must_use]
    pub fn alt(mut self, alt: impl Into<String>) -> Self {
        self.alt = Some(alt.into());
        self
    }

    /// Append one fallback URL.
    #[must_use]
    pub fn fallback(mut self, url: Url) -> Self {
        self.fallback_urls.push(url);
        self
    }

    /// Set [`Self::service`].
    #[must_use]
    pub fn service(mut self, service: impl Into<String>) -> Self {
        self.service = Some(service.into());
        self
    }

    /// Parse a `kind: 1063` event back into a typed bundle.
    ///
    /// # Errors
    ///
    /// - [`FileMetadataError::WrongKind`] for any other kind.
    /// - [`FileMetadataError::MissingUrl`] / `MissingMimeType` /
    ///   `MissingHash` when the corresponding required tag is absent.
    /// - [`FileMetadataError::InvalidUrl`] / `InvalidHash` /
    ///   `InvalidSize` / `InvalidDim` when the value is present but
    ///   malformed.
    pub fn from_event(event: &Event) -> Result<Self, FileMetadataError> {
        if event.kind != KIND_FILE_METADATA {
            return Err(FileMetadataError::WrongKind(event.kind));
        }
        Self::from_tags(&event.tags)
    }

    /// Parse a tag list (without requiring a wrapping event). Useful
    /// when callers already know the event kind matches and only
    /// want the metadata reconstruction.
    ///
    /// # Errors
    ///
    /// See [`Self::from_event`].
    pub fn from_tags(tags: &Tags) -> Result<Self, FileMetadataError> {
        let url_str = custom_value(tags, URL_TAG).ok_or(FileMetadataError::MissingUrl)?;
        let url = Url::parse(url_str).map_err(FileMetadataError::InvalidUrl)?;

        let mime_type = single_value(tags, Alphabet::M)
            .ok_or(FileMetadataError::MissingMimeType)?
            .to_owned();
        let hash_hex = single_value(tags, Alphabet::X).ok_or(FileMetadataError::MissingHash)?;
        let hash = parse_sha256(hash_hex)?;

        let mut metadata = Self::new(url, mime_type, hash);

        if let Some(raw) = custom_value(tags, OX_TAG) {
            metadata.original_hash = Some(parse_sha256(raw)?);
        }
        if let Some(raw) = custom_value(tags, SIZE_TAG) {
            metadata.size = Some(
                raw.parse::<u64>()
                    .map_err(|_| FileMetadataError::InvalidSize(raw.to_owned()))?,
            );
        }
        if let Some(raw) = custom_value(tags, DIM_TAG) {
            metadata.dim = Some(
                raw.parse::<ImageDimensions>()
                    .map_err(FileMetadataError::InvalidDim)?,
            );
        }
        if let Some(raw) = custom_value(tags, MAGNET_TAG) {
            metadata.magnet = Some(raw.to_owned());
        }
        if let Some(raw) = single_value(tags, Alphabet::I) {
            metadata.torrent_infohash = Some(raw.to_owned());
        }
        if let Some(raw) = custom_value(tags, BLURHASH_TAG) {
            metadata.blurhash = Some(raw.to_owned());
        }
        metadata.thumb = parse_variant(tags, THUMB_TAG)?;
        metadata.preview_image = parse_variant(tags, IMAGE_TAG)?;
        if let Some(raw) = custom_value(tags, SUMMARY_TAG) {
            metadata.summary = Some(raw.to_owned());
        }
        if let Some(raw) = custom_value(tags, ALT_TAG) {
            metadata.alt = Some(raw.to_owned());
        }
        for tag in tags.find_all(&TagKind::Custom(FALLBACK_TAG.to_owned())) {
            if let Some(raw) = tag.get(1) {
                let parsed = Url::parse(raw).map_err(FileMetadataError::InvalidUrl)?;
                metadata.fallback_urls.push(parsed);
            }
        }
        if let Some(raw) = custom_value(tags, SERVICE_TAG) {
            metadata.service = Some(raw.to_owned());
        }
        Ok(metadata)
    }

    /// Materialise the bundle into a `Vec<Tag>` ready for use with
    /// [`EventBuilder::tag`] / [`EventBuilder::tags`]. Required
    /// fields must be set; missing required fields produce an
    /// `Err(FileMetadataError::Missing*)` so authoring stays
    /// symmetric with reading.
    ///
    /// # Errors
    ///
    /// Returns the corresponding `Missing*` error when a required
    /// field is unset.
    pub fn to_tags(&self) -> Result<Vec<Tag>, FileMetadataError> {
        let url = self.url.as_ref().ok_or(FileMetadataError::MissingUrl)?;
        let mime = self
            .mime_type
            .as_deref()
            .ok_or(FileMetadataError::MissingMimeType)?;
        let hash = self.hash.ok_or(FileMetadataError::MissingHash)?;

        let mut tags: Vec<Tag> = Vec::with_capacity(3 + self.fallback_urls.len());
        tags.push(custom(URL_TAG, [url.as_str().to_owned()]));
        tags.push(letter(Alphabet::M, [mime.to_owned()]));
        tags.push(letter(Alphabet::X, [hex::encode(hash)]));

        if let Some(ox) = self.original_hash {
            tags.push(custom(OX_TAG, [hex::encode(ox)]));
        }
        if let Some(size) = self.size {
            tags.push(custom(SIZE_TAG, [size.to_string()]));
        }
        if let Some(dim) = self.dim {
            tags.push(custom(DIM_TAG, [dim.to_string()]));
        }
        if let Some(magnet) = &self.magnet {
            tags.push(custom(MAGNET_TAG, [magnet.clone()]));
        }
        if let Some(infohash) = &self.torrent_infohash {
            tags.push(letter(Alphabet::I, [infohash.clone()]));
        }
        if let Some(blurhash) = &self.blurhash {
            tags.push(custom(BLURHASH_TAG, [blurhash.clone()]));
        }
        if let Some(thumb) = &self.thumb {
            tags.push(variant_tag(THUMB_TAG, thumb));
        }
        if let Some(preview) = &self.preview_image {
            tags.push(variant_tag(IMAGE_TAG, preview));
        }
        if let Some(summary) = &self.summary {
            tags.push(custom(SUMMARY_TAG, [summary.clone()]));
        }
        if let Some(alt) = &self.alt {
            tags.push(custom(ALT_TAG, [alt.clone()]));
        }
        for fallback in &self.fallback_urls {
            tags.push(custom(FALLBACK_TAG, [fallback.as_str().to_owned()]));
        }
        if let Some(service) = &self.service {
            tags.push(custom(SERVICE_TAG, [service.clone()]));
        }
        Ok(tags)
    }
}

/// Errors raised by [`FileMetadata::from_event`] / [`FileMetadata::to_tags`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FileMetadataError {
    /// The event was not `kind: 1063`.
    #[error("expected kind 1063 (file metadata), got kind {}", .0.as_u16())]
    WrongKind(Kind),
    /// The required `url` tag is missing.
    #[error("NIP-94 event must carry a `url` tag")]
    MissingUrl,
    /// The required `m` (MIME) tag is missing.
    #[error("NIP-94 event must carry an `m` (MIME) tag")]
    MissingMimeType,
    /// The required `x` (SHA-256) tag is missing.
    #[error("NIP-94 event must carry an `x` (SHA-256) tag")]
    MissingHash,
    /// A URL value did not parse.
    #[error("invalid URL: {0}")]
    InvalidUrl(#[source] UrlError),
    /// A SHA-256 value did not decode as 32 bytes of hex.
    #[error("invalid SHA-256 hex: {0}")]
    InvalidHash(#[source] HexError),
    /// SHA-256 hex was the wrong length.
    #[error("SHA-256 must be 64 hex chars, got {0}")]
    InvalidHashLength(usize),
    /// The `size` value did not parse as `u64`.
    #[error("invalid `size` value `{0}`: must be unsigned integer bytes")]
    InvalidSize(String),
    /// The `dim` value did not parse as `<width>x<height>`.
    #[error("invalid `dim` value: {0}")]
    InvalidDim(#[source] ImageError),
}

fn parse_sha256(input: &str) -> Result<[u8; 32], FileMetadataError> {
    if input.len() != 64 {
        return Err(FileMetadataError::InvalidHashLength(input.len()));
    }
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(input, &mut bytes).map_err(FileMetadataError::InvalidHash)?;
    Ok(bytes)
}

fn parse_variant(tags: &Tags, name: &str) -> Result<Option<FileVariant>, FileMetadataError> {
    let head = TagKind::Custom(name.to_owned());
    let Some(tag) = tags.find_first(&head) else {
        return Ok(None);
    };
    let Some(url_str) = tag.get(1) else {
        return Ok(None);
    };
    let url = Url::parse(url_str).map_err(FileMetadataError::InvalidUrl)?;
    let hash = match tag.get(2) {
        Some(hex) if !hex.is_empty() => Some(parse_sha256(hex)?),
        _ => None,
    };
    Ok(Some(FileVariant { url, hash }))
}

fn variant_tag(name: &str, variant: &FileVariant) -> Tag {
    let mut values: Vec<String> = Vec::with_capacity(2);
    values.push(variant.url.as_str().to_owned());
    if let Some(hash) = variant.hash {
        values.push(hex::encode(hash));
    }
    custom(name, values)
}

fn single_value(tags: &Tags, letter: Alphabet) -> Option<&str> {
    let head = TagKind::single_letter(SingleLetterTag::lowercase(letter));
    tags.find_first(&head).and_then(|tag| tag.get(1))
}

fn custom_value<'a>(tags: &'a Tags, name: &str) -> Option<&'a str> {
    tags.iter()
        .find(|tag| tag.name() == name)
        .and_then(|tag| tag.get(1))
}

fn custom<I, S>(name: &str, args: I) -> Tag
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    Tag::with(&TagKind::Custom(name.to_owned()), args)
}

fn letter<I, S>(alphabet: Alphabet, args: I) -> Tag
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let head = TagKind::single_letter(SingleLetterTag::lowercase(alphabet));
    Tag::with(&head, args)
}

impl EventBuilder {
    /// Author a NIP-94 file-metadata event.
    ///
    /// `caption` becomes the event's `.content`. The bundle's
    /// required fields (`url`, `mime_type`, `hash`) must be set, or
    /// the call returns `Err(FileMetadataError::Missing*)`.
    ///
    /// # Errors
    ///
    /// Forwards [`FileMetadataError`] from the bundle-to-tags step.
    pub fn file_metadata(
        caption: impl Into<String>,
        metadata: &FileMetadata,
    ) -> Result<Self, FileMetadataError> {
        let tags = metadata.to_tags()?;
        let mut builder = Self::new(KIND_FILE_METADATA, caption);
        for tag in tags {
            builder = builder.tag(tag);
        }
        Ok(builder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;

    const HASH_HEX: &str = "1aea8e98e0e5d969b7124f553b88dfae47d1f00472ea8c0dbf4ac4577d39ef02";
    const ORIG_HEX: &str = "8a8c1d9c5b3e3e3a8b95d51b6f8a6f3a3a23bba1f1c5d9e7e1c0b3d8b9a0e3a4";
    const URL: &str = "https://image.nostr.build/99a95fcb4b7a2591ad32467032c52a62d90a204d3b176bc2459ad7427a3f2b89.jpg";

    fn keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    fn fixture_metadata() -> FileMetadata {
        let url = Url::parse(URL).unwrap();
        let hash = hex_array(HASH_HEX);
        FileMetadata::new(url, "image/jpeg", hash)
            .original_hash(hex_array(ORIG_HEX))
            .size(102_400)
            .dim(ImageDimensions::new(640, 480).unwrap())
            .magnet("magnet:?xt=urn:btih:abcd")
            .torrent_infohash("abcd1234")
            .blurhash("LE@:#0R%9F00ag~q-=^7^*9F8_-V")
            .thumb(FileVariant::new(
                Url::parse("https://example.com/t.jpg").unwrap(),
            ))
            .preview_image(
                FileVariant::new(Url::parse("https://example.com/p.jpg").unwrap())
                    .with_hash(hex_array(HASH_HEX)),
            )
            .summary("a sample image")
            .alt("scenic mountain view")
            .fallback(Url::parse("https://example.com/fallback1").unwrap())
            .fallback(Url::parse("https://example.com/fallback2").unwrap())
            .service("nip96")
    }

    fn hex_array(s: &str) -> [u8; 32] {
        let mut out = [0_u8; 32];
        hex::decode_to_slice(s, &mut out).unwrap();
        out
    }

    #[test]
    fn full_metadata_round_trips_through_event() {
        let original = fixture_metadata();
        let event = EventBuilder::file_metadata("caption text", &original)
            .unwrap()
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, KIND_FILE_METADATA);
        assert_eq!(event.content, "caption text");

        let parsed = FileMetadata::from_event(&event).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn missing_url_is_rejected_when_parsing() {
        let event = EventBuilder::new(KIND_FILE_METADATA, "")
            .tag(letter(Alphabet::M, ["image/jpeg"]))
            .tag(letter(Alphabet::X, [HASH_HEX]))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            FileMetadata::from_event(&event),
            Err(FileMetadataError::MissingUrl)
        ));
    }

    #[test]
    fn missing_mime_is_rejected_when_parsing() {
        let event = EventBuilder::new(KIND_FILE_METADATA, "")
            .tag(custom(URL_TAG, [URL]))
            .tag(letter(Alphabet::X, [HASH_HEX]))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            FileMetadata::from_event(&event),
            Err(FileMetadataError::MissingMimeType)
        ));
    }

    #[test]
    fn missing_hash_is_rejected_when_parsing() {
        let event = EventBuilder::new(KIND_FILE_METADATA, "")
            .tag(custom(URL_TAG, [URL]))
            .tag(letter(Alphabet::M, ["image/jpeg"]))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            FileMetadata::from_event(&event),
            Err(FileMetadataError::MissingHash)
        ));
    }

    #[test]
    fn malformed_hash_surfaces_typed_error() {
        let event = EventBuilder::new(KIND_FILE_METADATA, "")
            .tag(custom(URL_TAG, [URL]))
            .tag(letter(Alphabet::M, ["image/jpeg"]))
            .tag(letter(Alphabet::X, ["not-hex"]))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            FileMetadata::from_event(&event),
            Err(FileMetadataError::InvalidHashLength(_))
        ));
    }

    #[test]
    fn wrong_kind_is_rejected_when_parsing() {
        let event = EventBuilder::text_note("nope")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            FileMetadata::from_event(&event),
            Err(FileMetadataError::WrongKind(_))
        ));
    }

    #[test]
    fn invalid_size_surfaces_typed_error() {
        let event = EventBuilder::new(KIND_FILE_METADATA, "")
            .tag(custom(URL_TAG, [URL]))
            .tag(letter(Alphabet::M, ["image/jpeg"]))
            .tag(letter(Alphabet::X, [HASH_HEX]))
            .tag(custom(SIZE_TAG, ["abc"]))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            FileMetadata::from_event(&event),
            Err(FileMetadataError::InvalidSize(_))
        ));
    }

    #[test]
    fn invalid_dim_surfaces_typed_error() {
        let event = EventBuilder::new(KIND_FILE_METADATA, "")
            .tag(custom(URL_TAG, [URL]))
            .tag(letter(Alphabet::M, ["image/jpeg"]))
            .tag(letter(Alphabet::X, [HASH_HEX]))
            .tag(custom(DIM_TAG, ["bad"]))
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            FileMetadata::from_event(&event),
            Err(FileMetadataError::InvalidDim(_))
        ));
    }

    #[test]
    fn fallback_urls_round_trip_in_order() {
        let metadata =
            FileMetadata::new(Url::parse(URL).unwrap(), "image/jpeg", hex_array(HASH_HEX))
                .fallback(Url::parse("https://a.example/").unwrap())
                .fallback(Url::parse("https://b.example/").unwrap());
        let event = EventBuilder::file_metadata("", &metadata)
            .unwrap()
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = FileMetadata::from_event(&event).unwrap();
        assert_eq!(parsed.fallback_urls.len(), 2);
        assert_eq!(parsed.fallback_urls[0].as_str(), "https://a.example/");
        assert_eq!(parsed.fallback_urls[1].as_str(), "https://b.example/");
    }

    #[test]
    fn variant_without_hash_round_trips() {
        let metadata =
            FileMetadata::new(Url::parse(URL).unwrap(), "image/jpeg", hex_array(HASH_HEX))
                .thumb(FileVariant::new(Url::parse("https://t.example/").unwrap()));
        let event = EventBuilder::file_metadata("", &metadata)
            .unwrap()
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = FileMetadata::from_event(&event).unwrap();
        let thumb = parsed.thumb.unwrap();
        assert_eq!(thumb.url.as_str(), "https://t.example/");
        assert_eq!(thumb.hash, None);
    }
}
