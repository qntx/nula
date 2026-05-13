//! [NIP-92] Media Attachments.
//!
//! `imeta` ("inline metadata") tags attach NIP-94-style metadata to
//! URLs that appear inside an event's `.content`. Each tag is a
//! variadic list of space-delimited `key value` pairs that mirror the
//! NIP-94 tag shape:
//!
//! ```text
//! ["imeta",
//!  "url https://nostr.build/i/picture.jpg",
//!  "m image/jpeg",
//!  "blurhash <code>",
//!  "dim 3024x4032",
//!  "alt A scenic photo",
//!  "x <sha256-hex>",
//!  "fallback https://void.cat/alt1.jpg"]
//! ```
//!
//! Spec invariants enforced by the parser/builder:
//!
//! - exactly one `url` per `imeta` tag (required);
//! - at least one *other* field per `imeta` tag (required).
//!
//! Forward compatibility:
//!
//! - Unknown keys round-trip through [`MediaAttachment::extra_fields`].
//! - Multiple `fallback`s are concatenated into [`MediaAttachment::fallback_urls`].
//!
//! # Cross-NIP
//!
//! The set of keys is intentionally aligned with NIP-94: any field on
//! [`FileMetadata`] can appear inside an `imeta` tag. The
//! two-direction converters
//! [`MediaAttachment::from_file_metadata`] /
//! [`MediaAttachment::to_file_metadata`] make crossing the boundary
//! cheap.
//!
//! [NIP-92]: https://github.com/nostr-protocol/nips/blob/master/92.md

use thiserror::Error;

use crate::event::{Tag, TagKind, Tags};
use crate::nips::nip94::{
    ALT_TAG, BLURHASH_TAG, DIM_TAG, FALLBACK_TAG, FileMetadata, FileVariant, IMAGE_TAG, MAGNET_TAG,
    OX_TAG, SERVICE_TAG, SIZE_TAG, SUMMARY_TAG, THUMB_TAG, URL_TAG,
};
use crate::types::{ImageDimensions, ImageError, Url, UrlError};
use crate::util::hex::{self, HexError};

/// Wire name of the `imeta` tag.
pub const IMETA_TAG: &str = "imeta";

/// One inline media attachment.
///
/// Field semantics match the NIP-94 columns of the same name; see
/// [`FileMetadata`] for documentation that applies one-to-one.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MediaAttachment {
    /// Required `url` field.
    pub url: Option<Url>,
    /// `m` MIME type.
    pub mime_type: Option<String>,
    /// `x` SHA-256 of served bytes.
    pub hash: Option<[u8; 32]>,
    /// `ox` SHA-256 of original bytes.
    pub original_hash: Option<[u8; 32]>,
    /// `size` in bytes.
    pub size: Option<u64>,
    /// `dim` pixel dimensions.
    pub dim: Option<ImageDimensions>,
    /// `magnet` URI.
    pub magnet: Option<String>,
    /// `blurhash` placeholder.
    pub blurhash: Option<String>,
    /// `alt` accessibility description.
    pub alt: Option<String>,
    /// `summary` excerpt.
    pub summary: Option<String>,
    /// `thumb` variant.
    pub thumb: Option<FileVariant>,
    /// `image` preview variant.
    pub image: Option<FileVariant>,
    /// `fallback` URLs.
    pub fallback_urls: Vec<Url>,
    /// `service` identifier.
    pub service: Option<String>,
    /// Unknown keys carried through verbatim for forward
    /// compatibility. `(key, value)` pairs in insertion order.
    pub extra_fields: Vec<(String, String)>,
}

impl MediaAttachment {
    /// Construct an attachment seeded with the required `url` field.
    #[must_use]
    pub fn new(url: Url) -> Self {
        Self {
            url: Some(url),
            ..Self::default()
        }
    }

    /// Set [`Self::mime_type`].
    #[must_use]
    pub fn mime_type(mut self, mime_type: impl Into<String>) -> Self {
        self.mime_type = Some(mime_type.into());
        self
    }

    /// Set [`Self::hash`].
    #[must_use]
    pub const fn hash(mut self, hash: [u8; 32]) -> Self {
        self.hash = Some(hash);
        self
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

    /// Set [`Self::blurhash`].
    #[must_use]
    pub fn blurhash(mut self, blurhash: impl Into<String>) -> Self {
        self.blurhash = Some(blurhash.into());
        self
    }

    /// Set [`Self::alt`].
    #[must_use]
    pub fn alt(mut self, alt: impl Into<String>) -> Self {
        self.alt = Some(alt.into());
        self
    }

    /// Set [`Self::summary`].
    #[must_use]
    pub fn summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = Some(summary.into());
        self
    }

    /// Set [`Self::thumb`].
    #[must_use]
    pub fn thumb(mut self, thumb: FileVariant) -> Self {
        self.thumb = Some(thumb);
        self
    }

    /// Set [`Self::image`].
    #[must_use]
    pub fn image(mut self, image: FileVariant) -> Self {
        self.image = Some(image);
        self
    }

    /// Append a fallback URL.
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

    /// Append a forward-compatible `(key, value)` pair.
    ///
    /// Known NIP-94 keys submitted via this method are silently
    /// dropped — they live on the typed fields.
    #[must_use]
    pub fn extra(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        let key = key.into();
        if !is_known_key(&key) {
            self.extra_fields.push((key, value.into()));
        }
        self
    }

    /// Render to an `imeta` [`Tag`].
    ///
    /// # Errors
    ///
    /// Returns [`MediaAttachmentError::MissingUrl`] when [`Self::url`]
    /// is `None`, or [`MediaAttachmentError::MissingOtherField`]
    /// when no other field is populated (spec invariants).
    pub fn to_tag(&self) -> Result<Tag, MediaAttachmentError> {
        let url = self.url.as_ref().ok_or(MediaAttachmentError::MissingUrl)?;
        let mut fields: Vec<String> = Vec::new();
        fields.push(format!("{URL_TAG} {}", url.as_str()));
        let other_count_before = fields.len();
        push_optional(&mut fields, "m", self.mime_type.as_deref());
        if let Some(hash) = self.hash {
            fields.push(format!("x {}", hex::encode(hash)));
        }
        if let Some(hash) = self.original_hash {
            fields.push(format!("{OX_TAG} {}", hex::encode(hash)));
        }
        if let Some(size) = self.size {
            fields.push(format!("{SIZE_TAG} {size}"));
        }
        if let Some(dim) = self.dim {
            fields.push(format!("{DIM_TAG} {dim}"));
        }
        push_optional(&mut fields, MAGNET_TAG, self.magnet.as_deref());
        push_optional(&mut fields, BLURHASH_TAG, self.blurhash.as_deref());
        push_optional(&mut fields, ALT_TAG, self.alt.as_deref());
        push_optional(&mut fields, SUMMARY_TAG, self.summary.as_deref());
        if let Some(thumb) = &self.thumb {
            fields.push(format!("{THUMB_TAG} {}", thumb.url.as_str()));
        }
        if let Some(image) = &self.image {
            fields.push(format!("{IMAGE_TAG} {}", image.url.as_str()));
        }
        for fb in &self.fallback_urls {
            fields.push(format!("{FALLBACK_TAG} {}", fb.as_str()));
        }
        push_optional(&mut fields, SERVICE_TAG, self.service.as_deref());
        for (k, v) in &self.extra_fields {
            fields.push(format!("{k} {v}"));
        }
        if fields.len() == other_count_before {
            return Err(MediaAttachmentError::MissingOtherField);
        }
        Ok(Tag::with(&TagKind::from_wire(IMETA_TAG), fields))
    }

    /// Parse one `imeta` [`Tag`] back into a typed attachment.
    ///
    /// # Errors
    ///
    /// - [`MediaAttachmentError::WrongTag`] when the tag is not an
    ///   `imeta` tag.
    /// - [`MediaAttachmentError::MissingUrl`] when no `url` field is
    ///   present.
    /// - [`MediaAttachmentError::MissingOtherField`] when only `url`
    ///   is present.
    /// - [`MediaAttachmentError::MalformedField`] when a field has
    ///   no separator.
    /// - Various typed errors for malformed individual fields.
    pub fn from_tag(tag: &Tag) -> Result<Self, MediaAttachmentError> {
        if tag.name() != IMETA_TAG {
            return Err(MediaAttachmentError::WrongTag);
        }
        let mut attachment = Self::default();
        let mut other_field_count = 0_usize;
        for entry in tag.values().iter().skip(1) {
            let (key, value) = split_field(entry)?;
            if key != URL_TAG {
                other_field_count += 1;
            }
            apply_field(&mut attachment, key, value)?;
        }
        if attachment.url.is_none() {
            return Err(MediaAttachmentError::MissingUrl);
        }
        if other_field_count == 0 {
            return Err(MediaAttachmentError::MissingOtherField);
        }
        Ok(attachment)
    }

    /// Build an attachment from a [`FileMetadata`] bundle.
    ///
    /// The `url` field is required for an `imeta` tag; if the
    /// metadata bundle has no URL the returned attachment will fail
    /// [`Self::to_tag`].
    #[must_use]
    pub fn from_file_metadata(meta: &FileMetadata) -> Self {
        Self {
            url: meta.url.clone(),
            mime_type: meta.mime_type.clone(),
            hash: meta.hash,
            original_hash: meta.original_hash,
            size: meta.size,
            dim: meta.dim,
            magnet: meta.magnet.clone(),
            blurhash: meta.blurhash.clone(),
            alt: meta.alt.clone(),
            summary: meta.summary.clone(),
            thumb: meta.thumb.clone(),
            image: meta.preview_image.clone(),
            fallback_urls: meta.fallback_urls.clone(),
            service: meta.service.clone(),
            extra_fields: Vec::new(),
        }
    }

    /// Promote this attachment to a typed [`FileMetadata`].
    ///
    /// Unknown extra fields are dropped — they have no NIP-94 home.
    #[must_use]
    pub fn to_file_metadata(&self) -> FileMetadata {
        FileMetadata {
            url: self.url.clone(),
            mime_type: self.mime_type.clone(),
            hash: self.hash,
            original_hash: self.original_hash,
            size: self.size,
            dim: self.dim,
            magnet: self.magnet.clone(),
            torrent_infohash: None,
            blurhash: self.blurhash.clone(),
            thumb: self.thumb.clone(),
            preview_image: self.image.clone(),
            summary: self.summary.clone(),
            alt: self.alt.clone(),
            fallback_urls: self.fallback_urls.clone(),
            service: self.service.clone(),
        }
    }
}

/// Read every `imeta` tag off the given event tags.
///
/// # Errors
///
/// Returns the first error encountered while parsing a tag. To
/// tolerate malformed individual tags, walk the list manually with
/// [`MediaAttachment::from_tag`].
pub fn attachments_from_tags(tags: &Tags) -> Result<Vec<MediaAttachment>, MediaAttachmentError> {
    let head = TagKind::from_wire(IMETA_TAG);
    let mut out: Vec<MediaAttachment> = Vec::new();
    for tag in tags.find_all(&head) {
        out.push(MediaAttachment::from_tag(tag)?);
    }
    Ok(out)
}

fn push_optional(out: &mut Vec<String>, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        out.push(format!("{key} {value}"));
    }
}

fn split_field(raw: &str) -> Result<(&str, &str), MediaAttachmentError> {
    raw.split_once(' ')
        .ok_or_else(|| MediaAttachmentError::MalformedField(raw.to_owned()))
}

fn apply_field(
    out: &mut MediaAttachment,
    key: &str,
    value: &str,
) -> Result<(), MediaAttachmentError> {
    match key {
        URL_TAG => out.url = Some(Url::parse(value)?),
        "m" => out.mime_type = Some(value.to_owned()),
        "x" => out.hash = Some(parse_sha256(value)?),
        OX_TAG => out.original_hash = Some(parse_sha256(value)?),
        SIZE_TAG => {
            out.size = Some(
                value
                    .parse::<u64>()
                    .map_err(|_| MediaAttachmentError::InvalidSize(value.to_owned()))?,
            );
        }
        DIM_TAG => {
            out.dim = Some(
                value
                    .parse::<ImageDimensions>()
                    .map_err(MediaAttachmentError::InvalidDim)?,
            );
        }
        MAGNET_TAG => out.magnet = Some(value.to_owned()),
        BLURHASH_TAG => out.blurhash = Some(value.to_owned()),
        ALT_TAG => out.alt = Some(value.to_owned()),
        SUMMARY_TAG => out.summary = Some(value.to_owned()),
        THUMB_TAG => out.thumb = Some(FileVariant::new(Url::parse(value)?)),
        IMAGE_TAG => out.image = Some(FileVariant::new(Url::parse(value)?)),
        FALLBACK_TAG => out.fallback_urls.push(Url::parse(value)?),
        SERVICE_TAG => out.service = Some(value.to_owned()),
        other => out.extra_fields.push((other.to_owned(), value.to_owned())),
    }
    Ok(())
}

fn is_known_key(key: &str) -> bool {
    matches!(
        key,
        URL_TAG
            | "m"
            | "x"
            | OX_TAG
            | SIZE_TAG
            | DIM_TAG
            | MAGNET_TAG
            | BLURHASH_TAG
            | ALT_TAG
            | SUMMARY_TAG
            | THUMB_TAG
            | IMAGE_TAG
            | FALLBACK_TAG
            | SERVICE_TAG
    )
}

fn parse_sha256(input: &str) -> Result<[u8; 32], MediaAttachmentError> {
    if input.len() != 64 {
        return Err(MediaAttachmentError::InvalidHashLength(input.len()));
    }
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(input, &mut bytes).map_err(MediaAttachmentError::InvalidHashHex)?;
    Ok(bytes)
}

/// Errors raised by [`MediaAttachment`] parsers / builders.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MediaAttachmentError {
    /// The tag was not an `imeta` tag.
    #[error("expected `imeta` tag")]
    WrongTag,
    /// `url` field is missing.
    #[error("`imeta` tag must include a `url` field")]
    MissingUrl,
    /// No other field besides `url` is present.
    #[error("`imeta` tag must include at least one field besides `url`")]
    MissingOtherField,
    /// A field has no space separator.
    #[error("malformed imeta field `{0}`: expected `key value`")]
    MalformedField(String),
    /// The `size` value is not a `u64`.
    #[error("invalid size value: `{0}`")]
    InvalidSize(String),
    /// SHA-256 hash has the wrong length.
    #[error("invalid SHA-256 hash length: {0} chars (expected 64)")]
    InvalidHashLength(usize),
    /// SHA-256 hash hex decoding failed.
    #[error(transparent)]
    InvalidHashHex(#[from] HexError),
    /// `url` / `fallback` / `thumb` / `image` URL parse error.
    #[error(transparent)]
    InvalidUrl(#[from] UrlError),
    /// `dim` value parse error.
    #[error(transparent)]
    InvalidDim(#[from] ImageError),
}

impl Tag {
    /// Build a NIP-92 `imeta` tag from a [`MediaAttachment`].
    ///
    /// # Errors
    ///
    /// See [`MediaAttachment::to_tag`].
    pub fn imeta(attachment: &MediaAttachment) -> Result<Self, MediaAttachmentError> {
        attachment.to_tag()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EventBuilder;
    use crate::Keys;

    fn keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    fn url() -> Url {
        Url::parse("https://nostr.build/i/picture.jpg").unwrap()
    }

    #[test]
    fn round_trip_full_attachment() {
        let attachment = MediaAttachment::new(url())
            .mime_type("image/jpeg")
            .hash([0xab; 32])
            .size(1024)
            .dim("3024x4032".parse().unwrap())
            .blurhash("eVF$^OI:")
            .alt("scenic")
            .fallback(Url::parse("https://void.cat/alt1.jpg").unwrap())
            .fallback(Url::parse("https://nostrcheck.me/alt2.jpg").unwrap())
            .service("nip96");
        let tag = attachment.to_tag().unwrap();
        let parsed = MediaAttachment::from_tag(&tag).unwrap();
        assert_eq!(parsed, attachment);
    }

    #[test]
    fn round_trip_with_extras() {
        let attachment = MediaAttachment::new(url())
            .mime_type("image/jpeg")
            .extra("aspect", "16:9")
            .extra("custom", "extension");
        let tag = attachment.to_tag().unwrap();
        let parsed = MediaAttachment::from_tag(&tag).unwrap();
        assert_eq!(parsed.extra_fields, attachment.extra_fields);
    }

    #[test]
    fn missing_url_is_rejected() {
        let attachment = MediaAttachment::default();
        assert!(matches!(
            attachment.to_tag(),
            Err(MediaAttachmentError::MissingUrl)
        ));
    }

    #[test]
    fn missing_other_field_is_rejected() {
        let attachment = MediaAttachment::new(url());
        assert!(matches!(
            attachment.to_tag(),
            Err(MediaAttachmentError::MissingOtherField)
        ));
    }

    #[test]
    fn wrong_tag_is_rejected() {
        let tag = Tag::title("not imeta");
        assert!(matches!(
            MediaAttachment::from_tag(&tag),
            Err(MediaAttachmentError::WrongTag)
        ));
    }

    #[test]
    fn malformed_field_is_rejected() {
        let tag = Tag::with(&TagKind::from_wire(IMETA_TAG), ["no-separator"]);
        assert!(matches!(
            MediaAttachment::from_tag(&tag),
            Err(MediaAttachmentError::MalformedField(_))
        ));
    }

    #[test]
    fn known_key_submitted_via_extra_is_dropped() {
        let attachment = MediaAttachment::new(url())
            .mime_type("image/jpeg")
            .extra("alt", "should-be-ignored");
        assert!(attachment.extra_fields.is_empty());
    }

    #[test]
    fn attachments_from_tags_reads_event_tags() {
        let attachment = MediaAttachment::new(url()).mime_type("image/jpeg");
        let tag = attachment.to_tag().unwrap();
        let event = EventBuilder::text_note("hi")
            .tag(tag)
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = attachments_from_tags(&event.tags).unwrap();
        assert_eq!(parsed, vec![attachment]);
    }

    #[test]
    fn cross_conversion_with_file_metadata() {
        let meta = FileMetadata::new(url(), "image/jpeg", [0x11; 32])
            .size(42)
            .alt("alt-text");
        let attachment = MediaAttachment::from_file_metadata(&meta);
        let back = attachment.to_file_metadata();
        assert_eq!(back, meta);
    }
}
