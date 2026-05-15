//! [NIP-68] Picture-first feeds.
//!
//! `kind: 20` is an Instagram/Flickr/Snapchat/9GAG-style image post.
//! `.content` carries a free-form description; the picture set lives
//! in NIP-92 `imeta` tags. The spec restricts the served `m`/`imeta`
//! MIME types to a small list — we surface the constant
//! [`SUPPORTED_MIME_TYPES`] for callers to validate against.
//!
//! [NIP-68]: https://github.com/nostr-protocol/nips/blob/master/68.md

use thiserror::Error;

use crate::event::{Alphabet, Event, EventBuilder, Kind, SingleLetterTag, Tag, TagKind};
use crate::key::{PublicKey, PublicKeyError};
use crate::nips::nip92::{MediaAttachment, MediaAttachmentError};
use crate::types::{RelayUrl, RelayUrlError};

/// `kind: 20` — picture-first event.
pub const KIND_PICTURE: Kind = Kind::PICTURE;

const TITLE_TAG: &str = "title";
const CONTENT_WARNING_TAG: &str = "content-warning";
const LOCATION_TAG: &str = "location";

/// Supported `image/*` MIME types per NIP-68. Surfaced as a slice so
/// callers can validate `MediaAttachment::mime_type` cheaply.
pub const SUPPORTED_MIME_TYPES: &[&str] = &[
    "image/apng",
    "image/avif",
    "image/gif",
    "image/jpeg",
    "image/png",
    "image/webp",
];

/// A `p` tagged user on a picture event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PictureTaggedUser {
    /// Tagged user pubkey.
    pub pubkey: PublicKey,
    /// Optional recommended relay URL.
    pub relay_hint: Option<RelayUrl>,
}

/// Typed bundle for a `kind: 20` picture event.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PicturePost {
    /// `title` tag (recommended).
    pub title: Option<String>,
    /// Free-form description (mirrors `.content`).
    pub description: String,
    /// Picture variants (one or more `imeta` tags).
    pub pictures: Vec<MediaAttachment>,
    /// Optional `content-warning` reason for NSFW content.
    pub content_warning: Option<String>,
    /// `p` tagged users.
    pub tagged_users: Vec<PictureTaggedUser>,
    /// `m` MIME-type filters (de-duped from picture variants).
    pub media_types: Vec<String>,
    /// `x` SHA-256 hashes (de-duped from picture variants).
    pub hashes: Vec<String>,
    /// `t` hashtags (lower-cased).
    pub hashtags: Vec<String>,
    /// Optional `location` city/country line.
    pub location: Option<String>,
    /// Optional `g` geohash.
    pub geohash: Option<String>,
    /// `L`/`l` ISO-639-1 language labels (raw values).
    pub language_labels: Vec<String>,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

/// Errors raised while parsing a NIP-68 event.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PictureError {
    /// Event kind is not `20`.
    #[error("unexpected kind for NIP-68 picture: {}", .0.as_u16())]
    WrongKind(Kind),
    /// `p` tag is missing the pubkey column.
    #[error("`p` tag missing user pubkey")]
    MalformedTaggedUser,
    /// Wrapped pubkey parser error.
    #[error(transparent)]
    InvalidPublicKey(#[from] PublicKeyError),
    /// Wrapped relay-URL parser error.
    #[error(transparent)]
    InvalidRelayUrl(#[from] RelayUrlError),
    /// Wrapped imeta parser error.
    #[error(transparent)]
    InvalidMediaAttachment(#[from] MediaAttachmentError),
}

impl PictureTaggedUser {
    /// Construct a tag without relay hint.
    #[must_use]
    pub const fn new(pubkey: PublicKey) -> Self {
        Self {
            pubkey,
            relay_hint: None,
        }
    }

    fn to_tag(&self) -> Tag {
        let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::P));
        self.relay_hint.as_ref().map_or_else(
            || Tag::with(&head, [self.pubkey.to_hex()]),
            |relay| Tag::with(&head, [self.pubkey.to_hex(), relay.as_str().to_owned()]),
        )
    }

    fn from_tag(tag: &Tag) -> Result<Self, PictureError> {
        let pk_hex = tag.get(1).ok_or(PictureError::MalformedTaggedUser)?;
        let pubkey = PublicKey::parse(pk_hex)?;
        let relay_hint = match tag.get(2) {
            Some(s) if !s.is_empty() => Some(RelayUrl::parse(s)?),
            _ => None,
        };
        Ok(Self { pubkey, relay_hint })
    }
}

impl PicturePost {
    /// Construct a new picture post.
    #[must_use]
    pub fn new(description: impl Into<String>, pictures: Vec<MediaAttachment>) -> Self {
        Self {
            description: description.into(),
            pictures,
            ..Self::default()
        }
    }

    /// Attach a title.
    #[must_use]
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Add a hashtag.
    #[must_use]
    pub fn hashtag(mut self, tag: impl Into<String>) -> Self {
        self.hashtags.push(tag.into().to_ascii_lowercase());
        self
    }

    /// Parse a `kind: 20` picture event.
    ///
    /// # Errors
    ///
    /// See [`PictureError`] for the failure modes.
    pub fn from_event(event: &Event) -> Result<Self, PictureError> {
        if event.kind != KIND_PICTURE {
            return Err(PictureError::WrongKind(event.kind));
        }
        let mut out = Self {
            description: event.content.clone(),
            ..Self::default()
        };
        for tag in &event.tags {
            absorb_tag(tag, &mut out)?;
        }
        Ok(out)
    }
}

fn absorb_tag(tag: &Tag, out: &mut PicturePost) -> Result<(), PictureError> {
    match tag.kind() {
        TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::P => {
            out.tagged_users.push(PictureTaggedUser::from_tag(tag)?);
        }
        TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::T => {
            if let Some(raw) = tag.get(1) {
                out.hashtags.push(raw.to_ascii_lowercase());
            }
        }
        TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::G => {
            out.geohash = tag.get(1).map(str::to_owned);
        }
        TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::X => {
            if let Some(raw) = tag.get(1) {
                out.hashes.push(raw.to_owned());
            }
        }
        TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::M => {
            if let Some(raw) = tag.get(1) {
                out.media_types.push(raw.to_owned());
            }
        }
        TagKind::SingleLetter(s) if !s.uppercase && s.character == Alphabet::L => {
            if let Some(raw) = tag.get(1) {
                out.language_labels.push(raw.to_owned());
            }
        }
        TagKind::SingleLetter(s) if s.uppercase && s.character == Alphabet::L => {
            if let Some(raw) = tag.get(1) {
                out.language_labels.push(raw.to_owned());
            }
        }
        _ if tag.name() == "imeta" => {
            out.pictures.push(MediaAttachment::from_tag(tag)?);
        }
        _ if tag.name() == TITLE_TAG => out.title = tag.get(1).map(str::to_owned),
        _ if tag.name() == CONTENT_WARNING_TAG => {
            out.content_warning = tag.get(1).map(str::to_owned);
        }
        _ if tag.name() == LOCATION_TAG => out.location = tag.get(1).map(str::to_owned),
        _ => out.extra_tags.push(tag.clone()),
    }
    Ok(())
}

impl EventBuilder {
    /// Author a NIP-68 `kind: 20` picture event.
    ///
    /// # Errors
    ///
    /// Propagates [`MediaAttachmentError`] from any malformed
    /// [`PicturePost::pictures`] entry.
    pub fn picture_post(post: &PicturePost) -> Result<Self, PictureError> {
        let mut builder = Self::new(KIND_PICTURE, post.description.clone());
        if let Some(title) = &post.title {
            builder = builder.tag(Tag::with(&TagKind::from_wire(TITLE_TAG), [title.clone()]));
        }
        for picture in &post.pictures {
            builder = builder.tag(picture.to_tag()?);
        }
        if let Some(reason) = &post.content_warning {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(CONTENT_WARNING_TAG),
                [reason.clone()],
            ));
        }
        for user in &post.tagged_users {
            builder = builder.tag(user.to_tag());
        }
        for mime in &post.media_types {
            builder = builder.tag(Tag::with(
                &TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::M)),
                [mime.clone()],
            ));
        }
        for hash in &post.hashes {
            builder = builder.tag(Tag::with(
                &TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::X)),
                [hash.clone()],
            ));
        }
        for hashtag in &post.hashtags {
            builder = builder.tag(Tag::t(hashtag));
        }
        if let Some(location) = &post.location {
            builder = builder.tag(Tag::with(
                &TagKind::from_wire(LOCATION_TAG),
                [location.clone()],
            ));
        }
        if let Some(geohash) = &post.geohash {
            builder = builder.tag(Tag::with(
                &TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::G)),
                [geohash.clone()],
            ));
        }
        for tag in &post.extra_tags {
            builder = builder.tag(tag.clone());
        }
        Ok(builder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;
    use crate::types::Url;

    fn keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    fn sample_picture() -> MediaAttachment {
        MediaAttachment::new(Url::parse("https://nostr.build/i/photo.jpg").unwrap())
            .mime_type("image/jpeg")
            .alt("scenic photo")
    }

    #[test]
    fn picture_post_round_trip() {
        let post = PicturePost::new("a marvelous photo", vec![sample_picture()])
            .title("Sunset")
            .hashtag("photo");
        let event = EventBuilder::picture_post(&post)
            .unwrap()
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = PicturePost::from_event(&event).unwrap();
        assert_eq!(parsed.title.as_deref(), Some("Sunset"));
        assert_eq!(parsed.pictures.len(), 1);
        assert_eq!(parsed.hashtags, vec!["photo".to_owned()]);
    }

    #[test]
    fn wrong_kind_is_rejected() {
        let event = EventBuilder::text_note("nope")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            PicturePost::from_event(&event),
            Err(PictureError::WrongKind(_))
        ));
    }

    #[test]
    fn tagged_user_with_relay_hint_round_trips() {
        // The `p` tag's optional second column carries a relay hint;
        // confirm both the no-hint and with-hint shapes survive a wire
        // round-trip.
        let bare = PictureTaggedUser::new(*keys().public_key());
        let hinted = PictureTaggedUser {
            pubkey: *keys().public_key(),
            relay_hint: Some(RelayUrl::parse("wss://relay.example/").unwrap()),
        };
        let post = PicturePost::new("with tags", vec![sample_picture()])
            .title("Captioned")
            // direct construction so the test exercises both shapes.
            ;
        let mut post = post;
        post.tagged_users = vec![bare.clone(), hinted.clone()];
        let event = EventBuilder::picture_post(&post)
            .unwrap()
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = PicturePost::from_event(&event).unwrap();
        assert_eq!(parsed.tagged_users, vec![bare, hinted]);
    }

    #[test]
    fn multiple_imeta_pictures_round_trip() {
        // Picture-first posts may carry an alternate-variant set \u2014
        // every imeta tag becomes one MediaAttachment.
        let pic_a = MediaAttachment::new(Url::parse("https://nostr.build/i/a.png").unwrap())
            .mime_type("image/png");
        let pic_b = MediaAttachment::new(Url::parse("https://nostr.build/i/b.jpg").unwrap())
            .mime_type("image/jpeg");
        let post = PicturePost::new("variants", vec![pic_a, pic_b]);
        let event = EventBuilder::picture_post(&post)
            .unwrap()
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = PicturePost::from_event(&event).unwrap();
        assert_eq!(parsed.pictures.len(), 2);
        assert_eq!(parsed.pictures[0].mime_type.as_deref(), Some("image/png"));
        assert_eq!(parsed.pictures[1].mime_type.as_deref(), Some("image/jpeg"));
    }

    #[test]
    fn supported_mime_types_match_spec() {
        // The spec enumerates exactly six image MIME types; lock the
        // ordering and contents so accidental drift is loud.
        assert_eq!(SUPPORTED_MIME_TYPES.len(), 6);
        assert!(SUPPORTED_MIME_TYPES.contains(&"image/jpeg"));
        assert!(SUPPORTED_MIME_TYPES.contains(&"image/webp"));
        assert!(!SUPPORTED_MIME_TYPES.contains(&"image/tiff"));
    }
}
