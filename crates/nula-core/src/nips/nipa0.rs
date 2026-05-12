//! [NIP-A0] Voice Messages.
//!
//! Two regular kinds for short voice notes:
//!
//! - `kind: 1222` — root voice message. `.content` MUST be a URL
//!   pointing at an audio file.
//! - `kind: 1244` — voice reply. Follows NIP-22 comment scoping.
//!
//! Visual previews can be carried via NIP-92 `imeta` tags with the
//! per-spec `waveform` and `duration` fields.
//!
//! [NIP-A0]: https://github.com/nostr-protocol/nips/blob/master/A0.md

use thiserror::Error;

use crate::event::{Event, EventBuilder, Kind, Tag};
use crate::nips::nip92::{MediaAttachment, MediaAttachmentError};
use crate::types::{Url, UrlError};

/// `kind: 1222` — root voice message.
pub const KIND_VOICE_MESSAGE: Kind = Kind::VOICE_MESSAGE;

/// `kind: 1244` — voice reply.
pub const KIND_VOICE_MESSAGE_REPLY: Kind = Kind::VOICE_MESSAGE_REPLY;

/// Visual preview metadata for a voice attachment (NIP-92 `imeta`
/// extension).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VoicePreview {
    /// Whitespace-separated amplitude values (0–100).
    pub waveform: Option<String>,
    /// Audio length in seconds (stringified).
    pub duration_seconds: Option<u64>,
}

/// Typed bundle for a `kind: 1222` / `kind: 1244` voice event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoiceMessage {
    /// Whether this is a reply (`true` ⇒ `kind: 1244`).
    pub is_reply: bool,
    /// URL pointing at the audio file (mirrors `.content`).
    pub audio_url: Url,
    /// Optional NIP-92 `imeta` tag describing the audio.
    pub media: Option<MediaAttachment>,
    /// Optional preview parsed from the `imeta` tag.
    pub preview: VoicePreview,
    /// Forward-compatible passthrough for unknown tags.
    pub extra_tags: Vec<Tag>,
}

/// Errors raised while parsing a NIP-A0 event.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VoiceMessageError {
    /// Event kind is not `1222` / `1244`.
    #[error("unexpected kind for NIP-A0 voice message: {}", .0.as_u16())]
    WrongKind(Kind),
    /// `.content` is not a parseable URL.
    #[error(transparent)]
    InvalidAudioUrl(#[from] UrlError),
    /// Wrapped imeta parser error.
    #[error(transparent)]
    InvalidMediaAttachment(#[from] MediaAttachmentError),
    /// Voice preview `duration` could not be parsed as an integer.
    #[error("invalid voice preview `duration` value `{0}`")]
    InvalidDuration(String),
}

impl VoiceMessage {
    /// Construct a root voice message.
    #[must_use]
    pub fn root(audio_url: Url) -> Self {
        Self {
            is_reply: false,
            audio_url,
            media: None,
            preview: VoicePreview::default(),
            extra_tags: Vec::new(),
        }
    }

    /// Construct a reply voice message.
    #[must_use]
    pub fn reply(audio_url: Url) -> Self {
        Self {
            is_reply: true,
            ..Self::root(audio_url)
        }
    }

    /// Attach a NIP-92 media bundle. Side-extracts the
    /// `waveform`/`duration` extras into [`Self::preview`].
    #[must_use]
    pub fn media(mut self, media: MediaAttachment) -> Self {
        self.preview = preview_from_media(&media);
        self.media = Some(media);
        self
    }

    /// Parse a `kind: 1222` or `kind: 1244` voice-message event.
    ///
    /// # Errors
    ///
    /// See [`VoiceMessageError`] for the failure modes.
    pub fn from_event(event: &Event) -> Result<Self, VoiceMessageError> {
        let is_reply = match event.kind {
            KIND_VOICE_MESSAGE => false,
            KIND_VOICE_MESSAGE_REPLY => true,
            other => return Err(VoiceMessageError::WrongKind(other)),
        };
        let audio_url = Url::parse(event.content.trim())?;
        let mut media: Option<MediaAttachment> = None;
        let mut extra_tags: Vec<Tag> = Vec::new();
        for tag in &event.tags {
            if tag.name() == "imeta" && media.is_none() {
                media = Some(MediaAttachment::from_tag(tag)?);
            } else {
                extra_tags.push(tag.clone());
            }
        }
        let preview = media.as_ref().map(preview_from_media).unwrap_or_default();
        Ok(Self {
            is_reply,
            audio_url,
            media,
            preview,
            extra_tags,
        })
    }
}

fn preview_from_media(media: &MediaAttachment) -> VoicePreview {
    let mut preview = VoicePreview::default();
    for (key, value) in &media.extra_fields {
        match key.as_str() {
            "waveform" => preview.waveform = Some(value.clone()),
            "duration" => {
                if let Ok(secs) = value.parse::<u64>() {
                    preview.duration_seconds = Some(secs);
                }
            }
            _ => {}
        }
    }
    preview
}

impl EventBuilder {
    /// Author a NIP-A0 voice message.
    ///
    /// # Errors
    ///
    /// Propagates [`MediaAttachmentError`] when the optional
    /// [`VoiceMessage::media`] bundle violates NIP-92 invariants.
    pub fn voice_message(msg: &VoiceMessage) -> Result<Self, VoiceMessageError> {
        let kind = if msg.is_reply {
            KIND_VOICE_MESSAGE_REPLY
        } else {
            KIND_VOICE_MESSAGE
        };
        let mut builder = Self::new(kind, msg.audio_url.as_str());
        if let Some(media) = &msg.media {
            builder = builder.tag(media.to_tag()?);
        }
        for tag in &msg.extra_tags {
            builder = builder.tag(tag.clone());
        }
        Ok(builder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;

    fn keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    fn sample_media() -> MediaAttachment {
        MediaAttachment::new(Url::parse("https://example.com/voice.mp4").unwrap())
            .extra("waveform", "0 5 100 50")
            .extra("duration", "8")
    }

    #[test]
    fn voice_message_root_round_trip() {
        let url = Url::parse("https://example.com/voice.mp4").unwrap();
        let msg = VoiceMessage::root(url).media(sample_media());
        let event = EventBuilder::voice_message(&msg)
            .unwrap()
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = VoiceMessage::from_event(&event).unwrap();
        assert!(!parsed.is_reply);
        assert_eq!(parsed.preview.waveform.as_deref(), Some("0 5 100 50"));
        assert_eq!(parsed.preview.duration_seconds, Some(8));
    }

    #[test]
    fn voice_message_reply_round_trip() {
        let url = Url::parse("https://example.com/reply.mp4").unwrap();
        let msg = VoiceMessage::reply(url);
        let event = EventBuilder::voice_message(&msg)
            .unwrap()
            .sign_with_keys(&keys())
            .unwrap();
        let parsed = VoiceMessage::from_event(&event).unwrap();
        assert!(parsed.is_reply);
        assert!(parsed.media.is_none());
    }

    #[test]
    fn wrong_kind_is_rejected() {
        let event = EventBuilder::text_note("nope")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            VoiceMessage::from_event(&event),
            Err(VoiceMessageError::WrongKind(_))
        ));
    }
}
