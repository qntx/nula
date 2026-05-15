//! [NIP-96] HTTP File Storage Integration — typed bundles for the
//! kind-10096 file-server preference list and the JSON shapes a
//! NIP-96 server exchanges with its clients.
//!
//! > **Status:** upstream marks NIP-96 as `unrecommended` in favour
//! > of [NIP-B7] (Blossom). We still ship it because a meaningful
//! > slice of the deployed Nostr fleet (Damus, Iris, Coracle,
//! > nostr.build, nostrcheck.me, …) only speaks NIP-96 today.
//! > New code targeting greenfield servers should prefer
//! > [`crate::nips::nipb7`].
//!
//! # What this module covers
//!
//! 1. **`kind: 10096`** — [`FileServerList`]: the user's typed list
//!    of NIP-96 servers. Identical wire shape to the NIP-B7 server
//!    list, parked at a different kind.
//! 2. **`/.well-known/nostr/nip96.json`** — [`Nip96ServerConfig`]:
//!    full typed parse of every field the server advertises
//!    (`api_url`, `download_url`, `delegated_to_url`,
//!    `supported_nips`, `tos_url`, `content_types`, and the typed
//!    [`Nip96Plan`] map).
//! 3. **Upload response JSON** — [`Nip96UploadResponse`] plus the
//!    typed [`Nip96Status`] enum and the embedded
//!    [`EmbeddedNip94Event`] sub-bundle that carries the tags +
//!    content of the canonical NIP-94 file-metadata event the
//!    spec embeds in the response body.
//!
//! # What this module deliberately does NOT do
//!
//! - **HTTP transport.** Wiring up `multipart/form-data` belongs in
//!   the consumer crate; this module exposes only the typed
//!   data shapes so callers can stay backend-agnostic (`reqwest`,
//!   `hyper`, `surf`, …).
//! - **NIP-98 authorization.** That lives in
//!   [`crate::nips::nip98`]. Callers compose the `Authorization`
//!   header at the HTTP boundary.
//!
//! [NIP-96]: https://github.com/nostr-protocol/nips/blob/master/96.md
//! [NIP-B7]: https://github.com/nostr-protocol/nips/blob/master/B7.md

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

use crate::event::{Event, EventBuilder, Kind, Tag, TagError, TagKind};
use crate::types::{Url, UrlError};

/// `kind: 10096` — user's NIP-96 file-server preference list.
pub const KIND_FILE_SERVER_LIST: Kind = Kind::FILE_SERVER_LIST;

/// Canonical `Content-Type` value that NIP-96 servers serve their
/// well-known config under.
pub const NIP96_WELL_KNOWN_MEDIA_TYPE: &str = "application/json";

const SERVER_TAG: &str = "server";

/// Errors raised by the NIP-96 typed bundles.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Nip96Error {
    /// `kind:10096` server list event had the wrong kind.
    #[error("expected kind 10096, got {0}")]
    WrongKind(Kind),
    /// Server URL parse failure.
    #[error(transparent)]
    Url(#[from] UrlError),
    /// Typed [`Tag`] construction failure.
    #[error(transparent)]
    Tag(#[from] TagError),
}

// =============================================================================
// File-server preference list (kind 10096)
// =============================================================================

/// Typed bundle for the `kind: 10096` user file-server preference
/// list.
///
/// Identical wire shape to the NIP-B7 [`crate::nips::nipb7::BlossomServerList`]:
/// one `server` tag per URL, no `.content`. Servers are listed in
/// the user's preference order so clients SHOULD try the head of
/// the list first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileServerList {
    /// File-storage server URLs the user trusts.
    pub servers: Vec<Url>,
}

impl FileServerList {
    /// Construct a server list.
    #[must_use]
    pub fn new<I>(servers: I) -> Self
    where
        I: IntoIterator<Item = Url>,
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
                    &TagKind::custom(SERVER_TAG),
                    [server.as_str().to_owned()],
                )
            })
            .collect()
    }

    /// Parse a signed `kind:10096` event back into a typed bundle.
    ///
    /// # Errors
    ///
    /// Returns [`Nip96Error::WrongKind`] when the event's kind is
    /// not `10096`; forwards URL parse errors for each `server`
    /// tag.
    pub fn from_event(event: &Event) -> Result<Self, Nip96Error> {
        if event.kind != KIND_FILE_SERVER_LIST {
            return Err(Nip96Error::WrongKind(event.kind));
        }
        let mut servers: Vec<Url> = Vec::new();
        for tag in &event.tags {
            if tag.name() != SERVER_TAG {
                continue;
            }
            let Some(url) = tag.values().get(1) else {
                continue;
            };
            servers.push(Url::parse(url)?);
        }
        Ok(Self { servers })
    }
}

// =============================================================================
// /.well-known/nostr/nip96.json server config
// =============================================================================

/// Typed parse of `/.well-known/nostr/nip96.json`.
///
/// Every optional field stays `Option` so callers can distinguish
/// "absent" from "present-but-empty"; the spec leans on absent
/// fields heavily (e.g. `download_url` absent means downloads are
/// served from `api_url`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nip96ServerConfig {
    /// Required: the upload / delete API endpoint.
    pub api_url: String,
    /// Optional: alternate download base URL. Absent or empty
    /// means downloads are served from [`Self::api_url`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_url: Option<String>,
    /// Optional: when set, the well-known is a redirect from a
    /// relay to another server's well-known; [`Self::api_url`]
    /// MUST be empty in that case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_to_url: Option<String>,
    /// Optional: NIP numbers the server explicitly supports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supported_nips: Option<Vec<u16>>,
    /// Optional: server's Terms-of-Service URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tos_url: Option<String>,
    /// Optional: MIME types the server accepts (e.g.
    /// `"image/jpeg"`, `"audio/*"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_types: Option<Vec<String>>,
    /// Optional: plan-name → [`Nip96Plan`] map. The key `"free"`
    /// is spec-standardised and indicates the server offers a free
    /// tier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plans: Option<BTreeMap<String, Nip96Plan>>,
}

/// One entry in the [`Nip96ServerConfig::plans`] map.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nip96Plan {
    /// Human-readable plan name.
    pub name: String,
    /// Whether the plan requires NIP-98 auth on upload. Default
    /// `true`. The spec is explicit that all plans MUST support
    /// NIP-98 — this toggle only relaxes whether NIP-98 is the
    /// *only* accepted credential.
    #[serde(default = "default_true")]
    pub is_nip98_required: bool,
    /// Optional: plan's landing page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Optional: per-file upload size limit in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_byte_size: Option<u64>,
    /// Optional: `[min_days, max_days]` retention range. `0`
    /// means "no expiration", so `[0, 0]` is unlimited and
    /// `[7, 0]` is 7 days up to unlimited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_expiration: Option<[u64; 2]>,
    /// Optional: media-transformation capability map (e.g.
    /// `"image" -> ["resizing"]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_transformations: Option<BTreeMap<String, Vec<String>>>,
}

const fn default_true() -> bool {
    true
}

// =============================================================================
// Upload response JSON
// =============================================================================

/// Typed status column of a [`Nip96UploadResponse`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Nip96Status {
    /// `"success"` — upload accepted.
    Success,
    /// `"error"` — upload rejected; see
    /// [`Nip96UploadResponse::message`] for detail.
    Error,
    /// `"processing"` — upload accepted, deferred processing in
    /// progress (poll
    /// [`Nip96UploadResponse::processing_url`]).
    Processing,
}

/// Typed parse of a NIP-96 upload response body.
///
/// Spec wire shape:
///
/// ```jsonc
/// {
///   "status": "success",
///   "message": "Upload successful.",
///   "processing_url": "...",      // optional, deferred processing
///   "nip94_event": { ... }        // optional, embedded NIP-94 body
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nip96UploadResponse {
    /// `"success"` / `"error"` / `"processing"` discriminator.
    pub status: Nip96Status,
    /// Free-form human-readable message.
    pub message: String,
    /// Optional: poll URL for deferred-processing uploads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub processing_url: Option<String>,
    /// Optional: embedded NIP-94 file-metadata body. Absent on
    /// failure, present on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nip94_event: Option<EmbeddedNip94Event>,
    /// Optional: processing percentage for `status = "processing"`
    /// poll responses (0..=100).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub percentage: Option<u8>,
}

/// Embedded NIP-94-shaped sub-bundle in an upload response.
///
/// This is **not** a signed event: the spec strips `id`, `pubkey`,
/// `created_at`, and `sig` because the response body is already
/// authoritative under HTTP. Callers who need a typed view of the
/// tags can hydrate
/// [`crate::nips::nip94::FileMetadata::from_tags`] (note: that
/// helper takes the typed `Tags` collection; for the raw JSON rows
/// here, callers typically just walk
/// [`Self::tags`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbeddedNip94Event {
    /// NIP-94 tag rows (`[head, arg1, arg2, …]`).
    pub tags: Vec<Vec<String>>,
    /// NIP-94 content (free-form caption).
    #[serde(default)]
    pub content: String,
}

// =============================================================================
// Upload form-field helpers
// =============================================================================

/// Typed view of the optional NIP-96 multipart upload form fields.
///
/// The `file` field is the actual upload payload and lives at the
/// HTTP layer, so it is **not** modelled here. This struct exists
/// to keep the rest of the spec-defined columns spell-checked at
/// compile time.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Nip96UploadFields {
    /// `caption` — loose description (RECOMMENDED).
    pub caption: Option<String>,
    /// `expiration` — UNIX seconds, empty string for "forever".
    pub expiration: Option<u64>,
    /// `size` — declared byte count (lets server short-circuit
    /// uploads above its limit).
    pub size: Option<u64>,
    /// `alt` — strict alt text (RECOMMENDED for accessibility).
    pub alt: Option<String>,
    /// `media_type` — `"avatar"` or `"banner"` for special
    /// handling, omitted for normal uploads.
    pub media_type: Option<String>,
    /// `content_type` — MIME type hint, lets server short-circuit
    /// unsupported types.
    pub content_type: Option<String>,
    /// `no_transform` — when `true`, asks the server to keep the
    /// file byte-identical (used for cross-server replication so
    /// the resulting digest matches across mirrors).
    pub no_transform: bool,
}

impl Nip96UploadFields {
    /// Render the fields as `(name, value)` pairs ready to feed
    /// into a multipart-form builder.
    ///
    /// Boolean values are emitted as `"true"` per the spec.
    #[must_use]
    pub fn to_form_pairs(&self) -> Vec<(&'static str, String)> {
        let mut out: Vec<(&'static str, String)> = Vec::new();
        if let Some(caption) = &self.caption {
            out.push(("caption", caption.clone()));
        }
        if let Some(expiration) = self.expiration {
            out.push(("expiration", expiration.to_string()));
        }
        if let Some(size) = self.size {
            out.push(("size", size.to_string()));
        }
        if let Some(alt) = &self.alt {
            out.push(("alt", alt.clone()));
        }
        if let Some(media_type) = &self.media_type {
            out.push(("media_type", media_type.clone()));
        }
        if let Some(content_type) = &self.content_type {
            out.push(("content_type", content_type.clone()));
        }
        if self.no_transform {
            out.push(("no_transform", "true".to_owned()));
        }
        out
    }
}

// =============================================================================
// EventBuilder integration
// =============================================================================

impl EventBuilder {
    /// Author a NIP-96 `kind: 10096` user file-server list event
    /// from a typed [`FileServerList`].
    #[must_use]
    pub fn nip96_file_servers(list: &FileServerList) -> Self {
        let mut builder = Self::new(KIND_FILE_SERVER_LIST, "");
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

    #[test]
    fn server_list_round_trips_through_event() {
        let list = FileServerList::new([
            Url::parse("https://file.server.one").unwrap(),
            Url::parse("https://file.server.two").unwrap(),
        ]);
        let event = EventBuilder::nip96_file_servers(&list)
            .sign_with_keys(&keys())
            .unwrap();
        assert_eq!(event.kind, KIND_FILE_SERVER_LIST);
        let recovered = FileServerList::from_event(&event).unwrap();
        assert_eq!(recovered, list);
    }

    #[test]
    fn server_list_from_event_rejects_wrong_kind() {
        let event = EventBuilder::text_note("nope")
            .sign_with_keys(&keys())
            .unwrap();
        assert!(matches!(
            FileServerList::from_event(&event),
            Err(Nip96Error::WrongKind(_)),
        ));
    }

    #[test]
    fn well_known_config_round_trips_through_json() {
        let json = r#"{
            "api_url": "https://your-file-server.example/custom-api-path",
            "download_url": "https://a-cdn.example/a-path",
            "supported_nips": [96, 98],
            "tos_url": "https://your-file-server.example/terms-of-service",
            "content_types": ["image/jpeg", "video/webm", "audio/*"],
            "plans": {
                "free": {
                    "name": "Free Tier",
                    "is_nip98_required": true,
                    "url": "https://example/plans/free",
                    "max_byte_size": 10485760,
                    "file_expiration": [14, 90],
                    "media_transformations": {
                        "image": ["resizing"]
                    }
                }
            }
        }"#;
        let config: Nip96ServerConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            config.api_url,
            "https://your-file-server.example/custom-api-path"
        );
        let plans = config.plans.as_ref().unwrap();
        let free = plans.get("free").unwrap();
        assert_eq!(free.name, "Free Tier");
        assert!(free.is_nip98_required);
        assert_eq!(free.max_byte_size, Some(10_485_760));
        assert_eq!(free.file_expiration, Some([14, 90]));

        let reserialised = serde_json::to_string(&config).unwrap();
        let round_tripped: Nip96ServerConfig = serde_json::from_str(&reserialised).unwrap();
        assert_eq!(round_tripped, config);
    }

    #[test]
    fn well_known_config_supports_delegated_form() {
        let json = r#"{
            "api_url": "",
            "delegated_to_url": "https://your-file-server.example"
        }"#;
        let config: Nip96ServerConfig = serde_json::from_str(json).unwrap();
        assert!(config.api_url.is_empty());
        assert_eq!(
            config.delegated_to_url.as_deref(),
            Some("https://your-file-server.example"),
        );
    }

    #[test]
    fn plan_default_is_nip98_required_is_true() {
        let json = r#"{ "name": "Bare", "url": "https://example" }"#;
        let plan: Nip96Plan = serde_json::from_str(json).unwrap();
        assert!(plan.is_nip98_required);
    }

    #[test]
    fn upload_response_success_round_trips_through_json() {
        let json = r#"{
            "status": "success",
            "message": "Upload successful.",
            "nip94_event": {
                "tags": [
                    ["url", "https://srv.example/abc.png"],
                    ["ox", "719171db19525d9d08dd69cb716a18158a249b7b3b3ec4bbdec5698dca104b7b"],
                    ["x", "543244319525d9d08dd69cb716a18158a249b7b3b3ec4bbde5435543acb34443"],
                    ["m", "image/png"],
                    ["dim", "800x600"]
                ],
                "content": ""
            }
        }"#;
        let response: Nip96UploadResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.status, Nip96Status::Success);
        let embedded = response.nip94_event.as_ref().unwrap();
        assert_eq!(embedded.tags.len(), 5);
        assert_eq!(embedded.tags[0], vec!["url", "https://srv.example/abc.png"]);

        let reserialised = serde_json::to_string(&response).unwrap();
        let round_tripped: Nip96UploadResponse = serde_json::from_str(&reserialised).unwrap();
        assert_eq!(round_tripped, response);
    }

    #[test]
    fn upload_response_processing_carries_percentage() {
        let json = r#"{
            "status": "processing",
            "message": "Processing. Please check again later for updated status.",
            "percentage": 15
        }"#;
        let response: Nip96UploadResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.status, Nip96Status::Processing);
        assert_eq!(response.percentage, Some(15));
        assert!(response.nip94_event.is_none());
    }

    #[test]
    fn upload_fields_emit_only_set_pairs() {
        let fields = Nip96UploadFields {
            caption: Some("a meme".to_owned()),
            alt: Some("a meme that makes you laugh".to_owned()),
            no_transform: true,
            ..Default::default()
        };
        let pairs = fields.to_form_pairs();
        assert_eq!(
            pairs,
            vec![
                ("caption", "a meme".to_owned()),
                ("alt", "a meme that makes you laugh".to_owned()),
                ("no_transform", "true".to_owned()),
            ],
        );
    }
}
