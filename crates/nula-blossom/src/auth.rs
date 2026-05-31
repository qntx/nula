//! NIP-24242 Blossom authorization events.
//!
//! Authenticated Blossom endpoints expect an `Authorization: Nostr
//! <base64>` header whose payload is a base64-encoded, signed
//! `kind: 24242` event. The event carries:
//!
//! - a `t` tag naming the verb (`get` / `upload` / `list` / `delete`),
//! - a mandatory `expiration` tag (a NIP-40 deadline), and
//! - zero or more `x` tags pinning the blob sha256(s) the action targets.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use nula_core::JsonUtil;
use nula_core::event::{Alphabet, SingleLetterTag};
use nula_core::signer::NostrSigner;
use nula_core::{EventBuilder, Kind, Tag, TagKind, Timestamp};

use crate::error::Error;

/// `kind: 24242` — Blossom authorization event.
pub const KIND_AUTH: Kind = Kind::new(24_242);

/// The verb a Blossom authorization event grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlossomVerb {
    /// Retrieve a blob (`GET /<sha256>`).
    Get,
    /// Upload a blob (`PUT /upload`).
    Upload,
    /// List a pubkey's blobs (`GET /list/<pubkey>`).
    List,
    /// Delete a blob (`DELETE /<sha256>`).
    Delete,
}

impl BlossomVerb {
    /// The wire value used in the `t` tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Upload => "upload",
            Self::List => "list",
            Self::Delete => "delete",
        }
    }
}

/// Build and sign a `kind: 24242` event, then encode it as the value of
/// an `Authorization: Nostr <base64>` header.
pub(crate) async fn authorization_header(
    signer: &dyn NostrSigner,
    verb: BlossomVerb,
    hashes: &[String],
    description: &str,
    ttl_secs: u64,
) -> Result<String, Error> {
    let pubkey = signer.get_public_key().await?;
    let expiration = Timestamp::now()? + ttl_secs;

    let mut builder = EventBuilder::new(KIND_AUTH, description)
        .tag(verb_tag(verb))
        .expiration(expiration);
    for hash in hashes {
        builder = builder.tag(hash_tag(hash));
    }

    let unsigned = builder.build_unsigned(pubkey)?;
    let event = signer.sign_event(unsigned).await?;
    let json = event.try_to_json().map_err(Error::json)?;
    Ok(format!("Nostr {}", BASE64.encode(json)))
}

fn verb_tag(verb: BlossomVerb) -> Tag {
    let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::T));
    Tag::with(&head, [verb.as_str()])
}

fn hash_tag(hash: &str) -> Tag {
    let head = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::X));
    Tag::with(&head, [hash])
}

#[cfg(test)]
mod tests {
    use nula_core::event::Alphabet;
    use nula_core::{Event, Keys};

    use super::*;

    #[tokio::test]
    async fn header_wraps_signed_kind_24242_event() {
        let keys = Keys::generate().expect("generate keys");
        let hash = "aa".repeat(32); // 64 lowercase hex chars
        let header = authorization_header(
            &keys,
            BlossomVerb::Upload,
            std::slice::from_ref(&hash),
            "Upload blob",
            60,
        )
        .await
        .expect("build auth header");

        let encoded = header.strip_prefix("Nostr ").expect("`Nostr ` prefix");
        let json = BASE64.decode(encoded).expect("base64");
        let event = Event::from_json(String::from_utf8(json).expect("utf8")).expect("parse event");

        event.verify().expect("valid signature");
        assert_eq!(event.kind, KIND_AUTH);
        assert_eq!(event.pubkey, *keys.public_key());

        let verb = event
            .tags
            .find_letter(Alphabet::T)
            .next()
            .and_then(|t| t.content());
        assert_eq!(verb, Some("upload"));

        let pinned = event
            .tags
            .find_letter(Alphabet::X)
            .next()
            .and_then(|t| t.content());
        assert_eq!(pinned, Some(hash.as_str()));

        assert!(event.tags.expiration().is_some(), "expiration tag present");
    }
}
