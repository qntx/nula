//! NIP-17 private direct messages — SDK facade.
//!
//! [`nula_core::nips::nip17`] ships the wire-level primitives (build
//! kind-14 rumor → seal → gift wrap, parse kind 10050 DM-relays
//! list). This module wires those primitives to the
//! [`crate::Client`]: it picks the recipient list, drives the
//! per-recipient gift-wrap loop, and ships every wrap through the
//! relay pool.
//!
//! # Pipeline (`Client::send_private_msg`)
//!
//! ```text
//! sender_keys + recipients + content
//!         |
//!         v
//!   build kind-14 rumor (unsigned)
//!         |
//!         v
//!   for every recipient (incl. sender's pubkey):
//!     seal(rumor) + gift_wrap(seal) + send_event(wrap)
//!         |
//!         v
//!   merged Output<Vec<EventId>>
//! ```
//!
//! # Why explicit `&Keys` instead of the configured signer?
//!
//! NIP-59 sealing requires a *Schnorr-signing* key **and** the
//! *NIP-44 ECDH secret* for the sender. The SDK's
//! [`nula_core::NostrSigner`] abstraction is dyn-safe and only
//! exposes those two through async methods (`sign_event` /
//! `nip44_encrypt`), but the upstream gift-wrap helpers want a
//! synchronous [`Keys`]. Forcing a [`Keys`] argument on the SDK
//! surface is the simplest workable contract:
//!
//! - For local key-pair signers, callers already have a
//!   [`Keys`] in hand; passing it twice is cheap.
//! - For NIP-46 / hardware signers, the secret is intentionally
//!   inaccessible — those signers cannot perform NIP-17 today, and
//!   spec work is required upstream before they ever could.

use std::time::Duration;

use nula_core::event::{Event, EventId, Kind, UnsignedEvent};
use nula_core::key::Keys;
use nula_core::nips::nip17::{self as core_nip17, Recipient, ReplyTo};
use nula_core::nips::nip59;
use nula_core::types::RelayUrl;
use nula_relay_pool::Output;

use crate::client::Client;
use crate::error::Error;
use crate::util::{IntoRelayUrl, collect_relay_urls};

impl Client {
    /// Build, gift-wrap, and broadcast a NIP-17 chat-message rumor
    /// to every entry in `recipients`, plus an additional self-wrap
    /// so `sender_keys`'s public key receives the same rumor.
    ///
    /// Returns the merged [`Output`] across every per-relay
    /// publish. When `recipients` is empty the call short-circuits
    /// to [`Error::Nip17`] with [`core_nip17::Nip17Error::NoRecipients`].
    ///
    /// # Errors
    ///
    /// - [`Error::Nip17`] for empty recipient lists or any failure
    ///   from the gift-wrap pipeline.
    /// - [`Error::Pool`] from the underlying `send_event` call.
    pub async fn send_private_msg(
        &self,
        sender_keys: &Keys,
        recipients: &[Recipient],
        message: impl Into<String>,
        reply_to: Option<&ReplyTo>,
    ) -> Result<Output<Vec<EventId>>, Error> {
        let wraps = build_wraps(sender_keys, recipients, message, reply_to)?;
        send_wraps(self, wraps, None).await
    }

    /// Variant of [`Self::send_private_msg`] restricted to a
    /// caller-chosen relay set.
    ///
    /// # Errors
    ///
    /// In addition to the errors documented on
    /// [`Self::send_private_msg`]:
    ///
    /// - [`Error::RelayUrl`] for any unparseable url in `urls`.
    pub async fn send_private_msg_to<I, U>(
        &self,
        urls: I,
        sender_keys: &Keys,
        recipients: &[Recipient],
        message: impl Into<String>,
        reply_to: Option<&ReplyTo>,
    ) -> Result<Output<Vec<EventId>>, Error>
    where
        I: IntoIterator<Item = U>,
        U: IntoRelayUrl,
    {
        let urls = collect_relay_urls(urls)?;
        let wraps = build_wraps(sender_keys, recipients, message, reply_to)?;
        send_wraps(self, wraps, Some(urls)).await
    }

    /// Pull every kind-1059 gift wrap addressed to
    /// `receiver_keys`'s public key out of the configured pool and
    /// return the decrypted [`UnsignedEvent`] rumors plus the outer
    /// gift-wrap event ids.
    ///
    /// Wraps that fail to decrypt (key mismatch, tampered seal,
    /// pubkey forgery) are silently dropped: NIP-17 explicitly
    /// allows relays to keep wraps the receiver cannot read, so
    /// surfacing every failure as an error would be too noisy.
    ///
    /// `since` filters out gift wraps whose outer `created_at` is
    /// older than the supplied [`nula_core::Timestamp`]. Pass `None` to fetch
    /// the full history within `timeout`.
    ///
    /// # Errors
    ///
    /// - [`Error::Pool`] propagated from `fetch_events`.
    pub async fn receive_private_msgs(
        &self,
        receiver_keys: &Keys,
        since: Option<nula_core::Timestamp>,
        timeout: Option<Duration>,
    ) -> Result<Vec<ReceivedPrivateMsg>, Error> {
        let mut filter = nula_core::Filter::new()
            .kind(Kind::GIFT_WRAP)
            .pubkey(*receiver_keys.public_key());
        if let Some(ts) = since {
            filter = filter.since(ts);
        }
        let events = self.fetch_events(filter, timeout).await?;
        let mut out = Vec::with_capacity(events.len());
        for wrap in events {
            let wrap_id = wrap.id;
            // Per NIP-17 we drop unreadable wraps silently.
            if let Ok(rumor) = core_nip17::unwrap_dm_payload(receiver_keys, &wrap) {
                out.push(ReceivedPrivateMsg {
                    wrap_id,
                    wrap_pubkey: wrap.pubkey,
                    wrap_created_at: wrap.created_at,
                    rumor,
                });
            }
        }
        Ok(out)
    }

    /// Build a NIP-17 kind-10050 DM-relays event, sign it via the
    /// configured [`crate::Client::sign_event_builder`] surface,
    /// and broadcast it through the pool.
    ///
    /// Equivalent to calling
    /// [`core_nip17::build_dm_relays_event`] →
    /// [`Self::sign_event_builder`] → [`Self::send_event`].
    ///
    /// # Errors
    ///
    /// - [`Error::SignerNotConfigured`] when the client has no
    ///   signer attached.
    /// - [`Error::Pool`] from the underlying broadcast.
    pub async fn set_dm_relays(&self, relays: &[RelayUrl]) -> Result<Output<EventId>, Error> {
        let builder = core_nip17::build_dm_relays_event(relays);
        self.send_event_builder(builder).await
    }

    /// Fetch the latest kind-10050 DM-relays event for `pubkey` and
    /// parse its `relay` tags into a `Vec<RelayUrl>`.
    ///
    /// Returns `Ok(None)` when no kind-10050 event is found within
    /// the timeout.
    ///
    /// # Errors
    ///
    /// - [`Error::Pool`] propagated from `fetch_events`.
    /// - [`Error::Nip17`] when the published event is malformed
    ///   (e.g. wrong kind or unparseable relay url).
    pub async fn get_dm_relays(
        &self,
        pubkey: &nula_core::PublicKey,
        timeout: Option<Duration>,
    ) -> Result<Option<Vec<RelayUrl>>, Error> {
        let filter = nula_core::Filter::new()
            .kind(Kind::DM_RELAYS)
            .author(*pubkey)
            .limit(1);
        let events = self.fetch_events(filter, timeout).await?;
        let Some(event) = events.into_iter().next() else {
            return Ok(None);
        };
        let relays = core_nip17::parse_dm_relays_event(&event).map_err(Error::Nip17)?;
        Ok(Some(relays))
    }
}

/// One decrypted gift wrap plus the outer envelope coordinates the
/// caller needs to dedupe / acknowledge it.
#[derive(Debug, Clone)]
pub struct ReceivedPrivateMsg {
    /// Outer kind-1059 wrap event id.
    pub wrap_id: EventId,
    /// The throw-away pubkey the relay observed on the wrap. Has
    /// no relation to the real sender; useful only for relay-side
    /// diagnostics.
    pub wrap_pubkey: nula_core::PublicKey,
    /// Wrap-level `created_at` (randomised per NIP-59).
    pub wrap_created_at: nula_core::Timestamp,
    /// The decrypted, **unsigned** inner rumor. `rumor.pubkey` is
    /// the real sender. Spec mandates the rumor stay unsigned for
    /// deniability.
    pub rumor: UnsignedEvent,
}

/// Build the per-recipient gift wraps for a NIP-17 chat message.
///
/// Pulled out of [`Client::send_private_msg`] so the
/// `_to` variant can reuse the same rumor / seal / wrap pipeline
/// without duplication.
fn build_wraps(
    sender_keys: &Keys,
    recipients: &[Recipient],
    message: impl Into<String>,
    reply_to: Option<&ReplyTo>,
) -> Result<Vec<Event>, Error> {
    if recipients.is_empty() {
        return Err(Error::Nip17(core_nip17::Nip17Error::NoRecipients));
    }
    let timestamps = nip59::Timestamps::random_past()
        .map_err(|e| Error::Nip17(core_nip17::Nip17Error::Wrap(e)))?;
    let rumor = core_nip17::build_chat_message_rumor(
        sender_keys,
        recipients,
        message,
        timestamps.rumor,
        None,
        reply_to,
    );
    // `wrap_for_many` already prepends a self-wrap so the sender
    // keeps a copy of every outgoing rumor (NIP-17 §"Sender keeps a
    // copy"). We do not need an extra `wrap_for` call.
    core_nip17::wrap_for_many(sender_keys, recipients, &rumor, timestamps).map_err(Error::Nip17)
}

/// Ship every wrap through the pool. When `urls` is `Some`, every
/// wrap goes only to that subset; otherwise the pool's
/// WRITE-capable relays receive each wrap.
async fn send_wraps(
    client: &Client,
    wraps: Vec<Event>,
    urls: Option<Vec<RelayUrl>>,
) -> Result<Output<Vec<EventId>>, Error> {
    let mut merged = Output::<Vec<EventId>> {
        value: Vec::with_capacity(wraps.len()),
        ..Output::default()
    };
    for wrap in wraps {
        let per_wrap = match urls.as_ref() {
            Some(urls) => client.send_event_to(urls.clone(), wrap).await?,
            None => client.send_event(wrap).await?,
        };
        merged.value.push(per_wrap.value);
        merged.success.extend(per_wrap.success);
        for (url, reason) in per_wrap.failed {
            merged.failed.insert(url, reason);
        }
    }
    Ok(merged)
}
