// Copyright (c) 2026 QNTX <https://qntx.fun>
// Distributed under the MIT or Apache-2.0 license.

//! [NIP-17] Private Direct Messages.
//!
//! NIP-17 layers a *chat-message rumor* (kind 14) on top of the NIP-59
//! gift-wrap envelope. Each message is wrapped once per recipient *and*
//! once for the sender so both sides keep a copy. Per spec the inner
//! rumor is **never signed**: omitting the signature gives the sender
//! plausible deniability if the rumor leaks.
//!
//! # Pipeline
//!
//! ```text
//! sender ─────────────────┐
//!                         ▼
//!     build kind-14 rumor (unsigned, p-tags carry recipients)
//!                         │
//!         ┌───────────────┼───────────────────────┐
//!         ▼               ▼                       ▼
//!    seal+wrap to    seal+wrap to           seal+wrap to
//!    recipient #1    recipient #2     …    sender's own pk
//! ```
//!
//! The sender keeps a self-wrap so they can reconstruct their outgoing
//! history without storing plaintext locally; clients SHOULD publish
//! that copy to the sender's own [`Kind::DM_RELAYS`] preferred relays.
//!
//! # DM relays
//!
//! Kind `10050` advertises the relays a user wants gift-wrapped DMs
//! delivered to. Use [`build_dm_relays_event`] to produce the
//! replaceable list and [`parse_dm_relays_event`] to consume one.
//!
//! [NIP-17]: https://github.com/nostr-protocol/nips/blob/master/17.md

use thiserror::Error;

use crate::event::{
    Alphabet, Event, EventBuilder, Kind, SingleLetterTag, Tag, TagKind, Tags, UnsignedEvent,
};
use crate::key::{Keys, PublicKey};
use crate::nip59;
use crate::types::{RelayUrl, Timestamp};

/// Wire name of the conversation-title tag (NIP-17 §Chat Message).
const SUBJECT_TAG: &str = "subject";
/// Wire name of the reply-marker tag value (NIP-17 §Chat Message).
const REPLY_MARKER: &str = "reply";

/// Errors raised by the NIP-17 helpers.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Caller supplied an empty recipient list.
    ///
    /// NIP-17 only makes sense with at least one peer; even a "self
    /// note" pattern goes through this entry point with the sender's
    /// own pubkey in the recipient list.
    #[error("recipients list must not be empty")]
    NoRecipients,
    /// The DM-relays event was not kind 10050.
    #[error("expected kind 10050, got {0}")]
    UnexpectedKind(u16),
    /// A `relay` tag had no URL value.
    #[error("`relay` tag is missing the URL value")]
    MissingRelayUrl,
    /// A `relay` tag's URL did not parse.
    #[error(transparent)]
    InvalidRelayUrl(#[from] crate::types::RelayUrlError),
    /// Forwarded gift-wrap error.
    #[error(transparent)]
    Wrap(#[from] nip59::Error),
}

/// Recipient of a private message: a public key plus an optional relay
/// hint that gets baked into the inner rumor's `p` tag.
#[derive(Debug, Clone)]
pub struct Recipient<'a> {
    /// Recipient's BIP-340 x-only public key.
    pub public_key: PublicKey,
    /// Optional relay hint surfaced as the third element of the `p` tag.
    pub relay_hint: Option<&'a RelayUrl>,
}

impl<'a> Recipient<'a> {
    /// Build a recipient with no relay hint.
    #[must_use]
    pub const fn new(public_key: PublicKey) -> Self {
        Self {
            public_key,
            relay_hint: None,
        }
    }

    /// Attach a relay hint.
    #[must_use]
    pub const fn with_relay_hint(mut self, relay: &'a RelayUrl) -> Self {
        self.relay_hint = Some(relay);
        self
    }
}

/// Optional reply pointer: a NIP-10 `e` tag value built into the rumor.
#[derive(Debug, Clone)]
pub struct ReplyTo<'a> {
    /// Event id this message is a reply to.
    pub event_id: crate::event::EventId,
    /// Optional relay hint surfaced as the third element of the `e` tag.
    pub relay_hint: Option<&'a RelayUrl>,
}

/// Build the kind-14 chat-message *rumor* (per [NIP-17 §Chat Message]).
///
/// `recipients` populates one `["p", <pubkey>, <relay_hint>?]` tag per
/// entry, in the order supplied. Optional `subject` adds a single
/// `["subject", <title>]` tag. Optional `reply_to` adds a single
/// `["e", <id>, <relay_hint>, "reply"]` tag.
///
/// The returned [`UnsignedEvent`] is **never signed** — that is the
/// whole point of the deniable design. Pass it directly to
/// [`wrap_for`] / [`wrap_for_many`].
///
/// [NIP-17 §Chat Message]: https://github.com/nostr-protocol/nips/blob/master/17.md#chat-message
#[must_use]
pub fn build_chat_message_rumor(
    sender: &Keys,
    recipients: &[Recipient<'_>],
    message: impl Into<String>,
    created_at: Timestamp,
    subject: Option<&str>,
    reply_to: Option<&ReplyTo<'_>>,
) -> UnsignedEvent {
    let p_kind = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::P));
    let e_kind = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::E));
    let subject_kind = TagKind::from_wire(SUBJECT_TAG);

    let mut tags: Vec<Tag> = Vec::with_capacity(
        recipients.len() + usize::from(subject.is_some()) + usize::from(reply_to.is_some()),
    );

    for recipient in recipients {
        let values = recipient.relay_hint.map_or_else(
            || vec![recipient.public_key.to_hex()],
            |url| vec![recipient.public_key.to_hex(), url.as_str().to_owned()],
        );
        tags.push(Tag::with(&p_kind, values));
    }

    if let Some(reply) = reply_to {
        // Spec: `["e", <id>, <relay-url>, "reply"]`. Use the empty
        // string when no relay hint is available so the marker stays at
        // index 3.
        let relay = reply
            .relay_hint
            .map_or_else(String::new, |url| url.as_str().to_owned());
        tags.push(Tag::with(
            &e_kind,
            [reply.event_id.to_hex(), relay, REPLY_MARKER.to_owned()],
        ));
    }

    if let Some(title) = subject {
        tags.push(Tag::with(&subject_kind, [title.to_owned()]));
    }

    UnsignedEvent::new(
        *sender.public_key(),
        created_at,
        Kind::PRIVATE_DIRECT_MESSAGE,
        Tags::from_vec(tags),
        message,
    )
}

/// Build one gift-wrapped event per recipient *and* one for the sender.
///
/// Returns `Vec<Event>` in the order `[wrap_for_self, wrap_for_recipient_0, …]`.
/// Each wrap is fully signed by an ephemeral key; relays only see the
/// outer envelope and the recipient's `p` tag.
///
/// `relay_hints` parameter on each [`Recipient`] is reused on the gift
/// wrap's `p` tag (so relays can route it). If you do not have a hint,
/// pass `None` on the Recipient.
///
/// # Errors
///
/// Returns [`Error::NoRecipients`] if `recipients` is empty, or
/// [`Error::Wrap`] for any underlying NIP-59 / NIP-44 failure.
pub fn wrap_for_many(
    sender: &Keys,
    recipients: &[Recipient<'_>],
    rumor: &UnsignedEvent,
    timestamps: nip59::Timestamps,
) -> Result<Vec<Event>, Error> {
    if recipients.is_empty() {
        return Err(Error::NoRecipients);
    }

    let mut wraps = Vec::with_capacity(recipients.len() + 1);

    // Self-wrap: lets the sender reconstruct outgoing history without
    // keeping a separate plaintext archive.
    let self_seal = nip59::create_seal(sender, sender.public_key(), rumor, timestamps.seal)?;
    wraps.push(nip59::create_gift_wrap(
        &self_seal,
        sender.public_key(),
        None,
        timestamps.wrap,
    )?);

    // One wrap per peer.
    for recipient in recipients {
        let seal = nip59::create_seal(sender, &recipient.public_key, rumor, timestamps.seal)?;
        wraps.push(nip59::create_gift_wrap(
            &seal,
            &recipient.public_key,
            recipient.relay_hint,
            timestamps.wrap,
        )?);
    }

    Ok(wraps)
}

/// Build a single gift-wrapped event for one recipient.
///
/// Convenience wrapper around [`wrap_for_many`] for callers that want
/// the simple two-party case without the self-wrap. **No** copy is
/// produced for the sender — call [`wrap_for_many`] when you want one.
///
/// # Errors
///
/// See [`wrap_for_many`].
pub fn wrap_for(
    sender: &Keys,
    recipient: &Recipient<'_>,
    rumor: &UnsignedEvent,
    timestamps: nip59::Timestamps,
) -> Result<Event, Error> {
    let seal = nip59::create_seal(sender, &recipient.public_key, rumor, timestamps.seal)?;
    Ok(nip59::create_gift_wrap(
        &seal,
        &recipient.public_key,
        recipient.relay_hint,
        timestamps.wrap,
    )?)
}

/// Peel a gift-wrapped event and recover the inner kind-14 rumor.
///
/// Convenience alias for [`nip59::unwrap`] that asserts the rumor's
/// kind is `14` after unwrapping (kind `15` file messages and kind `7`
/// reactions are valid NIP-17 payloads too, see [`unwrap_dm_payload`]).
///
/// # Errors
///
/// Returns [`Error::UnexpectedKind`] when the rumor is not kind 14;
/// otherwise see [`nip59::unwrap`].
pub fn unwrap_chat_message(recipient: &Keys, gift_wrap: &Event) -> Result<UnsignedEvent, Error> {
    let rumor = nip59::unwrap(recipient, gift_wrap).map_err(Error::Wrap)?;
    if rumor.kind != Kind::PRIVATE_DIRECT_MESSAGE {
        return Err(Error::UnexpectedKind(rumor.kind.as_u16()));
    }
    Ok(rumor)
}

/// Peel a gift-wrapped event and accept any NIP-17 payload kind.
///
/// NIP-17 §Chat Rooms allows kind 14 (chat), kind 15 (file message),
/// and kind 7 (reaction) inside the wrap. Use this entry point when
/// the caller wants to handle the full set without manual kind
/// dispatch.
///
/// # Errors
///
/// See [`nip59::unwrap`]. Unlike [`unwrap_chat_message`] this function
/// does not assert the rumor's kind; callers should match on
/// `rumor.kind` themselves.
pub fn unwrap_dm_payload(recipient: &Keys, gift_wrap: &Event) -> Result<UnsignedEvent, Error> {
    nip59::unwrap(recipient, gift_wrap).map_err(Error::Wrap)
}

/// Build a [`Kind::DM_RELAYS`] (10050) replaceable event listing the
/// relays the author wants NIP-17 gift wraps delivered to.
///
/// The event's content is empty per spec; relays are encoded as one
/// `["relay", <url>]` tag each. The caller signs the resulting builder
/// with their own [`Keys`].
///
/// `relays` is taken in the order supplied; clients SHOULD list the
/// most-preferred relay first.
#[must_use]
pub fn build_dm_relays_event(relays: &[RelayUrl]) -> EventBuilder {
    let kind = TagKind::from_wire("relay");
    let tags: Vec<Tag> = relays
        .iter()
        .map(|url| Tag::with(&kind, [url.as_str().to_owned()]))
        .collect();
    EventBuilder::new(Kind::DM_RELAYS, "").tags(tags)
}

/// Parse a kind-10050 event into the list of relays the author
/// advertises for NIP-17 delivery.
///
/// `relay` tags whose URL fails to parse are surfaced as
/// [`Error::InvalidRelayUrl`] rather than silently dropped — relay
/// lists are a privacy-sensitive signal and silent corruption could
/// route DMs to the wrong server.
///
/// # Errors
///
/// Returns [`Error::UnexpectedKind`] if the event is not kind 10050
/// and [`Error::InvalidRelayUrl`] / [`Error::MissingRelayUrl`] for
/// malformed `relay` tags.
pub fn parse_dm_relays_event(event: &Event) -> Result<Vec<RelayUrl>, Error> {
    if event.kind != Kind::DM_RELAYS {
        return Err(Error::UnexpectedKind(event.kind.as_u16()));
    }
    let relay_kind = TagKind::from_wire("relay");
    let mut out = Vec::new();
    for tag in &event.tags {
        if tag.kind() != relay_kind {
            // Forward-compat: ignore non-`relay` tags.
            continue;
        }
        let value = tag.values().get(1).ok_or(Error::MissingRelayUrl)?;
        out.push(RelayUrl::parse(value)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;
    use crate::event::EventId;

    fn keys_alice() -> Keys {
        Keys::parse("000000000000000000000000000000000000000000000000000000000000a1ce").unwrap()
    }

    fn keys_bob() -> Keys {
        Keys::parse("00000000000000000000000000000000000000000000000000000000000000b0").unwrap()
    }

    fn keys_carol() -> Keys {
        Keys::parse("00000000000000000000000000000000000000000000000000000000000ca800").unwrap()
    }

    #[test]
    fn rumor_carries_p_tag_per_recipient() {
        let alice = keys_alice();
        let bob = keys_bob();
        let carol = keys_carol();
        let now = Timestamp::from_secs(1_700_000_000);

        let rumor = build_chat_message_rumor(
            &alice,
            &[
                Recipient::new(*bob.public_key()),
                Recipient::new(*carol.public_key()),
            ],
            "hello",
            now,
            None,
            None,
        );

        let p_kind = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::P));
        let p_tags: Vec<&Tag> = rumor.tags.iter().filter(|t| t.kind() == p_kind).collect();
        assert_eq!(p_tags.len(), 2);
        assert_eq!(
            p_tags[0].values().get(1).unwrap(),
            &bob.public_key().to_hex()
        );
        assert_eq!(
            p_tags[1].values().get(1).unwrap(),
            &carol.public_key().to_hex()
        );
        assert_eq!(rumor.kind, Kind::PRIVATE_DIRECT_MESSAGE);
        assert_eq!(rumor.content, "hello");
    }

    #[test]
    fn rumor_carries_subject_and_reply_tags() {
        let alice = keys_alice();
        let bob = keys_bob();
        let now = Timestamp::from_secs(1_700_000_000);
        let parent = EventId::from_byte_array([0xab; 32]);
        let relay = RelayUrl::parse("wss://relay.example/").unwrap();

        let rumor = build_chat_message_rumor(
            &alice,
            &[Recipient::new(*bob.public_key()).with_relay_hint(&relay)],
            "thread reply",
            now,
            Some("daily standup"),
            Some(&ReplyTo {
                event_id: parent,
                relay_hint: Some(&relay),
            }),
        );

        let subject_tag = rumor
            .tags
            .find_first(&TagKind::from_wire(SUBJECT_TAG))
            .unwrap();
        assert_eq!(subject_tag.values().get(1).unwrap(), "daily standup");

        let e_kind = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::E));
        let e_tag = rumor.tags.find_first(&e_kind).unwrap();
        let e_values = e_tag.values();
        assert_eq!(e_values.get(1).unwrap(), &parent.to_hex());
        assert_eq!(e_values.get(2).unwrap(), relay.as_str());
        assert_eq!(e_values.get(3).unwrap(), REPLY_MARKER);
    }

    #[test]
    fn wrap_for_many_produces_self_plus_recipient_copies() {
        let alice = keys_alice();
        let bob = keys_bob();
        let carol = keys_carol();
        let now = Timestamp::from_secs(1_700_000_000);
        let rumor = build_chat_message_rumor(
            &alice,
            &[
                Recipient::new(*bob.public_key()),
                Recipient::new(*carol.public_key()),
            ],
            "hi all",
            now,
            None,
            None,
        );

        let wraps = wrap_for_many(
            &alice,
            &[
                Recipient::new(*bob.public_key()),
                Recipient::new(*carol.public_key()),
            ],
            &rumor,
            nip59::Timestamps::all_at(now),
        )
        .unwrap();

        // 1 self + 2 recipients
        assert_eq!(wraps.len(), 3);

        // Alice can decrypt the self-wrap.
        let recovered_self = unwrap_chat_message(&alice, &wraps[0]).unwrap();
        assert_eq!(recovered_self.content, "hi all");

        // Bob can decrypt his copy.
        let recovered_bob = unwrap_chat_message(&bob, &wraps[1]).unwrap();
        assert_eq!(recovered_bob.content, "hi all");

        // Carol can decrypt hers.
        let recovered_carol = unwrap_chat_message(&carol, &wraps[2]).unwrap();
        assert_eq!(recovered_carol.content, "hi all");
    }

    #[test]
    fn wrap_for_many_rejects_empty_recipients() {
        let alice = keys_alice();
        let now = Timestamp::from_secs(1_700_000_000);
        let rumor = build_chat_message_rumor(&alice, &[], "ghost", now, None, None);
        let err = wrap_for_many(&alice, &[], &rumor, nip59::Timestamps::all_at(now)).unwrap_err();
        assert!(matches!(err, Error::NoRecipients));
    }

    #[test]
    fn unwrap_chat_message_rejects_wrong_inner_kind() {
        let alice = keys_alice();
        let bob = keys_bob();
        let now = Timestamp::from_secs(1_700_000_000);

        // Sneak a kind-1 rumor through the gift wrap.
        let rumor = UnsignedEvent::new(
            *alice.public_key(),
            now,
            Kind::TEXT_NOTE,
            Tags::new(),
            "not a DM",
        );
        let seal = nip59::create_seal(&alice, bob.public_key(), &rumor, now).unwrap();
        let wrap = nip59::create_gift_wrap(&seal, bob.public_key(), None, now).unwrap();

        let err = unwrap_chat_message(&bob, &wrap).unwrap_err();
        assert!(matches!(err, Error::UnexpectedKind(1)));

        // The same payload survives the more permissive entry point.
        let recovered = unwrap_dm_payload(&bob, &wrap).unwrap();
        assert_eq!(recovered.kind, Kind::TEXT_NOTE);
    }

    #[test]
    fn dm_relays_round_trip() {
        let alice = keys_alice();
        let relays = vec![
            RelayUrl::parse("wss://inbox.nostr.example/").unwrap(),
            RelayUrl::parse("wss://dm.nostr.example/").unwrap(),
        ];
        let event = build_dm_relays_event(&relays)
            .created_at(Timestamp::from_secs(1))
            .sign_with_keys(&alice)
            .unwrap();
        assert_eq!(event.kind, Kind::DM_RELAYS);
        let parsed = parse_dm_relays_event(&event).unwrap();
        assert_eq!(parsed, relays);
    }

    #[test]
    fn dm_relays_rejects_wrong_kind() {
        let alice = keys_alice();
        let event = EventBuilder::text_note("not a dm relays event")
            .created_at(Timestamp::from_secs(1))
            .sign_with_keys(&alice)
            .unwrap();
        let err = parse_dm_relays_event(&event).unwrap_err();
        assert!(matches!(err, Error::UnexpectedKind(1)));
    }

    #[test]
    fn dm_relays_rejects_missing_url() {
        let alice = keys_alice();
        let event = EventBuilder::new(Kind::DM_RELAYS, "")
            .tag(Tag::new(["relay"]).unwrap())
            .created_at(Timestamp::from_secs(1))
            .sign_with_keys(&alice)
            .unwrap();
        let err = parse_dm_relays_event(&event).unwrap_err();
        assert!(matches!(err, Error::MissingRelayUrl));
    }
}
