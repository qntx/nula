//! Outgoing-event break-down: resolve the outbox-model relay set an
//! event should be published to.
//!
//! Mirrors the wire semantics of `rust-nostr`'s gossip send path:
//!
//! | event kind            | targets                                        |
//! |-----------------------|------------------------------------------------|
//! | `kind:1059` gift wrap | recipients' NIP-17 DM relays (`kind:10050`)    |
//! | `kind:3` contacts     | author's NIP-65 outbox only                    |
//! | anything else         | author outbox ∪ each `#p` recipient's inbox    |
//!
//! A gift wrap is signed with a throw-away ephemeral key, so its
//! author carries no routing signal; only the `#p` recipients matter.
//! Per [NIP-17] a client SHOULD NOT publish a private message when the
//! recipient advertises no `kind:10050` relays, so that case is
//! surfaced distinctly via [`EventRoute::Orphan`]'s `private_message`
//! flag rather than silently falling back to a broadcast.
//!
//! [NIP-17]: https://github.com/nostr-protocol/nips/blob/master/17.md

use std::collections::{BTreeSet, HashSet};

use nula_core::event::Event;
use nula_core::{Kind, PublicKey, RelayUrl};

use crate::inner::Inner;
use crate::selection::{self, Limits};

/// Outcome of [`crate::Gossip::break_down_event`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EventRoute {
    /// Resolved publish targets — the author's outbox relays unioned
    /// with each `#p` recipient's inbox relays (or, for NIP-17 gift
    /// wraps, the recipients' DM relays).
    Relays(HashSet<RelayUrl>),

    /// The event addresses public keys (its author and/or `#p` tags)
    /// but the routing graph has no relays for any of them.
    Orphan {
        /// `true` when the event is a NIP-17 gift wrap (`kind:1059`).
        ///
        /// Per NIP-17 the client SHOULD NOT publish when the
        /// recipient has no `kind:10050` DM relays, so the caller
        /// should refuse to send rather than broadcast. For every
        /// other kind this is `false` and the caller may fall back to
        /// a generic WRITE broadcast.
        private_message: bool,
    },
}

/// Resolve the relay set for `event` using the outbox model. See the
/// module docs for the per-kind routing table.
pub(crate) async fn break_down_event(inner: &Inner, event: &Event) -> EventRoute {
    let limits = Limits::from_gossip(inner.options.limits);
    let allowed = inner.options.allowed;
    let dm_limit = inner.options.limits.dm_relays_per_user;
    let recipients: BTreeSet<PublicKey> = event.tags.public_keys().collect();

    let routes = inner.routes.read().await;

    // NIP-17 gift wrap: publish to recipients' DM relays only. The
    // outer author is a randomized ephemeral key and carries no route.
    if event.kind == Kind::GIFT_WRAP {
        let mut relays: HashSet<RelayUrl> = HashSet::new();
        for pk in &recipients {
            if let Some(user_routes) = routes.get(pk) {
                relays.extend(selection::dm_relays(user_routes, dm_limit, allowed));
            }
        }
        drop(routes);
        return if relays.is_empty() {
            EventRoute::Orphan {
                private_message: true,
            }
        } else {
            EventRoute::Relays(relays)
        };
    }

    // Author always publishes to their own outbox (write) relays.
    let mut relays: HashSet<RelayUrl> = routes
        .get(&event.pubkey)
        .map_or_else(HashSet::new, |user_routes| {
            selection::outbox(user_routes, limits, allowed)
        });

    // Mentions / replies also reach each recipient's inbox so they see
    // the event without polling the author's relays. Contact lists
    // (kind:3) are author-only — they advertise nothing to the tagged
    // followees' inboxes.
    if event.kind != Kind::CONTACTS {
        for pk in &recipients {
            if let Some(user_routes) = routes.get(pk) {
                relays.extend(selection::inbox(user_routes, limits, allowed));
            }
        }
    }
    drop(routes);

    if relays.is_empty() {
        EventRoute::Orphan {
            private_message: false,
        }
    } else {
        EventRoute::Relays(relays)
    }
}
