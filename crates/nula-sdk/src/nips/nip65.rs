//! NIP-65 relay-list metadata — SDK facade.
//!
//! [`nula_core::nips::nip65`] ships the wire-level
//! [`RelayList`] / [`RelayMarker`] types and the
//! kind-10002 (`RELAY_LIST`) event codec. This module wires those
//! primitives to [`crate::Client`]:
//!
//! - [`Client::set_relay_list`] signs and broadcasts the user's own
//!   relay list, and (when the `gossip` feature is on) feeds the
//!   freshly-published event back into the routing cache so
//!   subsequent `Client::send_event` calls already route to the new
//!   set.
//! - [`Client::get_relay_list`] fetches the latest kind-10002 for a
//!   peer and parses it into a [`RelayList`].
//! - [`Client::refresh_relay_metadata`] (only available with the
//!   `gossip` feature) re-fetches kind-10002 / kind-10050 for one
//!   or more peers and pushes the result through
//!   `Gossip::process`, so the routing graph picks up changes
//!   without restarting the client.

use std::time::Duration;

use nula_core::PublicKey;
use nula_core::event::{EventId, Kind};
use nula_core::filter::Filter;
pub use nula_core::nips::nip65::{RelayList, RelayListError};
use nula_relay_pool::Output;

use crate::client::Client;
use crate::error::Error;

impl Client {
    /// Sign and broadcast the supplied [`RelayList`] as a NIP-65
    /// kind-10002 event.
    ///
    /// When the `gossip` feature is enabled and a [`Gossip`] table
    /// is wired into the client, the freshly-built event is also
    /// fed through [`Gossip::process`] so the routing graph
    /// reflects the new list immediately.
    ///
    /// # Errors
    ///
    /// - [`Error::SignerNotConfigured`] when the client has no
    ///   signer attached.
    /// - [`Error::Pool`] from the underlying broadcast.
    ///
    /// [`Gossip`]: nula_gossip::Gossip
    /// [`Gossip::process`]: nula_gossip::Gossip::process
    pub async fn set_relay_list(
        &self,
        list: &RelayList,
    ) -> Result<Output<EventId>, Error> {
        let builder = list.to_event_builder();
        let signed = self.sign_event_builder(builder).await?;
        #[cfg(feature = "gossip")]
        if let Some(gossip) = self.gossip() {
            gossip.process(&signed, None).await;
        }
        self.send_event(signed).await
    }

    /// Fetch the latest NIP-65 kind-10002 relay list for `pubkey`.
    ///
    /// Returns `Ok(None)` when no kind-10002 event is found within
    /// the timeout. The query asks for `limit=1`; NIP-65 lists are
    /// replaceable so the relay should serve only the freshest one.
    ///
    /// # Errors
    ///
    /// - [`Error::Pool`] propagated from `fetch_events`.
    /// - [`Error::Nip65`] when the event the relay served does not
    ///   parse (wrong kind, malformed url, malformed marker).
    pub async fn get_relay_list(
        &self,
        pubkey: &PublicKey,
        timeout: Option<Duration>,
    ) -> Result<Option<RelayList>, Error> {
        let filter = Filter::new()
            .kind(Kind::RELAY_LIST)
            .author(*pubkey)
            .limit(1);
        let events = self.fetch_events(filter, timeout).await?;
        let Some(event) = events.into_iter().next() else {
            return Ok(None);
        };
        let list = RelayList::from_event(&event).map_err(Error::Nip65)?;
        Ok(Some(list))
    }

    /// `gossip`-only. Re-fetch every relay-routing-relevant list
    /// (kind 10002 NIP-65 + kind 10050 NIP-17 DM relays) for
    /// `pubkeys` and push every result through
    /// [`Gossip::process`]. Use this when a long-lived client has
    /// been running across a peer's relay-list rotation.
    ///
    /// Returns the number of *events* successfully ingested into
    /// the routing graph (so a peer that rotated only their NIP-65
    /// counts as 1, both lists counts as 2).
    ///
    /// Failures on individual fetches are silently aggregated --
    /// the routing graph is best-effort and partial refreshes are
    /// strictly better than aborting on the first miss.
    ///
    /// # Errors
    ///
    /// - [`Error::Pool`] when the underlying fetch path itself
    ///   refuses (no READ-capable relay, pool shut down, …).
    ///
    /// [`Gossip::process`]: nula_gossip::Gossip::process
    #[cfg(feature = "gossip")]
    #[cfg_attr(docsrs, doc(cfg(feature = "gossip")))]
    pub async fn refresh_relay_metadata<I>(
        &self,
        pubkeys: I,
        timeout: Option<Duration>,
    ) -> Result<usize, Error>
    where
        I: IntoIterator<Item = PublicKey>,
    {
        let Some(gossip) = self.gossip() else {
            return Ok(0);
        };
        let mut ingested = 0usize;
        let pubkeys: Vec<PublicKey> = pubkeys.into_iter().collect();
        for pk in pubkeys {
            ingested += refresh_one(self, gossip, pk, Kind::RELAY_LIST, timeout).await?;
            ingested += refresh_one(self, gossip, pk, Kind::DM_RELAYS, timeout).await?;
        }
        Ok(ingested)
    }
}

/// Helper for `refresh_relay_metadata`: fetch one (pubkey, kind)
/// pair, push the result through `Gossip::process`, return `1` if
/// an event was ingested or `0` otherwise.
#[cfg(feature = "gossip")]
async fn refresh_one(
    client: &Client,
    gossip: &nula_gossip::Gossip,
    pubkey: PublicKey,
    kind: Kind,
    timeout: Option<Duration>,
) -> Result<usize, Error> {
    let filter = Filter::new().kind(kind).author(pubkey).limit(1);
    let events = client.fetch_events(filter, timeout).await?;
    let Some(event) = events.into_iter().next() else {
        return Ok(0);
    };
    gossip.process(&event, None).await;
    Ok(1)
}

// Re-export the wire-level types so callers writing
// `client.set_relay_list(&list)` only need a single use:
// `use nula_sdk::nips::nip65::{RelayList, RelayMarker};`.
pub use nula_core::nips::nip65::RelayMarker;
