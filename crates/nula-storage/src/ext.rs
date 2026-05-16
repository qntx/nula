//! Default-implemented convenience methods on top of
//! [`NostrDatabase`].
//!
//! Everything in this module is layered on the core trait via filters
//! and `query`. Backends never need to implement the methods here;
//! callers get them for free by importing `NostrDatabaseExt`:
//!
//! ```rust,no_run
//! use std::sync::Arc;
//!
//! use nula_core::key::PublicKey;
//! use nula_storage::{Error, NostrDatabase, NostrDatabaseExt};
//!
//! async fn lookup(
//!     db: Arc<dyn NostrDatabase>,
//!     pubkey: PublicKey,
//! ) -> Result<(), Error> {
//!     if let Some(meta) = db.metadata(pubkey).await? {
//!         println!("display name: {:?}", meta.legacy_display_name());
//!     }
//!     Ok(())
//! }
//! ```

use nula_core::event::{Event, Kind};
use nula_core::filter::Filter;
use nula_core::key::PublicKey;
use nula_core::metadata::Metadata;
use nula_net::BoxFuture;

use crate::NostrDatabase;
use crate::error::Error;
use crate::profile::Profile;

/// Convenience methods layered on top of [`NostrDatabase`].
///
/// Every method has a default implementation that issues one or more
/// [`NostrDatabase::query`] calls under the hood. Backends inherit the
/// implementations for free; specialised backends may still override a
/// method to skip the round-trip through `query`.
pub trait NostrDatabaseExt: NostrDatabase {
    /// Fetch the latest kind-0 metadata payload for `public_key`.
    ///
    /// Returns `Ok(None)` if the store has never observed a kind-0
    /// event from that key, or if the most recent payload fails to
    /// decode as [`Metadata`].
    fn metadata(&self, public_key: PublicKey) -> BoxFuture<'_, Result<Option<Metadata>, Error>> {
        Box::pin(async move {
            let filter = Filter::new()
                .author(public_key)
                .kind(Kind::METADATA)
                .limit(1);
            let events = self.query(filter).await?;
            Ok(events
                .first_owned()
                .and_then(|e| Metadata::from_event_content(&e.content).ok()))
        })
    }

    /// Fetch the profile (public key + latest metadata) for
    /// `public_key`.
    ///
    /// Always returns a [`Profile`]; the `metadata` field is `None`
    /// when the store has no kind-0 event for the key.
    fn profile(&self, public_key: PublicKey) -> BoxFuture<'_, Result<Profile, Error>> {
        Box::pin(async move {
            Ok(self.metadata(public_key).await?.map_or_else(
                || Profile::anonymous(public_key),
                |m| Profile::new(public_key, m),
            ))
        })
    }

    /// Fetch the most recent NIP-65 relay list (kind 10002) for
    /// `public_key`, returned as the raw [`Event`].
    ///
    /// Callers that want the parsed relay-marker pairs decode the
    /// event with `nula_core::nips::nip65::RelayList::try_from`.
    fn relay_list_event(
        &self,
        public_key: PublicKey,
    ) -> BoxFuture<'_, Result<Option<Event>, Error>> {
        Box::pin(async move {
            let filter = Filter::new()
                .author(public_key)
                .kind(Kind::RELAY_LIST)
                .limit(1);
            Ok(self.query(filter).await?.first_owned())
        })
    }

    /// Fetch the most recent kind-3 contact list (NIP-02) for
    /// `public_key`, returned as the raw [`Event`].
    ///
    /// Callers that want the contact `PublicKey` set walk the
    /// returned event's `p` tags.
    fn contact_list_event(
        &self,
        public_key: PublicKey,
    ) -> BoxFuture<'_, Result<Option<Event>, Error>> {
        Box::pin(async move {
            let filter = Filter::new()
                .author(public_key)
                .kind(Kind::CONTACTS)
                .limit(1);
            Ok(self.query(filter).await?.first_owned())
        })
    }
}

/// Blanket impl: every [`NostrDatabase`] is automatically a
/// [`NostrDatabaseExt`].
impl<T: NostrDatabase + ?Sized> NostrDatabaseExt for T {}
