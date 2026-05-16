//! Error surface for [`crate::Gossip`] operations.
//!
//! Follows the workspace error contract from
//! [ADR-0004](../../docs/adr/0004-error-handling-thiserror.md):
//! `#[non_exhaustive]`, every variant carries typed data, every
//! boxed source is `Send + Sync + 'static`.

use nula_core::RelayUrl;
use thiserror::Error;

/// Errors raised by [`crate::Gossip`].
#[allow(
    clippy::error_impl_error,
    reason = "`Error` is the conventional crate-level error name"
)]
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The pool refused the helper call (typically because it was
    /// shut down or the requested relay is missing).
    #[error(transparent)]
    Pool(#[from] nula_relay_pool::Error),

    /// A storage-layer query / write failed.
    #[error(transparent)]
    Storage(#[from] nula_storage::Error),

    /// A NIP-65 event failed to parse.
    #[error(transparent)]
    Nip65(#[from] nula_core::nips::nip65::RelayListError),

    /// A NIP-17 DM-relays event (kind 10050) failed to parse.
    #[error(transparent)]
    Nip17(#[from] nula_core::nips::nip17::Nip17Error),

    /// A relay hint advertised on an event tag failed to parse.
    #[error("invalid relay hint '{hint}': {source}")]
    InvalidHint {
        /// The string that failed to parse.
        hint: String,
        /// Underlying URL parse error.
        #[source]
        source: nula_core::types::RelayUrlError,
    },

    /// `refresh()` was given an empty discovery relay set, so it had
    /// nowhere to send the lookup query.
    #[error("no discovery relays available for gossip refresh")]
    NoDiscoveryRelays,

    /// The lookup completed without observing the requested
    /// list-kind event for the user.
    #[error("no NIP-{list_kind:?} event was returned for user {user}")]
    NotFound {
        /// The user whose list was being refreshed.
        user: nula_core::PublicKey,
        /// Which list kind the lookup was after.
        list_kind: crate::ListKind,
    },

    /// Best-effort cleanup hook on the in-memory cache surfaced an
    /// error. Used by the background refresher when its parent
    /// [`crate::Gossip`] handle is already gone.
    #[error("gossip background refresher: {0}")]
    Refresher(&'static str),

    /// One of the relay hints (`r` tag value) referred to a relay
    /// the policy [`crate::AllowedRelays`] rejects. Reported on
    /// `process()` paths where the caller wants visibility into
    /// dropped hints; the cache itself silently ignores them.
    #[error("relay '{0}' rejected by AllowedRelays policy")]
    HintRejected(RelayUrl),
}
