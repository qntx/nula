//! Error surface for [`crate::Client`].
//!
//! Shaped according to [ADR-0004](../../docs/adr/0004-error-handling-thiserror.md):
//! `#[non_exhaustive]`, typed payloads, transparent forwarding of the
//! underlying layer's errors.

use thiserror::Error;

/// Errors raised by the [`crate::Client`] facade.
#[allow(
    clippy::error_impl_error,
    reason = "`Error` is the conventional crate-level error name"
)]
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Wraps a [`nula_relay_pool::Error`] from the underlying
    /// multi-relay coordinator.
    #[error(transparent)]
    Pool(#[from] nula_relay_pool::Error),

    /// Wraps a [`nula_relay::Error`] surfaced through a per-relay
    /// operation.
    #[error(transparent)]
    Relay(#[from] nula_relay::Error),

    /// Wraps a [`nula_core::event::EventBuilderError`] from the
    /// event builder / signer path (e.g. `sign_event_builder`).
    #[error("event builder error: {0}")]
    EventBuilder(nula_core::event::EventBuilderError),

    /// `gossip` feature only. Wraps a [`nula_gossip::Error`] from
    /// the NIP-65 routing helpers.
    #[cfg(feature = "gossip")]
    #[cfg_attr(docsrs, doc(cfg(feature = "gossip")))]
    #[error(transparent)]
    Gossip(#[from] nula_gossip::Error),

    /// `sync` feature only. Wraps a [`nula_sync::Error`] from the
    /// NIP-77 reconciliation helpers.
    #[cfg(feature = "sync")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sync")))]
    #[error(transparent)]
    Sync(#[from] nula_sync::Error),

    /// `sync` feature only. Wraps a [`nula_storage::Error`] from
    /// the database adapter the sync loop uses to source local
    /// items.
    #[cfg(feature = "sync")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sync")))]
    #[error(transparent)]
    Storage(#[from] nula_storage::Error),

    /// `Client::sign_event_builder` and friends were called but no
    /// signer was attached during [`crate::ClientBuilder`]
    /// configuration.
    #[error("no signer configured on this client")]
    SignerNotConfigured,

    /// Wraps a [`nula_core::signer::SignerError`] returned by the
    /// configured signer's `get_public_key` / `sign_event`
    /// (or NIP-04 / NIP-44 cipher) futures.
    #[error(transparent)]
    Signer(#[from] nula_core::signer::SignerError),

    /// [`nula_core::SubscriptionId::generate`] failed (OS RNG
    /// exhaustion).
    #[error(transparent)]
    SubscriptionIdGeneration(#[from] nula_core::message::SubscriptionIdError),

    /// A `&str` / `String` could not be parsed as a [`nula_core::RelayUrl`].
    #[error(transparent)]
    RelayUrl(#[from] nula_core::types::RelayUrlError),
}

impl From<nula_core::event::EventBuilderError> for Error {
    fn from(value: nula_core::event::EventBuilderError) -> Self {
        Self::EventBuilder(value)
    }
}
