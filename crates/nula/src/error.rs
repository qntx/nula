//! Error surface for [`crate::Client`].
//!
//! Shaped according to [ADR-0004](../../docs/adr/0004-error-handling-thiserror.md):
//! `#[non_exhaustive]`, typed payloads, transparent forwarding of the
//! underlying layer's errors.

use thiserror::Error;

/// Errors raised by the [`crate::Client`] facade.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Wraps a [`nula_relay::pool::Error`] from the underlying
    /// multi-relay coordinator.
    #[error(transparent)]
    Pool(#[from] nula_relay::pool::Error),

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

    /// `gossip` feature only. A NIP-17 gift wrap (`kind:1059`) was
    /// routed through the gossip engine but none of its `#p`
    /// recipients advertise `kind:10050` DM relays. Per
    /// [NIP-17](https://github.com/nostr-protocol/nips/blob/master/17.md)
    /// the client SHOULD NOT publish in this case, so the send path
    /// surfaces this error instead of falling back to a broadcast.
    #[cfg(feature = "gossip")]
    #[cfg_attr(docsrs, doc(cfg(feature = "gossip")))]
    #[error("no NIP-17 DM relays found for the gift wrap recipients")]
    PrivateMessageRelaysNotFound,

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

    /// The relay url passed to a per-relay method is not registered
    /// on the underlying pool. Add it via
    /// [`crate::Client::add_relay`] first, or pick one of the
    /// urls returned by [`crate::Client::relays`].
    #[error("unknown relay url: {url}")]
    UnknownRelay {
        /// The url the caller asked for.
        url: nula_core::types::RelayUrl,
    },

    /// A per-relay connect attempt exceeded the supplied timeout
    /// before the WebSocket handshake completed.
    #[error("connect to relay timed out: {url}")]
    ConnectTimeout {
        /// The url whose connect attempt timed out.
        url: nula_core::types::RelayUrl,
    },

    /// The remote peer returned a `NEG-ERR` frame mid-session.
    /// Inspect [`nula_core::message::MachineReadablePrefix`] on
    /// `reason` to recover the structured class.
    #[cfg(feature = "sync")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sync")))]
    #[error("relay-side NIP-77 error: {reason}")]
    SyncFailed {
        /// The reason string the relay supplied.
        reason: String,
    },

    /// The reconciliation handle ended before the session
    /// converged. Usually means the relay closed the connection
    /// while a `NEG-MSG` exchange was in flight.
    #[cfg(feature = "sync")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sync")))]
    #[error("NIP-77 stream ended before reconciliation converged")]
    SyncStreamClosed,

    /// The configured [`crate::policy::AdmitPolicy`] vetoed the
    /// action. `stage` records which gate fired ("relay",
    /// "connection", "event"); `reason` is the verbatim string
    /// the policy returned (or `None` if it did not provide one).
    #[error("policy rejected {stage}{}", reason.as_deref().map(|r| format!(": {r}")).unwrap_or_default())]
    PolicyRejected {
        /// Which admission hook fired the rejection.
        stage: &'static str,
        /// The reason string supplied by the policy, when any.
        reason: Option<String>,
    },

    /// The configured [`crate::policy::AdmitPolicy`] failed with
    /// a backend error before producing a verdict.
    #[error(transparent)]
    Policy(#[from] crate::policy::PolicyError),

    /// NIP-17 private-message helper failed (empty recipients,
    /// malformed kind-10050 list, or a forwarded NIP-59 / NIP-44
    /// gift-wrap error).
    #[error(transparent)]
    Nip17(#[from] nula_core::nips::nip17::Nip17Error),

    /// NIP-65 relay-list helper failed -- the served kind-10002
    /// event was malformed (wrong kind, unparseable url,
    /// unknown marker).
    #[error(transparent)]
    Nip65(#[from] nula_core::nips::nip65::RelayListError),
}

impl From<nula_core::event::EventBuilderError> for Error {
    fn from(value: nula_core::event::EventBuilderError) -> Self {
        Self::EventBuilder(value)
    }
}
