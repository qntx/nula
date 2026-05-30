//! Error surface for [`crate::NostrConnect`].
//!
//! Follows the workspace error contract from
//! [ADR-0004](../../docs/adr/0004-error-handling-thiserror.md).

use std::error::Error as StdError;

use nula_core::nips::nip46::Method;
use thiserror::Error;

/// Errors raised by [`crate::NostrConnect`].
#[allow(
    clippy::error_impl_error,
    reason = "`Error` is the conventional crate-level error name"
)]
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The pool refused the call (typically `Shutdown` or `RelayNotFound`).
    #[error(transparent)]
    Pool(#[from] nula_relay::pool::Error),

    /// A relay-level operation surfaced an error before the pool
    /// could route it into [`nula_relay::pool::Output`].
    #[error(transparent)]
    Relay(#[from] nula_relay::Error),

    /// NIP-46 protocol parsing / encoding failure.
    #[error(transparent)]
    Nip46(#[from] nula_core::nips::nip46::Nip46Error),

    /// NIP-44 encryption / decryption failure on the wire payload.
    #[error(transparent)]
    Nip44(#[from] nula_core::nips::nip44::Nip44Error),

    /// Event-builder failure (e.g. `created_at` overflow).
    #[error(transparent)]
    Event(#[from] nula_core::event::EventBuilderError),

    /// The remote signer did not reply within the configured
    /// timeout.
    #[error("timed out waiting for response to method `{method}`")]
    Timeout {
        /// The RPC method whose reply was being waited for.
        method: Method,
    },

    /// The remote signer replied with an `error` slot. The bundled
    /// string is the verbatim message the bunker returned.
    #[error("signer rejected method `{method}`: {message}")]
    Rejected {
        /// The RPC method whose reply carried the error.
        method: Method,
        /// Human-readable message from the signer.
        message: String,
    },

    /// The dispatcher actor terminated (typically because the pool
    /// stream ended). All pending RPCs are released with this
    /// error.
    #[error("nostr-connect dispatcher terminated: {0}")]
    DispatcherDown(&'static str),

    /// Sent only on the `nostrconnect://` flow when the signer's
    /// `connect` response did not echo the URI's mandatory secret.
    #[error("`nostrconnect://` connect response did not echo the URI secret")]
    Spoofed,

    /// `bootstrap()` was called before the URI's relay set could be
    /// added to the pool.
    #[error("nostr-connect bootstrap could not register relay '{0}': {1}")]
    BootstrapAddRelay(nula_core::RelayUrl, String),

    /// `adopt_relays()` was called on a [`crate::PoolMode::External`]
    /// instance, which does not own the pool it lives in.
    #[error("adopt_relays() requires an embedded RelayPool (PoolMode::Embedded)")]
    WrongPoolMode,

    /// [`crate::NostrConnectBuilder::build`] was called without a
    /// prior [`crate::NostrConnectBuilder::uri`] invocation.
    #[error("NostrConnectBuilder requires a URI (call `.uri(...)` before `.build()`)")]
    MissingUri,

    /// [`crate::NostrConnectBuilder::build`] was called without a
    /// prior [`crate::NostrConnectBuilder::pool`] or
    /// [`crate::NostrConnectBuilder::embedded_pool`] invocation.
    #[error(
        "NostrConnectBuilder requires a RelayPool (call `.pool(...)` or `.embedded_pool(...)` before `.build()`)"
    )]
    MissingPool,

    /// Decryption succeeded but the resulting JSON did not parse as
    /// a NIP-46 envelope.
    #[error("malformed NIP-46 envelope from signer: {0}")]
    MalformedEnvelope(serde_json::Error),

    /// Internal channel error that should be unreachable in a
    /// well-formed binary; surfaced for diagnostic completeness.
    #[error("nostr-connect internal channel cancelled: {0}")]
    Cancelled(&'static str),

    /// User-supplied [`crate::AuthUrlHandler`] returned an error.
    #[error("auth_url handler failed: {0}")]
    AuthUrl(#[source] Box<dyn StdError + Send + Sync>),
}

impl Error {
    /// Wrap an arbitrary error as a backend-side auth-handler
    /// failure (the conventional fallback for handlers that surface
    /// browser-open / IPC errors).
    pub fn auth_url<E>(err: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Self::AuthUrl(Box::new(err))
    }
}

impl From<Error> for nula_core::signer::SignerError {
    fn from(err: Error) -> Self {
        match err {
            Error::Rejected { message, method } => {
                Self::rejected_with_code(message, method.as_str())
            }
            other => Self::backend(other),
        }
    }
}
