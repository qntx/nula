//! Error surface for [`crate::NostrWalletConnect`].

use nula_core::nips::nip47::{ErrorCode, NwcError};
use thiserror::Error;

/// Errors raised by [`crate::NostrWalletConnect`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The pool refused the call (typically `Shutdown` or `RelayNotFound`).
    #[error(transparent)]
    Pool(#[from] nula_relay::pool::Error),

    /// A relay-level operation surfaced an error before the pool could
    /// route it into [`nula_relay::pool::Output`].
    #[error(transparent)]
    Relay(#[from] nula_relay::Error),

    /// NIP-47 protocol parsing / encryption failure.
    #[error(transparent)]
    Nwc(#[from] NwcError),

    /// Event-builder failure (e.g. `created_at` overflow, signing).
    #[error(transparent)]
    Event(#[from] nula_core::event::EventBuilderError),

    /// The wallet service replied with a populated `error` envelope.
    #[error("wallet rejected `{method}`: [{code}] {message}")]
    Wallet {
        /// Method that was rejected.
        method: String,
        /// Spec-defined error code.
        code: ErrorCode,
        /// Human-readable message from the wallet.
        message: String,
    },

    /// The wallet replied, but the response did not match the method's
    /// expected shape (wrong `result_type`, missing `result`, or a
    /// result that failed to deserialize into the typed payload).
    #[error("unexpected response to `{method}`: {message}")]
    UnexpectedResult {
        /// Method whose reply was malformed.
        method: String,
        /// Diagnostic detail.
        message: String,
    },

    /// The wallet did not reply within the configured timeout.
    #[error("timed out waiting for response to `{method}`")]
    Timeout {
        /// Method whose reply was being waited for.
        method: String,
    },

    /// The request could not be published to any relay.
    #[error("request publish failed on every relay: {0}")]
    PublishFailed(String),

    /// The dispatcher actor terminated (typically because the pool
    /// stream ended). Pending requests are released with this error.
    #[error("nwc dispatcher terminated: {0}")]
    DispatcherDown(&'static str),

    /// [`crate::NostrWalletConnectBuilder::build`] was called without a
    /// prior [`crate::NostrWalletConnectBuilder::uri`] invocation.
    #[error("NostrWalletConnectBuilder requires a connection URI (call `.uri(...)`)")]
    MissingUri,

    /// [`crate::NostrWalletConnectBuilder::build`] was called without a
    /// pool (call `.pool(...)` or `.embedded_pool(...)`).
    #[error("NostrWalletConnectBuilder requires a RelayPool")]
    MissingPool,

    /// Serialization / deserialization of a typed method payload failed.
    ///
    /// Boxed so the variant stays small relative to its siblings.
    #[error("invalid NWC JSON payload: {0}")]
    Json(#[source] Box<serde_json::Error>),
}

impl Error {
    /// Wrap a `serde_json` error from typed-payload (de)serialization.
    pub(crate) fn json(err: serde_json::Error) -> Self {
        Self::Json(Box::new(err))
    }
}
