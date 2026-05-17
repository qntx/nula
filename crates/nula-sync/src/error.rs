//! Error surface for [`crate`].
//!
//! Shaped according to
//! [ADR-0004](../../docs/adr/0004-error-handling-thiserror.md):
//! `#[non_exhaustive]`, typed payloads, and boxed sources stay
//! `Send + Sync + 'static`.

use nula_core::util::hex::HexError;
use thiserror::Error;

/// Errors raised by [`crate::Reconciliation`] and friends.
#[allow(
    clippy::error_impl_error,
    reason = "`Error` is the conventional crate-level error name"
)]
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The underlying [`negentropy`] state machine raised an error.
    ///
    /// Wrapped instead of `#[from]`'d so the upstream variants do
    /// not leak into our `#[non_exhaustive]` surface uncontrolled.
    #[error("negentropy algorithm error: {0}")]
    Algorithm(negentropy::Error),

    /// A NIP-77 wire payload failed hex decoding (either because the
    /// string carried non-hex characters or its length was not
    /// divisible by two).
    #[error("invalid hex payload: {0}")]
    Hex(#[from] HexError),

    /// The reconciliation request carried a payload that the
    /// algorithm rejected with a structural error — usually a
    /// protocol-version mismatch from a misbehaving peer.
    #[error("malformed NIP-77 message: {0}")]
    MalformedMessage(&'static str),

    /// `storage` feature only. A
    /// [`nula_storage::NostrDatabase`] call failed while assembling
    /// the storage vector for a reconciliation session.
    #[cfg(feature = "storage")]
    #[cfg_attr(docsrs, doc(cfg(feature = "storage")))]
    #[error(transparent)]
    Storage(#[from] nula_storage::Error),
}

impl From<negentropy::Error> for Error {
    fn from(value: negentropy::Error) -> Self {
        Self::Algorithm(value)
    }
}
