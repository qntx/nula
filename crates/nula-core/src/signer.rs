// Copyright (c) 2026 QNTX <https://qntx.fun>
// Distributed under the MIT or Apache-2.0 license.

//! `NostrSigner` trait — the universal signing interface used by every
//! higher-level crate.
//!
//! Implementations vary widely:
//!
//! - in-process [`Keys`] (default for client and relay tooling),
//! - NIP-07 browser extensions,
//! - NIP-46 remote signers / bunkers,
//! - hardware bunkers behind RPC.
//!
//! All of them eventually answer the same two questions: "what is your
//! public key?" and "please sign this unsigned event". The trait is
//! deliberately object-safe (`dyn NostrSigner`) so consumers can store an
//! `Arc<dyn NostrSigner>` in their state without committing to a concrete
//! signer at construction time.

use core::error::Error;
use core::fmt;
use core::future::Future;
use core::pin::Pin;
use std::sync::Arc;

use thiserror::Error as ThisError;

use crate::event::{Event, UnsignedEvent, UnsignedEventError};
use crate::key::{Keys, PublicKey};

/// A type-erased `Future` returned by [`NostrSigner`] methods.
///
/// Synchronous signers can wrap their work with [`std::future::ready`].
pub type SignerFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Errors raised by a [`NostrSigner`].
#[derive(Debug, ThisError)]
pub enum SignerError {
    /// The signer's public key did not match the unsigned event author.
    #[error(transparent)]
    AuthorMismatch(#[from] UnsignedEventError),
    /// The remote signer rejected the request (e.g. user denied a NIP-46
    /// prompt, NIP-07 returned `null`, …).
    #[error("signer rejected the request: {0}")]
    Rejected(String),
    /// The signer could not communicate with its backend.
    #[error("signer backend failure: {0}")]
    Backend(Box<dyn Error + Send + Sync>),
    /// The signer does not implement the requested operation.
    #[error("signer does not support `{0}`")]
    Unsupported(&'static str),
}

impl SignerError {
    /// Wrap an arbitrary error as a backend failure.
    pub fn backend<E>(err: E) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        Self::Backend(Box::new(err))
    }

    /// Convenience constructor for [`SignerError::Rejected`].
    pub fn rejected<S>(reason: S) -> Self
    where
        S: Into<String>,
    {
        Self::Rejected(reason.into())
    }
}

/// Universal signer trait.
///
/// Object-safe by design: every method returns a [`SignerFuture`]. Add new
/// methods only when every implementor can support them; encryption helpers
/// (NIP-04, NIP-44) live on derived traits in their respective NIP crates.
pub trait NostrSigner: fmt::Debug + Send + Sync {
    /// Return the signer's public key.
    ///
    /// The method is named `get_public_key` (rather than `public_key`) so it
    /// never shadows the inherent accessor on concrete keypair types like
    /// [`Keys`].
    fn get_public_key(&self) -> SignerFuture<'_, Result<PublicKey, SignerError>>;

    /// Sign an [`UnsignedEvent`] and return the resulting [`Event`].
    ///
    /// Implementations must reject events whose `pubkey` does not match the
    /// signer's own public key.
    fn sign_event(&self, unsigned: UnsignedEvent) -> SignerFuture<'_, Result<Event, SignerError>>;
}

impl NostrSigner for Keys {
    fn get_public_key(&self) -> SignerFuture<'_, Result<PublicKey, SignerError>> {
        let key = *self.public_key();
        Box::pin(async move { Ok(key) })
    }

    fn sign_event(&self, unsigned: UnsignedEvent) -> SignerFuture<'_, Result<Event, SignerError>> {
        Box::pin(async move {
            let event = unsigned.sign_with_keys(self)?;
            Ok(event)
        })
    }
}

impl<S> NostrSigner for Arc<S>
where
    S: NostrSigner + ?Sized,
{
    fn get_public_key(&self) -> SignerFuture<'_, Result<PublicKey, SignerError>> {
        (**self).get_public_key()
    }

    fn sign_event(&self, unsigned: UnsignedEvent) -> SignerFuture<'_, Result<Event, SignerError>> {
        (**self).sign_event(unsigned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventBuilder;
    use crate::types::Timestamp;

    fn fixture_keys() -> Keys {
        Keys::parse("0000000000000000000000000000000000000000000000000000000000000003").unwrap()
    }

    fn block_on<F: Future>(f: F) -> F::Output {
        // Smallest possible executor: poll once, panic if pending.
        use core::task::{Context, Poll, Waker};
        use std::pin::pin;

        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut fut = pin!(f);
        loop {
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(out) => return out,
                Poll::Pending => panic!("future is not synchronous; use a real executor"),
            }
        }
    }

    #[test]
    fn keys_implement_signer() {
        let keys = fixture_keys();
        let pk = block_on(keys.get_public_key()).unwrap();
        assert_eq!(pk, *keys.public_key());
    }

    #[test]
    fn keys_sign_event() {
        let keys = fixture_keys();
        let unsigned = EventBuilder::text_note("hi")
            .created_at(Timestamp::from_secs(1))
            .build_unsigned(*keys.public_key())
            .unwrap();
        let event = block_on(keys.sign_event(unsigned)).unwrap();
        event.verify().unwrap();
    }

    #[test]
    fn arc_signer_dispatches() {
        let keys: Arc<dyn NostrSigner> = Arc::new(fixture_keys());
        let pk = block_on(keys.get_public_key()).unwrap();
        assert_eq!(pk.to_byte_array().len(), 32);
    }

    #[test]
    fn rejected_error_carries_reason() {
        let err = SignerError::rejected("user denied");
        assert!(err.to_string().contains("user denied"));
    }

    #[test]
    fn backend_error_round_trip() {
        let inner = std::io::Error::other("oops");
        let err = SignerError::backend(inner);
        assert!(err.to_string().contains("oops"));
    }
}
