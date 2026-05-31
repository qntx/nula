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
//!
//! # Why `Pin<Box<dyn Future + Send>>` instead of `async fn`
//!
//! `async fn` in traits is stable since Rust 1.75, but the resulting
//! return-position-impl-trait makes the trait *not* `dyn`-safe on stable.
//! Higher-level crates need `Arc<dyn NostrSigner>` (relay pools, gossip
//! planners, multi-account UIs); a `dyn`-unsafe trait would force every
//! consumer to either (a) pick a concrete signer at construction time,
//! or (b) pull in a third-party adapter such as `trait_variant`.
//!
//! Boxing the future is the idiomatic stable workaround and the same
//! choice the `tokio` / `futures` ecosystem uses for object-safe async
//! traits. The single allocation per call is negligible compared to the
//! Schnorr signature itself, and impls that already produce a boxed
//! future (NIP-46 RPC, browser extensions) pay no extra cost.

use std::error::Error as StdError;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use thiserror::Error as ThisError;

use crate::event::{Event, UnsignedEvent, UnsignedEventError};
use crate::key::{Keys, PublicKey};

/// A type-erased `Future` returned by [`NostrSigner`] methods.
///
/// On every non-wasm target the future is `Send` so consumers can move
/// signer calls across `tokio::spawn` boundaries. On `wasm32` the `Send`
/// bound is dropped: NIP-07 browser signers return `!Send` `JsFuture`s
/// (the same target split [`crate::boxed::BoxFuture`] makes).
///
/// Synchronous signers can wrap their work with [`std::future::ready`].
#[cfg(not(target_arch = "wasm32"))]
pub type SignerFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A type-erased `Future` returned by [`NostrSigner`] methods. On
/// `wasm32` the `Send` bound is dropped because NIP-07 browser signers
/// return `!Send` `JsFuture`s.
#[cfg(target_arch = "wasm32")]
pub type SignerFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// Box and pin an `async` block as a [`SignerFuture`].
///
/// Convenience wrapper so signer impls can write
///
/// ```ignore
/// fn get_public_key(&self) -> SignerFuture<'_, Result<PublicKey, SignerError>> {
///     boxed_signer_future(async { Ok(*self.public_key()) })
/// }
/// ```
///
/// instead of repeating `Box::pin(async move { ... })` at every call
/// site. The function exists in `nula_core` so downstream crates do not
/// have to depend on `futures-util` or rewrite the boilerplate.
///
/// The `Send` bound on `future` follows the same target split as
/// [`SignerFuture`]: required off-wasm, dropped on `wasm32`.
#[cfg(not(target_arch = "wasm32"))]
pub fn boxed_signer_future<'a, F, T>(future: F) -> SignerFuture<'a, T>
where
    F: Future<Output = T> + Send + 'a,
{
    Box::pin(future)
}

/// Box and pin an `async` block as a [`SignerFuture`] (wasm32: no `Send`
/// bound, since browser signer futures are `!Send`).
#[cfg(target_arch = "wasm32")]
pub fn boxed_signer_future<'a, F, T>(future: F) -> SignerFuture<'a, T>
where
    F: Future<Output = T> + 'a,
{
    Box::pin(future)
}

/// Errors raised by a [`NostrSigner`].
#[derive(Debug, ThisError)]
#[non_exhaustive]
pub enum SignerError {
    /// The signer's public key did not match the unsigned event author.
    #[error(transparent)]
    AuthorMismatch(#[from] UnsignedEventError),
    /// The remote signer rejected the request (e.g. user denied a NIP-46
    /// prompt, NIP-07 returned `null`, …).
    ///
    /// `code` carries the machine-readable NIP-46 error string when the
    /// backend supplies one (`"user_rejected"`, `"timeout"`, etc.); leave
    /// it `None` for backends without a structured error channel.
    #[error(
        "signer rejected the request{}: {message}",
        code.as_ref().map_or_else(String::new, |c| format!(" (code = {c})"))
    )]
    Rejected {
        /// Human-readable explanation, suitable for display.
        message: String,
        /// Machine-readable error code when supplied by the backend.
        code: Option<String>,
    },
    /// The signer could not communicate with its backend.
    #[error("signer backend failure: {0}")]
    Backend(Box<dyn StdError + Send + Sync>),
    /// The signer does not implement the requested operation.
    #[error("signer does not support `{0}`")]
    Unsupported(&'static str),
}

impl SignerError {
    /// Wrap an arbitrary error as a backend failure.
    pub fn backend<E>(err: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Self::Backend(Box::new(err))
    }

    /// Convenience constructor for [`SignerError::Rejected`] without a
    /// structured backend code (NIP-07, sandbox signers, etc.).
    pub fn rejected<S>(message: S) -> Self
    where
        S: Into<String>,
    {
        Self::Rejected {
            message: message.into(),
            code: None,
        }
    }

    /// Convenience constructor for [`SignerError::Rejected`] with a
    /// machine-readable code (typically the NIP-46 `error` string).
    pub fn rejected_with_code<S, C>(message: S, code: C) -> Self
    where
        S: Into<String>,
        C: Into<String>,
    {
        Self::Rejected {
            message: message.into(),
            code: Some(code.into()),
        }
    }
}

/// Universal signer trait.
///
/// Object-safe by design: every method returns a [`SignerFuture`]. The
/// trait covers two responsibility levels:
///
/// 1. **Mandatory**: [`Self::get_public_key`] and [`Self::sign_event`].
///    Every signer can answer these — that's the whole point of a
///    signer.
/// 2. **Optional encryption capabilities** (NIP-04 / NIP-44 v2). The
///    four `*_encrypt` / `*_decrypt` methods carry default
///    implementations that return [`SignerError::Unsupported`].
///    Concrete signers override them when the underlying backend can
///    perform the operation:
///
///    | Signer        | NIP-04 | NIP-44 v2 |
///    |---------------|:------:|:---------:|
///    | [`Keys`]      |   ✅   |    ✅     |
///    | NIP-07        |   ✅   |    ✅     |
///    | NIP-46        |   ✅   |    ✅     |
///    | Hardware-only |   ❌   |    ❌     |
///
/// The opt-out style keeps the trait `dyn`-safe (capability supertraits
/// would require dynamic downcasts) and gives downstream code a single
/// import path instead of `where S: NostrSigner + Nip04Cipher + Nip44Cipher`.
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

    /// NIP-04 (legacy) encrypt to `peer`.
    ///
    /// # Errors
    ///
    /// Default impl returns [`SignerError::Unsupported`]; override in
    /// signers that can produce NIP-04 ciphertexts.
    fn nip04_encrypt<'a>(
        &'a self,
        _peer: &'a PublicKey,
        _plaintext: &'a str,
    ) -> SignerFuture<'a, Result<String, SignerError>> {
        boxed_signer_future(async { Err(SignerError::Unsupported("nip04_encrypt")) })
    }

    /// NIP-04 (legacy) decrypt from `peer`.
    ///
    /// # Errors
    ///
    /// See [`Self::nip04_encrypt`].
    fn nip04_decrypt<'a>(
        &'a self,
        _peer: &'a PublicKey,
        _ciphertext: &'a str,
    ) -> SignerFuture<'a, Result<String, SignerError>> {
        boxed_signer_future(async { Err(SignerError::Unsupported("nip04_decrypt")) })
    }

    /// NIP-44 v2 encrypt to `peer`.
    ///
    /// # Errors
    ///
    /// Default impl returns [`SignerError::Unsupported`]; override in
    /// signers that can produce NIP-44 ciphertexts.
    fn nip44_encrypt<'a>(
        &'a self,
        _peer: &'a PublicKey,
        _plaintext: &'a str,
    ) -> SignerFuture<'a, Result<String, SignerError>> {
        boxed_signer_future(async { Err(SignerError::Unsupported("nip44_encrypt")) })
    }

    /// NIP-44 v2 decrypt from `peer`.
    ///
    /// # Errors
    ///
    /// See [`Self::nip44_encrypt`].
    fn nip44_decrypt<'a>(
        &'a self,
        _peer: &'a PublicKey,
        _payload: &'a str,
    ) -> SignerFuture<'a, Result<String, SignerError>> {
        boxed_signer_future(async { Err(SignerError::Unsupported("nip44_decrypt")) })
    }
}

impl NostrSigner for Keys {
    fn get_public_key(&self) -> SignerFuture<'_, Result<PublicKey, SignerError>> {
        let key = *self.public_key();
        boxed_signer_future(async move { Ok(key) })
    }

    fn sign_event(&self, unsigned: UnsignedEvent) -> SignerFuture<'_, Result<Event, SignerError>> {
        boxed_signer_future(async move {
            let event = unsigned.sign_with_keys(self)?;
            Ok(event)
        })
    }

    #[cfg(feature = "nip04")]
    fn nip04_encrypt<'a>(
        &'a self,
        peer: &'a PublicKey,
        plaintext: &'a str,
    ) -> SignerFuture<'a, Result<String, SignerError>> {
        boxed_signer_future(async move {
            crate::nips::nip04::encrypt(self.secret_key(), peer, plaintext)
                .map_err(SignerError::backend)
        })
    }

    #[cfg(feature = "nip04")]
    fn nip04_decrypt<'a>(
        &'a self,
        peer: &'a PublicKey,
        ciphertext: &'a str,
    ) -> SignerFuture<'a, Result<String, SignerError>> {
        boxed_signer_future(async move {
            crate::nips::nip04::decrypt(self.secret_key(), peer, ciphertext)
                .map_err(SignerError::backend)
        })
    }

    #[cfg(feature = "nip44")]
    fn nip44_encrypt<'a>(
        &'a self,
        peer: &'a PublicKey,
        plaintext: &'a str,
    ) -> SignerFuture<'a, Result<String, SignerError>> {
        boxed_signer_future(async move {
            crate::nips::nip44::encrypt(self.secret_key(), peer, plaintext)
                .map_err(SignerError::backend)
        })
    }

    #[cfg(feature = "nip44")]
    fn nip44_decrypt<'a>(
        &'a self,
        peer: &'a PublicKey,
        payload: &'a str,
    ) -> SignerFuture<'a, Result<String, SignerError>> {
        boxed_signer_future(async move {
            crate::nips::nip44::decrypt(self.secret_key(), peer, payload)
                .map_err(SignerError::backend)
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

    fn nip04_encrypt<'a>(
        &'a self,
        peer: &'a PublicKey,
        plaintext: &'a str,
    ) -> SignerFuture<'a, Result<String, SignerError>> {
        (**self).nip04_encrypt(peer, plaintext)
    }

    fn nip04_decrypt<'a>(
        &'a self,
        peer: &'a PublicKey,
        ciphertext: &'a str,
    ) -> SignerFuture<'a, Result<String, SignerError>> {
        (**self).nip04_decrypt(peer, ciphertext)
    }

    fn nip44_encrypt<'a>(
        &'a self,
        peer: &'a PublicKey,
        plaintext: &'a str,
    ) -> SignerFuture<'a, Result<String, SignerError>> {
        (**self).nip44_encrypt(peer, plaintext)
    }

    fn nip44_decrypt<'a>(
        &'a self,
        peer: &'a PublicKey,
        payload: &'a str,
    ) -> SignerFuture<'a, Result<String, SignerError>> {
        (**self).nip44_decrypt(peer, payload)
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
        use std::pin::pin;
        use std::task::{Context, Poll, Waker};

        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        let mut fut = pin!(f);
        match fut.as_mut().poll(&mut cx) {
            Poll::Ready(out) => out,
            Poll::Pending => unreachable!("test futures must be synchronous"),
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
        let s = err.to_string();
        assert!(s.contains("user denied"));
        assert!(!s.contains("code"), "no structured code → no code suffix");
    }

    #[test]
    fn rejected_with_code_surfaces_machine_readable_code() {
        let err = SignerError::rejected_with_code("user denied", "user_rejected");
        let s = err.to_string();
        assert!(s.contains("user denied"));
        assert!(
            s.contains("code = user_rejected"),
            "expected code suffix in: {s}",
        );
    }

    #[test]
    fn backend_error_round_trip() {
        let inner = std::io::Error::other("oops");
        let err = SignerError::backend(inner);
        assert!(err.to_string().contains("oops"));
    }

    /// Minimal sign-only signer that opts out of every encryption
    /// capability. Used to exercise the default `Unsupported` return
    /// values on the trait, independent of which NIP feature flags
    /// are enabled in this build.
    #[derive(Debug)]
    struct SignOnlySigner(Keys);

    impl NostrSigner for SignOnlySigner {
        fn get_public_key(&self) -> SignerFuture<'_, Result<PublicKey, SignerError>> {
            self.0.get_public_key()
        }

        fn sign_event(
            &self,
            unsigned: UnsignedEvent,
        ) -> SignerFuture<'_, Result<Event, SignerError>> {
            self.0.sign_event(unsigned)
        }
        // No encryption overrides — every `nipNN_*` method falls back
        // to the trait default that returns `SignerError::Unsupported`.
    }

    #[test]
    fn default_encryption_methods_return_unsupported() {
        // Hardware-only signers cannot encrypt; the trait's default
        // impls must surface that as a structured error rather than a
        // panic, regardless of build features.
        let alice = SignOnlySigner(fixture_keys());
        let bob_pk =
            *Keys::parse("0000000000000000000000000000000000000000000000000000000000000007")
                .unwrap()
                .public_key();

        let cases: [(&str, SignerFuture<'_, _>); 4] = [
            ("nip04_encrypt", alice.nip04_encrypt(&bob_pk, "hi")),
            ("nip04_decrypt", alice.nip04_decrypt(&bob_pk, "")),
            ("nip44_encrypt", alice.nip44_encrypt(&bob_pk, "hi")),
            ("nip44_decrypt", alice.nip44_decrypt(&bob_pk, "")),
        ];
        for (label, fut) in cases {
            let err = block_on(fut).unwrap_err();
            assert!(
                matches!(err, SignerError::Unsupported(name) if name == label),
                "expected Unsupported({label}), got {err:?}",
            );
        }
    }

    #[cfg(feature = "nip04")]
    #[test]
    fn keys_nip04_round_trip_through_signer_trait() {
        let alice = fixture_keys();
        let bob = Keys::parse("0000000000000000000000000000000000000000000000000000000000000007")
            .unwrap();
        let payload = block_on(alice.nip04_encrypt(bob.public_key(), "legacy hi")).unwrap();
        let recovered = block_on(bob.nip04_decrypt(alice.public_key(), &payload)).unwrap();
        assert_eq!(recovered, "legacy hi");
    }

    #[cfg(feature = "nip44")]
    #[test]
    fn keys_nip44_round_trip_through_signer_trait() {
        // Two-party round trip using the `NostrSigner` trait surface.
        // This proves the trait wires the underlying `nips::nip44`
        // helpers correctly without leaking the secret key.
        let alice = fixture_keys();
        let bob = Keys::parse("0000000000000000000000000000000000000000000000000000000000000007")
            .unwrap();
        let payload = block_on(alice.nip44_encrypt(bob.public_key(), "secret")).unwrap();
        let recovered = block_on(bob.nip44_decrypt(alice.public_key(), &payload)).unwrap();
        assert_eq!(recovered, "secret");
    }

    #[cfg(feature = "nip44")]
    #[test]
    fn arc_dyn_signer_forwards_nip44_methods() {
        // Object-safe path: `Arc<dyn NostrSigner>` must transparently
        // delegate every encryption method to the wrapped signer.
        let alice: Arc<dyn NostrSigner> = Arc::new(fixture_keys());
        let bob = Keys::parse("0000000000000000000000000000000000000000000000000000000000000007")
            .unwrap();
        let payload = block_on(alice.nip44_encrypt(bob.public_key(), "via dyn")).unwrap();
        let recovered =
            block_on(bob.nip44_decrypt(&block_on(alice.get_public_key()).unwrap(), &payload))
                .unwrap();
        assert_eq!(recovered, "via dyn");
    }
}
