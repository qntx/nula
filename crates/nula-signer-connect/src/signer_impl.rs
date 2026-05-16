//! [`nula_core::NostrSigner`] bridge.
//!
//! This is the boundary that lets a [`NostrConnect`] handle drop
//! straight into any `Arc<dyn NostrSigner>` slot already used by
//! lower-level crates.

use nula_core::event::UnsignedEvent;
use nula_core::signer::{NostrSigner, SignerError, SignerFuture, boxed_signer_future};
use nula_core::{Event, PublicKey};

use crate::client::NostrConnect;
use crate::error::Error;

impl NostrSigner for NostrConnect {
    fn get_public_key(&self) -> SignerFuture<'_, Result<PublicKey, SignerError>> {
        boxed_signer_future(async move { self.get_public_key().await.map_err(map_error) })
    }

    fn sign_event(&self, unsigned: UnsignedEvent) -> SignerFuture<'_, Result<Event, SignerError>> {
        boxed_signer_future(async move { self.sign_event(unsigned).await.map_err(map_error) })
    }

    fn nip04_encrypt<'a>(
        &'a self,
        peer: &'a PublicKey,
        plaintext: &'a str,
    ) -> SignerFuture<'a, Result<String, SignerError>> {
        boxed_signer_future(
            async move { self.nip04_encrypt(peer, plaintext).await.map_err(map_error) },
        )
    }

    fn nip04_decrypt<'a>(
        &'a self,
        peer: &'a PublicKey,
        ciphertext: &'a str,
    ) -> SignerFuture<'a, Result<String, SignerError>> {
        boxed_signer_future(async move {
            self.nip04_decrypt(peer, ciphertext)
                .await
                .map_err(map_error)
        })
    }

    fn nip44_encrypt<'a>(
        &'a self,
        peer: &'a PublicKey,
        plaintext: &'a str,
    ) -> SignerFuture<'a, Result<String, SignerError>> {
        boxed_signer_future(
            async move { self.nip44_encrypt(peer, plaintext).await.map_err(map_error) },
        )
    }

    fn nip44_decrypt<'a>(
        &'a self,
        peer: &'a PublicKey,
        ciphertext: &'a str,
    ) -> SignerFuture<'a, Result<String, SignerError>> {
        boxed_signer_future(async move {
            self.nip44_decrypt(peer, ciphertext)
                .await
                .map_err(map_error)
        })
    }
}

fn map_error(err: Error) -> SignerError {
    err.into()
}
