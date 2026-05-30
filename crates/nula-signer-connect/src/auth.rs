//! Auth-URL handler trait.
//!
//! When a remote signer responds with the
//! [`nula_core::nips::nip46::ResponseResult::AuthUrl`] sentinel it
//! is asking the user to complete an out-of-band auth step (open a
//! URL, scan a QR code, …). The application embeds the [`NostrConnect`]
//! client and decides what to do with that URL — pop a browser, log
//! it, ignore it, …
//!
//! The default handler [`RejectAuthUrl`] surfaces every `auth_url`
//! response as a hard error. Production apps wire their own handler
//! via [`crate::NostrConnectBuilder::auth_url_handler`].
//!
//! [`NostrConnect`]: crate::NostrConnect

use std::error::Error as StdError;
use std::fmt::Debug;
use std::sync::Arc;

use nula_core::BoxFuture;
use url::Url;

/// Plug-in for handling [`nula_core::nips::nip46::ResponseResult::AuthUrl`].
///
/// Object-safe by design: the dispatcher actor stores the handler
/// behind `Arc<dyn AuthUrlHandler>`. Implementations must be
/// `Send + Sync`.
pub trait AuthUrlHandler: Debug + Send + Sync {
    /// Handle one `auth_url` instruction.
    ///
    /// Returning `Ok(())` lets the dispatcher continue waiting for
    /// the real response. Returning `Err(_)` short-circuits the
    /// pending RPC with [`crate::Error::AuthUrl`] so the caller
    /// knows the user-facing UX flow failed.
    ///
    /// # Errors
    ///
    /// Any error the handler chooses to report; it surfaces verbatim
    /// in [`crate::Error::AuthUrl`].
    fn on_auth_url(&self, url: Url) -> BoxFuture<'_, Result<(), Box<dyn StdError + Send + Sync>>>;
}

/// Default handler that always rejects the URL.
///
/// Suitable for unattended scenarios (servers, CI, headless tests)
/// where the bunker's interactive prompts cannot be satisfied.
#[derive(Debug, Default, Clone, Copy)]
pub struct RejectAuthUrl;

impl AuthUrlHandler for RejectAuthUrl {
    fn on_auth_url(&self, url: Url) -> BoxFuture<'_, Result<(), Box<dyn StdError + Send + Sync>>> {
        Box::pin(async move {
            Err(Box::<dyn StdError + Send + Sync>::from(format!(
                "auth_url ignored by default handler: {url}"
            )))
        })
    }
}

/// Conversion helper used by [`crate::NostrConnectBuilder::auth_url_handler`].
///
/// Mirrors the trait-erased shape that `nostr-connect` uses upstream
/// so callers can pass either a concrete handler or an
/// `Arc<dyn AuthUrlHandler>` and have the builder accept both.
pub trait IntoAuthUrlHandler {
    /// Erase the concrete type.
    fn into_auth_url_handler(self) -> Arc<dyn AuthUrlHandler>;
}

impl<T> IntoAuthUrlHandler for T
where
    T: AuthUrlHandler + 'static,
{
    fn into_auth_url_handler(self) -> Arc<dyn AuthUrlHandler> {
        Arc::new(self)
    }
}

impl IntoAuthUrlHandler for Arc<dyn AuthUrlHandler> {
    fn into_auth_url_handler(self) -> Arc<dyn AuthUrlHandler> {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reject_auth_url_returns_err() {
        let handler = RejectAuthUrl;
        let url = Url::parse("https://example.com/").expect("hardcoded url");
        let err = handler.on_auth_url(url).await.expect_err("must reject");
        assert!(err.to_string().contains("auth_url"));
    }

    #[derive(Debug, Default, Clone, Copy)]
    struct AcceptHandler;

    impl AuthUrlHandler for AcceptHandler {
        fn on_auth_url(
            &self,
            _url: Url,
        ) -> BoxFuture<'_, Result<(), Box<dyn StdError + Send + Sync>>> {
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn into_auth_url_handler_accepts_concrete_and_arc() {
        let concrete: Arc<dyn AuthUrlHandler> = AcceptHandler.into_auth_url_handler();
        concrete
            .on_auth_url(Url::parse("https://x").unwrap())
            .await
            .expect("accept");
        let cloned: Arc<dyn AuthUrlHandler> = Arc::clone(&concrete);
        let _: Arc<dyn AuthUrlHandler> = cloned.into_auth_url_handler();
    }
}
