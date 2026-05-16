//! Two-mode wrapper around a [`RelayPool`].
//!
//! The dispatcher actor only needs `add_relay`, `connect`,
//! `send_event_to`, and `stream_events_to`, so the dual-mode shape
//! exposes those four through a thin enum rather than swapping
//! traits at the boundary.

use std::sync::Arc;
use std::time::Duration;

use nula_core::{Event, Filter, RelayUrl};
use nula_net::BoxStream;
use nula_relay::SubscribeOptions;
use nula_relay_pool::{Output, RelayCapabilities, RelayPool};

/// Mode discriminator for the pool the [`crate::NostrConnect`]
/// client routes its RPC traffic over.
#[derive(Debug)]
pub enum PoolMode {
    /// The pool was supplied by the application; the client never
    /// shuts it down.
    External(Arc<RelayPool>),
    /// The pool was constructed by the [`crate::NostrConnectBuilder`];
    /// the client owns it and shuts it down on drop / `shutdown()`.
    Embedded(RelayPool),
}

impl PoolMode {
    /// Borrow the pool regardless of mode.
    #[must_use]
    pub(crate) fn pool(&self) -> &RelayPool {
        match self {
            Self::External(p) => p,
            Self::Embedded(p) => p,
        }
    }

    /// Convenience: register `urls` as `READ | WRITE` relays in the
    /// pool and wait for every connect attempt to settle.
    pub(crate) async fn add_and_connect(
        &self,
        urls: &[RelayUrl],
    ) -> Result<(), nula_relay_pool::Error> {
        let pool = self.pool();
        for url in urls {
            pool.add_relay(
                url.clone(),
                RelayCapabilities::READ | RelayCapabilities::WRITE,
            )
            .await?;
        }
        // `try_connect` is fire-and-collect; per-relay failures end
        // up in `Output::failed` and are tolerated here — the
        // dispatcher will retry through `stream_events_to` anyway.
        let _: Output<()> = pool.try_connect(Duration::from_secs(10)).await;
        Ok(())
    }

    /// `true` for [`Self::Embedded`].
    #[must_use]
    pub const fn is_embedded(&self) -> bool {
        matches!(self, Self::Embedded(_))
    }

    /// Borrow as a stream-events entry point.
    pub(crate) async fn stream_events_to(
        &self,
        urls: Vec<RelayUrl>,
        filters: Vec<Filter>,
        options: SubscribeOptions,
        timeout: Option<Duration>,
    ) -> Result<
        BoxStream<'static, (RelayUrl, Result<Event, nula_relay::Error>)>,
        nula_relay_pool::Error,
    > {
        self.pool()
            .stream_events_to(urls, filters, options, timeout)
            .await
    }

    /// Borrow as a publish entry point.
    pub(crate) async fn send_event_to(
        &self,
        urls: Vec<RelayUrl>,
        event: Event,
    ) -> Result<Output<nula_core::EventId>, nula_relay_pool::Error> {
        self.pool().send_event_to(urls, event).await
    }
}
