//! Two-mode wrapper around a [`RelayPool`].
//!
//! The NWC client either owns an embedded pool (shut down on drop) or
//! borrows an application-supplied one. The dispatcher and the request
//! path only need `add_and_connect`, `stream_events_to`, and
//! `send_event_to`, exposed here through a thin enum.

use std::sync::Arc;
use std::time::Duration;

use nula_core::{BoxStream, Event, EventId, Filter, RelayUrl};
use nula_relay::SubscribeOptions;
use nula_relay::pool::{Output, RelayCapabilities, RelayPool};

/// The pool an NWC client routes its traffic over.
#[derive(Debug)]
pub(crate) enum PoolMode {
    /// Application-owned pool; the client never shuts it down.
    External(Arc<RelayPool>),
    /// Client-owned pool; shut down on drop / `shutdown()`.
    Embedded(RelayPool),
}

impl PoolMode {
    fn pool(&self) -> &RelayPool {
        match self {
            Self::External(p) => p,
            Self::Embedded(p) => p,
        }
    }

    /// `true` for [`Self::Embedded`].
    pub(crate) const fn is_embedded(&self) -> bool {
        matches!(self, Self::Embedded(_))
    }

    /// Register `urls` as `READ | WRITE` relays and wait for every
    /// connect attempt to settle.
    pub(crate) async fn add_and_connect(
        &self,
        urls: &[RelayUrl],
    ) -> Result<(), nula_relay::pool::Error> {
        let pool = self.pool();
        for url in urls {
            pool.add_relay(
                url.clone(),
                RelayCapabilities::READ | RelayCapabilities::WRITE,
            )
            .await?;
        }
        // Fire-and-collect: per-relay failures land in `Output::failed`
        // and are tolerated — the dispatcher reconnects through
        // `stream_events_to` regardless.
        let _: Output<()> = pool.try_connect(Duration::from_secs(10)).await;
        Ok(())
    }

    pub(crate) async fn stream_events_to(
        &self,
        urls: Vec<RelayUrl>,
        filters: Vec<Filter>,
        options: SubscribeOptions,
        timeout: Option<Duration>,
    ) -> Result<
        BoxStream<'static, (RelayUrl, Result<Event, nula_relay::Error>)>,
        nula_relay::pool::Error,
    > {
        self.pool()
            .stream_events_to(urls, filters, options, timeout)
            .await
    }

    pub(crate) async fn send_event_to(
        &self,
        urls: Vec<RelayUrl>,
        event: Event,
    ) -> Result<Output<EventId>, nula_relay::pool::Error> {
        self.pool().send_event_to(urls, event).await
    }
}
