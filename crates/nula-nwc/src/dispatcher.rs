//! Dispatcher actor.
//!
//! One dispatcher runs per [`crate::NostrWalletConnect`]. It subscribes
//! to the wallet's response (`kind:23195`) and notification
//! (`kind:23197` / legacy `kind:23196`) events addressed to the client,
//! decrypts each body, and either resolves the matching pending request
//! (correlated through the response's `e` tag) or fans the notification
//! out over a broadcast channel.

use std::sync::Arc;

use futures::StreamExt as _;
use nula_core::nips::nip47::{
    self, KIND_NOTIFICATION, KIND_NOTIFICATION_LEGACY, KIND_RESPONSE, Notification,
};
use nula_core::{Filter, PublicKey, RelayUrl, SecretKey};
use nula_relay::SubscribeOptions;
use tokio::sync::broadcast;
use tokio::task::AbortHandle;

use crate::error::Error;
use crate::pending::PendingMap;
use crate::pool_handle::PoolMode;

/// Everything the dispatcher needs to start.
pub(crate) struct DispatcherConfig {
    pub(crate) pool: Arc<PoolMode>,
    pub(crate) client_secret: SecretKey,
    pub(crate) client_pubkey: PublicKey,
    pub(crate) wallet_pubkey: PublicKey,
    pub(crate) pending: Arc<PendingMap>,
    pub(crate) notifications: broadcast::Sender<Notification>,
    pub(crate) relays: Vec<RelayUrl>,
}

/// Spawn the dispatcher loop, returning an abort handle.
pub(crate) fn spawn(config: DispatcherConfig) -> AbortHandle {
    let pending_for_cleanup = Arc::clone(&config.pending);
    let join = tokio::spawn(async move {
        let res = run(config).await;
        pending_for_cleanup.cancel_all(&|| match res {
            Ok(()) => Error::DispatcherDown("stream ended"),
            Err(_) => Error::DispatcherDown("stream errored"),
        });
    });
    join.abort_handle()
}

async fn run(config: DispatcherConfig) -> Result<(), Error> {
    let DispatcherConfig {
        pool,
        client_secret,
        client_pubkey,
        wallet_pubkey,
        pending,
        notifications,
        relays,
    } = config;

    if relays.is_empty() {
        return Ok(());
    }

    let filter = Filter::new()
        .pubkey(client_pubkey)
        .kinds([KIND_RESPONSE, KIND_NOTIFICATION, KIND_NOTIFICATION_LEGACY])
        .limit(0);

    let mut stream = pool
        .stream_events_to(relays, vec![filter], SubscribeOptions::default(), None)
        .await?;

    while let Some((_url, item)) = stream.next().await {
        let Ok(event) = item else { continue };
        // Only ever trust events signed by the configured wallet; this
        // rejects spoofed responses authored by any other pubkey.
        if event.pubkey != wallet_pubkey {
            continue;
        }

        if event.kind == KIND_RESPONSE {
            let Ok(response) = nip47::decrypt_response(&event, &client_secret) else {
                continue;
            };
            // The response's `e` tag references the request event id.
            let Some(request_id) = event.tags.event_ids().next() else {
                continue;
            };
            pending.resolve(&request_id, Ok(response));
        } else if (event.kind == KIND_NOTIFICATION || event.kind == KIND_NOTIFICATION_LEGACY)
            && let Ok(notification) = nip47::decrypt_notification(&event, &client_secret)
        {
            // `send` errors only when there are no live receivers;
            // dropping the notification in that case is correct.
            notifications.send(notification).ok();
        }
    }
    Ok(())
}
