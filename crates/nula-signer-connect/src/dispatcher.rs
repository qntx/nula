//! Dispatcher actor.
//!
//! One dispatcher runs per [`crate::NostrConnect`] instance. It
//! subscribes to `kind:24133` events targeting the client's pubkey,
//! NIP-44 decrypts each payload, parses it as a NIP-46 envelope, and
//! routes the result to the matching pending RPC.
//!
//! `auth_url` responses are routed to the configured
//! [`crate::AuthUrlHandler`] without consuming the pending entry —
//! the bunker emits a second response with the same `id` carrying
//! the real result once the user finishes the out-of-band step.

use std::sync::Arc;

use futures::StreamExt as _;
use nula_core::nips::nip46::{Message, Method, Response, ResponseResult};
use nula_core::nips::{nip44, nip46};
use nula_core::{Filter, Keys, RelayUrl};
use nula_relay::SubscribeOptions;
use tokio::sync::OnceCell;
use tokio::task::AbortHandle;

use crate::auth::AuthUrlHandler;
use crate::error::Error;
use crate::pending::PendingMap;
use crate::pool_handle::PoolMode;

/// Configuration the dispatcher needs to start.
pub(crate) struct DispatcherConfig {
    pub(crate) pool: Arc<PoolMode>,
    pub(crate) client_keys: Keys,
    pub(crate) pending: Arc<PendingMap>,
    pub(crate) auth_url_handler: Option<Arc<dyn AuthUrlHandler>>,
    /// Set by the dispatcher once it observes a valid `connect`
    /// reply during the `nostrconnect://` bootstrap handshake. The
    /// `bunker://` flow pre-sets this from the URI.
    pub(crate) remote_signer_pk: Arc<OnceCell<nula_core::PublicKey>>,
    /// `Some(secret)` only on the `nostrconnect://` flow. The
    /// dispatcher must verify this matches the secret echoed in the
    /// signer's `connect` response before trusting `event.pubkey`
    /// as the remote signer's pubkey.
    pub(crate) nostrconnect_secret: Option<String>,
    /// Snapshot of the signer's relay set captured at bootstrap.
    /// Stable across the lifetime of the dispatcher because the
    /// pool's `add_relay` only happens on `bootstrap`.
    pub(crate) relays: Vec<RelayUrl>,
}

/// Spawn the dispatcher loop and return an abort handle.
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
        client_keys,
        pending,
        auth_url_handler,
        remote_signer_pk,
        nostrconnect_secret,
        relays,
    } = config;

    if relays.is_empty() {
        return Ok(());
    }

    let filter = Filter::new()
        .pubkey(*client_keys.public_key())
        .kind(nula_core::Kind::new(nip46::KIND))
        .limit(0);

    let mut stream = pool
        .stream_events_to(relays, vec![filter], SubscribeOptions::default(), None)
        .await?;

    while let Some((_url, item)) = stream.next().await {
        let Ok(event) = item else { continue };
        if event.kind != nula_core::Kind::new(nip46::KIND) {
            continue;
        }
        // Decryption failure means the event is not addressed to us.
        let Ok(plain) = nip44::decrypt(client_keys.secret_key(), &event.pubkey, &event.content)
        else {
            continue;
        };
        let envelope: Message = match serde_json::from_str(&plain) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let Message::Response { id, result, error } = envelope else {
            continue;
        };

        // `nostrconnect://` secret-echo gate: latch the signer
        // pubkey on the first response that echoes our URI secret.
        validate_secret_echo(
            &remote_signer_pk,
            nostrconnect_secret.as_deref(),
            &event.pubkey,
            result.as_deref(),
        );

        // Take the pending entry; if we hand it back unconsumed
        // (auth_url path), `reinsert` parks it for the real reply.
        let Some(pending_entry) = pending.take(&id) else {
            continue;
        };
        let outcome = decode_response(pending_entry.method, result.as_deref(), error);

        deliver_outcome(
            &pending,
            id,
            pending_entry,
            outcome,
            auth_url_handler.as_ref(),
        )
        .await;
    }
    Ok(())
}

async fn deliver_outcome(
    pending: &PendingMap,
    id: String,
    pending_entry: crate::pending::Pending,
    outcome: Decoded,
    auth_url_handler: Option<&Arc<dyn AuthUrlHandler>>,
) {
    match outcome {
        Decoded::Result(res) => {
            pending_entry.sender.send(res).ok();
        }
        Decoded::AuthUrl(target) => {
            handle_auth_url(pending, id, pending_entry, target, auth_url_handler).await;
        }
    }
}

async fn handle_auth_url(
    pending: &PendingMap,
    id: String,
    pending_entry: crate::pending::Pending,
    target: url::Url,
    auth_url_handler: Option<&Arc<dyn AuthUrlHandler>>,
) {
    let Some(handler) = auth_url_handler else {
        let method = pending_entry.method;
        pending_entry
            .sender
            .send(Err(Error::Rejected {
                method,
                message: format!("auth_url received but no handler installed (target = {target})"),
            }))
            .ok();
        return;
    };
    match handler.on_auth_url(target).await {
        Ok(()) => {
            // Park the pending entry back; the bunker emits another
            // response with the same id once the user finishes the
            // out-of-band step.
            pending.reinsert(id, pending_entry);
        }
        Err(handler_err) => {
            pending_entry
                .sender
                .send(Err(Error::AuthUrl(handler_err)))
                .ok();
        }
    }
}

/// Decoded view over a NIP-46 response.
enum Decoded {
    /// The dispatcher can deliver this verdict to the caller and
    /// consume the pending entry.
    Result(Result<ResponseResult, Error>),
    /// The bunker is asking for an out-of-band auth step; the
    /// dispatcher must call the handler and park the pending entry.
    AuthUrl(url::Url),
}

fn decode_response(method: Method, result: Option<&str>, error: Option<String>) -> Decoded {
    let parsed = match Response::from_wire(method, result, error) {
        Ok(r) => r,
        Err(err) => return Decoded::Result(Err(Error::from(err))),
    };
    if matches!(parsed.result, Some(ResponseResult::AuthUrl)) {
        // Per spec the URL travels in the `error` slot.
        let target = parsed
            .error
            .as_deref()
            .and_then(|s| url::Url::parse(s).ok());
        return target.map_or_else(
            || {
                Decoded::Result(Err(Error::Rejected {
                    method,
                    message: parsed
                        .error
                        .unwrap_or_else(|| "auth_url without target URL".to_owned()),
                }))
            },
            Decoded::AuthUrl,
        );
    }
    if let Some(message) = parsed.error {
        return Decoded::Result(Err(Error::Rejected { method, message }));
    }
    parsed.result.map_or_else(
        || {
            Decoded::Result(Err(Error::Rejected {
                method,
                message: "signer returned neither result nor error".to_owned(),
            }))
        },
        |value| Decoded::Result(Ok(value)),
    )
}

fn validate_secret_echo(
    remote_signer_pk: &OnceCell<nula_core::PublicKey>,
    expected_secret: Option<&str>,
    event_pubkey: &nula_core::PublicKey,
    result: Option<&str>,
) {
    if remote_signer_pk.get().is_some() {
        return;
    }
    let Some(secret) = expected_secret else {
        return;
    };
    let Some(value) = result else { return };
    if value == secret {
        remote_signer_pk.set(*event_pubkey).ok();
    }
}
