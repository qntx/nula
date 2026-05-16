//! Per-connection actor.
//!
//! One `handle_connection` future per accepted TCP socket. Owns the
//! split sink/stream halves, the per-connection authenticated flag,
//! and the in-flight subscription map. Exits cleanly on client close,
//! transport error, or relay-wide shutdown signal.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use nula_core::message::{MachineReadablePrefix, RelayMessage};
use nula_core::{ClientMessage, Event, EventId, Filter, JsonUtil, SubscriptionId};
use nula_storage::{NostrDatabase, SaveEventStatus};
use serde_json::Value;
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::Message as WsMessage;

use crate::policy::{AdmitVerdict, ReadPolicy, WritePolicy};

/// Connection-scoped resources. Cloned cheaply (every field is
/// `Arc`-shared with the relay handle).
#[derive(Clone)]
pub(crate) struct ConnectionContext {
    pub(crate) storage: Arc<dyn NostrDatabase>,
    pub(crate) write_policy: Arc<dyn WritePolicy>,
    pub(crate) read_policy: Arc<dyn ReadPolicy>,
    pub(crate) require_nip42: bool,
}

/// Drive a single accepted connection to completion.
///
/// Returns when the client disconnects, the WebSocket handshake or
/// frame parsing errors out, or the relay-wide `shutdown` channel is
/// closed.
pub(crate) async fn handle_connection(
    ws: WebSocketStream<TcpStream>,
    _peer: SocketAddr,
    ctx: ConnectionContext,
    mut shutdown: broadcast::Receiver<()>,
) {
    let (mut sink, mut stream) = ws.split();
    let mut subscriptions: HashMap<SubscriptionId, Vec<Filter>> = HashMap::new();

    // Optional NIP-42 challenge — fires once at the top of the loop.
    let challenge_required = ctx.require_nip42;
    let mut authenticated = !challenge_required;
    if challenge_required {
        let challenge = format!("nula-mock-{}", random_hex_token());
        let frame = encode_relay(&RelayMessage::Auth(challenge));
        if sink.send(WsMessage::text(frame)).await.is_err() {
            return;
        }
    }

    loop {
        tokio::select! {
            // Relay shutting down — close gracefully.
            _ = shutdown.recv() => {
                sink.send(WsMessage::Close(None)).await.ok();
                break;
            }

            // Inbound frame.
            next = stream.next() => {
                let Some(frame) = next else { break };
                let frame = match frame {
                    Ok(WsMessage::Text(text)) => text.as_str().to_owned(),
                    Ok(WsMessage::Binary(_)) => {
                        // NIP-01 mandates UTF-8 text; binary frames
                        // are protocol violations. Surface a NOTICE
                        // and drop the frame.
                        sink.send(WsMessage::text(encode_relay(&RelayMessage::Notice(
                            "binary frames are not part of NIP-01".to_owned(),
                        )))).await.ok();
                        continue;
                    }
                    Ok(WsMessage::Ping(payload)) => {
                        // Auto-pong; tungstenite normally does this
                        // for us when we drive the stream, but we
                        // are decomposing the stream so do it
                        // manually.
                        sink.send(WsMessage::Pong(payload)).await.ok();
                        continue;
                    }
                    Ok(WsMessage::Pong(_) | WsMessage::Frame(_)) => continue,
                    Ok(WsMessage::Close(_)) | Err(_) => break,
                };

                let msg = match ClientMessage::from_json(&frame) {
                    Ok(m) => m,
                    Err(e) => {
                        sink.send(WsMessage::text(encode_relay(&RelayMessage::Notice(
                            format!("invalid client message: {e}"),
                        ))))
                        .await
                        .ok();
                        continue;
                    }
                };

                if !authenticated && !is_auth_message(&msg) {
                    let reply = if let ClientMessage::Event(event) = &msg {
                        RelayMessage::Ok {
                            event_id: event.id,
                            accepted: false,
                            message: format!(
                                "{}: client must AUTH before publishing",
                                MachineReadablePrefix::AuthRequired.as_str()
                            ),
                        }
                    } else {
                        RelayMessage::Notice(
                            "auth-required: this relay requires NIP-42 authentication".into(),
                        )
                    };
                    sink.send(WsMessage::text(encode_relay(&reply))).await.ok();
                    continue;
                }

                if dispatch(
                    &ctx,
                    &mut subscriptions,
                    &mut sink,
                    msg,
                    &mut authenticated,
                )
                .await
                .is_err()
                {
                    break;
                }
            }
        }
    }
}

type Sink = futures::stream::SplitSink<WebSocketStream<TcpStream>, WsMessage>;

#[derive(Debug)]
struct DispatchError;

async fn dispatch(
    ctx: &ConnectionContext,
    subscriptions: &mut HashMap<SubscriptionId, Vec<Filter>>,
    sink: &mut Sink,
    msg: ClientMessage,
    authenticated: &mut bool,
) -> Result<(), DispatchError> {
    match msg {
        ClientMessage::Event(event) => {
            handle_event(ctx, sink, event).await?;
            Ok(())
        }
        ClientMessage::Req {
            subscription_id,
            filters,
        } => {
            handle_req(ctx, subscriptions, sink, subscription_id, filters).await?;
            Ok(())
        }
        ClientMessage::Close(id) => {
            subscriptions.remove(&id);
            Ok(())
        }
        ClientMessage::Auth(_event) => {
            // Transport-layer hook only: signature is **not**
            // verified. This is documented on
            // `MockRelayOptions::require_nip42`.
            *authenticated = true;
            Ok(())
        }
        ClientMessage::Count {
            subscription_id,
            filter,
        } => {
            let count = ctx.storage.count(filter).await.map_or(0, |n| n as u64);
            let frame = RelayMessage::Count {
                subscription_id,
                count,
            };
            send(sink, &frame).await
        }
        // `ClientMessage` is `#[non_exhaustive]`; future variants
        // surface as a NOTICE so the test harness sees the gap.
        _ => {
            send(
                sink,
                &RelayMessage::Notice("client message variant not implemented".into()),
            )
            .await
            .ok();
            Ok(())
        }
    }
}

async fn handle_event(
    ctx: &ConnectionContext,
    sink: &mut Sink,
    event: Event,
) -> Result<(), DispatchError> {
    let event_id: EventId = event.id;

    let verdict = ctx.write_policy.admit_event(&event).await;
    if let AdmitVerdict::Reject(reason) = verdict {
        return send(
            sink,
            &RelayMessage::Ok {
                event_id,
                accepted: false,
                message: format!("{}: {}", MachineReadablePrefix::Blocked.as_str(), reason),
            },
        )
        .await;
    }

    let result = ctx.storage.save_event(&event).await;
    let reply = match result {
        Ok(SaveEventStatus::Success) => RelayMessage::Ok {
            event_id,
            accepted: true,
            message: String::new(),
        },
        Ok(SaveEventStatus::Rejected(reason)) => RelayMessage::Ok {
            event_id,
            accepted: false,
            message: format!("{}: {reason:?}", MachineReadablePrefix::Invalid.as_str()),
        },
        Ok(_) => RelayMessage::Ok {
            event_id,
            accepted: false,
            message: format!("{}: rejected", MachineReadablePrefix::Error.as_str()),
        },
        Err(e) => RelayMessage::Ok {
            event_id,
            accepted: false,
            message: format!("{}: {e}", MachineReadablePrefix::Error.as_str()),
        },
    };

    send(sink, &reply).await
}

async fn handle_req(
    ctx: &ConnectionContext,
    subscriptions: &mut HashMap<SubscriptionId, Vec<Filter>>,
    sink: &mut Sink,
    subscription_id: SubscriptionId,
    filters: Vec<Filter>,
) -> Result<(), DispatchError> {
    if filters.is_empty() {
        return send(
            sink,
            &RelayMessage::Closed {
                subscription_id,
                message: format!(
                    "{}: REQ requires at least one filter",
                    MachineReadablePrefix::Invalid.as_str()
                ),
            },
        )
        .await;
    }

    // Per-filter admit gate.
    for filter in &filters {
        if let AdmitVerdict::Reject(reason) = ctx.read_policy.admit_filter(filter).await {
            return send(
                sink,
                &RelayMessage::Closed {
                    subscription_id,
                    message: format!("{}: {}", MachineReadablePrefix::Restricted.as_str(), reason),
                },
            )
            .await;
        }
    }

    // Stream historical matches one filter at a time, then EOSE.
    for filter in &filters {
        let events = match ctx.storage.query(filter.clone()).await {
            Ok(events) => events,
            Err(e) => {
                return send(
                    sink,
                    &RelayMessage::Closed {
                        subscription_id,
                        message: format!(
                            "{}: storage backend error: {e}",
                            MachineReadablePrefix::Error.as_str()
                        ),
                    },
                )
                .await;
            }
        };
        for event in events {
            send(
                sink,
                &RelayMessage::Event {
                    subscription_id: subscription_id.clone(),
                    event,
                },
            )
            .await?;
        }
    }
    send(
        sink,
        &RelayMessage::EndOfStoredEvents(subscription_id.clone()),
    )
    .await?;

    subscriptions.insert(subscription_id, filters);
    Ok(())
}

fn encode_relay(msg: &RelayMessage) -> String {
    msg.try_to_json()
        .unwrap_or_else(|_| Value::Null.to_string())
}

async fn send(sink: &mut Sink, msg: &RelayMessage) -> Result<(), DispatchError> {
    sink.send(WsMessage::text(encode_relay(msg)))
        .await
        .map_err(|_| DispatchError)
}

const fn is_auth_message(msg: &ClientMessage) -> bool {
    matches!(msg, ClientMessage::Auth(_))
}

/// Cheap pseudo-random hex token used for NIP-42 challenges. The
/// builder is a test fixture, not a cryptographic gate, so a 64-bit
/// token sourced from the system clock is plenty.
fn random_hex_token() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos: u128 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    // Mask to the low 64 bits — this is a transport-test fixture,
    // not a cryptographic gate, so any drift in the upper bits is
    // immaterial. The masked value always fits, so the `unwrap_or`
    // fallback is unreachable but kept to dodge `unwrap_used`.
    let lo: u64 = u64::try_from(nanos & u128::from(u64::MAX)).unwrap_or(0);
    format!("{lo:016x}")
}
