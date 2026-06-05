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
use nula_sync::Responder;
use serde_json::Value;
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::Message as WsMessage;

use crate::server::policy::{AdmitVerdict, ReadPolicy, WritePolicy};

/// Connection-scoped resources. Cloned cheaply (every field is
/// `Arc`-shared with the relay handle).
#[derive(Clone)]
pub(crate) struct ConnectionContext {
    pub(crate) storage: Arc<dyn NostrDatabase>,
    pub(crate) write_policy: Arc<dyn WritePolicy>,
    pub(crate) read_policy: Arc<dyn ReadPolicy>,
    pub(crate) require_nip42: bool,
    /// Minimum NIP-13 proof-of-work difficulty required of inbound
    /// events; `None` accepts any difficulty.
    pub(crate) min_pow: Option<u8>,
    /// Relay-wide live broadcast: every accepted [`ClientMessage::Event`]
    /// frame fans out to every connection's subscription matchers
    /// here. Slow consumers see `RecvError::Lagged`, not back
    /// pressure on the publish path.
    pub(crate) broadcast: broadcast::Sender<Event>,
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
    let mut neg_sessions: HashMap<SubscriptionId, Responder> = HashMap::new();
    let mut live = ctx.broadcast.subscribe();

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

            // Live event from another connection — fan out to every
            // subscription whose filter set matches.
            broadcast_evt = live.recv() => {
                let Ok(event) = broadcast_evt else { continue };
                if forward_to_subscriptions(&mut sink, &subscriptions, &event)
                    .await
                    .is_err()
                {
                    break;
                }
            }

            // Inbound frame.
            next = stream.next() => {
                if handle_inbound_frame(
                    &ctx,
                    &mut subscriptions,
                    &mut neg_sessions,
                    &mut sink,
                    &mut authenticated,
                    next,
                )
                .await
                .is_break()
                {
                    break;
                }
            }
        }
    }
}

type Sink = futures::stream::SplitSink<WebSocketStream<TcpStream>, WsMessage>;

/// Outcome of [`handle_inbound_frame`]: whether the connection
/// loop should keep going or terminate.
use std::ops::ControlFlow;

/// Handle one frame from the WebSocket stream. Extracted from the
/// main `select!` body so the orchestration loop stays well below
/// clippy's `cognitive_complexity` ceiling.
#[allow(
    clippy::too_many_arguments,
    reason = "per-connection state fan-in keeps the orchestration loop flat"
)]
async fn handle_inbound_frame(
    ctx: &ConnectionContext,
    subscriptions: &mut HashMap<SubscriptionId, Vec<Filter>>,
    neg_sessions: &mut HashMap<SubscriptionId, Responder>,
    sink: &mut Sink,
    authenticated: &mut bool,
    frame: Option<Result<WsMessage, tokio_tungstenite::tungstenite::Error>>,
) -> ControlFlow<()> {
    let Some(frame) = frame else {
        return ControlFlow::Break(());
    };
    let text = match frame {
        Ok(WsMessage::Text(text)) => text.as_str().to_owned(),
        Ok(WsMessage::Binary(_)) => {
            // NIP-01 mandates UTF-8 text; binary frames are protocol
            // violations. Surface a NOTICE and drop the frame.
            sink.send(WsMessage::text(encode_relay(&RelayMessage::Notice(
                "binary frames are not part of NIP-01".to_owned(),
            ))))
            .await
            .ok();
            return ControlFlow::Continue(());
        }
        Ok(WsMessage::Ping(payload)) => {
            // Auto-pong; tungstenite normally does this for us when
            // we drive the stream, but we are decomposing the stream
            // so do it manually.
            sink.send(WsMessage::Pong(payload)).await.ok();
            return ControlFlow::Continue(());
        }
        Ok(WsMessage::Pong(_) | WsMessage::Frame(_)) => return ControlFlow::Continue(()),
        Ok(WsMessage::Close(_)) | Err(_) => return ControlFlow::Break(()),
    };

    let msg = match ClientMessage::from_json(&text) {
        Ok(m) => m,
        Err(e) => {
            sink.send(WsMessage::text(encode_relay(&RelayMessage::Notice(
                format!("invalid client message: {e}"),
            ))))
            .await
            .ok();
            return ControlFlow::Continue(());
        }
    };

    if !*authenticated && !is_auth_message(&msg) {
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
            RelayMessage::Notice("auth-required: this relay requires NIP-42 authentication".into())
        };
        sink.send(WsMessage::text(encode_relay(&reply))).await.ok();
        return ControlFlow::Continue(());
    }

    if dispatch(ctx, subscriptions, neg_sessions, sink, msg, authenticated)
        .await
        .is_err()
    {
        return ControlFlow::Break(());
    }
    ControlFlow::Continue(())
}

#[derive(Debug)]
struct DispatchError;

#[allow(
    clippy::too_many_arguments,
    reason = "per-connection state fan-in keeps dispatch flat"
)]
async fn dispatch(
    ctx: &ConnectionContext,
    subscriptions: &mut HashMap<SubscriptionId, Vec<Filter>>,
    neg_sessions: &mut HashMap<SubscriptionId, Responder>,
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
        ClientMessage::NegOpen {
            subscription_id,
            filter,
            initial_message,
        } => {
            handle_neg_open(
                ctx,
                neg_sessions,
                sink,
                subscription_id,
                filter,
                initial_message,
            )
            .await
        }
        ClientMessage::NegMsg {
            subscription_id,
            message,
        } => handle_neg_msg(neg_sessions, sink, subscription_id, message).await,
        ClientMessage::NegClose { subscription_id } => {
            neg_sessions.remove(&subscription_id);
            Ok(())
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

    // NIP-13 admission gate (mirrors upstream `nostr-relay-builder`'s
    // `min_pow`): reject under-powered events before policy or storage.
    if let Some(min) = ctx.min_pow
        && let Err(err) = nula_core::nips::nip13::verify_pow(&event, min)
    {
        return send(
            sink,
            &RelayMessage::Ok {
                event_id,
                accepted: false,
                message: format!("{}: {err}", MachineReadablePrefix::Pow.as_str()),
            },
        )
        .await;
    }

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
    let (accepted, reply) = match result {
        // `Success` and `Rejected(Ephemeral)` both ACK with no
        // message: persisted records are durably stored, ephemeral
        // kinds (20000…<30000) per NIP-01 are broadcast to
        // subscribers but never persisted. Either way the publisher
        // sees `OK true` so the spec stays satisfied.
        Ok(
            SaveEventStatus::Success
            | SaveEventStatus::Rejected(nula_storage::RejectedReason::Ephemeral),
        ) => (
            true,
            RelayMessage::Ok {
                event_id,
                accepted: true,
                message: String::new(),
            },
        ),
        Ok(SaveEventStatus::Rejected(reason)) => (
            false,
            RelayMessage::Ok {
                event_id,
                accepted: false,
                message: format!("{}: {reason:?}", MachineReadablePrefix::Invalid.as_str()),
            },
        ),
        // `SaveEventStatus` is `#[non_exhaustive]`. Future protocol
        // additions land here as a generic refusal so the relay does
        // not silently mis-classify them.
        Ok(_) => (
            false,
            RelayMessage::Ok {
                event_id,
                accepted: false,
                message: format!(
                    "{}: unsupported SaveEventStatus variant",
                    MachineReadablePrefix::Error.as_str()
                ),
            },
        ),
        Err(e) => (
            false,
            RelayMessage::Ok {
                event_id,
                accepted: false,
                message: format!("{}: {e}", MachineReadablePrefix::Error.as_str()),
            },
        ),
    };

    send(sink, &reply).await?;
    if accepted {
        // Fan out to every other connection's live subscriptions.
        // `send` returns `Err` only when there are zero receivers,
        // which is fine — this side already replied OK.
        ctx.broadcast.send(event).ok();
    }
    Ok(())
}

async fn forward_to_subscriptions(
    sink: &mut Sink,
    subscriptions: &HashMap<SubscriptionId, Vec<Filter>>,
    event: &Event,
) -> Result<(), DispatchError> {
    use nula_core::filter::MatchEventOptions;
    let opts = MatchEventOptions::default();
    for (sub_id, filters) in subscriptions {
        if filters.iter().any(|f| f.match_event(event, opts)) {
            send(
                sink,
                &RelayMessage::Event {
                    subscription_id: sub_id.clone(),
                    event: event.clone(),
                },
            )
            .await?;
        }
    }
    Ok(())
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

async fn handle_neg_open(
    ctx: &ConnectionContext,
    neg_sessions: &mut HashMap<SubscriptionId, Responder>,
    sink: &mut Sink,
    subscription_id: SubscriptionId,
    filter: Filter,
    initial_message_hex: String,
) -> Result<(), DispatchError> {
    if neg_sessions.contains_key(&subscription_id) {
        return send_neg_err(
            sink,
            subscription_id,
            MachineReadablePrefix::Duplicate,
            "subscription already open",
        )
        .await;
    }

    // Per-filter admit gate -- mirror REQ semantics so policy still
    // applies to NIP-77 reads.
    if let AdmitVerdict::Reject(reason) = ctx.read_policy.admit_filter(&filter).await {
        return send_neg_err(
            sink,
            subscription_id,
            MachineReadablePrefix::Restricted,
            &reason,
        )
        .await;
    }

    let storage = match nula_sync::from_database(ctx.storage.as_ref(), filter).await {
        Ok(s) => s,
        Err(e) => {
            return send_neg_err(
                sink,
                subscription_id,
                MachineReadablePrefix::Error,
                format!("storage backend error: {e}"),
            )
            .await;
        }
    };

    let mut responder = match Responder::with_defaults(storage) {
        Ok(r) => r,
        Err(e) => {
            return send_neg_err(
                sink,
                subscription_id,
                MachineReadablePrefix::Error,
                format!("negentropy init error: {e}"),
            )
            .await;
        }
    };

    let reply_hex = match responder.reconcile_hex(&initial_message_hex) {
        Ok(hex) => hex,
        Err(e) => {
            return send_neg_err(
                sink,
                subscription_id,
                MachineReadablePrefix::Invalid,
                format!("negentropy reconcile error: {e}"),
            )
            .await;
        }
    };

    neg_sessions.insert(subscription_id.clone(), responder);
    send(
        sink,
        &RelayMessage::NegMsg {
            subscription_id,
            message: reply_hex,
        },
    )
    .await
}

async fn handle_neg_msg(
    neg_sessions: &mut HashMap<SubscriptionId, Responder>,
    sink: &mut Sink,
    subscription_id: SubscriptionId,
    message_hex: String,
) -> Result<(), DispatchError> {
    let Some(responder) = neg_sessions.get_mut(&subscription_id) else {
        return send_neg_err(
            sink,
            subscription_id,
            MachineReadablePrefix::Invalid,
            "no open NIP-77 session for this subscription id",
        )
        .await;
    };

    let reply_hex = match responder.reconcile_hex(&message_hex) {
        Ok(hex) => hex,
        Err(e) => {
            // Drop the broken session; the client must reopen.
            neg_sessions.remove(&subscription_id);
            return send_neg_err(
                sink,
                subscription_id,
                MachineReadablePrefix::Invalid,
                format!("negentropy reconcile error: {e}"),
            )
            .await;
        }
    };

    send(
        sink,
        &RelayMessage::NegMsg {
            subscription_id,
            message: reply_hex,
        },
    )
    .await
}

async fn send_neg_err(
    sink: &mut Sink,
    subscription_id: SubscriptionId,
    prefix: MachineReadablePrefix,
    detail: impl std::fmt::Display,
) -> Result<(), DispatchError> {
    let message = format!("{}: {detail}", prefix.as_str());
    send(
        sink,
        &RelayMessage::NegErr {
            subscription_id,
            message,
        },
    )
    .await
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
