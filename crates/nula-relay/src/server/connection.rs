//! Per-connection actor.
//!
//! One `handle_connection` future per accepted TCP socket. Owns the
//! split sink/stream halves, the per-connection authenticated flag,
//! and the in-flight subscription map. Exits cleanly on client close,
//! transport error, or relay-wide shutdown signal.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::ops::ControlFlow;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::{SinkExt, StreamExt};
use nula_core::message::{MachineReadablePrefix, RelayMessage};
use nula_core::nips::nip42;
use nula_core::{
    ClientMessage, Event, EventBuilder, EventId, Filter, JsonUtil, Keys, PublicKey, RelayUrl,
    SubscriptionId, Timestamp,
};
use nula_storage::{NostrDatabase, SaveEventStatus};
use nula_sync::Responder;
use serde_json::Value;
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::protocol::Message as WsMessage;

use crate::server::options::{Nip42Mode, RateLimit};
use crate::server::policy::{AdmitVerdict, QueryPolicy, WritePolicy};

/// Connection-scoped resources. Cloned cheaply (every field is
/// `Arc`-shared with the relay handle).
#[derive(Clone)]
pub(crate) struct ConnectionContext {
    pub(crate) storage: Arc<dyn NostrDatabase>,
    pub(crate) write_policy: Arc<dyn WritePolicy>,
    pub(crate) query_policy: Arc<dyn QueryPolicy>,
    /// Address of the connected client, set once per accepted socket
    /// in [`handle_connection`] and handed to every policy call.
    pub(crate) peer: SocketAddr,
    /// This relay's own url, used to verify the `relay` tag of an
    /// inbound NIP-42 AUTH event.
    pub(crate) relay_url: RelayUrl,
    /// NIP-42 authentication enforcement mode.
    pub(crate) nip42_mode: Nip42Mode,
    /// Minimum NIP-13 proof-of-work difficulty required of inbound
    /// events; `None` accepts any difficulty.
    pub(crate) min_pow: Option<u8>,
    /// Reject subscription ids longer than this many characters.
    /// `None` is unlimited; mirrors NIP-11 `max_subid_length`.
    pub(crate) max_subid_length: Option<usize>,
    /// Clamp every `REQ` / NIP-77 filter `limit` to at most this.
    /// `None` leaves client limits untouched; mirrors NIP-11 `max_limit`.
    pub(crate) max_filter_limit: Option<usize>,
    /// Maximum concurrent subscriptions per connection; `None` is
    /// unlimited. Mirrors NIP-11 `max_subscriptions`.
    pub(crate) max_active_subscriptions: Option<usize>,
    /// Default `limit` applied to a `REQ` / NIP-77 filter that omits
    /// one; `None` leaves it untouched. Mirrors NIP-11 `default_limit`.
    pub(crate) default_filter_limit: Option<usize>,
    /// Per-connection, per-minute rate limits.
    pub(crate) rate_limit: RateLimit,
    /// Test fault injection: never reply to NIP-01 frames.
    pub(crate) unresponsive: bool,
    /// Test fault injection: answer every `REQ` with this many random
    /// events instead of querying storage.
    pub(crate) send_random_events: Option<u16>,
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
    peer: SocketAddr,
    mut ctx: ConnectionContext,
    mut shutdown: broadcast::Receiver<()>,
) {
    ctx.peer = peer;
    let (mut sink, mut stream) = ws.split();
    let mut subscriptions: HashMap<SubscriptionId, Vec<Filter>> = HashMap::new();
    let mut neg_sessions: HashMap<SubscriptionId, Responder> = HashMap::new();
    let mut live = ctx.broadcast.subscribe();

    // Optional NIP-42 challenge — issued once at the top of the loop
    // when a non-`Disabled` mode is configured. The challenge string is
    // retained so the AUTH reply can be verified against it.
    let mut auth = AuthState {
        authenticated: !ctx.nip42_mode.is_enabled(),
        pubkey: None,
        challenge: String::new(),
    };
    if ctx.nip42_mode.is_enabled() {
        auth.challenge = format!("nula-mock-{}", random_hex_token());
        let frame = encode_relay(&RelayMessage::Auth(auth.challenge.clone()));
        if sink.send(WsMessage::text(frame)).await.is_err() {
            return;
        }
    }

    let mut rate = RateLimiter::new(ctx.rate_limit);

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

            next = stream.next() => {
                if handle_inbound_frame(
                    &ctx,
                    &mut subscriptions,
                    &mut neg_sessions,
                    &mut sink,
                    &mut auth,
                    &mut rate,
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

/// Handle one frame from the WebSocket stream. Extracted from the
/// main `select!` body so the orchestration loop stays well below
/// clippy's `cognitive_complexity` ceiling.
async fn handle_inbound_frame(
    ctx: &ConnectionContext,
    subscriptions: &mut HashMap<SubscriptionId, Vec<Filter>>,
    neg_sessions: &mut HashMap<SubscriptionId, Responder>,
    sink: &mut Sink,
    auth: &mut AuthState,
    rate: &mut RateLimiter,
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

    // Fault injection: swallow NIP-01 frames without replying. Control
    // frames (ping/pong/close) were handled in the match above.
    if ctx.unresponsive {
        return ControlFlow::Continue(());
    }

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

    if !auth.authenticated && message_needs_auth(&msg, ctx.nip42_mode) {
        let reply = match &msg {
            ClientMessage::Event(event) => RelayMessage::Ok {
                event_id: event.id,
                accepted: false,
                message: format!(
                    "{}: authentication required to publish",
                    MachineReadablePrefix::AuthRequired.as_str()
                ),
            },
            ClientMessage::Req {
                subscription_id, ..
            } => RelayMessage::Closed {
                subscription_id: subscription_id.clone(),
                message: format!(
                    "{}: authentication required to read",
                    MachineReadablePrefix::AuthRequired.as_str()
                ),
            },
            _ => RelayMessage::Notice(
                "auth-required: this relay requires NIP-42 authentication".into(),
            ),
        };
        sink.send(WsMessage::text(encode_relay(&reply))).await.ok();
        return ControlFlow::Continue(());
    }

    if let Some(reply) = rate.check(&msg) {
        sink.send(WsMessage::text(encode_relay(&reply))).await.ok();
        return ControlFlow::Continue(());
    }

    if dispatch(ctx, subscriptions, neg_sessions, sink, msg, auth)
        .await
        .is_err()
    {
        return ControlFlow::Break(());
    }
    ControlFlow::Continue(())
}

#[derive(Debug)]
struct DispatchError;

async fn dispatch(
    ctx: &ConnectionContext,
    subscriptions: &mut HashMap<SubscriptionId, Vec<Filter>>,
    neg_sessions: &mut HashMap<SubscriptionId, Responder>,
    sink: &mut Sink,
    msg: ClientMessage,
    auth: &mut AuthState,
) -> Result<(), DispatchError> {
    match msg {
        ClientMessage::Event(event) => {
            handle_event(ctx, sink, event, auth).await?;
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
        ClientMessage::Auth(event) => {
            let event_id = event.id;
            let reply = match verify_client_auth(&event, &ctx.relay_url, &auth.challenge) {
                Ok(()) => {
                    auth.authenticated = true;
                    auth.pubkey = Some(event.pubkey);
                    RelayMessage::Ok {
                        event_id,
                        accepted: true,
                        message: String::new(),
                    }
                }
                Err(reason) => RelayMessage::Ok {
                    event_id,
                    accepted: false,
                    message: format!("{}: {reason}", MachineReadablePrefix::Restricted.as_str()),
                },
            };
            send(sink, &reply).await
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

/// NIP-40 expiration: refuse already-expired events up front with the
/// spec reason. Storage also rejects them, but with a generic reason;
/// this mirrors upstream's `blocked: event is expired`.
fn check_expired(event_id: EventId, event: &Event) -> Option<RelayMessage> {
    let now = Timestamp::now().ok()?;
    if event.is_expired(now).unwrap_or(false) {
        Some(RelayMessage::Ok {
            event_id,
            accepted: false,
            message: format!(
                "{}: event is expired",
                MachineReadablePrefix::Blocked.as_str()
            ),
        })
    } else {
        None
    }
}

/// NIP-13 admission gate (mirrors upstream `nostr-relay-builder`'s
/// `min_pow`): reject under-powered events before policy or storage.
fn check_pow(event_id: EventId, event: &Event, min: u8) -> Option<RelayMessage> {
    if let Err(err) = nula_core::nips::nip13::verify_pow(event, min) {
        Some(RelayMessage::Ok {
            event_id,
            accepted: false,
            message: format!("{}: {err}", MachineReadablePrefix::Pow.as_str()),
        })
    } else {
        None
    }
}

/// NIP-70 protected events: a `["-"]` event may only be published by its
/// author, authenticated via NIP-42. Returns `Some((auth_msg, ok_msg))`
/// when the event must be rejected; the caller must send the AUTH
/// challenge (if present) followed by the OK refusal.
fn check_protected(
    event_id: EventId,
    event: &Event,
    auth: &mut AuthState,
) -> Option<(Option<RelayMessage>, RelayMessage)> {
    if !event.is_protected() || auth.pubkey == Some(event.pubkey) {
        return None;
    }
    if auth.pubkey.is_none() {
        if auth.challenge.is_empty() {
            auth.challenge = format!("nula-mock-{}", random_hex_token());
        }
        let auth_msg = RelayMessage::Auth(auth.challenge.clone());
        let ok_msg = RelayMessage::Ok {
            event_id,
            accepted: false,
            message: format!(
                "{}: this event may only be published by its author",
                MachineReadablePrefix::AuthRequired.as_str()
            ),
        };
        return Some((Some(auth_msg), ok_msg));
    }
    Some((
        None,
        RelayMessage::Ok {
            event_id,
            accepted: false,
            message: format!(
                "{}: this event may only be published by its author",
                MachineReadablePrefix::Blocked.as_str()
            ),
        },
    ))
}

async fn handle_event(
    ctx: &ConnectionContext,
    sink: &mut Sink,
    event: Event,
    auth: &mut AuthState,
) -> Result<(), DispatchError> {
    let event_id: EventId = event.id;

    if let Some(msg) = check_expired(event_id, &event) {
        return send(sink, &msg).await;
    }

    if let Some(min) = ctx.min_pow
        && let Some(msg) = check_pow(event_id, &event, min)
    {
        return send(sink, &msg).await;
    }

    if let Some((maybe_auth, msg)) = check_protected(event_id, &event, auth) {
        if let Some(auth_msg) = maybe_auth {
            send(sink, &auth_msg).await?;
        }
        return send(sink, &msg).await;
    }

    let verdict = ctx.write_policy.admit_event(&event, ctx.peer).await;
    if let AdmitVerdict::Reject { prefix, message } = verdict {
        return send(
            sink,
            &RelayMessage::Ok {
                event_id,
                accepted: false,
                message: format!("{}: {message}", prefix.as_str()),
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
    mut filters: Vec<Filter>,
) -> Result<(), DispatchError> {
    if let Some(max) = ctx.max_subid_length
        && subscription_id.as_str().len() > max
    {
        return send(
            sink,
            &RelayMessage::Closed {
                subscription_id,
                message: format!(
                    "{}: subscription id exceeds {max} characters",
                    MachineReadablePrefix::Invalid.as_str()
                ),
            },
        )
        .await;
    }

    // Per-connection active-subscription cap (mirrors upstream
    // `nostr-relay-builder`'s `max_reqs`). Re-using an existing id
    // replaces that subscription, so only a genuinely new id counts
    // against the cap.
    if let Some(max) = ctx.max_active_subscriptions
        && subscriptions.len() >= max
        && !subscriptions.contains_key(&subscription_id)
    {
        return send(
            sink,
            &RelayMessage::Closed {
                subscription_id,
                message: format!(
                    "{}: too many concurrent subscriptions (max {max})",
                    MachineReadablePrefix::RateLimited.as_str()
                ),
            },
        )
        .await;
    }

    // Fault injection: answer with random events instead of querying.
    if let Some(count) = ctx.send_random_events {
        return stream_random_events(sink, &subscription_id, count).await;
    }

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

    // Per-filter admit gate. The policy may rewrite each filter in
    // place (e.g. clamp an unbounded `limit`) before it is queried and
    // stored as the subscription.
    for filter in &mut filters {
        if let AdmitVerdict::Reject { prefix, message } =
            ctx.query_policy.admit_query(filter, ctx.peer).await
        {
            return send(
                sink,
                &RelayMessage::Closed {
                    subscription_id,
                    message: format!("{}: {message}", prefix.as_str()),
                },
            )
            .await;
        }
        apply_filter_limits(filter, ctx.default_filter_limit, ctx.max_filter_limit);
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

/// Apply the server's default and maximum filter `limit` policy. An
/// absent client `limit` is first filled with `default` (when set),
/// then every limit is clamped to `max` (when set) — which also fills
/// any still-absent limit, so an unbounded read cannot exhaust the
/// relay. Mirrors upstream's `default_filter_limit` + `max_filter_limit`.
fn apply_filter_limits(filter: &mut Filter, default: Option<usize>, max: Option<usize>) {
    if filter.limit.is_none()
        && let Some(default) = default
    {
        filter.limit = Some(default);
    }
    if let Some(max) = max {
        filter.limit = Some(filter.limit.map_or(max, |limit| limit.min(max)));
    }
}

/// Fault injection: stream `count` freshly-signed random events for
/// `subscription_id`, then `EOSE`. Each batch uses a throwaway key.
async fn stream_random_events(
    sink: &mut Sink,
    subscription_id: &SubscriptionId,
    count: u16,
) -> Result<(), DispatchError> {
    let keys = Keys::generate().map_err(|_| DispatchError)?;
    for i in 0..count {
        let Ok(event) = EventBuilder::text_note(format!("random-{i}")).sign_with_keys(&keys) else {
            continue;
        };
        send(
            sink,
            &RelayMessage::Event {
                subscription_id: subscription_id.clone(),
                event,
            },
        )
        .await?;
    }
    send(
        sink,
        &RelayMessage::EndOfStoredEvents(subscription_id.clone()),
    )
    .await
}

async fn handle_neg_open(
    ctx: &ConnectionContext,
    neg_sessions: &mut HashMap<SubscriptionId, Responder>,
    sink: &mut Sink,
    subscription_id: SubscriptionId,
    mut filter: Filter,
    initial_message_hex: String,
) -> Result<(), DispatchError> {
    if let Some(max) = ctx.max_subid_length
        && subscription_id.as_str().len() > max
    {
        return send_neg_err(
            sink,
            subscription_id,
            MachineReadablePrefix::Invalid,
            format!("subscription id exceeds {max} characters"),
        )
        .await;
    }

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
    if let AdmitVerdict::Reject { prefix, message } =
        ctx.query_policy.admit_query(&mut filter, ctx.peer).await
    {
        return send_neg_err(sink, subscription_id, prefix, message).await;
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

/// Per-connection NIP-42 state.
struct AuthState {
    /// Whether the client has completed a valid AUTH exchange.
    authenticated: bool,
    /// Public key proven by a successful AUTH; `None` until then.
    /// Used by the NIP-70 protected-event gate to verify authorship.
    pubkey: Option<PublicKey>,
    /// The challenge this connection issued; empty when none was sent.
    challenge: String,
}

/// Per-connection fixed-window rate limiter (one rolling 60-second
/// window per connection). Only `EVENT` and `REQ` are metered.
struct RateLimiter {
    limit: RateLimit,
    window_start: Instant,
    notes: u32,
    reqs: u32,
}

impl RateLimiter {
    fn new(limit: RateLimit) -> Self {
        Self {
            limit,
            window_start: Instant::now(),
            notes: 0,
            reqs: 0,
        }
    }

    /// Reset the counters when the current 60-second window elapsed.
    fn roll(&mut self) {
        if self.window_start.elapsed() >= Duration::from_mins(1) {
            self.window_start = Instant::now();
            self.notes = 0;
            self.reqs = 0;
        }
    }

    /// Record `msg` against the per-minute budget. Returns a rejection
    /// frame when the budget is exhausted, or `None` when the message
    /// may proceed.
    fn check(&mut self, msg: &ClientMessage) -> Option<RelayMessage> {
        self.roll();
        match msg {
            ClientMessage::Event(event) => {
                let max = self.limit.notes_per_minute?;
                if self.notes >= max {
                    return Some(RelayMessage::Ok {
                        event_id: event.id,
                        accepted: false,
                        message: format!(
                            "{}: more than {max} events per minute",
                            MachineReadablePrefix::RateLimited.as_str()
                        ),
                    });
                }
                self.notes += 1;
                None
            }
            ClientMessage::Req {
                subscription_id, ..
            } => {
                let max = self.limit.reqs_per_minute?;
                if self.reqs >= max {
                    return Some(RelayMessage::Closed {
                        subscription_id: subscription_id.clone(),
                        message: format!(
                            "{}: more than {max} REQs per minute",
                            MachineReadablePrefix::RateLimited.as_str()
                        ),
                    });
                }
                self.reqs += 1;
                None
            }
            _ => None,
        }
    }
}

/// Whether `msg` is blocked for an unauthenticated client under `mode`.
/// Reads (`REQ` / `COUNT` / NIP-77 `NEG-OPEN`) gate under
/// [`Nip42Mode::Read`] / [`Nip42Mode::Both`]; writes (`EVENT`) gate
/// under [`Nip42Mode::Write`] / [`Nip42Mode::Both`]. `AUTH` and the
/// session-control frames are always allowed.
const fn message_needs_auth(msg: &ClientMessage, mode: Nip42Mode) -> bool {
    match msg {
        ClientMessage::Event(_) => mode.requires_for_write(),
        ClientMessage::Req { .. } | ClientMessage::Count { .. } | ClientMessage::NegOpen { .. } => {
            mode.requires_for_read()
        }
        _ => false,
    }
}

/// Full server-side NIP-42 check: Schnorr signature first, then kind,
/// tags, challenge match, and freshness. Returns a human-readable
/// reason on failure for the `OK false` frame.
fn verify_client_auth(event: &Event, relay_url: &RelayUrl, challenge: &str) -> Result<(), String> {
    event
        .verify()
        .map_err(|e| format!("invalid auth event: {e}"))?;
    let now = Timestamp::now().map_err(|e| format!("relay clock unavailable: {e}"))?;
    nip42::verify_auth_event(
        event,
        relay_url,
        challenge,
        now,
        nip42::DEFAULT_MAX_AGE_SECS,
    )
    .map_err(|e| e.to_string())
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
