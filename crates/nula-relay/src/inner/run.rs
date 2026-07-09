//! Actor task — owns the socket and routes commands ↔ frames.
//!
//! Architecture:
//!
//! ```text
//!  Relay handle               Actor task                     Transport
//!  ────────────               ──────────                     ─────────
//!     Command ────cmd_rx────►   select! ────sink.send()────►   …
//!                              ╱   │  ╲
//!                            ╱     │    ╲
//! SubscriptionHandle ─close_rx─►   │      ◄── stream.next() ── …
//!                                  ▼
//!                             dispatch ─────► subscription sinks
//!                                       ─────► pending publish replies
//!                                       ─────► notification_tx
//! ```
//!
//! The actor loop processes one wakeup at a time and never holds an
//! awaiting borrow across a tokio yield — so the borrow checker
//! enforces the actor's single-task invariant directly.

use std::future::{Future, pending};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use futures::stream::StreamExt;
use nula_core::{Filter, RelayUrl, SubscriptionId};
use tokio::sync::mpsc;
use tokio::time::sleep_until;

use super::command::{Command, Reply, SubscriptionSink};
use super::dispatch::{FrameOutcome, handle_frame};
use super::outbound::{send_close, send_event, send_req};
use super::state::{ActorState, PendingPublish, StaticCtx, SubscriptionEntry};
use crate::error::Error;
use crate::notification::RelayNotification;
use crate::options::{PublishOptions, RelayOptions, SubscribeOptions};
use crate::stats::RelayStats;
use crate::status::{AtomicRelayStatus, RelayStatus};
use crate::transport::{WebSocketStream, WebSocketTransport};

/// Channels the public [`crate::Relay`] handle keeps after spawn.
///
/// The actor task is detached: tokio drops the `JoinHandle` on
/// return from [`spawn_actor`]. The actor exits when it observes
/// the [`Command::Shutdown`] sent from `Inner::Drop`, or when
/// `command_rx` closes because the last sender was dropped.
pub(crate) struct ActorChannels {
    pub(crate) command_tx: mpsc::UnboundedSender<Command>,
    pub(crate) close_tx: mpsc::UnboundedSender<SubscriptionId>,
    pub(crate) notification_rx: mpsc::UnboundedReceiver<RelayNotification>,
    pub(crate) status: Arc<AtomicRelayStatus>,
    pub(crate) stats: Arc<RelayStats>,
}

/// Inputs the spawn function takes. Bundled to keep the call site
/// readable.
#[derive(Debug)]
pub(crate) struct ActorContext {
    pub(crate) url: RelayUrl,
    pub(crate) transport: Arc<dyn WebSocketTransport>,
    pub(crate) options: RelayOptions,
}

/// Spawn the actor task and return the channels the public handle
/// will keep.
pub(crate) fn spawn_actor(ctx: ActorContext) -> ActorChannels {
    let status = Arc::new(AtomicRelayStatus::default());
    let stats = Arc::new(RelayStats::default());

    let (command_tx, command_rx) = mpsc::unbounded_channel();
    let (close_tx, close_rx) = mpsc::unbounded_channel();
    let (notification_tx, notification_rx) = mpsc::unbounded_channel();

    let static_ctx = StaticCtx {
        url: ctx.url,
        transport: ctx.transport,
        options: ctx.options,
        status: Arc::clone(&status),
        stats: Arc::clone(&stats),
    };

    // Detach the task — the actor's lifecycle is driven by the
    // Shutdown command (or `command_rx` closure), not by anyone
    // awaiting the JoinHandle.
    tokio::spawn(actor_run(static_ctx, command_rx, close_rx, notification_tx));

    ActorChannels {
        command_tx,
        close_tx,
        notification_rx,
        status,
        stats,
    }
}

async fn actor_run(
    ctx: StaticCtx,
    mut command_rx: mpsc::UnboundedReceiver<Command>,
    mut close_rx: mpsc::UnboundedReceiver<SubscriptionId>,
    notification_tx: mpsc::UnboundedSender<RelayNotification>,
) {
    set_status(&ctx, &notification_tx, RelayStatus::Initialized);
    let mut state = ActorState::new();
    let mut reconnect_deadline: Option<Instant> = None;

    loop {
        // Build the wakeup timers as boxed dyn futures so each
        // `select!` arm has a single concrete type regardless of
        // whether a deadline is currently armed. `sleep_until` is
        // cancel-safe and rebuilding it on every wakeup is correct
        // because the absolute deadline carries through.
        let mut next_reconnect: Pin<Box<dyn Future<Output = ()> + Send>> =
            timer_for(reconnect_deadline);
        let mut next_publish_timeout: Pin<Box<dyn Future<Output = ()> + Send>> =
            timer_for(state.earliest_publish_deadline());

        tokio::select! {
            biased;

            cmd = command_rx.recv() => {
                let Some(cmd) = cmd else { break };
                if matches!(cmd, Command::Shutdown) {
                    break;
                }
                handle_command(&ctx, &mut state, &notification_tx, cmd, &mut reconnect_deadline)
                    .await;
            }

            Some(id) = close_rx.recv() => {
                handle_drop_subscription(&mut state, id).await;
            }

            maybe_frame = recv_inbound(state.stream.as_mut()) => {
                let outcome = maybe_frame.map_or(
                    FrameOutcome::Disconnected,
                    |frame| handle_frame(&ctx, &mut state, &notification_tx, frame),
                );
                if matches!(outcome, FrameOutcome::Disconnected) {
                    transition_to_disconnected(&ctx, &mut state, &notification_tx);
                    reconnect_deadline = schedule_reconnect(&ctx, &state);
                }
            }

            () = next_reconnect.as_mut() => {
                reconnect_deadline = None;
                run_reconnect(&ctx, &mut state, &notification_tx).await;
                if !state.is_connected() && ctx.status.load() != RelayStatus::Terminated {
                    reconnect_deadline = schedule_reconnect(&ctx, &state);
                }
            }

            () = next_publish_timeout.as_mut() => {
                // The post-select expiry sweep below does the actual work.
            }
        }

        // After every wakeup, fail any publishes whose deadline has
        // elapsed. Done outside the select! so it runs regardless of
        // which arm fired.
        expire_pending_publishes(&mut state);
    }

    set_status(&ctx, &notification_tx, RelayStatus::Terminated);
    state.drop_socket();
    drop(notification_tx.send(RelayNotification::Shutdown));
}

/// Build a sleep future for an optional absolute deadline. `None`
/// yields a future that never resolves, keeping the corresponding
/// `select!` arm permanently disarmed.
fn timer_for(deadline: Option<Instant>) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    match deadline {
        Some(d) => Box::pin(sleep_until(d.into())),
        None => Box::pin(pending::<()>()),
    }
}

/// Dispatch a single command to the right handler. Pulled out of the
/// `select!` body so the actor loop stays well under the cognitive
/// complexity threshold and `Command::Shutdown` is handled inline at
/// the loop level.
async fn handle_command(
    ctx: &StaticCtx,
    state: &mut ActorState,
    notification_tx: &mpsc::UnboundedSender<RelayNotification>,
    cmd: Command,
    reconnect_deadline: &mut Option<Instant>,
) {
    match cmd {
        Command::Connect { reply } => {
            handle_connect(ctx, state, notification_tx, reply).await;
            *reconnect_deadline = None;
        }
        Command::Disconnect { reply } => {
            handle_disconnect(ctx, state, notification_tx);
            *reconnect_deadline = None;
            // `reply.send(())` returns `Result<(), ()>` (a `Copy`
            // type) so `drop` is a no-op. Match the value out to
            // explicitly acknowledge the result.
            match reply.send(()) {
                Ok(()) | Err(()) => {}
            }
        }
        Command::Subscribe {
            id,
            filters,
            options,
            sink,
            reply,
        } => {
            handle_subscribe(ctx, state, id, filters, options, sink, reply).await;
        }
        Command::SubscribeNeg {
            id,
            filter,
            initial_message_hex,
            sink,
            reply,
        } => {
            handle_subscribe_neg(ctx, state, id, filter, initial_message_hex, sink, reply).await;
        }
        Command::Publish {
            event,
            options,
            reply,
        } => {
            handle_publish(ctx, state, event, options, reply).await;
        }
        #[cfg(feature = "nip42")]
        Command::Authenticate { event, reply } => {
            handle_authenticate(state, event, reply).await;
        }
        Command::SendMsg { message, reply } => {
            handle_send_msg(state, message, reply).await;
        }
        Command::Shutdown => {
            // Already filtered at the loop level; reaching this arm
            // would be a logic bug. Treating it as a shutdown is the
            // safe behaviour.
        }
    }
}

async fn handle_connect(
    ctx: &StaticCtx,
    state: &mut ActorState,
    notification_tx: &mpsc::UnboundedSender<RelayNotification>,
    reply: Reply<Result<(), Error>>,
) {
    if ctx.status.load() == RelayStatus::Connected {
        drop(reply.send(Ok(())));
        return;
    }

    let result = perform_connect(ctx, state, notification_tx).await;
    if result.is_ok() {
        reissue_subscriptions(state).await;
    }
    drop(reply.send(result));
}

async fn perform_connect(
    ctx: &StaticCtx,
    state: &mut ActorState,
    notification_tx: &mpsc::UnboundedSender<RelayNotification>,
) -> Result<(), Error> {
    set_status(ctx, notification_tx, RelayStatus::Connecting);
    ctx.stats.connect_attempts.fetch_add(1, Ordering::Relaxed);

    let started = Instant::now();
    let connect_fut = ctx
        .transport
        .connect(&ctx.url, &ctx.options.connection_mode);
    let timed = tokio::time::timeout(ctx.options.connect_timeout, connect_fut).await;

    let (sink, stream) = match timed {
        Ok(Ok(pair)) => pair,
        Ok(Err(err)) => {
            set_status(ctx, notification_tx, RelayStatus::Disconnected);
            return Err(Error::Transport(err));
        }
        Err(_) => {
            set_status(ctx, notification_tx, RelayStatus::Disconnected);
            return Err(Error::ConnectTimeout(ctx.options.connect_timeout));
        }
    };

    let elapsed = started.elapsed().as_nanos();
    let elapsed_u64 = u64::try_from(elapsed).unwrap_or(u64::MAX);
    ctx.stats
        .last_handshake_nanos
        .store(elapsed_u64, Ordering::Relaxed);
    ctx.stats.connect_successes.fetch_add(1, Ordering::Relaxed);

    state.sink = Some(sink);
    state.stream = Some(stream);
    state.reconnect_attempts = 0;
    set_status(ctx, notification_tx, RelayStatus::Connected);
    Ok(())
}

/// Drop the live socket and announce `Disconnected`. Used by the
/// `Disconnect` command and by IO-error paths.
fn handle_disconnect(
    ctx: &StaticCtx,
    state: &mut ActorState,
    notification_tx: &mpsc::UnboundedSender<RelayNotification>,
) {
    state.drop_socket();
    set_status(ctx, notification_tx, RelayStatus::Disconnected);
}

/// Same logic as [`handle_disconnect`] but reads better at the call
/// site that handles an inbound IO error / EOF.
fn transition_to_disconnected(
    ctx: &StaticCtx,
    state: &mut ActorState,
    notification_tx: &mpsc::UnboundedSender<RelayNotification>,
) {
    handle_disconnect(ctx, state, notification_tx);
}

fn schedule_reconnect(ctx: &StaticCtx, state: &ActorState) -> Option<Instant> {
    let delay = ctx
        .options
        .reconnect_policy
        .next_delay(state.reconnect_attempts)?;
    Some(Instant::now() + delay)
}

async fn run_reconnect(
    ctx: &StaticCtx,
    state: &mut ActorState,
    notification_tx: &mpsc::UnboundedSender<RelayNotification>,
) {
    state.reconnect_attempts = state.reconnect_attempts.saturating_add(1);
    if perform_connect(ctx, state, notification_tx).await.is_err() {
        return;
    }
    reissue_subscriptions(state).await;
}

/// Re-issue every active subscription on the current socket. Called
/// after a successful handshake, both for the first connect and for
/// every reconnect.
async fn reissue_subscriptions(state: &mut ActorState) {
    let Some(sink) = state.sink.as_mut() else {
        return;
    };
    for (id, entry) in &state.subscriptions {
        if entry.skip_reissue {
            // NIP-77 reconciliation sessions cannot be resumed
            // across a reconnect; the Negentropy state machine
            // would diverge from the relay's view. The session is
            // surfaced as a `NegErr { message: "closed: ..." }`
            // by the dispatch path when the relay drops it on
            // reconnect, so the caller will see a clean shutdown.
            continue;
        }
        drop(send_req(sink, id.clone(), entry.filters.clone()).await);
    }
}

async fn handle_subscribe(
    ctx: &StaticCtx,
    state: &mut ActorState,
    id: SubscriptionId,
    filters: Vec<Filter>,
    options: SubscribeOptions,
    sink: SubscriptionSink,
    reply: Reply<Result<(), Error>>,
) {
    if state.subscriptions.contains_key(&id) {
        drop(reply.send(Err(Error::DuplicateSubscription(id))));
        return;
    }
    if state.subscriptions.len() >= ctx.options.limits.max_subscriptions {
        drop(reply.send(Err(Error::TooManySubscriptions {
            limit: ctx.options.limits.max_subscriptions,
        })));
        return;
    }

    state.subscriptions.insert(
        id.clone(),
        SubscriptionEntry {
            filters: filters.clone(),
            options,
            sink,
            skip_reissue: false,
        },
    );

    if let Some(wire_sink) = state.sink.as_mut()
        && let Err(err) = send_req(wire_sink, id, filters).await
    {
        // The wire is gone. The dispatch loop will pick up the
        // disconnect on the next read; surface the error here so
        // the caller does not have to wait for that to happen.
        drop(reply.send(Err(err)));
        return;
    }
    drop(reply.send(Ok(())));
}

async fn handle_subscribe_neg(
    ctx: &StaticCtx,
    state: &mut ActorState,
    id: SubscriptionId,
    filter: Filter,
    initial_message_hex: String,
    sink: SubscriptionSink,
    reply: Reply<Result<(), Error>>,
) {
    if state.subscriptions.contains_key(&id) {
        drop(reply.send(Err(Error::DuplicateSubscription(id))));
        return;
    }
    if state.subscriptions.len() >= ctx.options.limits.max_subscriptions {
        drop(reply.send(Err(Error::TooManySubscriptions {
            limit: ctx.options.limits.max_subscriptions,
        })));
        return;
    }

    state.subscriptions.insert(
        id.clone(),
        SubscriptionEntry {
            filters: vec![filter.clone()],
            options: SubscribeOptions::new(),
            sink,
            skip_reissue: true,
        },
    );

    let Some(wire_sink) = state.sink.as_mut() else {
        // Removed the entry on the failure path so the slot does
        // not leak into the actor's bookkeeping.
        state.subscriptions.remove(&id);
        drop(reply.send(Err(Error::NotConnected)));
        return;
    };
    let neg_open = nula_core::ClientMessage::NegOpen {
        subscription_id: id.clone(),
        filter,
        initial_message: initial_message_hex,
    };
    if let Err(err) = super::outbound::send_msg(wire_sink, neg_open).await {
        state.subscriptions.remove(&id);
        drop(reply.send(Err(err)));
        return;
    }
    drop(reply.send(Ok(())));
}

async fn handle_drop_subscription(state: &mut ActorState, id: SubscriptionId) {
    if state.subscriptions.remove(&id).is_some()
        && let Some(wire_sink) = state.sink.as_mut()
    {
        drop(send_close(wire_sink, id).await);
    }
}

async fn handle_publish(
    ctx: &StaticCtx,
    state: &mut ActorState,
    event: nula_core::Event,
    options: PublishOptions,
    reply: Reply<Result<(), Error>>,
) {
    if !state.is_connected() {
        drop(reply.send(Err(Error::NotConnected)));
        return;
    }
    if state.pending_publishes.len() >= ctx.options.limits.max_pending_publishes {
        drop(reply.send(Err(Error::TooManyPendingPublishes {
            limit: ctx.options.limits.max_pending_publishes,
        })));
        return;
    }

    let timeout = options.timeout.unwrap_or(ctx.options.publish_timeout);
    let event_id = event.id;

    if let Some(wire_sink) = state.sink.as_mut()
        && let Err(err) = send_event(wire_sink, event).await
    {
        drop(reply.send(Err(err)));
        return;
    }

    ctx.stats.events_published.fetch_add(1, Ordering::Relaxed);
    state.pending_publishes.insert(
        event_id,
        PendingPublish {
            reply,
            deadline: Instant::now() + timeout,
            timeout,
        },
    );
}

#[cfg(feature = "nip42")]
async fn handle_authenticate(
    state: &mut ActorState,
    event: nula_core::Event,
    reply: Reply<Result<(), Error>>,
) {
    use super::outbound::send_auth;
    let result = match state.sink.as_mut() {
        Some(wire_sink) => send_auth(wire_sink, event).await.map(|_| ()),
        None => Err(Error::NotConnected),
    };
    drop(reply.send(result));
}

async fn handle_send_msg(
    state: &mut ActorState,
    message: nula_core::ClientMessage,
    reply: Reply<Result<(), Error>>,
) {
    use super::outbound::send_msg;
    let result = match state.sink.as_mut() {
        Some(wire_sink) => send_msg(wire_sink, message).await.map(|_| ()),
        None => Err(Error::NotConnected),
    };
    drop(reply.send(result));
}

fn expire_pending_publishes(state: &mut ActorState) {
    let now = Instant::now();
    let timed_out: Vec<nula_core::EventId> = state
        .pending_publishes
        .iter()
        .filter(|(_, p)| p.deadline <= now)
        .map(|(id, _)| *id)
        .collect();
    for id in timed_out {
        if let Some(pending) = state.pending_publishes.remove(&id) {
            drop(pending.reply.send(Err(Error::PublishTimeout {
                event_id: id,
                timeout: pending.timeout,
            })));
        }
    }
}

impl ActorState {
    fn is_connected(&self) -> bool {
        self.sink.is_some() && self.stream.is_some()
    }
}

fn set_status(
    ctx: &StaticCtx,
    notification_tx: &mpsc::UnboundedSender<RelayNotification>,
    new: RelayStatus,
) {
    let prev = ctx.status.load();
    if prev == new {
        return;
    }
    ctx.status.set(new);
    drop(notification_tx.send(RelayNotification::Status(new)));
    #[cfg(feature = "tracing")]
    tracing::debug!(status = %new, prev = %prev, "relay status transition");
}

async fn recv_inbound(
    stream: Option<&mut WebSocketStream>,
) -> Option<Result<crate::transport::Message, Error>> {
    if let Some(s) = stream {
        s.next().await.map(|res| res.map_err(Error::from))
    } else {
        pending().await
    }
}
