//! Inbound dispatch: parse a [`nula_net::Message`] into a
//! [`nula_core::RelayMessage`] and route it to the right handler.

use std::sync::atomic::Ordering;

use nula_core::message::RelayMessage;
use nula_net::Message;
use tokio::sync::mpsc;

use super::state::{ActorState, StaticCtx};
use crate::error::Error;
use crate::notification::RelayNotification;
use crate::subscription::SubscriptionItem;

/// Outcome of processing one inbound frame. Drives the actor's
/// reconnect logic from [`super::run`].
#[derive(Debug)]
pub(super) enum FrameOutcome {
    /// Continue processing further frames.
    Continue,
    /// The wire stream ended (peer closed cleanly or returned `None`).
    /// The actor should drop the socket and consider reconnecting.
    Disconnected,
}

/// Process one inbound frame. Returns [`FrameOutcome::Disconnected`]
/// when the stream ended; otherwise [`FrameOutcome::Continue`].
///
/// `notification_tx` is unbounded so this function never awaits on a
/// slow consumer — sticking to non-blocking sends lets the actor
/// remain responsive to other commands and the keepalive timer.
pub(super) fn handle_frame(
    ctx: &StaticCtx,
    state: &mut ActorState,
    notification_tx: &mpsc::UnboundedSender<RelayNotification>,
    frame: Result<Message, Error>,
) -> FrameOutcome {
    let frame = match frame {
        Ok(f) => f,
        Err(err) => {
            #[cfg(feature = "tracing")]
            tracing::debug!(error = %err, "transport surfaced an inbound error");
            #[cfg(not(feature = "tracing"))]
            drop(err);
            return FrameOutcome::Disconnected;
        }
    };

    match frame {
        Message::Text(text) => handle_text_frame(ctx, state, notification_tx, &text),
        Message::Binary(_) => {
            // NIP-01 only specifies text frames. Drop binary
            // payloads silently — they are not protocol-relevant.
            #[cfg(feature = "tracing")]
            tracing::debug!("dropping inbound binary frame");
            FrameOutcome::Continue
        }
        Message::Pong(_) | Message::Ping(_) => {
            // Pings are answered by the transport itself; pongs are
            // observability data only.
            FrameOutcome::Continue
        }
        Message::Close(_) => FrameOutcome::Disconnected,
        // `Message` is `#[non_exhaustive]`; future raw-frame
        // variants are treated as inert data frames.
        _ => FrameOutcome::Continue,
    }
}

fn handle_text_frame(
    ctx: &StaticCtx,
    state: &mut ActorState,
    notification_tx: &mpsc::UnboundedSender<RelayNotification>,
    text: &str,
) -> FrameOutcome {
    let bytes = text.len();
    if bytes > ctx.options.limits.max_message_bytes {
        #[cfg(feature = "tracing")]
        tracing::warn!(
            bytes,
            cap = ctx.options.limits.max_message_bytes,
            "dropping oversized inbound frame",
        );
        return FrameOutcome::Continue;
    }

    ctx.stats
        .bytes_received
        .fetch_add(bytes as u64, Ordering::Relaxed);

    let parsed: RelayMessage = match serde_json::from_str(text) {
        Ok(msg) => msg,
        Err(err) => {
            #[cfg(feature = "tracing")]
            tracing::warn!(error = %err, "failed to parse inbound RelayMessage");
            #[cfg(not(feature = "tracing"))]
            drop(err);
            return FrameOutcome::Continue;
        }
    };

    dispatch_relay_message(ctx, state, notification_tx, parsed);
    FrameOutcome::Continue
}

fn dispatch_relay_message(
    ctx: &StaticCtx,
    state: &mut ActorState,
    notification_tx: &mpsc::UnboundedSender<RelayNotification>,
    message: RelayMessage,
) {
    match message {
        RelayMessage::Event {
            subscription_id,
            event,
        } => {
            ctx.stats.events_received.fetch_add(1, Ordering::Relaxed);
            if let Some(entry) = state.subscriptions.get(&subscription_id) {
                drop(entry.sink.send(SubscriptionItem::Event(event)));
            }
            // Orphan events (subscription dropped between unsubscribe
            // and the relay observing the CLOSE) are silently
            // discarded — they are not protocol violations and
            // surfacing them would just produce noise.
        }
        RelayMessage::EndOfStoredEvents(subscription_id) => {
            if let Some(entry) = state.subscriptions.get(&subscription_id) {
                drop(entry.sink.send(SubscriptionItem::EndOfStoredEvents));
                if entry.options.close_on_eose {
                    state.subscriptions.remove(&subscription_id);
                }
            }
        }
        RelayMessage::Closed {
            subscription_id,
            message,
        } => {
            if let Some(entry) = state.subscriptions.remove(&subscription_id) {
                drop(entry.sink.send(SubscriptionItem::Closed { message }));
            }
            // Dropping `entry.sink` (via remove) ends the
            // `SubscriptionHandle` stream cleanly.
        }
        RelayMessage::Ok {
            event_id,
            accepted,
            message,
        } => {
            if let Some(pending) = state.pending_publishes.remove(&event_id) {
                let result = if accepted {
                    Ok(())
                } else {
                    Err(Error::PublishRejected { event_id, message })
                };
                drop(pending.reply.send(result));
            }
        }
        RelayMessage::Notice(message) => {
            drop(notification_tx.send(RelayNotification::Notice(message)));
        }
        #[cfg(feature = "nip42")]
        RelayMessage::Auth(challenge) => {
            drop(notification_tx.send(RelayNotification::AuthChallenge { challenge }));
        }
        // When the `nip42` feature is off the challenge is silently
        // dropped — the relay will see no AUTH reply and either
        // tolerate the unauthenticated session or close it with a
        // `restricted:` CLOSED, surfaced through the normal stream.
        #[cfg(not(feature = "nip42"))]
        RelayMessage::Auth(_) => {}
        RelayMessage::Count { .. } => {
            // NIP-45 COUNT replies are not part of Phase 2; route
            // them as a no-op for now.
        }
        // `RelayMessage` is `#[non_exhaustive]`; unknown variants
        // are silently dropped — surfacing them would force callers
        // to handle a moving target.
        _ => {}
    }
}
