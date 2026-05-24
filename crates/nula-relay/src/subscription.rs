//! Caller-facing subscription handle.
//!
//! `SubscriptionHandle` is what [`crate::Relay::subscribe`] returns:
//! a `Stream` over the events bound to that one subscription, plus
//! the `Eose` and `Closed` lifecycle markers, plus an automatic
//! `["CLOSE", <id>]` on drop. The design follows nostr-tools' "per
//! subscription stream" model rather than rust-nostr's "shared
//! broadcast you filter yourself" model — it removes one whole
//! category of bug (delivering an event to the wrong subscription)
//! and keeps the call site readable.

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::stream::Stream;
use nula_core::{Event, SubscriptionId};
use tokio::sync::mpsc;

/// One frame on a [`SubscriptionHandle`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SubscriptionItem {
    /// An event matched by this subscription.
    Event(Event),
    /// The relay sent EOSE: every historical match has been delivered;
    /// future events arrive in real time.
    EndOfStoredEvents,
    /// The relay sent CLOSED: the subscription is over and the
    /// stream will end after this item.
    Closed {
        /// The reason string. Use
        /// [`nula_core::message::MachineReadablePrefix::from_reason`]
        /// to recover a structured prefix.
        message: String,
    },
    /// The relay sent a NIP-77 `NEG-MSG` reconciliation step. Only
    /// arrives on subscriptions opened via
    /// [`crate::Relay::subscribe_neg`].
    NegMsg {
        /// Reconciliation payload, lowercase hex-encoded.
        message: String,
    },
    /// The relay sent a NIP-77 `NEG-ERR` terminal error frame. The
    /// stream ends after this item; check the conventional
    /// [`nula_core::message::MachineReadablePrefix`] prefix on
    /// `message` for the failure class.
    NegErr {
        /// Reason string supplied by the relay.
        message: String,
    },
}

/// Caller-facing subscription stream.
///
/// Drops auto-`CLOSE` the subscription with the relay actor — there
/// is no need to call an explicit `unsubscribe`.
#[derive(Debug)]
pub struct SubscriptionHandle {
    id: SubscriptionId,
    rx: mpsc::UnboundedReceiver<SubscriptionItem>,
    /// Drop guard: notifies the actor on drop so it can issue a
    /// `["CLOSE", <id>]` and free the subscription slot.
    _close_signal: CloseGuard,
}

impl SubscriptionHandle {
    pub(crate) fn new(
        id: SubscriptionId,
        rx: mpsc::UnboundedReceiver<SubscriptionItem>,
        close_tx: mpsc::UnboundedSender<SubscriptionId>,
    ) -> Self {
        Self {
            id: id.clone(),
            rx,
            _close_signal: CloseGuard {
                id,
                close_tx: Some(close_tx),
            },
        }
    }

    /// The subscription identifier this handle is bound to.
    #[must_use]
    pub const fn id(&self) -> &SubscriptionId {
        &self.id
    }
}

impl Stream for SubscriptionHandle {
    type Item = SubscriptionItem;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

/// RAII guard that signals the actor to send `["CLOSE", <id>]` when
/// the [`SubscriptionHandle`] is dropped.
///
/// `close_tx` is wrapped in `Option` so we can `take()` it inside
/// `Drop` without violating the `&mut self` rule that consumers
/// would otherwise see for moving sender values out.
#[derive(Debug)]
struct CloseGuard {
    id: SubscriptionId,
    close_tx: Option<mpsc::UnboundedSender<SubscriptionId>>,
}

impl Drop for CloseGuard {
    fn drop(&mut self) {
        if let Some(tx) = self.close_tx.take() {
            // The actor may already have shut down; in that case the
            // send fails silently — the subscription map is gone too,
            // so there is nothing left to clean up.
            drop(tx.send(self.id.clone()));
        }
    }
}
