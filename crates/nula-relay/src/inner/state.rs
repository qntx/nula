//! Mutable bookkeeping owned by the actor task.
//!
//! Lives in a single struct so the [`super::run`] loop can pass it
//! by `&mut` to focused helpers without re-shaping arguments on
//! every change.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use nula_core::Filter;
use nula_core::{EventId, SubscriptionId};
use nula_net::{WebSocketSink, WebSocketStream};
use tokio::sync::oneshot;

use super::command::SubscriptionSink;
use crate::error::Error;
use crate::options::{RelayOptions, SubscribeOptions};
use crate::stats::RelayStats;
use crate::status::AtomicRelayStatus;

/// What a subscription needs while the actor is keeping it alive.
#[derive(Debug)]
pub(super) struct SubscriptionEntry {
    pub(super) filters: Vec<Filter>,
    pub(super) options: SubscribeOptions,
    pub(super) sink: SubscriptionSink,
}

/// What a publish call needs while the actor is waiting for an `OK`
/// frame.
#[derive(Debug)]
pub(super) struct PendingPublish {
    pub(super) reply: oneshot::Sender<Result<(), Error>>,
    /// Wall-clock deadline beyond which the publish is considered
    /// timed out. The [`super::run`] loop polls this against
    /// `Instant::now()` on every wakeup.
    pub(super) deadline: Instant,
    /// The original timeout the caller configured. Surfaced
    /// verbatim in [`crate::Error::PublishTimeout`] so observers see
    /// the value they asked for rather than a recovered
    /// approximation.
    pub(super) timeout: std::time::Duration,
}

/// All actor-side mutable state.
///
/// Held by one task; never aliased.
pub(super) struct ActorState {
    /// Outbound half of the live connection. `None` when the actor
    /// is `Initialized` / `Disconnected` / `Terminated`.
    pub(super) sink: Option<WebSocketSink>,
    /// Inbound half of the live connection. Mirrors `sink`.
    pub(super) stream: Option<WebSocketStream>,
    /// Subscriptions the actor is responsible for re-issuing on the
    /// next successful connect.
    pub(super) subscriptions: HashMap<SubscriptionId, SubscriptionEntry>,
    /// Outstanding publishes the actor is waiting on `OK` for.
    pub(super) pending_publishes: HashMap<EventId, PendingPublish>,
    /// Number of consecutive failed reconnect attempts. Reset to 0
    /// on a successful handshake.
    pub(super) reconnect_attempts: u32,
}

impl std::fmt::Debug for ActorState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Sink/Stream type-erased trait objects do not implement
        // Debug; expose meaningful counters instead.
        f.debug_struct("ActorState")
            .field("connected", &(self.sink.is_some() && self.stream.is_some()))
            .field("subscriptions", &self.subscriptions.len())
            .field("pending_publishes", &self.pending_publishes.len())
            .field("reconnect_attempts", &self.reconnect_attempts)
            .finish()
    }
}

impl ActorState {
    pub(super) fn new() -> Self {
        Self {
            sink: None,
            stream: None,
            subscriptions: HashMap::new(),
            pending_publishes: HashMap::new(),
            reconnect_attempts: 0,
        }
    }

    /// Drop the live socket. Used by every disconnect-style
    /// transition (`Disconnect` command, IO error from the stream,
    /// reconnect) before the actor moves to a non-connected state.
    pub(super) fn drop_socket(&mut self) {
        self.sink = None;
        self.stream = None;
    }

    /// Earliest deadline across all in-flight publishes. The actor's
    /// `select!` loop arms a timer against this value so the publish
    /// timeout sweep runs without depending on external wakeups.
    pub(super) fn earliest_publish_deadline(&self) -> Option<Instant> {
        self.pending_publishes.values().map(|p| p.deadline).min()
    }
}

/// Read-only context the actor task closes over for the entire run.
///
/// Holds everything the actor needs that does not change after
/// spawn: the URL, the transport, the options snapshot, the shared
/// status / stats atomics, and the [`crate::SubscriptionItem`]
/// publishing channel for orphan events.
#[derive(Debug)]
pub(super) struct StaticCtx {
    pub(super) url: nula_core::RelayUrl,
    pub(super) transport: Arc<dyn nula_net::WebSocketTransport>,
    pub(super) options: RelayOptions,
    pub(super) status: Arc<AtomicRelayStatus>,
    pub(super) stats: Arc<RelayStats>,
}
