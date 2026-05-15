//! Internal actor that owns the WebSocket connection and routes
//! frames between the wire and the public API handles.
//!
//! Module layout:
//!
//! - [`command`] — `Command` enum sent from public API to the actor.
//! - [`state`] — `ActorState`, the actor's mutable bookkeeping.
//! - [`run`] — the `select!` loop driving the actor.
//! - [`dispatch`] — inbound frame parsing and routing.
//! - [`outbound`] — helpers that serialise [`nula_core::ClientMessage`] and push it on the sink.
//!
//! The actor is single-task: a `tokio::spawn`ed future owns every
//! mutable structure, so internal invariants are enforced by Rust's
//! borrow checker without any locks on the hot path. The public
//! [`crate::Relay`] handle communicates exclusively via channels.

mod command;
mod dispatch;
mod outbound;
mod run;
mod state;

pub(crate) use self::command::Command;
pub(crate) use self::run::{ActorContext, spawn_actor};
