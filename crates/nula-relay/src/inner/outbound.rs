//! Helpers that convert [`nula_core::ClientMessage`] / event payloads
//! into wire-shaped [`nula_relay::transport::Message`] frames and push them on a
//! [`nula_relay::transport::WebSocketSink`].

use futures::SinkExt;
use nula_core::{ClientMessage, Event, Filter, SubscriptionId};

use crate::error::Error;
use crate::transport::{Message, WebSocketSink};

/// Serialise a [`ClientMessage`] into a single text frame.
pub(super) fn encode(message: &ClientMessage) -> Result<Message, Error> {
    let json = serde_json::to_string(message)?;
    Ok(Message::Text(json))
}

/// Send an outbound `["REQ", <id>, <filters…>]` frame.
pub(super) async fn send_req(
    sink: &mut WebSocketSink,
    id: SubscriptionId,
    filters: Vec<Filter>,
) -> Result<usize, Error> {
    let msg = ClientMessage::req(id, filters);
    let frame = encode(&msg)?;
    let bytes = frame_byte_len(&frame);
    sink.send(frame).await?;
    Ok(bytes)
}

/// Send an outbound `["CLOSE", <id>]` frame.
pub(super) async fn send_close(
    sink: &mut WebSocketSink,
    id: SubscriptionId,
) -> Result<usize, Error> {
    let msg = ClientMessage::close(id);
    let frame = encode(&msg)?;
    let bytes = frame_byte_len(&frame);
    sink.send(frame).await?;
    Ok(bytes)
}

/// Send an outbound `["EVENT", <event>]` frame.
pub(super) async fn send_event(sink: &mut WebSocketSink, event: Event) -> Result<usize, Error> {
    let msg = ClientMessage::Event(event);
    let frame = encode(&msg)?;
    let bytes = frame_byte_len(&frame);
    sink.send(frame).await?;
    Ok(bytes)
}

/// Send an outbound `["AUTH", <event>]` frame.
#[cfg(feature = "nip42")]
pub(super) async fn send_auth(sink: &mut WebSocketSink, event: Event) -> Result<usize, Error> {
    let msg = ClientMessage::Auth(event);
    let frame = encode(&msg)?;
    let bytes = frame_byte_len(&frame);
    sink.send(frame).await?;
    Ok(bytes)
}

/// Send an arbitrary [`ClientMessage`] frame.
///
/// Used by [`crate::Relay::send_msg`] so callers can ship message
/// variants this crate does not have a bespoke `send_*` helper for
/// (e.g. NIP-77 `NegOpen` / `NegMsg` / `NegClose`).
pub(super) async fn send_msg(
    sink: &mut WebSocketSink,
    message: ClientMessage,
) -> Result<usize, Error> {
    let frame = encode(&message)?;
    let bytes = frame_byte_len(&frame);
    sink.send(frame).await?;
    Ok(bytes)
}

/// Best-effort byte length for stats accounting. Control frames
/// (ping/pong/close) are not counted; they don't carry application
/// data.
const fn frame_byte_len(frame: &Message) -> usize {
    match frame {
        Message::Text(s) => s.len(),
        Message::Binary(b) => b.len(),
        // Ping / Pong / Close + every future non-exhaustive variant
        // count as zero application-level bytes.
        _ => 0,
    }
}
