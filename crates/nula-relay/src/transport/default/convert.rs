//! Conversion glue between `nula-net`'s wire types and the
//! `tokio-tungstenite` (re-exported `tungstenite`) types.
//!
//! Kept private: the public API only exposes [`crate::transport::Message`] and
//! [`crate::transport::Error`], so backend types never leak into rustdoc.

use std::borrow::Cow;

use tokio_tungstenite::tungstenite::Utf8Bytes;
use tokio_tungstenite::tungstenite::error::{Error as TgError, ProtocolError};
use tokio_tungstenite::tungstenite::protocol::{CloseFrame as TgCloseFrame, Message as TgMessage};

use crate::transport::error::Error;
use crate::transport::message::{CloseFrame, Message};

/// Translate a `nula-net` [`Message`] into a `tungstenite` frame.
pub(super) fn to_tungstenite(msg: Message) -> TgMessage {
    match msg {
        Message::Text(s) => TgMessage::Text(Utf8Bytes::from(s)),
        Message::Binary(b) => TgMessage::Binary(b.into()),
        Message::Ping(p) => TgMessage::Ping(p.into()),
        Message::Pong(p) => TgMessage::Pong(p.into()),
        Message::Close(frame) => TgMessage::Close(frame.map(close_frame_to_tungstenite)),
    }
}

/// Translate a `tungstenite` frame into a `nula-net` [`Message`].
///
/// # Errors
///
/// Returns [`Error::ProtocolViolation`] when the inbound frame is a
/// raw `Frame` variant, which only appears when the underlying
/// `WebSocketConfig::frame_size` is misconfigured. Production
/// deployments should never observe this branch.
pub(super) fn from_tungstenite(msg: TgMessage) -> Result<Message, Error> {
    match msg {
        TgMessage::Text(s) => Ok(Message::Text(s.as_str().to_owned())),
        TgMessage::Binary(b) => Ok(Message::Binary(b.to_vec())),
        TgMessage::Ping(p) => Ok(Message::Ping(p.to_vec())),
        TgMessage::Pong(p) => Ok(Message::Pong(p.to_vec())),
        TgMessage::Close(frame) => Ok(Message::Close(
            frame.as_ref().map(close_frame_from_tungstenite),
        )),
        TgMessage::Frame(_) => Err(Error::ProtocolViolation {
            reason: "raw Frame variants are not supported by the default transport",
        }),
    }
}

fn close_frame_to_tungstenite(frame: CloseFrame) -> TgCloseFrame {
    TgCloseFrame {
        code: frame.code.into(),
        reason: Utf8Bytes::from(frame.reason.into_owned()),
    }
}

fn close_frame_from_tungstenite(frame: &TgCloseFrame) -> CloseFrame {
    CloseFrame {
        code: frame.code.into(),
        reason: Cow::Owned(frame.reason.as_str().to_owned()),
    }
}

/// Translate a `tungstenite` error into the workspace [`Error`].
pub(super) fn from_tungstenite_error(err: TgError) -> Error {
    match err {
        TgError::Io(io) => Error::Io(io),
        TgError::ConnectionClosed
        | TgError::AlreadyClosed
        | TgError::Protocol(ProtocolError::ResetWithoutClosingHandshake) => Error::ConnectionClosed,
        TgError::Tls(e) => Error::Tls(Box::new(e)),
        TgError::Http(resp) => {
            let status = resp.status().as_u16();
            let message = resp
                .body()
                .as_ref()
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .map(str::to_owned);
            Error::Handshake { status, message }
        }
        other => Error::backend(other),
    }
}
