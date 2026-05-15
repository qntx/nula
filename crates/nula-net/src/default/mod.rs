//! `tokio-tungstenite`-backed [`crate::WebSocketTransport`] implementation.
//!
//! Available when the `default-transport` feature is enabled (it is on
//! by default). Disable it via `default-features = false` if you need
//! a wasm build or a fully custom transport.
//!
//! The implementation wires `tokio-tungstenite::connect_async` into the
//! crate's `Message`/`Error` types and is configurable through
//! [`DefaultTransport::builder`].

mod convert;
mod sink;
mod transport;

pub use self::transport::{DefaultTransport, DefaultTransportBuilder};
