//! Runtime-agnostic Nostr WebSocket transport.
//!
//! This module defines the [`WebSocketTransport`] trait that the
//! single-relay client and pool consume, and ships a tokio-backed
//! implementation behind the `default-transport` feature so the relay
//! is immediately useful on native targets.
//!
//! # Layering
//!
//! The surface is exposed through the parent crate's Cargo features:
//!
//! | Feature             | Default | Surface                                                                            |
//! | ------------------- | :-----: | ---------------------------------------------------------------------------------- |
//! | _none_              |    —    | Trait + types only. Compiles on any target including `wasm32-unknown-unknown`.     |
//! | `default-transport` |   ✅    | Adds [`default::DefaultTransport`] backed by `tokio-tungstenite` + rustls.         |
//! | `mock`              |   ❌    | Adds [`mock::MockTransport`] + [`mock::MockHandle`] for upper-layer integration.   |
//! | `tracing`           |   ❌    | Emits `tracing` spans on handshake, send, recv (field names per ADR-0005).         |
//!
//! # Quickstart
//!
//! ```rust,no_run
//! # #[cfg(feature = "default-transport")] {
//! use futures::{SinkExt, StreamExt};
//! use nula_core::RelayUrl;
//! use nula_relay::transport::{
//!     ConnectionMode, IntoWebSocketTransport, Message, WebSocketTransport,
//! };
//!
//! # async fn doc() -> Result<(), Box<dyn std::error::Error>> {
//! # use nula_relay::transport::default::DefaultTransport;
//! let transport = DefaultTransport::new().into_transport();
//! let url = RelayUrl::parse("wss://relay.damus.io")?;
//! let (mut sink, mut stream) = transport.connect(&url, &ConnectionMode::Direct).await?;
//!
//! sink.send(Message::text(r#"["REQ","sub",{}]"#)).await?;
//!
//! while let Some(frame) = stream.next().await {
//!     if let Message::Text(line) = frame? {
//!         println!("{line}");
//!     }
//! }
//! # Ok(()) }
//! # }
//! ```
//!
//! # Workspace ADRs
//!
//! - [ADR-0001](../../docs/adr/0001-workspace-architecture.md) records the
//!   workspace crate layout.
//! - [ADR-0003](../../docs/adr/0003-async-runtime-strategy.md) records why
//!   the trait surface is runtime-agnostic while the default implementation
//!   pulls in Tokio behind a feature.
//! - [ADR-0004](../../docs/adr/0004-error-handling-thiserror.md) describes
//!   the [`Error`] enum shape.

pub mod error;
pub mod message;
pub mod mode;
pub mod ws;

#[cfg(feature = "default-transport")]
#[cfg_attr(docsrs, doc(cfg(feature = "default-transport")))]
pub mod default;

#[cfg(feature = "mock")]
#[cfg_attr(docsrs, doc(cfg(feature = "mock")))]
pub mod mock;

pub use self::error::Error;
pub use self::message::{CloseFrame, Message};
pub use self::mode::ConnectionMode;
pub use self::ws::{IntoWebSocketTransport, WebSocketSink, WebSocketStream, WebSocketTransport};
