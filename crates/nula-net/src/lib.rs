//! Runtime-agnostic Nostr WebSocket transport.
//!
//! `nula-net` sits at Layer 2 of the `nula` workspace: it defines the
//! [`WebSocketTransport`] trait that every upper layer (single-relay
//! client, relay pool, SDK) consumes, and ships a tokio-backed
//! implementation behind the `default-transport` feature so the crate
//! is immediately useful on native targets.
//!
//! # Layering
//!
//! The crate is intentionally split into three regions, exposed by
//! Cargo features:
//!
//! | Feature             | Default | Surface                                                                            |
//! | ------------------- | :-----: | ---------------------------------------------------------------------------------- |
//! | _none_              |    —    | Trait + types only. Compiles on any target including `wasm32-unknown-unknown`.     |
//! | `default-transport` |   ✅    | Adds [`default::DefaultTransport`] backed by `tokio-tungstenite` + rustls.         |
//! | `mock`              |   ❌    | Adds [`mock::MockTransport`] + [`mock::MockHandle`] for upper-layer integration.   |
//! | `tracing`           |   ❌    | Emits `tracing` spans on handshake, send, recv (field names per ADR-0005).         |
//!
//! Disable defaults for wasm or fully custom backends:
//!
//! ```toml
//! nula-net = { version = "0.1", default-features = false }
//! ```
//!
//! # Quickstart
//!
//! ```rust,no_run
//! # #[cfg(feature = "default-transport")] {
//! use futures::{SinkExt, StreamExt};
//! use nula_core::RelayUrl;
//! use nula_net::default::DefaultTransport;
//! use nula_net::{ConnectionMode, IntoWebSocketTransport, Message, WebSocketTransport};
//!
//! # async fn doc() -> Result<(), Box<dyn std::error::Error>> {
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
//! - [ADR-0001](../../docs/adr/0001-workspace-architecture.md) records why
//!   transport and protocol state are split between this crate and `nula-relay`.
//! - [ADR-0003](../../docs/adr/0003-async-runtime-strategy.md) records why
//!   the trait surface is runtime-agnostic while the default implementation
//!   pulls in Tokio behind a feature.
//! - [ADR-0004](../../docs/adr/0004-error-handling-thiserror.md) describes
//!   the [`Error`] enum shape.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(html_root_url = "https://docs.rs/nula-net")]
#![forbid(unsafe_code)]

pub mod boxed;
pub mod error;
pub mod message;
pub mod mode;
pub mod transport;

#[cfg(feature = "default-transport")]
#[cfg_attr(docsrs, doc(cfg(feature = "default-transport")))]
pub mod default;

#[cfg(feature = "mock")]
#[cfg_attr(docsrs, doc(cfg(feature = "mock")))]
pub mod mock;

pub use self::boxed::{BoxFuture, BoxStream};
pub use self::error::Error;
pub use self::message::{CloseFrame, Message};
pub use self::mode::ConnectionMode;
pub use self::transport::{
    IntoWebSocketTransport, WebSocketSink, WebSocketStream, WebSocketTransport,
};
