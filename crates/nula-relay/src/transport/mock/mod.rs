//! In-memory [`crate::transport::WebSocketTransport`] implementation for tests.
//!
//! Available when the `mock` feature is enabled. The implementation
//! pairs a [`MockTransport`] with one or more [`MockHandle`]s exposed
//! to the test body: every frame written into the transport's sink
//! shows up on the handle's `next_outbound()` call, and every frame
//! pushed via `push_inbound()` is delivered to the transport's stream.
//!
//! The mock is intentionally minimal — it has no handshake, no TLS,
//! no retry semantics. Upper-layer crates (e.g. `nula-relay-pool`)
//! exercise their state machines against it without paying for an
//! actual socket.

mod transport;

pub use self::transport::{MockHandle, MockTransport};
