//! Error surface for [`crate::server::MockRelay`].
//!
//! Follows the workspace error contract from
//! [ADR-0004](../../docs/adr/0004-error-handling-thiserror.md):
//! `#[non_exhaustive]`, every variant carries typed data, every boxed
//! source is `Send + Sync + 'static`.

use std::net::SocketAddr;

use thiserror::Error;

/// Errors raised by [`crate::server::MockRelay`] / [`crate::server::MockRelayBuilder`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Binding the listening socket failed.
    #[error("failed to bind {addr}: {source}")]
    Bind {
        /// The socket address the builder tried to bind.
        addr: SocketAddr,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The configured storage backend raised an error during start-up
    /// (e.g. `event_by_id` failed when the relay was probing it).
    #[error(transparent)]
    Storage(#[from] nula_storage::Error),

    /// The relay has been shut down. Returned by accessors on a
    /// [`crate::server::MockRelay`] handle whose accept loop has already
    /// exited.
    #[error("mock relay has been shut down")]
    Shutdown,
}
