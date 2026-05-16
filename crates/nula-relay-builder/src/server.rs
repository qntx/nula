//! Public [`MockRelay`] handle and accept-loop driver.
//!
//! The handle is `Arc`-cheap to clone; every clone shares state.
//! Dropping the last clone fires the relay-wide shutdown channel,
//! which makes the accept loop and every per-connection actor exit
//! gracefully.

use std::net::SocketAddr;
use std::sync::Arc;

use nula_core::RelayUrl;
use nula_storage::NostrDatabase;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

use crate::connection::{ConnectionContext, handle_connection};
use crate::error::Error;
use crate::options::MockRelayOptions;
use crate::policy::{ReadPolicy, WritePolicy};

/// In-process Nostr relay used as a test fixture.
///
/// Construct via [`crate::MockRelayBuilder`]. The handle clones
/// cheaply; the last clone going out of scope shuts the relay down.
#[derive(Debug, Clone)]
pub struct MockRelay {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    url: RelayUrl,
    addr: SocketAddr,
    storage: Arc<dyn NostrDatabase>,
    shutdown_tx: broadcast::Sender<()>,
    /// Set once and never replaced. Held inside an `Option` so
    /// `Inner::Drop` can `take()` it and join the accept loop.
    accept_handle: tokio::sync::Mutex<Option<JoinHandle<()>>>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Best-effort signal: the accept loop holds its own copy of
        // the receiver, so a `send` after the loop is gone is fine.
        self.shutdown_tx.send(()).ok();
        // We cannot await the JoinHandle from a non-async drop, but
        // `tokio::task::JoinHandle::abort()` is sync-callable and
        // ensures the task is reaped.
        if let Ok(mut guard) = self.accept_handle.try_lock()
            && let Some(handle) = guard.take()
        {
            handle.abort();
        }
    }
}

impl MockRelay {
    /// Build a relay against the supplied collaborators and start
    /// listening.
    ///
    /// Most callers should reach for [`crate::MockRelayBuilder`]
    /// instead — this is the low-level entry point used by the
    /// builder under the hood.
    ///
    /// # Errors
    ///
    /// [`Error::Bind`] when the listening socket cannot be opened.
    pub async fn start(
        options: MockRelayOptions,
        storage: Arc<dyn NostrDatabase>,
        write_policy: Arc<dyn WritePolicy>,
        read_policy: Arc<dyn ReadPolicy>,
    ) -> Result<Self, Error> {
        let listener = TcpListener::bind(options.bind_addr)
            .await
            .map_err(|source| Error::Bind {
                addr: options.bind_addr,
                source,
            })?;
        let local_addr = listener.local_addr().map_err(|source| Error::Bind {
            addr: options.bind_addr,
            source,
        })?;
        let url_str = format!("ws://{local_addr}");
        let url = RelayUrl::parse(&url_str).map_err(|_| Error::Bind {
            addr: local_addr,
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "the bound socket address could not be rendered as a relay url",
            ),
        })?;

        let (shutdown_tx, _) = broadcast::channel(1);
        // 4096 in-flight live events. Slow connections drop with
        // `Lagged` rather than back-pressure the publish path.
        let (live_tx, _) = broadcast::channel(4096);

        let ctx = ConnectionContext {
            storage: Arc::clone(&storage),
            write_policy,
            read_policy,
            require_nip42: options.require_nip42,
            broadcast: live_tx,
        };

        let accept_loop = spawn_accept_loop(listener, ctx, shutdown_tx.clone());

        Ok(Self {
            inner: Arc::new(Inner {
                url,
                addr: local_addr,
                storage,
                shutdown_tx,
                accept_handle: tokio::sync::Mutex::new(Some(accept_loop)),
            }),
        })
    }

    /// The relay's url (e.g. `ws://127.0.0.1:54321`).
    #[must_use]
    pub fn url(&self) -> &RelayUrl {
        &self.inner.url
    }

    /// The bound socket address.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.inner.addr
    }

    /// The event store every connection routes EVENTs into.
    #[must_use]
    pub fn database(&self) -> &Arc<dyn NostrDatabase> {
        &self.inner.storage
    }

    /// Trigger a graceful shutdown.
    ///
    /// Idempotent: subsequent calls are no-ops. Existing connections
    /// see the shutdown signal on their next `select!` poll and
    /// exit; the accept loop refuses new connections.
    pub fn shutdown(&self) {
        self.inner.shutdown_tx.send(()).ok();
    }
}

fn spawn_accept_loop(
    listener: TcpListener,
    ctx: ConnectionContext,
    shutdown_tx: broadcast::Sender<()>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut shutdown = shutdown_tx.subscribe();
        loop {
            tokio::select! {
                _ = shutdown.recv() => break,
                accept = listener.accept() => {
                    let Ok((stream, peer)) = accept else { continue };
                    let ctx = ctx.clone();
                    let conn_shutdown = shutdown_tx.subscribe();
                    tokio::spawn(async move {
                        let Ok(ws) = tokio_tungstenite::accept_async(stream).await else {
                            return;
                        };
                        handle_connection(ws, peer, ctx, conn_shutdown).await;
                    });
                }
            }
        }
    })
}
