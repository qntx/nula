//! Single-writer worker thread that serialises every mutation
//! against the LMDB environment.
//!
//! LMDB is multi-reader / single-writer at the env level: while
//! concurrent `RoTxn`s scale, only one `RwTxn` can be live at a
//! time. The ingester owns the only `RwTxn`-issuing path so callers
//! never have to think about that — they fire-and-forget [`IngestCmd`]
//! values into the [`flume::Sender`] and await the corresponding
//! [`tokio::sync::oneshot`] reply.

use std::thread::{self, JoinHandle};

use flume::{Receiver, Sender};
use nula_core::event::Event;
use nula_core::filter::Filter;
use nula_core::types::Timestamp;
use tokio::sync::oneshot;

use crate::SaveEventStatus;
use crate::lmdb::error::Error;
use crate::lmdb::store::Store;

/// A single mutation request fanned out to the ingester thread.
pub(crate) enum IngestCmd {
    Save {
        event: Event,
        reply: oneshot::Sender<Result<SaveEventStatus, Error>>,
    },
    Delete {
        filter: Filter,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    Wipe {
        reply: oneshot::Sender<Result<(), Error>>,
    },
    Shutdown {
        reply: oneshot::Sender<()>,
    },
}

/// Spawn the writer thread. Returns the command sender plus the
/// thread handle so the caller can `join()` it on shutdown.
pub(crate) fn spawn(store: Store) -> (Sender<IngestCmd>, JoinHandle<()>) {
    let (tx, rx) = flume::unbounded();
    // OS thread spawn failures are unrecoverable (process is too
    // resource-starved to run anything else); propagate as a panic
    // rather than smuggling an error through the constructor.
    #[allow(
        clippy::expect_used,
        reason = "OS thread spawn failure is unrecoverable; propagate as panic"
    )]
    let handle = thread::Builder::new()
        .name("nula-lmdb-ingester".into())
        .spawn(move || run(&store, &rx))
        .expect("OS thread spawn must succeed");
    (tx, handle)
}

fn run(store: &Store, rx: &Receiver<IngestCmd>) {
    while let Ok(cmd) = rx.recv() {
        match cmd {
            IngestCmd::Save { event, reply } => {
                let now =
                    Timestamp::now().map_err(|e| Error::Io(std::io::Error::other(e.to_string())));
                let result = match now {
                    Ok(now) => store.save_event(&event, now),
                    Err(e) => Err(e),
                };
                // Receiver may have dropped; that's fine.
                drop(reply.send(result));
            }
            IngestCmd::Delete { filter, reply } => {
                drop(reply.send(store.delete_matching(&filter)));
            }
            IngestCmd::Wipe { reply } => {
                drop(reply.send(store.wipe()));
            }
            IngestCmd::Shutdown { reply } => {
                // `oneshot::Sender::send` returns the message back
                // on error (here `()` — Copy), so we have to ignore
                // it explicitly rather than via `drop`.
                let _send = reply.send(());
                break;
            }
        }
    }
}
