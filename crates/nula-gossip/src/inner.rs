//! Shared mutable state behind every [`crate::Gossip`] clone.

use std::collections::HashMap;
use std::sync::Arc;

use nula_core::PublicKey;
use tokio::sync::RwLock;

use crate::options::GossipOptions;
use crate::routes::UserRoutes;

/// Hot in-memory routing cache.
///
/// Persistence is delegated to the [`nula_storage::NostrDatabase`]
/// the [`crate::Gossip`] was constructed with — every NIP-65 / NIP-17
/// event passed to `process()` is forwarded to the store, and every
/// `refresh()` writes the freshly-fetched event back too. This means
/// the cache is rebuildable from the store; restart `warm_up()`
/// re-hydrates the cache from disk.
#[derive(Debug)]
pub(crate) struct Inner {
    pub(crate) options: GossipOptions,
    pub(crate) db: Arc<dyn nula_storage::NostrDatabase>,
    pub(crate) routes: RwLock<HashMap<PublicKey, UserRoutes>>,
}

impl Inner {
    pub(crate) fn new(db: Arc<dyn nula_storage::NostrDatabase>, options: GossipOptions) -> Self {
        Self {
            options,
            db,
            routes: RwLock::new(HashMap::new()),
        }
    }
}
