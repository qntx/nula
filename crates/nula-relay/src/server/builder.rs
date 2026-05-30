//! Fluent builder for [`crate::server::MockRelay`].

use std::sync::Arc;

use nula_storage::NostrDatabase;

use crate::server::error::Error;
use crate::server::options::MockRelayOptions;
use crate::server::policy::{AcceptAllReads, AcceptAllWrites, ReadPolicy, WritePolicy};
use crate::server::relay::MockRelay;

/// Builder for [`MockRelay`].
///
/// Construct via [`MockRelayBuilder::default`] for a one-liner
/// with all defaults, or call [`MockRelayBuilder::new`] when you
/// want to plug in a custom storage backend or admit policy.
#[derive(Debug)]
#[must_use]
pub struct MockRelayBuilder {
    storage: Option<Arc<dyn NostrDatabase>>,
    write_policy: Option<Arc<dyn WritePolicy>>,
    read_policy: Option<Arc<dyn ReadPolicy>>,
    options: MockRelayOptions,
}

impl Default for MockRelayBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl MockRelayBuilder {
    /// Begin configuring a new mock relay.
    pub fn new() -> Self {
        Self {
            storage: None,
            write_policy: None,
            read_policy: None,
            options: MockRelayOptions::default(),
        }
    }

    /// Override the storage backend.
    ///
    /// Defaults to a fresh
    /// [`nula_storage::memory::MemoryDatabase`]
    /// when the `memory` feature is on.
    pub fn storage(mut self, storage: Arc<dyn NostrDatabase>) -> Self {
        self.storage = Some(storage);
        self
    }

    /// Override the write-admit policy. Defaults to "accept all".
    pub fn write_policy(mut self, policy: Arc<dyn WritePolicy>) -> Self {
        self.write_policy = Some(policy);
        self
    }

    /// Override the read-admit policy. Defaults to "accept all".
    pub fn read_policy(mut self, policy: Arc<dyn ReadPolicy>) -> Self {
        self.read_policy = Some(policy);
        self
    }

    /// Override the runtime options. See [`MockRelayOptions`] for
    /// available knobs.
    pub const fn options(mut self, options: MockRelayOptions) -> Self {
        self.options = options;
        self
    }

    /// Spawn the relay and return the handle.
    ///
    /// # Errors
    ///
    /// [`Error::Bind`] when the listening socket cannot be opened.
    ///
    /// # Panics
    ///
    /// Panics when the `memory` feature is disabled and no storage
    /// backend was supplied via [`Self::storage`].
    pub async fn run(self) -> Result<MockRelay, Error> {
        let storage = self.storage.unwrap_or_else(default_storage);
        let write_policy = self
            .write_policy
            .unwrap_or_else(|| Arc::new(AcceptAllWrites));
        let read_policy = self.read_policy.unwrap_or_else(|| Arc::new(AcceptAllReads));
        MockRelay::start(self.options, storage, write_policy, read_policy).await
    }
}

fn default_storage() -> Arc<dyn NostrDatabase> {
    Arc::new(nula_storage::memory::MemoryDatabase::new())
}
