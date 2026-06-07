//! Fluent builder for [`crate::server::MockRelay`].

use std::sync::Arc;

use nula_core::PublicKey;
use nula_core::nips::nip11::RelayInformation;
use nula_storage::NostrDatabase;

use crate::server::error::Error;
use crate::server::management::ManagementState;
use crate::server::options::MockRelayOptions;
use crate::server::policy::{AcceptAllQueries, AcceptAllWrites, QueryPolicy, WritePolicy};
use crate::server::relay::{MockRelay, derive_relay_info};

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
    query_policy: Option<Arc<dyn QueryPolicy>>,
    relay_info: Option<RelayInformation>,
    management: Option<Arc<ManagementState>>,
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
            query_policy: None,
            relay_info: None,
            management: None,
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

    /// Override the query-admit policy. Defaults to "accept all".
    ///
    /// A [`QueryPolicy`] sees the client address and may rewrite each
    /// `REQ` / NIP-77 filter in place (e.g. clamp an unbounded `limit`).
    pub fn query_policy(mut self, policy: Arc<dyn QueryPolicy>) -> Self {
        self.query_policy = Some(policy);
        self
    }

    /// Override the runtime options. See [`MockRelayOptions`] for
    /// available knobs.
    pub const fn options(mut self, options: MockRelayOptions) -> Self {
        self.options = options;
        self
    }

    /// Override the served NIP-11 relay information document.
    ///
    /// When unset, the relay serves a document auto-derived from the
    /// configured [`MockRelayOptions`] and policies.
    pub fn relay_info(mut self, info: RelayInformation) -> Self {
        self.relay_info = Some(info);
        self
    }

    /// Enable the NIP-86 relay management API, authorizing `admins` to
    /// call it.
    ///
    /// Installs a [`ManagementState`] as the relay's write policy (so
    /// bans and allowlists applied over the API take effect on the very
    /// next `EVENT`) and serves the NIP-86 HTTP endpoint. Retrieve the
    /// state after [`Self::run`] via [`MockRelay::management`]. Mutually
    /// exclusive with [`Self::write_policy`]; management wins.
    pub fn management(mut self, admins: impl IntoIterator<Item = PublicKey>) -> Self {
        self.management = Some(Arc::new(ManagementState::new(admins)));
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
        let management = self.management;
        // Management, when enabled, is the write policy (so bans take
        // effect immediately) and marks the relay restricted. Otherwise a
        // custom write policy implies restricted writes for NIP-11.
        let restricted_writes = management.is_some() || self.write_policy.is_some();
        let write_policy: Arc<dyn WritePolicy> = match &management {
            Some(state) => {
                // Clone to the concrete `Arc` first, then unsize-coerce
                // to the trait object in a second step (a one-step
                // `Arc::clone` would infer its arg as `&Arc<dyn _>`).
                let concrete: Arc<ManagementState> = Arc::clone(state);
                let policy: Arc<dyn WritePolicy> = concrete;
                policy
            }
            None => self
                .write_policy
                .unwrap_or_else(|| Arc::new(AcceptAllWrites)),
        };
        let query_policy = self
            .query_policy
            .unwrap_or_else(|| Arc::new(AcceptAllQueries));
        let relay_info = self
            .relay_info
            .unwrap_or_else(|| derive_relay_info(&self.options, restricted_writes));
        MockRelay::start(
            self.options,
            storage,
            write_policy,
            query_policy,
            relay_info,
            management,
        )
        .await
    }
}

fn default_storage() -> Arc<dyn NostrDatabase> {
    Arc::new(nula_storage::memory::MemoryDatabase::new())
}
