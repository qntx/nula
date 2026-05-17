//! Public [`Gossip`] handle.
//!
//! Cloning [`Gossip`] is cheap (one `Arc` bump). Every clone shares
//! the same in-memory route cache, the same [`nula_storage::NostrDatabase`]
//! handle, and the same background-refresher abort handle.

use std::collections::{BTreeSet, HashSet};
use std::num::NonZeroUsize;
use std::sync::Arc;

use futures::StreamExt as _;
use nula_core::event::{Alphabet, Event, SingleLetterTag, TagKind};
use nula_core::nips::nip17::parse_dm_relays_event;
use nula_core::nips::nip65::RelayList;
use nula_core::types::Timestamp;
use nula_core::{Filter, Kind, PublicKey, RelayUrl};
use nula_relay_pool::RelayPool;

use crate::error::Error;
use crate::filter::{BrokenDownFilters, break_down};
use crate::inner::Inner;
use crate::options::{GossipOptions, ListKind};
use crate::ttl::{OutdatedKey, PublicKeyStatus};

/// Multi-relay routing graph.
///
/// `Gossip` ingests Nostr events ([`Self::process`]), maintains a
/// per-user routing cache ([`Self::outbox_relays`] /
/// [`Self::inbox_relays`] / [`Self::dm_relays`]), and breaks
/// outgoing filters into per-relay sub-filters
/// ([`Self::break_down_filter`]).
///
/// See the crate-level docs and [ADR-0009] for the full design.
///
/// [ADR-0009]: ../../docs/adr/0009-multi-relay-routing-remote-signer.md
#[derive(Debug, Clone)]
pub struct Gossip {
    pub(crate) inner: Arc<Inner>,
}

impl Gossip {
    /// Begin configuring a [`Gossip`]. See [`GossipBuilder`] for the
    /// available knobs.
    pub fn builder() -> GossipBuilder {
        GossipBuilder::new()
    }

    /// Read access to the runtime configuration this `Gossip` was
    /// built with.
    #[must_use]
    pub fn options(&self) -> &GossipOptions {
        &self.inner.options
    }

    /// Read-only borrow of the [`nula_storage::NostrDatabase`] every
    /// clone shares.
    #[must_use]
    pub fn database(&self) -> &Arc<dyn nula_storage::NostrDatabase> {
        &self.inner.db
    }

    /// Ingest one event.
    ///
    /// - `kind:10002` (NIP-65) → updates the user's read/write list.
    /// - `kind:10050` (NIP-17) → updates the user's DM relays.
    /// - any other event → its `r` tags are folded into the user's
    ///   hint histogram, and `source_relay` (if any) is folded into
    ///   the most-received histogram.
    ///
    /// Failures parse-only — every malformed list event is
    /// **silently ignored** so a noisy stream does not break
    /// routing. Callers that want strict validation should call
    /// [`nula_core::nips::nip65::RelayList::from_event`] directly.
    pub async fn process(&self, event: &Event, source_relay: Option<&RelayUrl>) {
        let needs_persist = matches!(event.kind, Kind::RELAY_LIST | Kind::DM_RELAYS);
        let allowed = self.inner.options.allowed;
        {
            let mut routes = self.inner.routes.write().await;
            let entry = routes.entry(event.pubkey).or_default();
            apply_event_to_entry(event, entry, allowed);
            if let Some(relay) = source_relay
                && allowed.is_allowed(relay)
            {
                entry.bump_most_received(relay.clone());
            }
            drop(routes);
        }
        // Persist NIP-65 / NIP-17 events in the underlying store so
        // the cache can be rebuilt across process restarts. Best
        // effort — failures are silenced so a flaky store does not
        // break ingest.
        if needs_persist {
            self.inner.db.save_event(event).await.ok();
        }
    }

    /// Outbox (write) relays for `user`, capped by
    /// [`crate::GossipLimits::write_relays_per_user`] +
    /// [`crate::GossipLimits::hint_relays_per_user`] +
    /// [`crate::GossipLimits::most_received_per_user`] and filtered
    /// through [`crate::GossipOptions::allowed`].
    pub async fn outbox_relays(&self, user: &PublicKey) -> HashSet<RelayUrl> {
        let routes = self.inner.routes.read().await;
        routes.get(user).map_or_else(HashSet::new, |r| {
            crate::selection::outbox(
                r,
                crate::selection::Limits::from_gossip(self.inner.options.limits),
                self.inner.options.allowed,
            )
        })
    }

    /// Inbox (read) relays for `user`.
    pub async fn inbox_relays(&self, user: &PublicKey) -> HashSet<RelayUrl> {
        let routes = self.inner.routes.read().await;
        routes.get(user).map_or_else(HashSet::new, |r| {
            crate::selection::inbox(
                r,
                crate::selection::Limits::from_gossip(self.inner.options.limits),
                self.inner.options.allowed,
            )
        })
    }

    /// NIP-17 DM relays for `user`.
    pub async fn dm_relays(&self, user: &PublicKey) -> HashSet<RelayUrl> {
        let routes = self.inner.routes.read().await;
        routes.get(user).map_or_else(HashSet::new, |r| {
            crate::selection::dm_relays(
                r,
                self.inner.options.limits.dm_relays_per_user,
                self.inner.options.allowed,
            )
        })
    }

    /// Break a single filter into per-relay sub-filters. See
    /// [`BrokenDownFilters`] for the three possible outcomes.
    pub async fn break_down_filter(&self, filter: Filter) -> BrokenDownFilters {
        break_down(&self.inner, filter).await
    }

    /// Freshness verdict for a stored list.
    pub async fn status(&self, user: &PublicKey, kind: ListKind) -> PublicKeyStatus {
        let routes = self.inner.routes.read().await;
        let Some(user_routes) = routes.get(user) else {
            return PublicKeyStatus::Missing;
        };
        let Some(observed_at) = user_routes.list_event_at(kind) else {
            return PublicKeyStatus::Missing;
        };
        let ttl = self.inner.options.list_ttl.as_secs();
        drop(routes);
        let Ok(now) = Timestamp::now() else {
            return PublicKeyStatus::Outdated { observed_at };
        };
        if now.as_secs().saturating_sub(observed_at.as_secs()) > ttl {
            PublicKeyStatus::Outdated { observed_at }
        } else {
            PublicKeyStatus::Updated
        }
    }

    /// Up to `limit` `(public_key, observed_at)` pairs whose stored
    /// list event is older than [`crate::GossipOptions::list_ttl`].
    /// Sorted by oldest first so the caller can refresh staleest
    /// keys first.
    pub async fn outdated(&self, kind: ListKind, limit: NonZeroUsize) -> BTreeSet<OutdatedKey> {
        let Ok(now) = Timestamp::now() else {
            return BTreeSet::new();
        };
        let ttl = self.inner.options.list_ttl.as_secs();
        let mut out: BTreeSet<OutdatedKey> = BTreeSet::new();
        let routes = self.inner.routes.read().await;
        for (pk, user_routes) in routes.iter() {
            if let Some(observed_at) = user_routes.list_event_at(kind)
                && now.as_secs().saturating_sub(observed_at.as_secs()) > ttl
            {
                out.insert(OutdatedKey::new(*pk, Some(observed_at)));
            }
            if out.len() >= limit.get() {
                break;
            }
        }
        drop(routes);
        out
    }

    /// Force-refresh `user`'s NIP-65 (or NIP-17) list by fetching
    /// the most recent event of the requested kind from
    /// `discovery_relays` via `pool`.
    ///
    /// Updates the in-memory cache **and** writes the event back to
    /// the configured [`nula_storage::NostrDatabase`] so the next
    /// process start can warm up from disk.
    ///
    /// Honours [`GossipOptions::min_fetch_interval`] — repeat calls
    /// inside the debounce window return `Ok(())` without contacting
    /// any relay.
    ///
    /// # Errors
    ///
    /// - [`Error::NoDiscoveryRelays`] when `discovery_relays` is
    ///   empty.
    /// - [`Error::Pool`] when the pool refuses the fan-out.
    /// - [`Error::NotFound`] when no event of the requested kind
    ///   came back inside the timeout.
    pub async fn refresh(
        &self,
        pool: &RelayPool,
        user: &PublicKey,
        kind: ListKind,
        discovery_relays: impl IntoIterator<Item = RelayUrl> + Send,
        timeout: std::time::Duration,
    ) -> Result<(), Error> {
        let discovery: Vec<RelayUrl> = discovery_relays.into_iter().collect();
        if discovery.is_empty() {
            return Err(Error::NoDiscoveryRelays);
        }

        // Debounce on the in-memory `*_fetched_at` fields.
        let now = Timestamp::now().ok();
        let allowed_to_fetch = {
            let routes = self.inner.routes.read().await;
            routes
                .get(user)
                .and_then(|r| r.list_fetched_at(kind))
                .zip(now)
                .is_none_or(|(prev, now)| {
                    now.as_secs().saturating_sub(prev.as_secs())
                        >= self.inner.options.min_fetch_interval.as_secs()
                })
        };
        if !allowed_to_fetch {
            return Ok(());
        }

        // Bookkeeping: bump the fetched_at *before* we start so
        // concurrent callers debounce correctly.
        if let Some(now) = now {
            let mut routes = self.inner.routes.write().await;
            let entry = routes.entry(*user).or_default();
            match kind {
                ListKind::Nip65 => entry.nip65_fetched_at = Some(now),
                ListKind::Nip17 => entry.nip17_fetched_at = Some(now),
            }
            drop(routes);
        }

        let event = pull_newest(pool, *user, kind, discovery, timeout).await?;
        let Some(event) = event else {
            return Err(Error::NotFound {
                user: *user,
                list_kind: kind,
            });
        };
        self.process(&event, None).await;
        Ok(())
    }

    /// Re-hydrate the in-memory cache from the underlying
    /// [`nula_storage::NostrDatabase`] for every public key in
    /// `users`.
    ///
    /// Useful on process startup when you know which user identities
    /// you care about. Skipped users (no stored event) leave the
    /// cache untouched.
    ///
    /// # Errors
    ///
    /// Forwards every storage failure as [`Error::Storage`].
    pub async fn warm_up(&self, users: impl IntoIterator<Item = PublicKey>) -> Result<(), Error> {
        for pk in users {
            self.warm_up_user(pk).await?;
        }
        Ok(())
    }

    async fn warm_up_user(&self, pk: PublicKey) -> Result<(), Error> {
        for kind in [ListKind::Nip65, ListKind::Nip17] {
            if let Some(event) = self.warm_up_one(pk, kind).await? {
                self.process(&event, None).await;
            }
        }
        Ok(())
    }

    async fn warm_up_one(&self, pk: PublicKey, kind: ListKind) -> Result<Option<Event>, Error> {
        let filter = Filter::new().author(pk).kind(kind.event_kind()).limit(1);
        let events = self.inner.db.query(filter).await?;
        Ok(events.into_iter().next())
    }
}

/// Builder for a [`Gossip`].
///
/// # Examples
///
/// ```rust,no_run
/// use std::sync::Arc;
///
/// use nula_gossip::{Error, Gossip};
/// use nula_storage::NostrDatabase;
///
/// fn build(db: Arc<dyn NostrDatabase>) -> Result<Gossip, Error> {
///     Gossip::builder().database(db).build()
/// }
/// ```
#[derive(Debug, Default)]
#[must_use]
pub struct GossipBuilder {
    options: GossipOptions,
    db: Option<Arc<dyn nula_storage::NostrDatabase>>,
}

impl GossipBuilder {
    /// Construct a builder with default options and no database.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the runtime configuration. Defaults to
    /// [`GossipOptions::default`].
    pub const fn options(mut self, options: GossipOptions) -> Self {
        self.options = options;
        self
    }

    /// Attach the persistence backend. **Required** — `build`
    /// returns [`Error::MissingDatabase`] without one.
    pub fn database(mut self, db: Arc<dyn nula_storage::NostrDatabase>) -> Self {
        self.db = Some(db);
        self
    }

    /// Finalise the builder.
    ///
    /// # Errors
    ///
    /// [`Error::MissingDatabase`] when [`Self::database`] was not
    /// called.
    pub fn build(self) -> Result<Gossip, Error> {
        let db = self.db.ok_or(Error::MissingDatabase)?;
        Ok(Gossip {
            inner: Arc::new(Inner::new(db, self.options)),
        })
    }
}

/// Fold one event into the per-user routes entry. Extracted from
/// [`Gossip::process`] so the entry-point keeps shallow and clippy's
/// `excessive_nesting` stays happy.
fn apply_event_to_entry(
    event: &Event,
    entry: &mut crate::routes::UserRoutes,
    allowed: crate::AllowedRelays,
) {
    match event.kind {
        Kind::RELAY_LIST => {
            if let Ok(list) = RelayList::from_event(event)
                && entry
                    .nip65_event_at
                    .is_none_or(|prev| prev < event.created_at)
            {
                entry.nip65 = Some(list);
                entry.nip65_event_at = Some(event.created_at);
            }
        }
        Kind::DM_RELAYS => {
            if let Ok(relays) = parse_dm_relays_event(event)
                && entry
                    .nip17_event_at
                    .is_none_or(|prev| prev < event.created_at)
            {
                entry.nip17 = relays
                    .into_iter()
                    .filter(|url| allowed.is_allowed(url))
                    .collect();
                entry.nip17_event_at = Some(event.created_at);
            }
        }
        _ => harvest_relay_hints(event, entry, allowed),
    }
}

fn harvest_relay_hints(
    event: &Event,
    entry: &mut crate::routes::UserRoutes,
    allowed: crate::AllowedRelays,
) {
    // NIP-12 / NIP-24 use `r` as a generic web reference; we only
    // ingest values that parse as relay URLs.
    let r_kind = TagKind::single_letter(SingleLetterTag::lowercase(Alphabet::R));
    for tag in &event.tags {
        if tag.kind() != r_kind {
            continue;
        }
        let Some(value) = tag.content() else { continue };
        let Ok(url) = RelayUrl::parse(value) else {
            continue;
        };
        if allowed.is_allowed(&url) {
            entry.bump_hint(url);
        }
    }
}

/// Pull the newest event matching the requested filter from the
/// supplied discovery relays. Extracted from [`Gossip::refresh`] so
/// the entry-point stays readable.
async fn pull_newest(
    pool: &RelayPool,
    user: PublicKey,
    kind: ListKind,
    discovery: Vec<RelayUrl>,
    timeout: std::time::Duration,
) -> Result<Option<Event>, Error> {
    let filter = Filter::new().author(user).kind(kind.event_kind()).limit(1);
    let opts = nula_relay::SubscribeOptions::default().close_on_eose(true);
    let mut stream = pool
        .stream_events_to(discovery, vec![filter], opts, Some(timeout))
        .await?;
    let mut newest: Option<Event> = None;
    while let Some((_url, item)) = stream.next().await {
        let Ok(event) = item else { continue };
        if event.kind != kind.event_kind() || event.pubkey != user {
            continue;
        }
        let is_newer = newest
            .as_ref()
            .is_none_or(|prev| prev.created_at < event.created_at);
        if is_newer {
            newest = Some(event);
        }
    }
    Ok(newest)
}
