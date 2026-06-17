//! NIP-77 reconciliation driver for [`crate::Client`].
//!
//! The Layer-3 [`nula_sync`] crate ships the algorithm-only
//! [`Reconciliation`] state machine plus a database adapter
//! ([`from_database`]). This module wraps both behind a
//! [`Client::sync_to_relay`] / [`Client::sync_with`] surface that:
//!
//! 1. Sources the local `(EventId, Timestamp)` set from the
//!    client's configured database.
//! 2. Opens a NIP-77 session on the chosen relay via
//!    [`nula_relay::Relay::subscribe_neg`].
//! 3. Folds every `NEG-MSG` reply back through
//!    [`Reconciliation::reconcile_hex`], emits the next
//!    `NEG-MSG` via [`nula_relay::Relay::send_msg`], and stops as
//!    soon as the session converges.
//! 4. Optionally pushes the local-only events to the relay
//!    ([`SyncDirection::Up`]) and / or pulls the relay-only events
//!    into the local database ([`SyncDirection::Down`]).
//! 5. Sends a final `NEG-CLOSE` (best-effort) and returns a
//!    [`SyncSummary`] describing every observable side effect.
//!
//! Multi-relay sync is supported through [`Client::sync_with`],
//! which fans out [`Client::sync_to_relay`] calls and merges the
//! per-relay summaries (each peer's Negentropy state machine
//! still runs independently -- the protocol does not allow
//! sharing a session id across relays).

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use futures::StreamExt;
use nula_core::event::EventId;
use nula_core::filter::Filter;
use nula_core::message::{ClientMessage, SubscriptionId};
use nula_core::types::RelayUrl;
use nula_relay::SubscriptionItem;
use nula_sync::{Reconciliation, from_database};
use tokio::sync::watch;
use tokio::time::timeout;

use crate::client::Client;
use crate::error::Error;
use crate::util::{IntoRelayUrl, collect_relay_urls};

/// Direction of a NIP-77 sync.
///
/// Mirrors the `nostr-sdk` `SyncDirection` shape so application
/// code that already treats sync as a directed primitive can port
/// across with no semantic surprise.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SyncDirection {
    /// Send local-only events to the relay. Reconciliation still
    /// runs to compute the delta; only the upload phase is enabled.
    Up,
    /// Pull relay-only events into the local database. Default,
    /// because the most common reason to sync is "make sure I have
    /// what the relay has".
    #[default]
    Down,
    /// Run both phases in sequence: upload local-only first, then
    /// download relay-only.
    Both,
}

impl SyncDirection {
    /// `true` when [`SyncOptions`] should attempt the upload phase.
    #[must_use]
    pub const fn do_up(self) -> bool {
        matches!(self, Self::Up | Self::Both)
    }

    /// `true` when [`SyncOptions`] should attempt the download phase.
    #[must_use]
    pub const fn do_down(self) -> bool {
        matches!(self, Self::Down | Self::Both)
    }
}

/// Streaming progress signal for an in-flight sync. Each tick
/// reports the running totals; subscribe with
/// [`SyncOptions::with_progress`] before the call.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SyncProgress {
    /// Total events the reconciliation has classified so far
    /// (`local + remote`, modulo the active direction).
    pub total: u64,
    /// Events the upload / download phases have already processed.
    pub current: u64,
}

/// End-of-call summary for a single-relay [`Client::sync_to_relay`]
/// or aggregated [`Client::sync_with`] call.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncSummary {
    /// Events the local replica had that the relay did not. With
    /// [`SyncDirection::Up`] / [`SyncDirection::Both`] these are
    /// the upload candidates.
    pub local: HashSet<EventId>,
    /// Events the relay had that the local replica did not. With
    /// [`SyncDirection::Down`] / [`SyncDirection::Both`] these are
    /// the download candidates.
    pub remote: HashSet<EventId>,
    /// Events the upload phase **successfully** delivered to the
    /// relay (`OK true` ack).
    pub sent: HashSet<EventId>,
    /// Events the download phase **successfully** received and
    /// persisted into the local database.
    pub received: HashSet<EventId>,
    /// Per-event upload failures. Keyed by [`EventId`]; the value
    /// is the relay-supplied reason (or
    /// `"<sdk reason>"` for client-side failures such as the event
    /// row missing from the local database).
    pub send_failures: HashMap<EventId, String>,
    /// Events the configured [`crate::policy::AdmitPolicy`] vetoed
    /// during the download phase. Keyed by [`EventId`]; the value
    /// is the policy's reason string (or `None` if it did not
    /// supply one). These events are **not** persisted to the
    /// local database and are not counted in `received`.
    pub rejected_by_policy: HashMap<EventId, Option<String>>,
}

impl SyncSummary {
    /// `true` when nothing was exchanged in either direction. A
    /// "no-op" sync still leaves `local + remote` populated when
    /// reconciliation was run with `dry_run = true`.
    #[must_use]
    pub fn is_empty_exchange(&self) -> bool {
        self.sent.is_empty() && self.received.is_empty() && self.send_failures.is_empty()
    }

    /// Merge `other` into `self`. Used by [`Client::sync_with`] to
    /// fold per-relay summaries.
    pub fn merge(&mut self, other: Self) {
        self.local.extend(other.local);
        self.remote.extend(other.remote);
        self.sent.extend(other.sent);
        self.received.extend(other.received);
        self.send_failures.extend(other.send_failures);
        self.rejected_by_policy.extend(other.rejected_by_policy);
    }
}

/// Per-call options for [`Client::sync_to_relay`] /
/// [`Client::sync_with`].
#[derive(Debug, Clone, Default)]
pub struct SyncOptions {
    direction: SyncDirection,
    op_timeout: Option<Duration>,
    dry_run: bool,
    progress: Option<watch::Sender<SyncProgress>>,
}

impl SyncOptions {
    /// Construct with all defaults: [`SyncDirection::Down`],
    /// no overall timeout, full event exchange, no progress
    /// channel.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the direction. Default is [`SyncDirection::Down`].
    #[must_use]
    pub const fn direction(mut self, direction: SyncDirection) -> Self {
        self.direction = direction;
        self
    }

    /// Cap the overall round-trip time (reconciliation +
    /// upload + download). `None` means "wait forever".
    #[must_use]
    pub const fn timeout(mut self, op_timeout: Option<Duration>) -> Self {
        self.op_timeout = op_timeout;
        self
    }

    /// When `true`, skip the upload + download phases and return
    /// the reconciliation summary only. Useful for "what would
    /// sync do" diagnostics.
    #[must_use]
    pub const fn dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    /// Attach a progress watch sender. The sync loop calls
    /// `send_modify` on every reconciliation round and once per
    /// upload / download batch.
    #[must_use]
    pub fn with_progress(mut self, progress: watch::Sender<SyncProgress>) -> Self {
        self.progress = Some(progress);
        self
    }
}

/// Maximum number of `NEG-MSG` round-trips a single sync call
/// will perform before bailing with [`Error::SyncStreamClosed`].
/// Keeps a malicious or buggy peer from spinning the loop forever.
const MAX_NEG_ROUNDS: usize = 1024;

impl Client {
    /// Run a NIP-77 reconciliation against `relay_url` and (per
    /// `opts.direction`) ship local-only events up and / or pull
    /// relay-only events down.
    ///
    /// Returns a [`SyncSummary`] with the full per-direction
    /// breakdown.
    ///
    /// # Errors
    ///
    /// - [`Error::UnknownRelay`] when `relay_url` is not registered
    ///   on the underlying pool.
    /// - [`Error::Storage`] when the configured database refuses
    ///   the [`from_database`] request or a `save_event` during the
    ///   download phase.
    /// - [`Error::Sync`] for algorithm-side failures (frame size
    ///   limit exceeded, hex decode error, …).
    /// - [`Error::Relay`] from the underlying socket commands.
    /// - [`Error::SyncFailed`] when the relay returned `NEG-ERR`.
    /// - [`Error::SyncStreamClosed`] when the handle stream ended
    ///   before the session converged or the round-trip safety
    ///   cap was exceeded.
    pub async fn sync_to_relay(
        &self,
        relay_url: &RelayUrl,
        filter: Filter,
        opts: SyncOptions,
    ) -> Result<SyncSummary, Error> {
        let driver = self.run_sync_to_relay(relay_url, filter, &opts);
        match opts.op_timeout {
            Some(deadline) => timeout(deadline, driver)
                .await
                .map_err(|_elapsed| Error::SyncStreamClosed)?,
            None => driver.await,
        }
    }

    /// [`Self::sync_to_relay`] fanned out to a caller-chosen relay
    /// set. The summaries are merged into a single
    /// [`SyncSummary`]; per-relay errors abort the whole call (the
    /// pool's failure modes match `fetch_events_from`).
    ///
    /// # Errors
    ///
    /// - [`Error::RelayUrl`] for unparseable urls.
    /// - All errors documented on [`Self::sync_to_relay`] for the
    ///   first relay that fails.
    pub async fn sync_with<I, U>(
        &self,
        urls: I,
        filter: Filter,
        opts: SyncOptions,
    ) -> Result<SyncSummary, Error>
    where
        I: IntoIterator<Item = U>,
        U: IntoRelayUrl,
    {
        let urls = collect_relay_urls(urls)?;
        let mut merged = SyncSummary::default();
        for url in urls {
            // Clone the per-call inputs the loop body consumes;
            // every relay drives an independent Negentropy session.
            let opts_for_relay = SyncOptions {
                direction: opts.direction,
                op_timeout: opts.op_timeout,
                dry_run: opts.dry_run,
                progress: opts.progress.clone(),
            };
            let summary = self
                .sync_to_relay(&url, filter.clone(), opts_for_relay)
                .await?;
            merged.merge(summary);
        }
        Ok(merged)
    }

    async fn run_sync_to_relay(
        &self,
        relay_url: &RelayUrl,
        filter: Filter,
        opts: &SyncOptions,
    ) -> Result<SyncSummary, Error> {
        let relay = self
            .pool()
            .relay(relay_url)
            .await
            .ok_or_else(|| Error::UnknownRelay {
                url: relay_url.clone(),
            })?;

        // 1. Build Negentropy storage from the local replica.
        let storage = from_database(self.database().as_ref(), filter.clone()).await?;
        let mut session = Reconciliation::with_defaults(storage)?;
        let opening_hex = session.opening_message_hex();

        // 2. Run the NIP-77 round-trip loop.
        let sub_id = SubscriptionId::generate()?;
        let mut summary = SyncSummary::default();
        let recon_result = reconcile_loop(
            &relay,
            sub_id.clone(),
            filter.clone(),
            opening_hex,
            &mut session,
            &mut summary,
            opts,
        )
        .await;

        // Always best-effort NEG-CLOSE so the relay frees the slot,
        // even if reconciliation errored mid-flight.
        let close_msg = ClientMessage::NegClose {
            subscription_id: sub_id.clone(),
        };
        drop(relay.send_msg(close_msg).await);

        recon_result?;

        if opts.dry_run {
            return Ok(summary);
        }

        // 3. Upload phase: ship every local-only event.
        if opts.direction.do_up() {
            self.upload_phase(&relay, &mut summary, opts).await;
        }

        // 4. Download phase: pull every relay-only event into the
        // local database. Reuse the existing fetch_events_from
        // pipeline so the dedup / save_event plumbing stays
        // identical to a normal fetch.
        if opts.direction.do_down() && !summary.remote.is_empty() {
            self.download_phase(relay_url, &sub_id, &mut summary, opts)
                .await?;
        }

        Ok(summary)
    }

    async fn upload_phase(
        &self,
        relay: &nula_relay::Relay,
        summary: &mut SyncSummary,
        opts: &SyncOptions,
    ) {
        let local_ids: Vec<EventId> = summary.local.iter().copied().collect();
        for event_id in local_ids {
            let event = match self.database().event_by_id(&event_id).await {
                Ok(Some(event)) => event,
                Ok(None) => {
                    summary
                        .send_failures
                        .insert(event_id, "event not found in local database".to_owned());
                    continue;
                }
                Err(e) => {
                    summary.send_failures.insert(event_id, e.to_string());
                    continue;
                }
            };
            match relay
                .publish(event, nula_relay::PublishOptions::default())
                .await
            {
                Ok(()) => {
                    summary.sent.insert(event_id);
                }
                Err(e) => {
                    summary.send_failures.insert(event_id, e.to_string());
                }
            }
            tick_progress(opts);
        }
    }

    async fn download_phase(
        &self,
        relay_url: &RelayUrl,
        subscription_id: &SubscriptionId,
        summary: &mut SyncSummary,
        opts: &SyncOptions,
    ) -> Result<(), Error> {
        let need_ids: Vec<EventId> = summary.remote.iter().copied().collect();
        let download_filter = Filter::new().ids(need_ids.iter().copied());
        let events = self
            .fetch_events_from(vec![relay_url.clone()], download_filter, opts.op_timeout)
            .await?;
        for event in &events {
            // Run the admission gate before touching the database.
            // A `Rejected` verdict drops the event from `received`
            // and records it on `rejected_by_policy` so the caller
            // sees what was filtered out.
            match self
                .check_admit_event(relay_url, subscription_id, event)
                .await
            {
                Ok(()) => {}
                Err(Error::PolicyRejected { reason, .. }) => {
                    summary.rejected_by_policy.insert(event.id, reason);
                    tick_progress(opts);
                    continue;
                }
                Err(e) => return Err(e),
            }
            // Persist into the local database. `auto_save` on the
            // pool is on by default, but the user might have
            // disabled it; either way, double-save is idempotent
            // for honest backends.
            match self.database().save_event(event).await {
                Ok(_) => {
                    summary.received.insert(event.id);
                }
                Err(e) => {
                    summary.send_failures.insert(event.id, e.to_string());
                }
            }
            tick_progress(opts);
        }
        Ok(())
    }
}

/// Drive the NIP-77 round-trip loop until convergence or error.
async fn reconcile_loop(
    relay: &nula_relay::Relay,
    sub_id: SubscriptionId,
    filter: Filter,
    opening_hex: String,
    session: &mut Reconciliation,
    summary: &mut SyncSummary,
    opts: &SyncOptions,
) -> Result<(), Error> {
    let mut handle = relay
        .subscribe_neg(sub_id.clone(), filter, opening_hex)
        .await?;

    for _ in 0..MAX_NEG_ROUNDS {
        let Some(item) = handle.next().await else {
            return Err(Error::SyncStreamClosed);
        };
        match item {
            SubscriptionItem::NegMsg { message } => {
                let outcome = session.reconcile_hex(&message)?;
                fold_outcome(&outcome, summary, opts);
                if let Some(next_hex) = outcome.next_message_hex() {
                    relay
                        .send_msg(ClientMessage::NegMsg {
                            subscription_id: sub_id.clone(),
                            message: next_hex,
                        })
                        .await?;
                } else {
                    return Ok(());
                }
            }
            SubscriptionItem::NegErr { message } => {
                return Err(Error::SyncFailed { reason: message });
            }
            // Sync sessions never emit Event / Eose / Closed; the
            // actor only routes NegMsg / NegErr to the handle.
            _ => {}
        }
    }
    Err(Error::SyncStreamClosed)
}

fn tick_progress(opts: &SyncOptions) {
    if let Some(progress) = &opts.progress {
        progress.send_modify(|state| {
            state.current = state.current.saturating_add(1);
        });
    }
}

fn fold_outcome(
    outcome: &nula_sync::ReconcileOutcome,
    summary: &mut SyncSummary,
    opts: &SyncOptions,
) {
    let mut delta: u64 = 0;
    if opts.direction.do_up() {
        delta = delta.saturating_add(insert_all(&outcome.have, &mut summary.local));
    }
    if opts.direction.do_down() {
        delta = delta.saturating_add(insert_all(&outcome.need, &mut summary.remote));
    }
    if delta > 0
        && let Some(progress) = &opts.progress
    {
        progress.send_modify(|state| {
            state.total = state.total.saturating_add(delta);
        });
    }
}

fn insert_all(ids: &[EventId], target: &mut HashSet<EventId>) -> u64 {
    let mut delta: u64 = 0;
    for id in ids {
        if target.insert(*id) {
            delta += 1;
        }
    }
    delta
}
