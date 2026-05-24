//! NIP-77 reconciliation driver for [`crate::Client`].
//!
//! The Layer-3 [`nula_sync`] crate exposes the algorithm-only
//! [`Reconciliation`] state machine plus a database adapter
//! ([`nula_sync::from_database`]); this module wraps both behind a
//! [`crate::Client::sync_to_relay`] method that:
//!
//! 1. Sources the local `(EventId, Timestamp)` set from the
//!    client's configured database.
//! 2. Opens a NIP-77 session on the chosen relay via
//!    [`nula_relay::Relay::subscribe_neg`] (sends
//!    `["NEG-OPEN", id, filter, opening_hex]`).
//! 3. Folds every `NEG-MSG` reply back through
//!    [`Reconciliation::reconcile_hex`], emits the next outbound
//!    `NEG-MSG` via [`nula_relay::Relay::send_msg`], and stops as
//!    soon as the session converges.
//! 4. Sends a final `NEG-CLOSE` (best-effort) and returns the
//!    accumulated `(have, need)` ids the local replica observed
//!    relative to the relay's view.
//!
//! Multi-relay sync is *not* in scope here: callers needing to
//! reconcile across a relay set are expected to call
//! [`crate::Client::sync_to_relay`] in a fan-out (the per-relay
//! state must stay independent because each peer's Negentropy
//! state machine cannot share a session id).

use std::time::Duration;

use futures::StreamExt;
use nula_core::event::EventId;
use nula_core::filter::Filter;
use nula_core::message::{ClientMessage, SubscriptionId};
use nula_core::types::RelayUrl;
use nula_relay::SubscriptionItem;
use nula_sync::{Reconciliation, from_database};
use tokio::time::timeout;

use crate::client::Client;
use crate::error::Error;

/// Outcome of a single-relay [`Client::sync_to_relay`] call.
///
/// The `have` set is what the local replica already had that the
/// relay did *not* (i.e. events the caller could ship via
/// `send_event`). The `need` set is what the relay has but the
/// local replica does not (i.e. ids the caller should fetch via
/// `fetch_events`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncOutput {
    /// Event ids the local replica holds that the relay does not.
    pub have: Vec<EventId>,
    /// Event ids the relay holds that the local replica does not.
    pub need: Vec<EventId>,
}

/// Maximum number of `NEG-MSG` round-trips a single sync call
/// will perform before bailing with [`Error::SyncStreamClosed`].
/// Keeps a malicious or buggy peer from spinning the loop forever.
const MAX_NEG_ROUNDS: usize = 1024;

impl Client {
    /// Run a NIP-77 reconciliation against `relay_url` for the
    /// caller-supplied `filter`. Returns the deduplicated
    /// `(have, need)` id sets from the local replica's perspective.
    ///
    /// `timeout` caps the overall round-trip time. `None` means
    /// "wait forever" -- pick a value that matches your application's
    /// liveness contract.
    ///
    /// # Errors
    ///
    /// - [`Error::UnknownRelay`] when `relay_url` is not registered
    ///   on the underlying pool.
    /// - [`Error::Storage`] when the configured database refuses
    ///   the [`from_database`] request.
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
        op_timeout: Option<Duration>,
    ) -> Result<SyncOutput, Error> {
        let relay = self
            .pool()
            .relay(relay_url)
            .await
            .ok_or_else(|| Error::UnknownRelay {
                url: relay_url.clone(),
            })?;

        // 1. Local replica → Negentropy storage → opening message.
        let storage = from_database(self.database().as_ref(), filter.clone()).await?;
        let mut session = Reconciliation::with_defaults(storage)?;
        let opening_hex = session.opening_message_hex();

        // 2. Open the NIP-77 subscription. The handle yields
        // SubscriptionItem::NegMsg / NegErr frames.
        let sub_id = SubscriptionId::generate()?;
        let driver = run_session(&relay, sub_id.clone(), filter, opening_hex, &mut session);

        let outcome = match op_timeout {
            Some(deadline) => timeout(deadline, driver)
                .await
                .map_err(|_elapsed| Error::SyncStreamClosed)??,
            None => driver.await?,
        };

        // 3. Best-effort NEG-CLOSE so the relay frees the slot.
        // Errors here (NotConnected, Shutdown) are not the caller's
        // problem -- the actor / relay will reap the entry on its
        // own.
        let close_msg = ClientMessage::NegClose {
            subscription_id: sub_id,
        };
        drop(relay.send_msg(close_msg).await);

        Ok(outcome)
    }
}

/// Drive the NIP-77 round-trip loop until convergence or error.
async fn run_session(
    relay: &nula_relay::Relay,
    sub_id: SubscriptionId,
    filter: Filter,
    opening_hex: String,
    session: &mut Reconciliation,
) -> Result<SyncOutput, Error> {
    let mut handle = relay
        .subscribe_neg(sub_id.clone(), filter, opening_hex)
        .await?;

    let mut output = SyncOutput::default();
    for _ in 0..MAX_NEG_ROUNDS {
        let Some(item) = handle.next().await else {
            return Err(Error::SyncStreamClosed);
        };
        match item {
            SubscriptionItem::NegMsg { message } => {
                let outcome = session.reconcile_hex(&message)?;
                output.have.extend(outcome.have.iter().copied());
                output.need.extend(outcome.need.iter().copied());
                match outcome.next_message_hex() {
                    Some(next_hex) => {
                        let next_msg = ClientMessage::NegMsg {
                            subscription_id: sub_id.clone(),
                            message: next_hex,
                        };
                        relay.send_msg(next_msg).await?;
                    }
                    None => return Ok(output),
                }
            }
            SubscriptionItem::NegErr { message } => {
                return Err(Error::SyncFailed { reason: message });
            }
            // Sync sessions never emit Event / Eose / Closed; the
            // actor only routes NegMsg / NegErr to the handle.
            // Future-proof against new variants by ignoring them.
            _ => {}
        }
    }
    Err(Error::SyncStreamClosed)
}
