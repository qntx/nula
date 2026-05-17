//! Stateful NIP-77 reconciliation sessions.
//!
//! Two roles in the protocol map onto two types here:
//!
//! - [`Reconciliation`] — the *initiator* (typically the client).
//!   Produces the [`PROTOCOL_VERSION`] opening message via
//!   [`Reconciliation::initiate`] and then folds each `NEG-MSG`
//!   reply from the responder into [`ReconcileOutcome`].
//! - [`Responder`] — the *non-initiator* (typically a relay or test
//!   harness). Accepts every initiator message via
//!   [`Responder::reconcile`] and produces the next frame.
//!
//! Each side owns its own [`negentropy::NegentropyStorageVector`]
//! built from a `(EventId, Timestamp)` set via
//! [`crate::prepare_storage`]. Neither type touches I/O —
//! the caller is responsible for moving bytes over the wire
//! (typically by wrapping the payloads in
//! [`nula_core::ClientMessage::NegOpen`] /
//! [`nula_core::ClientMessage::NegMsg`] and
//! [`nula_core::RelayMessage::NegMsg`]).
//!
//! [`PROTOCOL_VERSION`]: negentropy::PROTOCOL_VERSION

use negentropy::{Negentropy, NegentropyStorageVector};
use nula_core::event::EventId;
use nula_core::util::hex;

use crate::error::Error;
use crate::storage_vec::neg_id_to_event_id;

/// NIP-77 frame size limit, in bytes.
///
/// Matches the default the [reference C++ implementation](https://github.com/hoytech/strfry)
/// negotiates with relays and the value the upstream
/// [`negentropy`] crate documents as a safe cap. Must be 0 (no cap)
/// or ≥ 4096 per [`Negentropy::new`].
pub const DEFAULT_FRAME_SIZE_LIMIT: u64 = 60_000;

/// Outcome of folding one peer message into a [`Reconciliation`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconcileOutcome {
    /// Event ids the **local** side holds but the peer does not.
    /// The caller should publish each event to the peer (relay).
    pub have: Vec<EventId>,
    /// Event ids the **peer** holds but the local side does not.
    /// The caller should subscribe to (or otherwise fetch) each
    /// event from the peer.
    pub need: Vec<EventId>,
    /// Bytes the local side must send back as the next `NEG-MSG`
    /// payload. `None` signals that the session converged: there is
    /// nothing more to reconcile and the caller should issue a
    /// `NEG-CLOSE` to release the relay-side subscription.
    pub next_message: Option<Vec<u8>>,
}

impl ReconcileOutcome {
    /// `true` when the session converged on this turn.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.next_message.is_none()
    }

    /// Hex-encode [`Self::next_message`] for direct inclusion in a
    /// [`nula_core::ClientMessage::NegMsg`] frame. `None` when the
    /// session converged.
    #[must_use]
    pub fn next_message_hex(&self) -> Option<String> {
        self.next_message.as_deref().map(hex::encode)
    }
}

/// Initiator-side NIP-77 reconciliation session.
///
/// Construct via [`Self::initiate`]; feed each `NEG-MSG` payload the
/// responder sends back through [`Self::reconcile`] /
/// [`Self::reconcile_hex`]. The session is finished when
/// [`ReconcileOutcome::is_complete`] returns `true`.
#[derive(Debug)]
pub struct Reconciliation {
    /// `Negentropy` borrows from its storage, so we keep them
    /// together. The `'static` lifetime is satisfied by using
    /// [`negentropy::Storage::Owned`] under the hood.
    inner: Negentropy<'static, NegentropyStorageVector>,
    /// Cached opening message produced on construction so callers
    /// can grab it later without re-running `initiate` (which would
    /// error with `AlreadyBuiltInitialMessage`).
    opening: Vec<u8>,
}

impl Reconciliation {
    /// Build a reconciliation session and produce its opening
    /// message in one shot.
    ///
    /// `frame_size_limit` follows the [`Negentropy::new`] contract:
    /// pass `0` for "no cap", otherwise a value ≥ 4096. The crate
    /// default [`DEFAULT_FRAME_SIZE_LIMIT`] is a good baseline.
    ///
    /// # Errors
    ///
    /// - [`Error::Algorithm`] if the [`negentropy`] machine refuses
    ///   the supplied storage or frame size.
    pub fn initiate(
        storage: NegentropyStorageVector,
        frame_size_limit: u64,
    ) -> Result<Self, Error> {
        let mut inner = Negentropy::owned(storage, frame_size_limit)?;
        let opening = inner.initiate()?;
        Ok(Self { inner, opening })
    }

    /// Convenience constructor using [`DEFAULT_FRAME_SIZE_LIMIT`].
    ///
    /// # Errors
    ///
    /// Forwards every failure from [`Self::initiate`].
    pub fn with_defaults(storage: NegentropyStorageVector) -> Result<Self, Error> {
        Self::initiate(storage, DEFAULT_FRAME_SIZE_LIMIT)
    }

    /// Cached opening message bytes. Send these as the
    /// `initial_message` payload of a
    /// [`nula_core::ClientMessage::NegOpen`].
    #[must_use]
    pub fn opening_message(&self) -> &[u8] {
        &self.opening
    }

    /// Hex-encoded opening message, ready for direct wire use.
    #[must_use]
    pub fn opening_message_hex(&self) -> String {
        hex::encode(&self.opening)
    }

    /// Fold one responder `NEG-MSG` payload into the session.
    ///
    /// # Errors
    ///
    /// - [`Error::Algorithm`] propagated from
    ///   [`Negentropy::reconcile_with_ids`].
    pub fn reconcile(&mut self, query: &[u8]) -> Result<ReconcileOutcome, Error> {
        let mut have_ids = Vec::new();
        let mut need_ids = Vec::new();
        let next = self
            .inner
            .reconcile_with_ids(query, &mut have_ids, &mut need_ids)?;
        Ok(ReconcileOutcome {
            have: have_ids.into_iter().map(neg_id_to_event_id).collect(),
            need: need_ids.into_iter().map(neg_id_to_event_id).collect(),
            next_message: next,
        })
    }

    /// Hex-aware wrapper around [`Self::reconcile`]: decodes
    /// `query_hex` (the exact string carried by a
    /// [`nula_core::RelayMessage::NegMsg`]) and folds it in.
    ///
    /// # Errors
    ///
    /// - [`Error::Hex`] if `query_hex` is not a valid lowercase hex
    ///   string of even length.
    /// - [`Error::Algorithm`] propagated from [`Self::reconcile`].
    pub fn reconcile_hex(&mut self, query_hex: &str) -> Result<ReconcileOutcome, Error> {
        let bytes = hex::decode(query_hex)?;
        self.reconcile(&bytes)
    }
}

/// Non-initiator-side NIP-77 reconciliation session.
///
/// Construct via [`Self::new`]; feed each initiator message through
/// [`Self::reconcile`] / [`Self::reconcile_hex`] and forward the
/// returned bytes back to the initiator inside a
/// [`nula_core::RelayMessage::NegMsg`] frame.
#[derive(Debug)]
pub struct Responder {
    inner: Negentropy<'static, NegentropyStorageVector>,
}

impl Responder {
    /// Build a responder session.
    ///
    /// # Errors
    ///
    /// Same contract as [`Reconciliation::initiate`] — the only
    /// failure path is the [`negentropy`] constructor refusing the
    /// supplied storage or frame size.
    pub fn new(storage: NegentropyStorageVector, frame_size_limit: u64) -> Result<Self, Error> {
        let inner = Negentropy::owned(storage, frame_size_limit)?;
        Ok(Self { inner })
    }

    /// Convenience constructor using [`DEFAULT_FRAME_SIZE_LIMIT`].
    ///
    /// # Errors
    ///
    /// Forwards every failure from [`Self::new`].
    pub fn with_defaults(storage: NegentropyStorageVector) -> Result<Self, Error> {
        Self::new(storage, DEFAULT_FRAME_SIZE_LIMIT)
    }

    /// Reply to one initiator message.
    ///
    /// The returned [`Vec<u8>`] is always populated — the responder
    /// never decides on its own that the session is done; the
    /// initiator does, by emitting a `NEG-CLOSE`.
    ///
    /// # Errors
    ///
    /// - [`Error::Algorithm`] propagated from [`Negentropy::reconcile`].
    pub fn reconcile(&mut self, query: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.inner.reconcile(query)?)
    }

    /// Hex-aware wrapper around [`Self::reconcile`].
    ///
    /// # Errors
    ///
    /// - [`Error::Hex`] for invalid hex.
    /// - [`Error::Algorithm`] propagated from [`Self::reconcile`].
    pub fn reconcile_hex(&mut self, query_hex: &str) -> Result<String, Error> {
        let bytes = hex::decode(query_hex)?;
        let reply = self.reconcile(&bytes)?;
        Ok(hex::encode(reply))
    }
}

#[cfg(test)]
mod tests {
    use nula_core::Keys;
    use nula_core::event::EventBuilder;
    use nula_core::types::Timestamp;

    use super::*;
    use crate::storage_vec::prepare_storage;

    fn make_event_id(seed: u8, kind_byte: u8) -> EventId {
        let mut hex = [b'0'; 64];
        hex[63] = match seed {
            0..=9 => b'0' + seed,
            10..=15 => b'a' + (seed - 10),
            _ => unreachable!(),
        };
        let keys = Keys::parse(core::str::from_utf8(&hex).unwrap()).unwrap();
        let payload = format!("seed-{seed}-{kind_byte}");
        EventBuilder::text_note(payload)
            .sign_with_keys(&keys)
            .unwrap()
            .id
    }

    #[test]
    fn opening_message_is_non_empty() {
        let storage = prepare_storage([(make_event_id(1, 0), Timestamp::from_secs(100))]).unwrap();
        let session = Reconciliation::with_defaults(storage).unwrap();
        assert!(!session.opening_message().is_empty());
        let hex = session.opening_message_hex();
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(hex.len(), session.opening_message().len() * 2);
    }

    #[test]
    fn two_identical_sets_converge_in_two_round_trips() {
        // Same item on both sides → no `have`, no `need`, session
        // converges as soon as the responder echoes the fingerprint
        // back.
        let shared = (make_event_id(2, 0), Timestamp::from_secs(200));
        let initiator_storage = prepare_storage([shared]).unwrap();
        let responder_storage = prepare_storage([shared]).unwrap();

        let mut initiator = Reconciliation::with_defaults(initiator_storage).unwrap();
        let mut responder = Responder::with_defaults(responder_storage).unwrap();

        let opening = initiator.opening_message().to_vec();
        let reply = responder.reconcile(&opening).unwrap();
        let outcome = initiator.reconcile(&reply).unwrap();

        assert!(outcome.have.is_empty());
        assert!(outcome.need.is_empty());
        assert!(outcome.is_complete());
    }

    #[test]
    fn divergent_sets_yield_have_and_need() {
        // Initiator has {A, B}; responder has {B, C}.
        let a = (make_event_id(3, 0), Timestamp::from_secs(100));
        let b = (make_event_id(4, 0), Timestamp::from_secs(200));
        let c = (make_event_id(5, 0), Timestamp::from_secs(300));

        let initiator_storage = prepare_storage([a, b]).unwrap();
        let responder_storage = prepare_storage([b, c]).unwrap();

        let mut initiator = Reconciliation::with_defaults(initiator_storage).unwrap();
        let mut responder = Responder::with_defaults(responder_storage).unwrap();

        let mut last = initiator.opening_message().to_vec();
        let mut total_have: Vec<EventId> = Vec::new();
        let mut total_need: Vec<EventId> = Vec::new();
        // Bound the loop so a bug in the algorithm or our adapter
        // cannot hang the test runner.
        for _ in 0..16 {
            let reply = responder.reconcile(&last).unwrap();
            let outcome = initiator.reconcile(&reply).unwrap();
            total_have.extend(outcome.have);
            total_need.extend(outcome.need);
            match outcome.next_message {
                Some(next) => last = next,
                None => break,
            }
        }

        assert!(
            total_have.contains(&a.0),
            "A is unique to the initiator, must show up as `have`"
        );
        assert!(
            total_need.contains(&c.0),
            "C is unique to the responder, must show up as `need`"
        );
        assert!(
            !total_have.contains(&b.0),
            "shared event B must not appear in `have`"
        );
        assert!(
            !total_need.contains(&b.0),
            "shared event B must not appear in `need`"
        );
    }

    #[test]
    fn reconcile_hex_round_trips_a_real_message() {
        let shared = (make_event_id(6, 0), Timestamp::from_secs(400));
        let initiator_storage = prepare_storage([shared]).unwrap();
        let responder_storage = prepare_storage([shared]).unwrap();

        let mut initiator = Reconciliation::with_defaults(initiator_storage).unwrap();
        let mut responder = Responder::with_defaults(responder_storage).unwrap();

        let opening_hex = initiator.opening_message_hex();
        let reply_hex = responder.reconcile_hex(&opening_hex).unwrap();
        let outcome = initiator.reconcile_hex(&reply_hex).unwrap();
        assert!(outcome.is_complete());
    }

    #[test]
    fn reconcile_hex_rejects_invalid_hex() {
        let storage = prepare_storage([(make_event_id(7, 0), Timestamp::from_secs(500))]).unwrap();
        let mut initiator = Reconciliation::with_defaults(storage).unwrap();
        let err = initiator.reconcile_hex("not-hex").unwrap_err();
        assert!(matches!(err, Error::Hex(_)));
    }
}
