//! Adapter that builds a sealed
//! [`negentropy::NegentropyStorageVector`] from a
//! [`nula_storage::NostrDatabase`].
//!
//! Hidden behind the `storage` feature so embedded / browser
//! deployments that hand-roll their item iteration can still depend
//! on the algorithm-only surface in [`crate::session`].

use negentropy::NegentropyStorageVector;
use nula_core::Filter;
use nula_storage::NostrDatabase;

use crate::error::Error;
use crate::storage_vec::prepare_storage;

/// Pull the `(EventId, Timestamp)` pairs for `filter` out of `db`
/// and seal them into a [`NegentropyStorageVector`].
///
/// Backends that advertise [`nula_storage::Features::FAST_NEGENTROPY`]
/// will serve this from a secondary index instead of materialising
/// every event.
///
/// # Errors
///
/// - [`Error::Storage`] if the underlying
///   [`NostrDatabase::negentropy_items`] call fails.
/// - [`Error::Algorithm`] if the [`negentropy`] crate refuses to
///   seal the storage (currently unreachable, kept for forward
///   compatibility).
pub async fn from_database(
    db: &(dyn NostrDatabase + Send + Sync),
    filter: Filter,
) -> Result<NegentropyStorageVector, Error> {
    let items = db.negentropy_items(filter).await?;
    prepare_storage(items)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use nula_core::Keys;
    use nula_core::Kind;
    use nula_core::event::EventBuilder;
    use nula_storage_memory::MemoryDatabase;

    use super::*;
    use crate::session::{Reconciliation, Responder};

    fn keys(seed: u8) -> Keys {
        let mut hex = [b'0'; 64];
        hex[63] = match seed {
            0..=9 => b'0' + seed,
            10..=15 => b'a' + (seed - 10),
            _ => unreachable!(),
        };
        Keys::parse(core::str::from_utf8(&hex).unwrap()).unwrap()
    }

    async fn seed_db(db: &MemoryDatabase, payloads: &[&str], k: &Keys) {
        for payload in payloads {
            let ev = EventBuilder::text_note(*payload).sign_with_keys(k).unwrap();
            db.save_event(&ev).await.unwrap();
        }
    }

    #[tokio::test]
    async fn from_database_converges_two_in_memory_replicas() {
        let k = keys(8);
        let alice = Arc::new(MemoryDatabase::new());
        let bob = Arc::new(MemoryDatabase::new());

        seed_db(&alice, &["a-1", "a-2", "shared"], &k).await;
        seed_db(&bob, &["shared", "b-1"], &k).await;

        let filter = Filter::new().kind(Kind::TEXT_NOTE);

        let initiator_storage = from_database(alice.as_ref(), filter.clone()).await.unwrap();
        let responder_storage = from_database(bob.as_ref(), filter).await.unwrap();

        let mut initiator = Reconciliation::with_defaults(initiator_storage).unwrap();
        let mut responder = Responder::with_defaults(responder_storage).unwrap();

        let mut last = initiator.opening_message().to_vec();
        let mut total_have = Vec::new();
        let mut total_need = Vec::new();
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

        // Alice exclusively holds two text notes, Bob holds one.
        assert_eq!(total_have.len(), 2, "two unique-to-alice events");
        assert_eq!(total_need.len(), 1, "one unique-to-bob event");
    }
}
