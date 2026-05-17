//! Build a sealed [`NegentropyStorageVector`] from
//! `(EventId, Timestamp)` items.
//!
//! Both the initiator side ([`crate::Reconciliation`]) and the
//! responder side ([`crate::Responder`]) hold their items in this
//! shape. Splitting the constructor into its own module keeps the
//! session types focused on protocol state.

use negentropy::{Id, NegentropyStorageVector};
use nula_core::event::EventId;
use nula_core::types::Timestamp;

use crate::error::Error;

/// Build a sealed [`NegentropyStorageVector`] from an iterator of
/// `(EventId, Timestamp)` items.
///
/// The returned vector is `seal()`-ed: it is ready to back a
/// [`negentropy::Negentropy`] session and rejects further
/// [`NegentropyStorageVector::insert`] calls.
///
/// # Errors
///
/// Returns [`Error::Algorithm`] if the underlying
/// [`negentropy`] crate refuses an insert (it currently only does so
/// after sealing, which we control here, so this is effectively a
/// belt-and-braces propagation).
pub fn prepare_storage<I>(items: I) -> Result<NegentropyStorageVector, Error>
where
    I: IntoIterator<Item = (EventId, Timestamp)>,
{
    let iter = items.into_iter();
    let (lower, _) = iter.size_hint();
    let mut storage = NegentropyStorageVector::with_capacity(lower);
    for (id, ts) in iter {
        storage.insert(ts.as_secs(), event_id_to_neg_id(id))?;
    }
    storage.seal()?;
    Ok(storage)
}

/// Convert a [`nula_core::EventId`] into a negentropy [`Id`].
#[inline]
#[must_use]
pub const fn event_id_to_neg_id(id: EventId) -> Id {
    Id::from_byte_array(id.to_byte_array())
}

/// Convert a negentropy [`Id`] back into a [`nula_core::EventId`].
///
/// Not `const`: [`negentropy::Id::to_bytes`] is not a `const fn`.
#[inline]
#[must_use]
pub fn neg_id_to_event_id(id: Id) -> EventId {
    EventId::from_byte_array(id.to_bytes())
}

#[cfg(test)]
mod tests {
    use nula_core::Keys;
    use nula_core::event::EventBuilder;

    use super::*;

    fn event_id(seed: u8) -> EventId {
        let mut hex = [b'0'; 64];
        hex[63] = match seed {
            0..=9 => b'0' + seed,
            10..=15 => b'a' + (seed - 10),
            _ => unreachable!(),
        };
        let keys = Keys::parse(core::str::from_utf8(&hex).unwrap()).unwrap();
        EventBuilder::text_note("ping")
            .sign_with_keys(&keys)
            .unwrap()
            .id
    }

    #[test]
    fn prepare_storage_seals_and_sizes() {
        let items = vec![
            (event_id(1), Timestamp::from_secs(100)),
            (event_id(2), Timestamp::from_secs(200)),
            (event_id(3), Timestamp::from_secs(300)),
        ];
        let storage = prepare_storage(items).unwrap();
        // Sealed: a subsequent insert must fail.
        let mut storage = storage;
        let err = storage.insert(400, Id::from_byte_array([0u8; 32]));
        assert!(err.is_err(), "sealed storage must reject inserts");
    }

    #[test]
    fn empty_iterator_is_accepted() {
        let storage = prepare_storage(core::iter::empty()).unwrap();
        let mut storage = storage;
        assert!(storage.insert(0, Id::from_byte_array([0u8; 32])).is_err());
    }

    #[test]
    fn event_id_round_trip_through_neg_id() {
        let eid = event_id(5);
        let neg = event_id_to_neg_id(eid);
        let back = neg_id_to_event_id(neg);
        assert_eq!(eid, back);
    }
}
