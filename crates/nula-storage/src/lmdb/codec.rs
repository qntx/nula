//! On-disk event codec.
//!
//! Every event payload stored in the LMDB `events` dbi carries a
//! one-byte version prefix followed by the `postcard`-serialised
//! [`Event`]. The version prefix lets future schema changes be
//! detected at read time without forcing a coordinated downgrade —
//! readers older than the current `STORED_EVENT_VERSION` simply error
//! out with [`crate::lmdb::Error::UnsupportedCodecVersion`].
//!
//! The codec is deliberately opaque: it round-trips through the
//! upstream `Event` serde impls and adds nothing of its own beyond
//! the version byte. If a future deserialisation needs to read a
//! superset of `Event` (e.g. an indexing hint), that lives in a
//! `StoredEventVN` newtype with its own version byte, not by
//! shoe-horning extra fields onto the wire shape.

use nula_core::event::Event;

use crate::lmdb::error::Error;

/// Current on-disk format identifier. Bump any time the encoded
/// shape changes in a way old readers cannot understand.
///
/// We start at 1 (not 0) so a zero-byte payload — which a corrupt
/// LMDB read could plausibly hand back — is unambiguously invalid.
pub(crate) const STORED_EVENT_VERSION: u8 = 1;

/// Encode `event` for storage.
///
/// Layout: `[version: u8] [postcard(event): &[u8]]`.
pub(crate) fn encode(event: &Event) -> Result<Vec<u8>, Error> {
    let body = postcard::to_allocvec(event).map_err(Error::Encode)?;
    let mut buf = Vec::with_capacity(body.len() + 1);
    buf.push(STORED_EVENT_VERSION);
    buf.extend_from_slice(&body);
    Ok(buf)
}

/// Decode a stored payload back into an [`Event`].
pub(crate) fn decode(bytes: &[u8]) -> Result<Event, Error> {
    let (version, rest) = bytes.split_first().ok_or(Error::EmptyPayload)?;
    match *version {
        STORED_EVENT_VERSION => postcard::from_bytes(rest).map_err(Error::Decode),
        other => Err(Error::UnsupportedCodecVersion(other)),
    }
}

#[cfg(test)]
mod tests {
    use nula_core::event::EventBuilder;
    use nula_core::key::Keys;
    use nula_core::types::Timestamp;

    use super::*;

    fn fixture() -> Event {
        let keys = Keys::generate().expect("os rng");
        EventBuilder::text_note("round-trip")
            .created_at(Timestamp::from_secs(1_700_000_000))
            .sign_with_keys(&keys)
            .expect("sign")
    }

    #[test]
    fn round_trip_preserves_event() {
        let event = fixture();
        let bytes = encode(&event).expect("encode");
        let decoded = decode(&bytes).expect("decode");
        assert_eq!(decoded, event);
    }

    #[test]
    fn unknown_version_byte_is_rejected() {
        let event = fixture();
        let mut bytes = encode(&event).expect("encode");
        // Bump the version prefix to an unsupported value. The
        // first byte is always present because `encode` writes it
        // up front, so the indexed write is bounds-safe.
        #[allow(
            clippy::indexing_slicing,
            reason = "encode always emits a non-empty buffer; the first byte is the version prefix"
        )]
        {
            bytes[0] = 0xFF;
        }
        let err = decode(&bytes).expect_err("must reject unknown version");
        assert!(matches!(err, Error::UnsupportedCodecVersion(0xFF)));
    }

    #[test]
    fn empty_payload_is_rejected() {
        let err = decode(&[]).expect_err("empty payload");
        assert!(matches!(err, Error::EmptyPayload));
    }
}
