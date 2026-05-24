//! On-disk event codec for the `SQLite` backend. Identical wire shape
//! to `nula-storage-lmdb`: a single version byte followed by the
//! `postcard`-serialised [`Event`] body. Sharing the codec lets users
//! migrate from one backend to the other without re-encoding.

use nula_core::event::Event;

use crate::error::Error;

/// Current on-disk format identifier. Bump any time the encoded
/// shape changes in a way old readers cannot understand.
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
