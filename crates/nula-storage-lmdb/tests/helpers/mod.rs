//! Shared fixtures for the LMDB integration tests.

#![allow(dead_code, reason = "different test files exercise different helpers")]

use nula_core::event::{Event, EventBuilder, Kind, Tag};
use nula_core::key::Keys;
use nula_core::types::Timestamp;
use nula_storage_lmdb::{Error, LmdbDatabase};
use tempfile::TempDir;

/// Construct a fresh signing keypair via the OS RNG.
pub(crate) fn keys() -> Keys {
    Keys::generate().expect("OS RNG works in tests")
}

/// Open a `LmdbDatabase` rooted at a freshly minted temp directory.
/// Returns the handle plus the temp guard — the database must
/// outlive the temp guard.
pub(crate) async fn fresh_db() -> (LmdbDatabase, TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir creation");
    let db = LmdbDatabase::builder(tmp.path())
        .build()
        .await
        .expect("open lmdb");
    (db, tmp)
}

/// Open a fresh `LmdbDatabase`, returning a typed error so callers
/// can assert on failure conditions if they want to.
pub(crate) async fn try_open(path: impl AsRef<std::path::Path>) -> Result<LmdbDatabase, Error> {
    LmdbDatabase::builder(path.as_ref().to_owned())
        .build()
        .await
}

pub(crate) fn text_note(keys: &Keys, content: &str, created_at: u64) -> Event {
    EventBuilder::text_note(content)
        .created_at(Timestamp::from_secs(created_at))
        .sign_with_keys(keys)
        .expect("text-note signs")
}

pub(crate) fn metadata_event(keys: &Keys, content: &str, created_at: u64) -> Event {
    EventBuilder::new(Kind::METADATA, content)
        .created_at(Timestamp::from_secs(created_at))
        .sign_with_keys(keys)
        .expect("metadata signs")
}

pub(crate) fn event_with_tags(
    keys: &Keys,
    kind: Kind,
    content: &str,
    created_at: u64,
    tags: impl IntoIterator<Item = Tag>,
) -> Event {
    let mut builder = EventBuilder::new(kind, content).created_at(Timestamp::from_secs(created_at));
    for tag in tags {
        builder = builder.tag(tag);
    }
    builder.sign_with_keys(keys).expect("custom event signs")
}
