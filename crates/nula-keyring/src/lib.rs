//! Persist Nostr [`nula_core::Keys`] in the operating system's
//! native secret store -- macOS Keychain, Linux Secret Service,
//! Windows Credential Manager.
//!
//! `nula-keyring` is a thin async wrapper over the
//! [`keyring`](https://docs.rs/keyring) crate, plumbed for the
//! `nula-core` `Keys` type. The blocking `keyring` calls run on
//! tokio's blocking pool so the async API never starves the runtime;
//! a parallel sync API is provided for callers that already sit
//! behind a synchronous boundary (CLI startup, system tray menus,
//! ...).
//!
//! See the crate-level [README] for a quickstart and platform
//! support matrix.
//!
//! [README]: https://docs.rs/crate/nula-keyring/latest/source/README.md

#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc(html_root_url = "https://docs.rs/nula-keyring")]
#![forbid(unsafe_code)]

use nula_core::Keys;
use nula_core::key::SecretKey;
use thiserror::Error;
use tokio::task;

/// Errors raised by [`Keyring`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Underlying OS keyring backend returned an error.
    #[error(transparent)]
    Keyring(#[from] keyring::Error),

    /// Bytes stored in the keyring failed to parse as a NIP-01
    /// secret key. Indicates either a corrupted entry or one that
    /// was written by a different application using the same
    /// service / name.
    #[error("stored bytes are not a valid Nostr secret key: {0}")]
    InvalidSecret(#[from] nula_core::key::SecretKeyError),

    /// The blocking worker tokio scheduled the keyring call on
    /// panicked. Unlikely in practice; surfaced as a typed error so
    /// the caller does not have to introspect [`task::JoinError`].
    #[error(transparent)]
    Join(#[from] task::JoinError),
}

/// Cheap-to-clone keyring handle scoped to a single service name.
///
/// The OS keychain is keyed by `(service, name)` pairs. `service`
/// is the application identifier passed to [`Self::new`]; `name` is
/// the per-entry label supplied at each call site.
#[derive(Debug, Clone)]
pub struct Keyring {
    service: String,
}

impl Keyring {
    /// Construct a keyring handle for `service`.
    ///
    /// Conventionally `service` is the application's reverse-domain
    /// identifier (e.g. `"com.example.myapp"`). It scopes every
    /// entry written through this handle to the same logical
    /// "credential pile" inside the OS keychain.
    #[must_use]
    pub fn new<S>(service: S) -> Self
    where
        S: Into<String>,
    {
        Self {
            service: service.into(),
        }
    }

    /// The service identifier this handle was constructed with.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Persist `keys` under `name`. Overwrites any existing entry.
    ///
    /// # Errors
    ///
    /// - [`Error::Keyring`] propagated from the OS backend.
    /// - [`Error::Join`] when the blocking worker panicked.
    pub async fn set(&self, name: &str, keys: &Keys) -> Result<(), Error> {
        let entry = self.entry(name)?;
        let secret_bytes: [u8; 32] = keys.secret_key().to_byte_array();
        task::spawn_blocking(move || entry.set_secret(&secret_bytes)).await??;
        Ok(())
    }

    /// Synchronous sibling of [`Self::set`].
    ///
    /// # Errors
    ///
    /// Same surface as [`Self::set`], minus the join failure path.
    pub fn set_blocking(&self, name: &str, keys: &Keys) -> Result<(), Error> {
        let entry = self.entry(name)?;
        let secret_bytes: [u8; 32] = keys.secret_key().to_byte_array();
        entry.set_secret(&secret_bytes)?;
        Ok(())
    }

    /// Load the [`Keys`] previously written under `name`.
    ///
    /// # Errors
    ///
    /// - [`Error::Keyring`] with a `NoEntry` payload when nothing
    ///   was ever written under this name.
    /// - [`Error::InvalidSecret`] when the stored bytes are not a
    ///   well-formed secret key (usually means a different app
    ///   reused the same `(service, name)` pair).
    /// - [`Error::Join`] when the blocking worker panicked.
    pub async fn get(&self, name: &str) -> Result<Keys, Error> {
        let entry = self.entry(name)?;
        let bytes = task::spawn_blocking(move || entry.get_secret()).await??;
        let secret_key = SecretKey::from_slice(&bytes)?;
        Ok(Keys::from_secret_key(secret_key))
    }

    /// Synchronous sibling of [`Self::get`].
    ///
    /// # Errors
    ///
    /// Same surface as [`Self::get`], minus the join failure path.
    pub fn get_blocking(&self, name: &str) -> Result<Keys, Error> {
        let entry = self.entry(name)?;
        let bytes = entry.get_secret()?;
        let secret_key = SecretKey::from_slice(&bytes)?;
        Ok(Keys::from_secret_key(secret_key))
    }

    /// Delete the entry stored under `name`. Returns `Ok(())` for
    /// missing entries as well -- the operation is idempotent.
    ///
    /// # Errors
    ///
    /// - [`Error::Keyring`] propagated from the OS backend, except
    ///   the `NoEntry` case which is normalised to `Ok(())`.
    /// - [`Error::Join`] when the blocking worker panicked.
    pub async fn delete(&self, name: &str) -> Result<(), Error> {
        let entry = self.entry(name)?;
        let result = task::spawn_blocking(move || entry.delete_credential()).await?;
        normalise_delete(result)
    }

    /// Synchronous sibling of [`Self::delete`].
    ///
    /// # Errors
    ///
    /// Same surface as [`Self::delete`], minus the join failure
    /// path.
    pub fn delete_blocking(&self, name: &str) -> Result<(), Error> {
        let entry = self.entry(name)?;
        normalise_delete(entry.delete_credential())
    }

    fn entry(&self, name: &str) -> Result<keyring::Entry, Error> {
        Ok(keyring::Entry::new(&self.service, name)?)
    }
}

fn normalise_delete(result: Result<(), keyring::Error>) -> Result<(), Error> {
    match result {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(Error::from(e)),
    }
}
