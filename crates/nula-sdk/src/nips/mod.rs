//! NIP-specific high-level helpers built on top of [`crate::Client`].
//!
//! Each submodule exposes the *facade* shape of a NIP: the
//! cryptographic primitives stay in `nula_core::nips::*`; this
//! layer only wires them up to the SDK's relay pool, signer, and
//! database.

pub mod nip17;
