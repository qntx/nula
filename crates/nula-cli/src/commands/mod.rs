//! Subcommand implementations. Each module exposes one async (or
//! sync) function per leaf subcommand; argument parsing happens
//! upstream in `crate::cli`.

pub(crate) mod event;
pub(crate) mod keys;
pub(crate) mod relay;
