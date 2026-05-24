//! Shared output helpers.
//!
//! Every subcommand writes exactly one JSON object to `stdout`. The
//! shape is documented in the README so downstream `jq` pipelines
//! can rely on it.

use std::io::Write;

use anyhow::{Context, Result};

/// Pretty-print `value` as JSON to `stdout`, followed by `\n`.
///
/// Pretty (instead of compact) because human-first ergonomics
/// matter more for CLI than wire efficiency; downstream `jq -c .`
/// can compact when needed.
///
/// # Errors
///
/// Propagates any [`std::io::Error`] from writing to `stdout`.
pub(crate) fn write_json(value: &serde_json::Value) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, value).context("serialise JSON to stdout")?;
    writeln!(stdout).context("trailing newline to stdout")?;
    Ok(())
}
