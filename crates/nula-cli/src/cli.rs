//! Top-level clap definitions.
//!
//! Every leaf subcommand lives under the `commands` module; this
//! module is the pure declarative shape (no business logic, no
//! `await`s) that `clap` parses against.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::commands::{event, keys, relay};

/// Top-level CLI parsed by [`clap::Parser`].
#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "nula -- Layer-5 Nostr CLI",
    long_about = None,
    propagate_version = true,
)]
pub(crate) struct Cli {
    /// Subcommand group.
    #[command(subcommand)]
    pub(crate) command: Command,
}

impl Cli {
    /// Dispatch the parsed CLI to the matching subcommand handler.
    ///
    /// # Errors
    ///
    /// Forwards every subcommand's `anyhow::Result`.
    pub(crate) async fn run(self) -> Result<()> {
        match self.command {
            Command::Keys(args) => args.run(),
            Command::Relay(args) => args.run().await,
            Command::Event(args) => args.run().await,
        }
    }
}

/// Top-level subcommand group.
#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Manage Nostr keypairs.
    Keys(KeysArgs),
    /// Run a local in-process relay.
    Relay(RelayArgs),
    /// Publish / fetch events.
    Event(EventArgs),
}

/// `nula keys ...`
#[derive(Debug, clap::Args)]
pub(crate) struct KeysArgs {
    /// Subcommand under `keys`.
    #[command(subcommand)]
    pub(crate) command: KeysCommand,
}

impl KeysArgs {
    fn run(self) -> Result<()> {
        match self.command {
            KeysCommand::Generate => keys::generate(),
            KeysCommand::Parse { input } => keys::parse(&input),
        }
    }
}

/// Subcommands under `keys`.
#[derive(Debug, Subcommand)]
pub(crate) enum KeysCommand {
    /// Generate a fresh keypair (prints `nsec` / `npub` / hex as JSON).
    Generate,
    /// Decode any of `nsec` / `npub` / hex into every other form.
    Parse {
        /// `nsec1...`, `npub1...`, or a 64-char hex secret key.
        input: String,
    },
}

/// `nula relay ...`
#[derive(Debug, clap::Args)]
pub(crate) struct RelayArgs {
    /// Subcommand under `relay`.
    #[command(subcommand)]
    pub(crate) command: RelayCommand,
}

impl RelayArgs {
    async fn run(self) -> Result<()> {
        match self.command {
            RelayCommand::Run { bind } => relay::run(bind).await,
        }
    }
}

/// Subcommands under `relay`.
#[derive(Debug, Subcommand)]
pub(crate) enum RelayCommand {
    /// Start a local mock relay. Blocks until Ctrl-C.
    Run {
        /// Bind address. Default `127.0.0.1:0` (OS picks the port).
        #[arg(long, default_value = "127.0.0.1:0")]
        bind: SocketAddr,
    },
}

/// `nula event ...`
#[derive(Debug, clap::Args)]
pub(crate) struct EventArgs {
    /// Subcommand under `event`.
    #[command(subcommand)]
    pub(crate) command: EventCommand,
}

impl EventArgs {
    async fn run(self) -> Result<()> {
        match self.command {
            EventCommand::Publish(args) => event::publish(args).await,
            EventCommand::Fetch(args) => event::fetch(args).await,
        }
    }
}

/// Subcommands under `event`.
#[derive(Debug, Subcommand)]
pub(crate) enum EventCommand {
    /// Sign a text note and publish it to one or more relays.
    Publish(PublishArgs),
    /// One-shot REQ fetch against the supplied relays.
    Fetch(FetchArgs),
}

/// Arguments for `nula event publish`.
#[derive(Debug, clap::Args)]
pub(crate) struct PublishArgs {
    /// Relay URL. Repeat for multi-relay publish.
    #[arg(long = "relay", required = true)]
    pub(crate) relays: Vec<String>,
    /// Secret key (`nsec1...` or 64-char hex). Falls back to the
    /// `NULA_SECRET` env var when omitted.
    #[arg(long, env = "NULA_SECRET", hide_env_values = true)]
    pub(crate) secret: String,
    /// Event content. Required unless `--content-file` is given.
    #[arg(long, conflicts_with = "content_file")]
    pub(crate) content: Option<String>,
    /// Read content from a file. Use `-` for stdin.
    #[arg(long, value_name = "PATH", conflicts_with = "content")]
    pub(crate) content_file: Option<PathBuf>,
    /// Event kind. Default `1` (text note).
    #[arg(long, default_value_t = 1)]
    pub(crate) kind: u16,
    /// Per-relay connect timeout, in seconds.
    #[arg(long, default_value_t = 10)]
    pub(crate) timeout: u64,
}

/// Arguments for `nula event fetch`.
#[derive(Debug, clap::Args)]
pub(crate) struct FetchArgs {
    /// Relay URL. Repeat for multi-relay fetch.
    #[arg(long = "relay", required = true)]
    pub(crate) relays: Vec<String>,
    /// Author public key (`npub1...` or 64-char hex). Repeatable.
    #[arg(long = "author")]
    pub(crate) authors: Vec<String>,
    /// Event kind. Repeatable.
    #[arg(long = "kind")]
    pub(crate) kinds: Vec<u16>,
    /// Max number of events to return per relay.
    #[arg(long)]
    pub(crate) limit: Option<usize>,
    /// `created_at >= since` (Unix seconds).
    #[arg(long)]
    pub(crate) since: Option<u64>,
    /// `created_at <= until` (Unix seconds).
    #[arg(long)]
    pub(crate) until: Option<u64>,
    /// Per-relay fetch timeout, in seconds.
    #[arg(long, default_value_t = 10)]
    pub(crate) timeout: u64,
}
