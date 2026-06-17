//! `nula dm send` / `nula dm recv` — NIP-17 private direct messages.
//!
//! `send` builds a kind-14 chat rumor, gift-wraps it (NIP-59) once
//! per recipient plus a self-wrap, and broadcasts every wrap. `recv`
//! pulls kind-1059 gift wraps addressed to the caller and decrypts
//! the inner rumors. Both subcommands emit a single JSON object on
//! stdout per the CLI contract.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use nula::Client;
use nula_core::Timestamp;
use nula_core::nips::nip17::Recipient;
use serde_json::json;

use crate::cli::{DmRecvArgs, DmSendArgs};
use crate::commands::{parse_public_key, parse_secret};
use crate::output::write_json;

/// `nula dm send`. Sign + gift-wrap a NIP-17 chat message to one or
/// more recipients and publish every wrap to the supplied relays.
///
/// Returns `Ok(())` if at least one wrap reached at least one relay;
/// errors (non-zero exit) when every publish failed.
pub(crate) async fn send(args: DmSendArgs) -> Result<()> {
    let keys = parse_secret(&args.secret)?;

    let recipients = args
        .to
        .iter()
        .map(|raw| {
            parse_public_key(raw)
                .map(|public_key| Recipient {
                    public_key,
                    relay_hint: None,
                })
                .with_context(|| format!("invalid recipient public key: {raw}"))
        })
        .collect::<Result<Vec<_>>>()?;

    let client = Client::builder()
        .signer(keys.clone())
        .build()
        .context("build SDK client")?;
    for url in &args.relays {
        client
            .add_relay(url.as_str())
            .await
            .with_context(|| format!("add relay {url}"))?;
    }
    let connect = client.try_connect(Duration::from_secs(args.timeout)).await;
    tracing::info!(
        success = connect.success.len(),
        failed = connect.failed.len(),
        "connect attempt complete",
    );

    let output = client
        .send_private_msg(&keys, &recipients, args.content, None)
        .await
        .context("send_private_msg failed")?;

    let value = json!({
        "kind": "dm_sent",
        "wrap_ids": output.value.iter().map(|id| id.to_hex()).collect::<Vec<_>>(),
        "success": output.success.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "failed": output
            .failed
            .iter()
            .map(|(url, reason)| json!({ "url": url.to_string(), "reason": reason }))
            .collect::<Vec<_>>(),
    });
    write_json(&value)?;

    client.shutdown().await;
    if output.success.is_empty() {
        bail!("every relay rejected the gift-wrapped message");
    }
    Ok(())
}

/// `nula dm recv`. Fetch every kind-1059 gift wrap addressed to the
/// caller's public key, decrypt the inner rumors, and print them.
pub(crate) async fn recv(args: DmRecvArgs) -> Result<()> {
    let keys = parse_secret(&args.secret)?;

    let client = Client::builder()
        .signer(keys.clone())
        .build()
        .context("build SDK client")?;
    for url in &args.relays {
        client
            .add_relay(url.as_str())
            .await
            .with_context(|| format!("add relay {url}"))?;
    }
    let connect = client.try_connect(Duration::from_secs(args.timeout)).await;
    tracing::info!(
        success = connect.success.len(),
        failed = connect.failed.len(),
        "connect attempt complete",
    );

    let since = args.since.map(Timestamp::from_secs);
    let messages = client
        .receive_private_msgs(&keys, since, Some(Duration::from_secs(args.timeout)))
        .await
        .context("receive_private_msgs failed")?;

    let value = json!({
        "kind": "dm_received",
        "count": messages.len(),
        "messages": messages
            .iter()
            .map(|msg| json!({
                "wrap_id": msg.wrap_id.to_hex(),
                "sender": msg.rumor.pubkey.to_hex(),
                "created_at": msg.rumor.created_at.as_secs(),
                "rumor_kind": msg.rumor.kind.as_u16(),
                "content": msg.rumor.content,
            }))
            .collect::<Vec<_>>(),
    });
    write_json(&value)?;

    client.shutdown().await;
    Ok(())
}
