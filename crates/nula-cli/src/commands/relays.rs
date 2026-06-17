//! `nula relays set` / `nula relays get` — NIP-65 relay-list metadata.
//!
//! `set` builds a kind-10002 event from `--read` / `--write` /
//! `--both` relay flags and publishes it. `get` fetches the latest
//! kind-10002 for a pubkey and prints the parsed list. Both emit a
//! single JSON object on stdout per the CLI contract.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use nula::Client;
use nula_core::RelayUrl;
use nula_core::nips::nip65::{RelayList, RelayMarker};
use serde_json::json;

use crate::cli::{RelaysGetArgs, RelaysSetArgs};
use crate::commands::{parse_public_key, parse_secret};
use crate::output::write_json;

/// `nula relays set`. Compose a [`RelayList`] from the `--read` /
/// `--write` / `--both` flags, sign the kind-10002 event, and
/// broadcast it.
///
/// Returns `Ok(())` when at least one relay accepted the list;
/// errors (non-zero exit) when every publish failed or the list is
/// empty.
pub(crate) async fn set(args: RelaysSetArgs) -> Result<()> {
    let keys = parse_secret(&args.secret)?;

    let mut list = RelayList::new();
    insert_all(&mut list, &args.read, RelayMarker::Read)?;
    insert_all(&mut list, &args.write, RelayMarker::Write)?;
    insert_all(&mut list, &args.both, RelayMarker::ReadWrite)?;
    if list.is_empty() {
        bail!("at least one of --read / --write / --both is required");
    }

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
        .set_relay_list(&list)
        .await
        .context("set_relay_list failed")?;

    let value = json!({
        "kind": "relay_list_published",
        "event_id": output.value.to_hex(),
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
        bail!("every relay rejected the relay list");
    }
    Ok(())
}

/// `nula relays get`. Fetch the latest kind-10002 for `--pubkey`
/// and print the parsed read / write relays.
pub(crate) async fn get(args: RelaysGetArgs) -> Result<()> {
    let pubkey = parse_public_key(&args.pubkey).context("invalid --pubkey")?;

    let client = Client::new();
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

    let list = client
        .get_relay_list(&pubkey, Some(Duration::from_secs(args.timeout)))
        .await
        .context("get_relay_list failed")?;

    let value = list.map_or_else(
        || json!({ "kind": "relay_list", "found": false }),
        |list| relay_list_to_json(&list),
    );
    write_json(&value)?;

    client.shutdown().await;
    Ok(())
}

/// Render a fetched [`RelayList`] as the `relay_list` JSON object.
fn relay_list_to_json(list: &RelayList) -> serde_json::Value {
    json!({
        "kind": "relay_list",
        "found": true,
        "read": list.read_relays().map(RelayUrl::to_string).collect::<Vec<_>>(),
        "write": list.write_relays().map(RelayUrl::to_string).collect::<Vec<_>>(),
        "relays": list
            .iter()
            .map(|(url, marker)| json!({ "url": url.to_string(), "marker": marker.to_string() }))
            .collect::<Vec<_>>(),
    })
}

/// Parse every raw url in `raws` and insert it into `list` under
/// `marker`.
fn insert_all(list: &mut RelayList, raws: &[String], marker: RelayMarker) -> Result<()> {
    for raw in raws {
        let url = RelayUrl::parse(raw).with_context(|| format!("invalid relay url: {raw}"))?;
        list.insert(url, marker);
    }
    Ok(())
}
