//! `nula event publish` / `nula event fetch` implementations.

use std::io::Read;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use nula_core::nips::nip19::FromBech32;
use nula_core::{EventBuilder, Filter, Keys, Kind, PublicKey, SecretKey, Timestamp};
use nula_sdk::Client;
use serde_json::json;

use crate::cli::{FetchArgs, PublishArgs};
use crate::output::write_json;

/// `nula event publish`. Signs a kind-`args.kind` event with
/// `args.content` and ships it to every URL in `args.relays`.
///
/// Returns `Ok(())` if **any** relay accepted the publish; if every
/// relay failed, returns an error so the process exits non-zero
/// (which `cargo install`ed users can react to in CI pipelines).
pub(crate) async fn publish(args: PublishArgs) -> Result<()> {
    let keys = parse_secret(&args.secret)?;
    let content = read_content(&args)?;
    let kind = Kind::new(args.kind);

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

    let builder =
        EventBuilder::new(kind, content).created_at(Timestamp::now().context("read system clock")?);

    let output = client
        .send_event_builder(builder)
        .await
        .context("send_event_builder failed")?;

    let value = json!({
        "kind": "event_published",
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
        bail!("every relay rejected the publish");
    }
    Ok(())
}

/// `nula event fetch`. One-shot `REQ` with `close_on_eose` semantics
/// against the supplied relay set; collects, deduplicates, and
/// prints every event the relay returned.
pub(crate) async fn fetch(args: FetchArgs) -> Result<()> {
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

    let filter = build_filter(&args)?;
    let events = client
        .fetch_events(filter, Some(Duration::from_secs(args.timeout)))
        .await
        .context("fetch_events failed")?;

    let value = json!({
        "kind": "events_fetched",
        "count": events.len(),
        "events": events
            .iter()
            .map(|event| serde_json::to_value(event).unwrap_or_else(|err| {
                tracing::error!(?err, "serialize Event to JSON");
                serde_json::Value::Null
            }))
            .collect::<Vec<_>>(),
    });
    write_json(&value)?;

    client.shutdown().await;
    Ok(())
}

/// Convert `args` into a NIP-01 filter.
fn build_filter(args: &FetchArgs) -> Result<Filter> {
    let mut filter = Filter::new();

    for raw in &args.authors {
        let pk =
            parse_public_key(raw).with_context(|| format!("invalid author public key: {raw}"))?;
        filter = filter.author(pk);
    }
    for kind in &args.kinds {
        filter = filter.kind(Kind::new(*kind));
    }
    if let Some(limit) = args.limit {
        filter = filter.limit(limit);
    }
    if let Some(since) = args.since {
        filter = filter.since(Timestamp::from_secs(since));
    }
    if let Some(until) = args.until {
        filter = filter.until(Timestamp::from_secs(until));
    }
    Ok(filter)
}

/// Resolve `--content` / `--content-file -` / `--content-file PATH`.
fn read_content(args: &PublishArgs) -> Result<String> {
    if let Some(inline) = &args.content {
        return Ok(inline.clone());
    }
    let Some(path) = &args.content_file else {
        bail!("either --content or --content-file must be provided");
    };
    if path.as_os_str() == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("read content from stdin")?;
        return Ok(buf);
    }
    std::fs::read_to_string(path).with_context(|| format!("read content file {}", path.display()))
}

/// Accept `nsec1...` or 64-char hex for the secret key.
fn parse_secret(raw: &str) -> Result<Keys> {
    if let Ok(sk) = SecretKey::from_bech32(raw) {
        return Ok(Keys::from_secret_key(sk));
    }
    if let Ok(sk) = SecretKey::parse(raw) {
        return Ok(Keys::from_secret_key(sk));
    }
    Err(anyhow!("secret must be nsec1... or 64-char hex"))
}

/// Accept `npub1...` or 64-char hex for an author public key.
fn parse_public_key(raw: &str) -> Result<PublicKey> {
    if let Ok(pk) = PublicKey::from_bech32(raw) {
        return Ok(pk);
    }
    PublicKey::parse(raw).map_err(Into::into)
}
