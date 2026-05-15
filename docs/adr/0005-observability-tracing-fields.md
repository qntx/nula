# ADR-0005: Observability field conventions for `tracing`

**Status**: Accepted
**Date**: 2026-05-14

## Context

Every layer in the workspace will emit `tracing` spans on hot paths
(event signing, verification, relay I/O, storage queries, NIP-46
round-trips, gossip routing). Subscribers ingest those spans into
production pipelines — most commonly Grafana Loki/Tempo, Honeycomb,
or OpenTelemetry collectors — where dashboard queries reference span
field names directly.

Without a workspace-wide convention, every crate would invent its
own names: `kind`, `event_kind`, `nostr_kind`, `nostr.kind`,
`nostr.event_kind`. The cost of that drift is real:

- `Grafana` queries written against `nula-core` spans break when
  upper layers emit semantically equivalent fields with different
  names.
- Span attribute cardinality balloons when the same logical field
  appears under multiple keys.
- Log redaction rules (no secrets!) must be re-derived per crate
  rather than inherited from a single allow-list.

`crates/nula-core/src/observe.rs` already pins a small catalogue of
field constants (`FIELD_EVENT_KIND`, `FIELD_PUBKEY_SHORT`,
`FIELD_NIP`, …) for the protocol-core spans. This ADR promotes that
catalogue to a workspace-wide invariant and extends it to cover the
transport, storage, and pool layers we have not yet built.

## Decision

All `#[tracing::instrument(...)]` annotations in the workspace use
field names drawn from the **`nula-core::observe` constants module**
(re-exported by every dependent crate). Field name shape is
`nostr.<subject>.<attribute>`. The dot is preserved in JSON
subscribers (Tempo, OpenTelemetry) and rewritten to `_` by the
default `fmt` subscriber; both are acceptable.

### Field catalogue (canonical)

|              Constant            | Field name                          | Owner crate          | Meaning                                                                          |
| -------------------------------- | ----------------------------------- | -------------------- | -------------------------------------------------------------------------------- |
| `FIELD_EVENT_KIND`               | `nostr.event.kind`                  | `nula-core`          | Event kind as `u16`.                                                             |
| `FIELD_EVENT_CONTENT_SIZE`       | `nostr.event.content_size`          | `nula-core`          | Byte length of the event `content` post-encoding.                                |
| `FIELD_EVENT_TAG_COUNT`          | `nostr.event.tag_count`             | `nula-core`          | Number of top-level tags.                                                        |
| `FIELD_EVENT_ID`                 | `nostr.event.id`                    | `nula-core`          | 64-char lowercase hex event id (only after compute).                             |
| `FIELD_PUBKEY_SHORT`             | `nostr.pubkey.short`                | `nula-core`          | First 8 hex chars of pubkey. Never the secret key.                               |
| `FIELD_NIP`                      | `nostr.nip`                         | `nula-core`          | Spec number most directly exercised (e.g. `44`).                                 |
| `FIELD_PLAINTEXT_SIZE`           | `nostr.encryption.plaintext_size`   | `nula-core`          | Byte length of NIP-04 / NIP-44 plaintext.                                        |
| `FIELD_CIPHERTEXT_SIZE`          | `nostr.encryption.ciphertext_size`  | `nula-core`          | Byte length of ciphertext.                                                       |
| `FIELD_BECH32_HRP`               | `nostr.bech32.hrp`                  | `nula-core`          | HRP of the bech32 string being processed.                                        |
| `FIELD_RELAY_URL`                | `nostr.relay.url`                   | `nula-net`           | Sanitised relay URL (no userinfo, no query).                                     |
| `FIELD_RELAY_STATUS`             | `nostr.relay.status`                | `nula-relay`         | Connection state: `idle`, `connecting`, `connected`, `closed`, `terminated`.     |
| `FIELD_SUBSCRIPTION_ID`          | `nostr.subscription.id`             | `nula-relay-pool`    | Subscription identifier as opaque string (truncated at 32 chars).                |
| `FIELD_STORAGE_BACKEND`          | `nostr.storage.backend`             | `nula-storage`       | `memory`, `lmdb`, …                                                              |
| `FIELD_GOSSIP_HINT_COUNT`        | `nostr.gossip.hint_count`           | `nula-gossip`        | Number of relay hints in NIP-65 graph for the target pubkey.                     |

Crates beyond `nula-core` add new constants to a per-crate `observe`
module and import the protocol-level constants from
`nula_core::observe`. The owner column lists the crate that defines
the constant; no two crates may define the same field name.

### Redaction rule

The following values **MUST NEVER** appear on a span, in any field:

- `nula_core::SecretKey` bytes or their hex/bech32 forms.
- NIP-44 / NIP-04 plaintext bytes.
- NIP-44 `ConversationKey` material.
- NIP-49 password bytes.
- NIP-46 secret tokens.
- Raw socket buffers from `nula-net`.

Every `#[tracing::instrument]` that touches secret material **must**
pass that parameter through `skip(...)`. We enforce this two ways:

1. A clippy lint `disallowed_methods` in `clippy.toml` (already in
   place for `std::env::set_var` etc.) bans direct interpolation of
   `SecretKey` into `tracing` macros once we land the
   corresponding helper.
2. Code review checklist (see `CONTRIBUTING.md`).

### Span level conventions

| Layer                     | Default level | Notes                                                                                                  |
| ------------------------- | ------------- | ------------------------------------------------------------------------------------------------------ |
| `nula-core` cryptography  | `debug`       | Costs in tight inner loops; `trace` for byte-level diagnostics.                                        |
| `nula-net` transport      | `info`        | One span per connection lifecycle, `debug` per frame.                                                  |
| `nula-relay`              | `info`        | One span per `REQ` / `EVENT` exchange.                                                                 |
| `nula-storage`            | `debug`       | `info` for migrations, schema upgrades.                                                                |
| `nula-relay-pool`         | `info`        | One span per pool-level subscription, `debug` per relay fan-out.                                       |
| `nula-gossip`             | `debug`       | `info` for the snapshot publish / rotation events.                                                     |
| `nula-signer-connect`     | `info`        | One span per RPC, `error!` on rejected requests.                                                       |
| `nula-sdk` / `nula-cli`   | `info`        | High-level user actions; never deeper than `debug`.                                                    |

`tracing` is feature-gated in every library crate (`features =
["tracing"]`). Disabling the feature compiles every span to a no-op
so consumers that don't integrate a subscriber pay zero overhead.

## Consequences

### Positive

- A single Grafana / Tempo query keyed on `nostr.event.kind` or
  `nostr.relay.url` works for spans emitted by any layer.
- New crates start by importing the constants module; they cannot
  drift accidentally because the field-name string is owned by
  `nula-core`.
- The secret-redaction policy is enforceable by reading `observe.rs`
  alone.

### Negative

- Whenever a layer needs a new field, it must add the constant
  (and update this ADR) before it can emit. We treat that as a
  feature, not a bug: each new field is a deliberate decision about
  what to expose in dashboards.
- The constants module grows in lockstep with the workspace. We will
  split it per-crate (with the owner column) before it exceeds ~200
  lines; until then a single file is the simplest mapping.

### Rollback

If we ever want to switch instrumentation libraries (e.g. to
`opentelemetry-otlp`'s native API), the constants module is the
single migration target. Replacing the inner `&str` constants with
OTel `Key` values would be a mechanical refactor.

## References

- ADR-0001 — Workspace architecture.
- ADR-0004 — Error handling via `thiserror`.
- `crates/nula-core/src/observe.rs` — current canonical implementation.
- [`tracing`](https://docs.rs/tracing/latest/tracing/).
- [OpenTelemetry semantic conventions](https://opentelemetry.io/docs/specs/semconv/).
