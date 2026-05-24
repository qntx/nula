# nula-cli

Command-line interface for the [`nula`](https://github.com/qntx/nula)
workspace. Wraps `nula-sdk` and `nula-relay-builder` into a single
`nula` binary with four subcommand groups:

| Group   | Subcommand      | Purpose                                               |
| ------- | --------------- | ----------------------------------------------------- |
| `keys`  | `generate`      | Generate a Nostr keypair, print `nsec` / `npub` / hex |
| `keys`  | `parse <INPUT>` | Convert any of `nsec` / `npub` / hex into all forms   |
| `relay` | `run`           | Start an in-process relay (`MockRelayBuilder`)        |
| `event` | `publish`       | Sign a text note and publish to one or more relays    |
| `event` | `fetch`         | One-shot `REQ` fetch with NIP-01 filter knobs         |

## Install

```bash
cargo install --path crates/nula-cli
```

## Usage

```bash
# Fresh keypair (always JSON; suitable for shell-piping)
nula keys generate

# Inspect any key
nula keys parse nsec1...
nula keys parse npub1...
nula keys parse 0000000000000000000000000000000000000000000000000000000000000003

# Spin up a local relay (Ctrl-C to stop)
nula relay run --bind 127.0.0.1:7777

# Publish a text note
NULA_SECRET=nsec1... nula event publish \
    --relay ws://127.0.0.1:7777 \
    --content "hello, nostr"

# Fetch latest 10 text notes from an author
nula event fetch \
    --relay ws://127.0.0.1:7777 \
    --author npub1... \
    --kind 1 \
    --limit 10
```

## Output

Every subcommand emits a single JSON object on `stdout` so output
can be piped into `jq` or any downstream tool. Logs go to `stderr`
under the `RUST_LOG` env var (default `info`).

## Exit codes

- `0` on success.
- `1` on user error (bad input, missing flag, parse failure).
- `2` on relay / network error (every relay rejected the request).
