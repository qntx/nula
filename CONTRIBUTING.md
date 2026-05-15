# Contributing to nula

Thanks for the interest. This document is the single source of
truth for how patches land in the `nula` workspace. The
architectural rationale behind these rules lives in `docs/adr/`;
read at least ADR-0001 before opening a non-trivial PR.

## Table of contents

- [Local setup](#local-setup)
- [Branching model](#branching-model)
- [Commit messages](#commit-messages)
- [Pull-request checklist](#pull-request-checklist)
- [Code style](#code-style)
- [Adding or modifying an ADR](#adding-or-modifying-an-adr)
- [Reporting bugs and security issues](#reporting-bugs-and-security-issues)

## Local setup

The workspace requires a single Rust toolchain — `1.94` — pinned in
`rust-toolchain.toml`. `rustup` picks it up automatically. The MSRV
is also `1.94`; never use a feature that needs anything newer
without first updating `workspace.package.rust-version` in
`Cargo.toml` and the `msrv-check` job in `.github/workflows/ci.yml`.

The `3rdparty/nostr/` directory is a developer-local reference
checkout, **not** a submodule. After cloning the workspace, fetch
the pinned upstream SHA documented in
[ADR-0002](docs/adr/0002-rust-nostr-reference-sync.md):

```bash
mkdir -p 3rdparty
git clone https://github.com/rust-nostr/nostr 3rdparty/nostr
git -C 3rdparty/nostr checkout d8675eabf7067cd0c685292e68c0883169ca6b93
```

That SHA is the source of truth. The CI does not depend on the
checkout — `cargo check --workspace --all-features` builds without
it — but most porting work consults it side-by-side.

The `Makefile` carries the everyday commands:

```bash
make fmt          # rustfmt (nightly)
make clippy       # clippy --workspace --all-targets --all-features -- -D warnings
make test         # cargo test --workspace --all-features
make doc          # cargo doc --workspace --no-deps
```

## Branching model

We use a trunk-based model. `main` is always green and is the only
long-lived branch.

- Feature branches: `feat/<scope>-<short-name>` (e.g.
  `feat/nula-net-websocket-trait`).
- Bug-fix branches: `fix/<scope>-<short-name>`.
- Documentation-only branches: `docs/<short-name>`.
- ADR drafts: `adr/<NNNN>-<short-slug>`.

Open the PR against `main` once CI is green locally. Force-pushes on
the feature branch are fine; force-pushes on `main` are not.

Squash-merging is the default — a single Conventional Commit message
goes onto `main`. Use "merge commit" only when the PR genuinely
needs to preserve a sequence of commits (e.g. a port from
`rust-nostr` that we want to attribute commit-by-commit).

## Commit messages

We follow [Conventional Commits](https://www.conventionalcommits.org)
**strictly**. Subjects are imperative, ≤ 50 chars, no trailing
period. The full body wraps at 72 chars. Subjects and bodies are
written in **English** — no Chinese in the commit message.

Allowed types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`,
`test`, `chore`, `revert`, `ci`, `build`. Examples:

```text
feat(nula-net): introduce runtime-agnostic WebSocket trait
fix(nula-core): correct NIP-44 padding for boundary inputs
docs(adr): record async runtime layering decision
refactor(nula-storage): extract NostrDatabaseExt to its own module
```

Breaking changes carry a footer:

```text
feat(nula-core)!: rename Event::tags() to Event::tag_list()

BREAKING CHANGE: callers must rename Event::tags() to
Event::tag_list(); the old accessor returned a slice and the new
one returns the strongly-typed Tags wrapper.
```

## Pull-request checklist

Before requesting review:

- [ ] `make fmt` produces no diff.
- [ ] `make clippy` is clean (`-D warnings`).
- [ ] `cargo test --workspace --all-features` passes locally.
- [ ] `cargo doc --workspace --no-deps` is warning-free.
- [ ] New public APIs carry rustdoc with at least one runnable
      example (`cargo test --doc` will exercise it).
- [ ] New error variants are `#[non_exhaustive]` and follow the
      template in [ADR-0004](docs/adr/0004-error-handling-thiserror.md).
- [ ] New `tracing` spans use field names from
      [ADR-0005](docs/adr/0005-observability-tracing-fields.md). No
      secret material in any field.
- [ ] CHANGELOG entry added under the unreleased section in the
      affected crate (use the format already present in
      `CHANGELOG.md`).
- [ ] PR description references the ADR(s) the change implements
      or amends.

CI replays the same checks plus the full matrix
(`x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`,
`x86_64-pc-windows-msvc`, optionally `wasm32-unknown-unknown`).

## Code style

We rely on tooling rather than prose:

- `rustfmt.toml` pins formatting (run with the nightly toolchain so
  `group_imports = "StdExternalCrate"` is honoured).
- `clippy.toml` pins lint thresholds and disallowed APIs (notably
  `std::env::set_var`, `std::mem::transmute`, `std::thread::sleep` in
  async contexts).
- Workspace-level lint groups live in `Cargo.toml` under
  `[workspace.lints]`. `pedantic` and `nursery` are warn-only;
  `correctness` and `suspicious` are deny.
- `#[forbid(unsafe_code)]` in every crate. Exceptions require an
  ADR.
- No comments of the form `// ── Section heading ──`. Use proper
  doc comments or descriptive function names. This rule is
  enforced by review, not tooling — see the global guidance in the
  workspace memory.

Imports are grouped `std → external → crate` and reordered by
`rustfmt`. Hand-written grouping is fine as long as it survives
`make fmt`.

## Adding or modifying an ADR

`docs/adr/README.md` describes the format. The short version:

1. Pick the next free four-digit number.
2. Copy an existing ADR as a template; do not reuse a superseded
   one's body.
3. Open the PR with a `docs(adr): record decision …` commit. Land
   the ADR in the same PR as the implementation when feasible.
4. If the new ADR supersedes an older one, update the older one's
   `Status` to `Superseded by NNNN` in the same PR.

## Reporting bugs and security issues

Functional bugs go to GitHub Issues. Use the templates in
`.github/ISSUE_TEMPLATE/` (added in Phase 1).

Security issues are reported privately. See
[`SECURITY.md`](SECURITY.md) for the disclosure procedure.
