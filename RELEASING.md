# Releasing nula

This document is the runbook for cutting releases of every crate in
the workspace. The architectural rules behind it are recorded in
[ADR-0001](docs/adr/0001-workspace-architecture.md).

## Cadence and versioning

- The workspace ships **independently versioned crates** that share
  a common `workspace.package.version` value during the 0.x phase.
  After 1.0 we will move each crate to its own version line.
- We follow [Semantic Versioning](https://semver.org). During 0.x
  every minor bump may contain breaking changes (allowed by SemVer
  for `0.y.z` releases); we still document those in `CHANGELOG.md`
  as `BREAKING CHANGE:` entries.
- Patch releases are reserved for bug fixes and security
  advisories. They never carry public-API changes.

There is no fixed release cadence yet. We cut a release whenever an
upstream user reports a need or a security fix is ready.

## Release ordering

Crates are released **bottom-up** along the dependency DAG. Within
each layer the alphabetical order in the table from ADR-0001
applies. The published order is:

```text
Layer 1: nula-core
Layer 2: nula-net
Layer 3: nula-relay → nula-storage → nula-storage-memory → nula-storage-lmdb
Layer 4: nula-gossip → nula-relay-builder → nula-relay-pool → nula-signer-connect
Layer 5: nula-cli → nula-sdk
```

`nula-fuzz` is not published — it lives in the workspace but is
listed under `publish = false`.

If a release only touches a single crate, only that crate is
published. Workspace-wide releases bump every crate in lockstep.

## Pre-release checklist

Before any release PR:

- [ ] `main` is green on CI.
- [ ] `cargo test --workspace --all-features` passes locally.
- [ ] `cargo doc --workspace --no-deps` is warning-free.
- [ ] `cargo deny check` is clean.
- [ ] `cargo vet check` is clean (every new transitive dep has an
      audit row in `supply-chain/audits.toml`).
- [ ] The unreleased section of every affected `CHANGELOG.md` is
      fleshed out (no `TODO`, no empty `### Added`).
- [ ] Every public API change references the ADR that authorised it.
- [ ] If MSRV moved, `rust-toolchain.toml`,
      `workspace.package.rust-version`, the `msrv-check` job, and the
      `Supported versions` block of `SECURITY.md` are all updated in
      one PR.

## Release PR

1. Create a branch `release/<crate>-<version>` (workspace-wide
   releases use `release/workspace-<version>`).
2. Bump the version in `Cargo.toml` (workspace or per-crate). Use
   `cargo set-version` from
   [`cargo-edit`](https://github.com/killercup/cargo-edit) so the
   workspace dependency table stays in sync:

   ```bash
   cargo set-version --workspace 0.2.0
   ```

3. Rewrite each affected `CHANGELOG.md`: move the unreleased section
   under a new `## [<version>] — <YYYY-MM-DD>` heading, add a link
   reference at the bottom of the file, and start a fresh empty
   `## [Unreleased]` block.
4. Open the PR with a Conventional Commit subject
   (`chore(release): vX.Y.Z`). The PR description lists the crates
   being published.
5. Wait for CI green. Squash-merge.

## Tagging and publication

After the release PR lands on `main`:

1. Tag the merge commit:

   ```bash
   git tag -a vX.Y.Z -m "vX.Y.Z"
   git push origin vX.Y.Z
   ```

   Per-crate releases use `nula-core-vX.Y.Z` (etc.) as the tag name.

2. Publish in dependency order. Use the smoke-tested helper:

   ```bash
   cargo publish -p nula-core
   cargo publish -p nula-net
   # … continue in the layer order documented above
   ```

   If a single crate fails (network blip, version conflict),
   `cargo publish` is idempotent — re-run for that crate, then keep
   going.

3. Verify each published crate is visible at
   `https://crates.io/crates/<name>` before publishing the next
   layer. We publish layer by layer so a bad `nula-core` release
   does not strand the upper layers waiting on a yanked dependency.

4. Create a GitHub Release from the tag (`gh release create`). The
   body is the relevant CHANGELOG section, copy-pasted.

## Yank and hotfix policy

- A published version is yanked only when it contains a security
  vulnerability or a build-blocking bug. Yanking is announced in a
  GitHub Release update and in `CHANGELOG.md` under a `### Yanked`
  heading.
- Hotfixes branch from the affected release tag, not from `main`.
  After publishing the patched version, the fix is forward-ported
  to `main` in a follow-up PR.

## Post-release housekeeping

After the release is live:

- Update `docs/adr/0001-workspace-architecture.md`'s status table if
  any ADR moved to `Superseded`.
- Close milestone, open the next one.
- Refresh `Cargo.lock` on `main` with the published versions so
  CI's `--locked` test runs against what users will install.

## Release automation

There is currently no `cargo-release` or `release-plz`
configuration; releases are manual. We will revisit automation once
the workspace stabilises (target: post-1.0).
