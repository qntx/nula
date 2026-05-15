# ADR-0002: `rust-nostr` reference vendoring & sync convention

**Status**: Accepted
**Date**: 2026-05-14

## Context

The workspace was born as a hard fork of [`rust-nostr/nostr`](https://github.com/rust-nostr/nostr).
We keep a full read-only checkout of the upstream repository at
`3rdparty/nostr/` for three operational reasons:

1. **API diffing** — when we lift a module (e.g. `database/`, `gossip/`,
   `sdk/transport/`) into a `nula-*` crate, we need to see the original
   source side-by-side with the port to verify nothing semantically
   meaningful is lost.
2. **NIP reference tests** — upstream maintains a corpus of NIP test
   vectors (most notably the `nip44_vectors.rs` JSON corpus) that we
   re-use verbatim. Vendoring them avoids drift between our test
   fixtures and the spec authors'.
3. **Future merge rebasing** — if `rust-nostr` lands a NIP we have not
   yet ported, having the checkout in-tree lets `git diff --no-index`
   against our port and cherry-pick patches cleanly.

The checkout is **not** intended to be:

- a git submodule (operationally noisy, blocks `cargo publish` for
  workspace consumers, requires CI fetch tokens for private mirrors);
- a `git subtree` (commits would pollute our history and hide the
  upstream provenance);
- a Cargo `path = "../3rdparty/nostr"` dependency (we have already
  diverged on `no_std`, `thiserror` adoption, and NIP coverage; the
  bidirectional ABI cost is prohibitive).

The current state on disk is:

- `3rdparty/` is listed in the top-level `.gitignore`, so the
  upstream checkout is **not** tracked by our repository.
- The checkout is an independent clone with its own `.git/` working
  tree. Each developer fetches it manually after `git clone`.
- There is no `.gitmodules` file.

## Decision

`3rdparty/nostr/` remains a **developer-local untracked clone** of
the upstream repository. We do **not** convert it to a submodule.

The synchronisation contract is:

- **Pinned reference SHA**: `d8675eabf7067cd0c685292e68c0883169ca6b93`
  (rust-nostr@master, 2026-05-08, "nostr: update `UnsignedEvent::mine`
  and `UnsignedEvent::mine_async` to take adapter reference").
- **Bump cadence**: When a maintainer wants to consult or re-port from
  a newer upstream commit, they bump the SHA in this ADR (status moves
  to `Superseded by NNNN` if the bump is large enough to merit a new
  decision) and run `git -C 3rdparty/nostr fetch && git -C 3rdparty/nostr checkout <sha>`.
- **CI invariants**: CI builds `nula-*` crates only. The reference
  checkout is never compiled, linted, fuzzed, or tested by our CI. CI
  jobs that need NIP-44 / NIP-19 vectors copy them into
  `crates/nula-core/tests/vectors/` at port time.
- **License attribution**: Every file in `crates/nula-*` ported from
  the reference checkout carries a `// Lifted from rust-nostr at
  <SHA>:<path>` comment on the first non-doc line. The original
  authors retain authorship of those lines under the MIT license; our
  workspace `LICENSE-MIT` covers our additions.

### Setup steps for new contributors

The `CONTRIBUTING.md` file references this section. The canonical
incantation is:

```bash
mkdir -p 3rdparty
git clone https://github.com/rust-nostr/nostr 3rdparty/nostr
git -C 3rdparty/nostr checkout d8675eabf7067cd0c685292e68c0883169ca6b93
```

The exact SHA above is the source of truth — `CONTRIBUTING.md` only
quotes it; this ADR owns it.

## Consequences

### Positive

- No CI hidden state. A fresh `git clone qntx/nula` is sufficient to
  build, test, lint, and release the workspace.
- The reference checkout never appears in `cargo metadata`,
  `cargo doc`, or in `cargo deny check` output, so we do not inherit
  upstream's `multiple-versions` warnings.
- Bumping the reference SHA is a doc-only change (an ADR amendment).
  It cannot accidentally break our build.

### Negative

- New contributors must run the clone step manually after cloning the
  workspace; this is documented in `CONTRIBUTING.md` but is one extra
  step compared to a submodule.
- Reproducing a port-PR review requires the reviewer to be on the
  same SHA as the porter. The PR description must quote the SHA being
  diffed against, and the reviewer must `git -C 3rdparty/nostr checkout`
  that SHA locally.
- We give up the optional flow of running `cargo test` inside the
  reference checkout from our CI. This is acceptable: that corpus is
  upstream's responsibility, not ours.

### Rollback

If the manual-clone friction becomes a problem (e.g. we onboard many
new contributors), we can flip to a submodule by:

1. `git submodule add https://github.com/rust-nostr/nostr 3rdparty/nostr`
2. Removing `3rdparty/` from `.gitignore`.
3. Replacing this ADR with one titled
   `0002-rust-nostr-submodule-pin.md` and marking this file as
   `Superseded by 0006`.

## References

- ADR-0001 — Workspace architecture.
- [rust-nostr README](https://github.com/rust-nostr/nostr/blob/master/README.md).
- [Pinned upstream commit](https://github.com/rust-nostr/nostr/commit/d8675eabf7067cd0c685292e68c0883169ca6b93).
