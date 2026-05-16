# Architecture Decision Records

This directory captures the architectural decisions that shape the
`nula` workspace. The format follows [Michael Nygard's original ADR
template](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions),
trimmed to the four sections that actually carry information across
revisions:

1. **Context** — what forces are at play, what we know about the
   surrounding code, what we are deliberately not deciding.
2. **Decision** — the chosen direction, stated as a single sentence
   followed by the implementation contract (file paths, crate names,
   feature flags, MSRV implications).
3. **Consequences** — both the positive and the negative ones. Be
   explicit about what becomes harder, what tests must guard the
   invariant, and what the rollback path looks like.
4. **References** — links to upstream RFCs, prior art, related ADRs,
   issue threads, and benchmark data. No bare URLs in the prose; put
   them here so the body stays scannable.

## Lifecycle

- An ADR is **proposed** in a pull request that touches the affected
  code. The ADR file itself is part of that PR.
- It becomes **accepted** when the PR merges. Status is recorded at
  the top of the file.
- It is **superseded** by another ADR that points back to it in its
  `References` section. The original file is never deleted; instead
  its status changes to `Superseded by NNNN`.

## Numbering

ADRs are numbered with a four-digit zero-padded counter (`NNNN`) so
that lexical sort matches creation order. New entries pick the next
free number. Reserved numbers (e.g. for an in-flight draft) are
allowed but should be claimed in a PR within two weeks or recycled.

## Current Records

|    # | Title                                              | Status   |
| ---- | -------------------------------------------------- | -------- |
| 0001 | Workspace architecture (13-crate plan)             | Accepted |
| 0002 | `rust-nostr` reference vendoring & sync convention | Accepted |
| 0003 | Async runtime layering strategy                    | Accepted |
| 0004 | Error handling via `thiserror`                     | Accepted |
| 0005 | Observability field conventions for `tracing`      | Accepted |
| 0006 | Single relay actor model                           | Accepted |
| 0007 | Layer-3 storage architecture                       | Accepted |
