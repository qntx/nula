# Security policy

## Supported versions

`nula` is pre-1.0. Until we cut the first stable release, **only the
`main` branch and the most recent point release of each `nula-*`
crate on crates.io receive security fixes**. Older point releases
will not be patched; consumers should upgrade.

Once we ship `1.0`, this section will be replaced by the standard
"latest minor + one back" table that mirrors what most ecosystem
projects use.

## Reporting a vulnerability

If you discover a vulnerability — anything that lets an attacker
forge events, leak `SecretKey` material, bypass the NIP-44 padding
or HMAC, derive keys from chosen plaintexts, or coerce the
`nula-relay` / `nula-storage-lmdb` layers into unsafe states —
please **do not** open a public issue.

The disclosure channel is:

1. Use the GitHub "Report a vulnerability" link on
   <https://github.com/qntx/nula/security> (preferred). This opens a
   private advisory thread with the maintainers.
2. Or email **<security@qntx.fun>** with the subject prefix
   `[nula-security]` and as much of the following as you can put
   together:
   - The affected crate(s) and version(s) (or commit SHA from
     `main`).
   - A minimal reproducer or proof-of-concept payload. For
     cryptographic issues, a single failing test vector is enough.
   - The impact you observed and your assessment of the worst-case
     impact.
   - Any mitigations the user can apply while a fix is pending.

We aim to acknowledge new reports within **3 business days** and
publish a CVE-tagged advisory plus patched crate within **30 days**
of confirmation. Coordinated-disclosure timelines beyond 30 days are
negotiated case by case.

## Scope

In scope:

- Every crate in `crates/` (the published `nula-*` crates).
- The CI pipeline definitions in `.github/workflows/` if a flaw
  there could land malicious code on `main`.
- Build-time dependencies pulled in by the workspace `Cargo.toml`
  (we mediate those through `cargo-deny` and `cargo-vet`).

Out of scope:

- The `3rdparty/nostr/` reference checkout — it is not part of our
  shipping artefact; report findings to the upstream `rust-nostr`
  project instead.
- Vulnerabilities in third-party relays or signers that happen to
  interoperate with `nula`. We will document workarounds but the
  fix belongs upstream.

## Handling of secrets in reports

Please do not include real production private keys or NIP-44
ciphertexts in reports. If a reproducer requires keys, generate
fresh ones with `Keys::generate()` and include them inline; we
treat any private key embedded in an advisory as compromised on
publication.

## Public advisories

Once a fix is released we publish:

- A GitHub Security Advisory with the affected versions, CVSS
  vector, and credit (or "anonymous" at the reporter's request).
- A `RUSTSEC-…` entry in <https://rustsec.org/> for any crate that
  reached crates.io.
- An entry in the affected crate's `CHANGELOG.md` under a
  `### Security` heading.

Patched crates are released as minor or patch bumps, never as
silent re-publishes of an existing version.

## Hall of thanks

Reporters who agree to be named will be listed in
`docs/security-credits.md` (added at first disclosure). Anonymous
reports are equally welcome.
