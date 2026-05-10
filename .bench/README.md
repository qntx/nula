# Benchmark baselines

Phase 1 keeps a per-iteration markdown snapshot of the criterion run
under `.bench/baseline-<wN>.md` so we can track how the hot paths
evolve while the diff lives across many commits.

The full criterion artefacts (per-target plots, raw samples) live under
`target/criterion/`; that directory is `target/`-scoped and therefore
gitignored. The markdown snapshots in this directory **are** committed
because they are tiny and reviewable.

To save a new baseline:

```bash
cargo bench -p nula-core -- --save-baseline <label>
```

Then summarise the run by appending a new file in this directory.

To compare a working tree against a saved baseline:

```bash
cargo bench -p nula-core -- --baseline <label>
```

Phase 1 release-bench gate: any run flagged ">5% regression" by
criterion against the `w1` baseline must either be justified in the
commit message or fixed before merging.
