# Contributing

## Principles

1. Correctness and safety before coverage
2. Prefer refusing an unsafe rewrite over shipping a partial adapter as “done”
3. Synthetic fixtures only — never real credentials or customer transcripts
4. Keep scan/scrub/verify offline

## Dev loop

```bash
cargo fmt
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

## Adding a detector

1. Add a rule in `src/detectors/secrets.rs` or `pii.rs`
2. Extend corpus tests (positive + benign lookalikes)
3. Ensure reports still never emit raw values

## Adding an adapter

1. Implement `SourceAdapter` with honest `capabilities`
2. Add versioned fixtures under `tests/fixtures/<adapter>/`
3. If rewrite is unproven, set `redaction: false` and keep scan-only
