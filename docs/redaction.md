# Redaction

## Modes

- **Mask (default):** replace matched spans with `[REDACTED:CATEGORY]`
- Dry-run is the CLI default; nothing is written without `--confirm`

## Pipeline

1. Parse with a format-identified adapter
2. Detect secrets/PII → findings with offsets, masks, fingerprints
3. `scrub` plans rewrites; dry-run emits receipts without touching files
4. `--confirm` locks file, rechecks content hash, writes tempfile, atomically replaces
5. `verify` re-parses and re-scans; checks JSON/JSONL structure validity

## Safety rules

- Adapters declare capabilities; CLI refuses unsupported rewrite
- Cursor rewrite is **disabled** in v0.1 (scan-only)
- Structure validation must pass or write is refused
- Backups optional but on by default (`--no-backup` to disable)

## Receipts

Sanitized receipts include paths, hashes, redaction counts, fingerprints — never raw secrets.
