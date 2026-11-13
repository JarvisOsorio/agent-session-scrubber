# agentscrub

**Local-first Rust CLI** that discovers, scans, classifies, and redacts **secrets and PII** in AI agent session transcripts — without cloud, accounts, telemetry, or network calls during scan/scrub.

> **Status:** v0.1.0 working scanner. Private repo until coordinator confirms acceptance. Not production-ready marketing until CI + acceptance targets are green and reviewed.

## Why agentscrub

Peers often race on agent count or optional live key verification. agentscrub optimizes for **depth and safety**:

- Verified adapters for **Claude Code**, **Codex**, **Cursor** (read-only rewrite until proven), and **generic JSONL/JSON**
- **Secrets + initial PII** with severity, confidence, masking, and HMAC fingerprints (no raw secrets in reports)
- **Dry-run → `--confirm` → atomic rewrite → verify → sanitized receipts**
- **Retention architecture** present but **`retention.enabled = false`** (deletion refused)
- Offline by default · Apache-2.0 · single native binary

## Install (from source)

```bash
cargo install --path .
# or
cargo build --release
./target/release/agentscrub --help
```

Requires Rust **1.89+**.

## Quick start

```bash
# Discover session files under configured roots or explicit paths
agentscrub discover --path ./tests/fixtures

# Scan for secrets + PII (terminal or JSON)
agentscrub scan --path ./tests/fixtures/claude --format terminal
agentscrub scan --path ./tests/fixtures --format json --output report.json

# Dry-run redaction (default)
agentscrub scrub --path ./tests/fixtures/claude/.keep-or-copy-first

# Apply redaction only with explicit confirm
agentscrub scrub --path /path/to/session.jsonl --confirm

# Verify structure / remaining findings
agentscrub verify /path/to/session.jsonl

# Retention (plan/status only while flagged off)
agentscrub retention status
agentscrub retention plan --path /path/to/sessions
```

## Commands

| Command | Purpose |
|---------|---------|
| `discover` | List recognized session files |
| `scan` | Detect secrets/PII; exit `8` if scan incomplete |
| `report` | Re-render a saved JSON report (or re-scan) |
| `scrub` | Dry-run redaction by default; `--confirm` to write |
| `verify` | Post-remediation check |
| `retention` | `status` / `plan` / `apply` / `verify` (apply refuses while flag off) |
| `config` | Show effective config |

### Exit codes

`0` ok · `1` general · `2` bad args · `3` unsupported · `4` permission · `5` validation · `6` remediation · `7` policy · `8` incomplete scan

Incomplete ≠ clean.

## Configuration

See [`config/default.toml`](config/default.toml). Key defaults:

- `retention.enabled = false`
- `detection.enable_pii = true`
- dry-run scrub unless `--confirm`
- local HMAC fingerprint key (never transmitted)

## Adapters (v0.1)

| Adapter | Read | Redact | Notes |
|---------|------|--------|-------|
| `claude_code` | ✓ | ✓ | JSONL sessions |
| `codex` | ✓ | ✓ | JSONL sessions |
| `cursor` | ✓ | ✗ | JSONL + SQLite `state.vscdb` scan; rewrite gated read-only |
| `generic_jsonl` | ✓ | ✓ | Configurable text fields |
| `generic_json` | ✓ | ✓ | Single JSON documents |

Unsupported / malformed files are **skipped and reported**, never silently modified.

## Security posture

- Local-only; no telemetry; no network for scan/scrub/verify
- Never logs raw secrets; reports use masked values + fingerprints
- Atomic same-filesystem replace + exclusive lock + pre-write hash recheck
- Symlink targets refused for modification
- Redaction does **not** erase backups, snapshots, or provider-side copies — rotate leaked credentials at the issuer

## Docs

- [SECURITY.md](SECURITY.md)
- [docs/privacy.md](docs/privacy.md)
- [docs/threat-model.md](docs/threat-model.md)
- [docs/redaction.md](docs/redaction.md)

## Development

```bash
cargo fmt
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo audit --deny warnings
```

Fixtures under `tests/fixtures/` are **synthetic only** — never real credentials or customer transcripts.

### CI matrix

GitHub Actions runs:

| Job | Platforms |
|-----|-----------|
| `test` | Ubuntu, macOS, Windows (`cargo test`) |
| `fmt` / `clippy` | Ubuntu only |
| `build` (release) | `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc` |
| `audit` | Ubuntu — **blocking** `cargo audit --deny warnings` |

Linux x86_64 is required. macOS/Windows are included in Actions; native cross-compile outside those runners is not claimed.

## License

Apache-2.0 © Jarvis Osorio
