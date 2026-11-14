# agentscrub

**Local-first Rust CLI** that discovers, scans, and redacts **secrets and PII** in AI agent session transcripts — offline, no accounts, no telemetry.

> **Status:** **v0.1.0** private until pre-public GO. CI green on Linux/macOS/Windows. Cursor rewrite is read-only; retention deletion is flagged off.

## Problem

Agent transcripts (Claude Code, Codex, Cursor, and generic JSONL) often store API keys, cloud credentials, and PII in plain text on disk. agentscrub finds them locally and can rewrite supported formats safely (dry-run by default).

## Install

```bash
git clone https://github.com/JarvisOsorio/agent-session-scrubber.git
cd agent-session-scrubber
cargo install --path .
# or: cargo build --release && ./target/release/agentscrub --help
```

Requires Rust **1.89+**. Not on crates.io / Homebrew yet.

## Three commands that work (fixtures)

Copy fixtures first — never scrub the originals in-tree during experiments:

```bash
mkdir -p /tmp/agentscrub-demo/.claude
cp tests/fixtures/claude/session_secrets.jsonl /tmp/agentscrub-demo/.claude/

# 1) Find sessions
agentscrub discover --path /tmp/agentscrub-demo

# 2) Scan (masked values + fingerprints only — no raw secrets in output)
agentscrub scan --path /tmp/agentscrub-demo --format terminal

# 3) Dry-run → confirm scrub → verify clean
agentscrub scrub --path /tmp/agentscrub-demo/.claude/session_secrets.jsonl
agentscrub scrub --path /tmp/agentscrub-demo/.claude/session_secrets.jsonl --confirm
agentscrub verify /tmp/agentscrub-demo/.claude/session_secrets.jsonl --format json
# expect: clean=true, remaining_findings=0, exit 0
```

Against your own agent homes (defaults also look under `~/.claude`, Codex/Cursor roots when configured):

```bash
agentscrub discover
agentscrub scan --path ~/.claude --format json --output report.json
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

`0` ok · `1` general · `2` bad args · `3` unsupported · `4` permission · `5` validation / unclean verify · `6` remediation · `7` policy · `8` incomplete scan

Incomplete ≠ clean. Unclean `verify` exits `5`.

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
| `cursor` | ✓ | ✗ | JSONL + SQLite `state.vscdb` **scan only** — rewrite intentionally disabled |
| `generic_jsonl` | ✓ | ✓ | Configurable text fields |
| `generic_json` | ✓ | ✓ | Single JSON documents |

Unsupported / malformed files are **skipped and reported**, never silently modified.

### Known limitations (do not overclaim)

- **Cursor:** discovery + scan work; **redaction/rewrite is refused** until SQLite/transcript mutation is proven safe.
- **Retention:** `retention plan` / `status` are read-only. **`retention.enabled = false` by default**; `retention apply` refuses deletion while the flag is off.
- **Not** a credential revocation service — rotate secrets at the provider after a finding.
- **Not** on crates.io or Homebrew yet — install from this GitHub repo.

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

| Job | Platforms |
|-----|-----------|
| `test` | Ubuntu, macOS, Windows (`cargo test`) |
| `fmt` / `clippy` | Ubuntu only |
| `build` (release) | `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc` |
| `audit` | Ubuntu — **blocking** `cargo audit --deny warnings` |

## License

Apache-2.0 © Jarvis Osorio
