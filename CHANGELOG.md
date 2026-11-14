# Changelog

## 0.1.0 — working scanner

- Clap CLI: `discover`, `scan`, `report`, `scrub`, `verify`, `retention`, `config`
- Adapters: Claude Code, Codex, Cursor (read-only rewrite), generic JSONL, generic JSON
- ≥20 secret detectors + initial PII (email, phone, IP, Luhn credit cards)
- Masked findings + HMAC fingerprints; terminal/JSON/Markdown reports
- Dry-run redaction default; `--confirm` atomic rewrite with lock + hash recheck
- Verification + sanitized receipts
- Retention status/plan; deletion refused while `retention.enabled = false`
- Apache-2.0, SECURITY, privacy/threat/redaction docs, CI workflow

### Harden (same 0.1.0 line)

- Detection corpora ≥100 secrets / ≥100 PII / ≥100 benign with recall/precision asserts
- Redaction safety tests: structure preserve, invalid rewrite refuses write, hash TOCTOU
- Retention planner: uncertain mtime → KEEP; CLI plan read-only; apply gate tests
- CI: Ubuntu/macOS/Windows test + multi-OS release builds; blocking `cargo audit`
- Bump `rusqlite` to 0.42 (patched `libsqlite3-sys`) for RUSTSEC-2026-0459

