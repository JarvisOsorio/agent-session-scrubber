# Changelog

## 0.1.0 — working scanner

- Clap CLI: `discover`, `scan`, `report`, `scrub`, `verify`, `retention`, `config`
- Adapters: Claude Code, Codex, Cursor (read-only rewrite), generic JSONL, generic JSON
- ≥20 secret detectors + initial PII (email, phone, IP, Luhn credit cards)
- Masked findings + HMAC fingerprints; terminal/JSON/Markdown reports
- Dry-run redaction default; `--confirm` atomic rewrite with lock + hash recheck
- Verification + sanitized receipts
- Retention status/plan stubs; deletion refused while `retention.enabled = false`
- Apache-2.0, SECURITY, privacy/threat/redaction docs, CI workflow
