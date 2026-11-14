# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes |

## Reporting a vulnerability

Prefer a [GitHub private security advisory](https://github.com/JarvisOsorio/agent-session-scrubber/security/advisories/new) on this repository, or contact via [jarvisosorio.com](https://jarvisosorio.com).

Please include:

- agentscrub version / commit
- OS and reproduction steps
- Whether transcript contents were involved (do **not** paste real secrets)

## Design guarantees (intent)

- Offline-first: scan, scrub, and verify do not require network access
- No telemetry or automatic uploads
- Findings are emitted as masked values + HMAC fingerprints, not raw secrets
- Destructive operations require explicit authorization (`--confirm`)
- Retention deletion is feature-flagged off by default
- Fail closed on remediation validation failure

## Non-goals / honesty

Redaction of local transcripts does **not**:

- revoke credentials at providers
- erase Time Machine / volume snapshots / editor backups
- rewrite Cursor stores in v0.1 — **Cursor adapter is scan-only** (rewrite capability off)
- delete sessions by retention policy while `retention.enabled = false` (default) — plan/status only; apply refuses

Rotate any exposed credential at the issuing provider.
