# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes (pre-release / working scanner) |

## Reporting a vulnerability

Email security concerns to the maintainer via [jarvisosorio.com](https://jarvisosorio.com) contact channels, or open a **private** security advisory on the GitHub repository when the repo is public.

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
- guarantee Cursor SQLite rewrite safety (v0.1 stays read-only for Cursor rewrite)

Rotate any exposed credential at the issuing provider.
