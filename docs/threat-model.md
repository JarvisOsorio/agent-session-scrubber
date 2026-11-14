# Threat model (v0.1)

## Assets

- AI agent session transcripts (Claude Code, Codex, Cursor, generic JSON/JSONL)
- Secrets and PII embedded in those transcripts
- Integrity of transcript structure after remediation
- Operator trust that incomplete scans are not reported as clean

## Adversaries / failure modes

1. **Accidental secret leakage** into agent chats (primary use case)
2. **Malformed or hostile transcript input** (huge files, invalid JSONL, path tricks)
3. **Unsafe rewrite** of formats we do not fully understand (especially SQLite)
4. **Silent destructive failure** (partial writes, symlink escapes, TOCTOU)
5. **Report leakage** of raw secrets into logs/CI artifacts

## Mitigations

| Threat | Mitigation |
|--------|------------|
| Network exfil by tool | No network in scan/scrub/verify paths |
| Raw secret in reports | Masking + HMAC fingerprints only |
| TOCTOU overwrite | Exclusive lock + hash recheck before commit |
| Partial write | tempfile + atomic rename on same filesystem |
| Symlink escape | Refuse modifying symlink targets; no follow outside roots by default |
| Unknown Cursor DB rewrite | Capability flag: read-only redaction for Cursor in v0.1 |
| Incomplete discovery treated as clean | Exit code `8` |
| Accidental mass delete | `retention.enabled = false`; apply requires flag + `--confirm` |

## Out of scope (v0.1)

- Prevention hooks that mutate agent configs
- Live HTTP verification of credentials
- Cloud dashboards / multi-tenant SaaS
- Guaranteeing erasure of all OS-level copies
