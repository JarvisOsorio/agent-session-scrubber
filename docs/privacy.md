# Privacy

`agentscrub` is designed to keep agent transcript data on the machine where it already lives.

## Data handling

- Processes local files only
- Does not create accounts or call hosted APIs during scan/scrub/verify
- Does not phone home or send telemetry
- Does not upload transcripts, findings, or receipts

## Reports and receipts

Terminal/JSON/Markdown reports include:

- file paths
- detector ids / categories
- severity and confidence
- **masked** values
- HMAC fingerprints

They intentionally omit raw secret/PII values.

## Backups

When scrubbing with `--confirm` and backups enabled, `.bak.<timestamp>` copies are written locally next to the target file (mode `0600` on Unix when the OS allows). You control retention of those backups.

## Retention

Retention policy evaluation may plan KEEP/REDACT/DELETE actions, but **deletion remains disabled** until `retention.enabled = true` and safety acceptance tests pass. Apply refuses while the flag is off.
