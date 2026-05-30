# LogSentry — Known Issues & Blockers

## Blockers

- **Integration tests require live Postgres** — 23 mocked tests pass, but no CI with a real Postgres instance. The `docker-compose.yml` provides one for manual runs but is not wired into CI.

## Known Bugs

- **None currently tracked** — all known issues have been resolved.

## Detected but Unresolved

- WebSocket tail broadcasts to all connected clients; no per-client auth verification on the WS endpoint (auth is checked on upgrade only).
- `logsentry ingest --dry-run` counts files but doesn't show sample parsed records.
- No rate limiting on the syslog UDP/TCP listener — a noisy source can flood the ingestion pipeline.
- No graceful SIGHUP reload — daemon must be restarted to pick up config changes.

## Feature Gaps (Phase 5 — v0.2.0 Parity)

These features exist in the CLI but haven't been ported to the engine detection pipeline:

- YARA scanning on ingested logs
- Attack timeline reconstruction
- MITRE Navigator export from stored data
- Sigma rule conversion from detections
- MISP / TheHive push on detection trigger
