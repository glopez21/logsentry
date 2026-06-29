# LogSentry — Known Issues & Blockers

## Blockers

- **Integration tests require live Postgres** — 23 mocked tests pass, but no CI with a real Postgres instance. The `docker-compose.yml` provides one for manual runs but is not wired into CI.

## Known Bugs

- **Schema expression index** (resolved 2026-05-31): `CREATE INDEX ... ON logsentry.threat_intel_cache (updated_at + (ttl_seconds * interval '1 second'))` — TimescaleDB-specific syntax, commented out in `db/schema.py` for plain PostgreSQL compatibility.  
  **NOTE**: `pipx install` from GitHub HEAD before this fix still has the broken index. Run `pipx upgrade logsentry` to get the fixed version. The error is `psycopg2.errors.SyntaxError: syntax error at or near "+"` at LINE 74 of the schema init.
- **Auto-enable Augur notifier** (resolved 2026-05-31): Config `"enabled": False` was ignoring `AUGUR_URL` env var. Fixed to `"enabled": bool(os.environ.get("AUGUR_URL"))`.

## Detected but Unresolved

- WebSocket tail broadcasts to all connected clients; no per-client auth verification on the WS endpoint (auth is checked on upgrade only).
- `logsentry ingest --dry-run` counts files but doesn't show sample parsed records.
- No rate limiting on the syslog UDP/TCP listener — a noisy source can flood the ingestion pipeline.
- No graceful SIGHUP reload — daemon must be restarted to pick up config changes.
- **Daemon logging**: no stdout/stderr handler configured — `journalctl -u augur-logsentry` shows nothing after successful startup. Python `logging` module uses `NullHandler` by default; needs a `StreamHandler` or `logging.basicConfig()` in daemon startup.

## Deployment

- `/home/w01f/projects/logsentry/logsentry.yaml` hardcoded path removed from `config/config.py` defaults — now searches `/etc/logsentry/`, `./`, `~/.config/logsentry/`.
- `n3xus.py` must be force-included in wheel (added to `pyproject.toml` force-include).
- Remote nodes: set `N3XUSLIB_MODE=http` to push events via Omn1L1nk instead of direct DB.
- **systemd ExecStart path**: `ExecStart=logsentry daemon` fails on some systems (e.g., WSL) because the pipx shim isn't on systemd's PATH. Workaround: use full path `/root/.local/bin/logsentry daemon` or start manually with `& disown`.

## Feature Gaps (Phase 5 — v0.2.0 Parity)

These features exist in the CLI but haven't been ported to the engine detection pipeline:

- YARA scanning on ingested logs
- Attack timeline reconstruction
- MITRE Navigator export from stored data
- Sigma rule conversion from detections
- MISP / TheHive push on detection trigger
