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

## SOC Deployment — 192.168.1.33 Forwarders → Engine on .30 (2026-08-05)

Priority-ordered open items (easy → complex), none fixed yet:

1. **[EASY] Switch container forwarders 5514 → 514** — all 6 LXC containers on 192.168.1.33 still send syslog to test port 5514; change `/etc/rsyslog.d/90-logsentry.conf` to `192.168.1.30:514` and restart rsyslog so logs actually reach the engine.
2. **[EASY] Guard `apply_tenant_filter` in Augur agent heartbeat** — Augur's `POST /agents/heartbeat` fails closed (`WHERE false()`) when no tenant context → 404 even with a valid agent token; engine heartbeats never succeed. Augur-side fix (same guard already applied to register).
3. **[MEDIUM] Persist augur-client auth_token fix** — engine client now stores the per-agent `auth_token` from register and uses it as Bearer (was sending API key → 401). Copied into running container only; image still installs augur-client from git, so rebuild loses it.
4. **[RESOLVED 2026-08-05] Log storage fails: `'str' object has no attribute 'strftime'`** — parsers return string timestamps (RFC 5424/3164/ISO) but the store layer called `ts.strftime()` on them. Fixed by adding `_coerce_timestamp()` in `db/store.py` and applying it at all insert boundaries (sync `insert_log`/`insert_logs_batch`, async `insert_log`/`insert_logs_batch`). Verified live: UDP packets on :514 parsed and stored in `logsentry.logs` (host/event_type/severity populated), health shows `logs_stored: 4`. **NOTE**: fix copied into running container only (`docker cp`); commit to repo and rebuild image to persist.
5. **[MEDIUM] Verify end-to-end** — confirmed 2026-08-05: packets sent to :514 are parsed (event_type `syslog_rfc5424`, severity, host) and stored in `logsentry.logs` on .33; `logs_stored` counter increments.
6. **[MEDIUM] Run shadowsim** — `/home/w01f/projects/shadowsim` against the containers for rich traffic.
7. **[COMPLEX] Ollama enrichment not reachable** — `/api/v1/health` shows `ollama: reachable: false` on Augur side.

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
