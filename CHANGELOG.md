# Changelog

All notable changes to LogSentry will be documented in this file.

## [0.3.0] - 2026-05-21

### Added

#### Engine Mode
- **Daemon loop** (`daemon.py`) — persistent ingest → store → detect → alert pipeline
  - Syslog UDP/TCP listener with RFC3164/RFC5424 support
  - File watcher for local log files
  - Configurable detection interval and stats interval
  - `--init-db` flag to bootstrap Postgres schema
  - `--check` flag to validate config and exit

- **PostgreSQL storage layer** (`db/store.py`, `db/schema.py`)
  - Daily-partitioned `logs` table with BRIN + GIN indexes
  - Full-text search via tsvector
  - Auto-partitioning on ingest
  - Retention policy with `drop_old_partitions(days)`
  - Detection results table (`logsentry.detections`)
  - Threat intel cache (`logsentry.threat_intel_cache`)
  - Cross-project shared schemas (`shared.hosts`, `shared.apps`)

- **Config system** (`config/config.py`)
  - YAML config with lookup: `./logsentry.yaml` → `~/.config/logsentry/` → `/etc/logsentry/`
  - Environment variable overrides
  - Cross-project schema sections (logsentry, alertflow, threatpulse, shared)

#### CLI Commands
- `logsentry daemon` — run the engine
- `logsentry query` — query stored logs (table/json/csv output)
- `logsentry ingest <path>` — bulk backfill with recursive glob, label tagging, dry-run
- `logsentry tail` — WebSocket live tail
- `logsentry gen-rsyslog` — generate rsyslog forwarder config (UDP/TCP, RFC3164/RFC5424)

#### FastAPI Server
- `/ingest` — POST log ingestion
- `/api/v1/query` — query with filters (severity, source_ip, event_type, search, time range)
- `/api/v1/stats` — storage statistics
- `/api/v1/tail/ws` — WebSocket live tail
- `/lookup/{ip}` — threat intel cache lookup
- `/health` — health check
- `/export/navigator` — MITRE Navigator export
- `/metrics` — Prometheus text-format metrics
- `/grafana/search`, `/grafana/query` — SimpleJSON datasource

#### Detection & Alerting
- Alert rules engine — YAML-defined rules in `logsentry.yaml`
- Detection checks: failed login bursts, new accounts, MITRE tactic extraction
- Notification backends: Discord webhook, Slack webhook, Telegram bot
- Prometheus metrics for detection pipeline

#### Deployment
- Systemd unit (`deploy/logsentry.service`)
- Docker Compose (`docker-compose.yml`) with postgres, logsentry, db-init
- Dockerfile with rsyslog support
- `deploy/install.sh` installer script

#### Auth
- API key middleware on HTTP endpoints (Bearer token + query param fallback)
- Public paths exempted: `/health`, `/metrics`, `/grafana/`

### Testing
- 23 integration tests (`tests/test_integration.py`) with mocked Postgres
  - Store: insert, query, detection, host registration, threat intel, stats, retention
  - Detection: burst detection, MITRE extraction, false positive checks
  - Parsers: SSH fail/success, syslog, empty lines
  - Daemon: alert rule evaluation, notifier dispatch
  - Config: defaults, env overrides, YAML loading

### Changed
- `uv run python main.py` → `uv run main.py` throughout
- moved from file-based detection to DB-backed engine pipeline

### Dependencies
- Added: psycopg2-binary, pyyaml, fastapi, uvicorn, prometheus-client, websockets

## [0.2.0] - 2026-05-09

### Added

#### New Modules
- **Alerts Module** (`alerts/`) - Alert suppression and grouping to reduce alert fatigue
  - `AlertSuppressor` class for grouping similar events
  - Configurable time windows and thresholds
  - Suppression reporting

- **Attack Timeline** (`attack_timeline/`) - Kill chain reconstruction
  - `AttackTimeline` class with MITRE ATT&CK phases
  - Attack stage detection and correlation
  - Confidence scoring

- **Navigator Export** (`navigator/`) - MITRE ATT&CK Navigator layer export
  - Export to `.json` layer format
  - Technique scoring based on severity
  - Compatible with ATT&CK Navigator v4.5+

- **YARA Rules** (`yara_rules/`) - YARA-style pattern matching
  - 8 built-in rules (brute force, suspicious IPs, malware, etc.)
  - Custom rule loading from YAML/JSON
  - Threshold-based matching

- **Integrity** (`integrity/`) - Log file hash verification
  - SHA256 hash computation
  - Integrity recording and verification
  - Forensic chain of custody support

- **Baselines** (`baselines/`) - Persistent baseline storage
  - Statistical baseline computation (mean, std, p95, p99)
  - Persistent storage to `.baselines/` directory
  - Value comparison with z-score

#### Integrations
- **MISP** (`integrations/misp.py`) - IOC push to MISP
  - IP, domain, hash export
  - Tag support
  - Config via `MISP_URL` and `MISP_API_KEY`

- **TheHive** (`integrations/thehive.py`) - Case creation
  - Create cases from log analysis
  - Observable attachment
  - Alert creation
  - Config via `THEHIVE_URL` and `THEHIVE_API_KEY`

- **Sigma** (`integrations/sigma.py`) - Sigma rule converter
  - Convert LogSentry detections to Sigma YAML
  - MITRE tag mapping
  - Batch export to `sigma_rules/` directory

- **STIX/TAXII** (`integrations/stix.py`) - Threat intel feeds
  - TAXII 2.x client for feed consumption
  - STIX 2.1 bundle builder
  - Indicator export

#### CLI Commands
- **diff** - Compare two log files
  - New/removed IPs and users
  - Severity comparison
  - Change detection

- **replay** - Time-compressed log replay
  - Configurable speed multiplier
  - Event limit control

- **schedule** - Periodic monitoring
  - Cron-style scheduling
  - Command execution

- **serve** - REST API server
  - `/parse` - Upload and parse logs
  - `/lookup/{ip}` - Threat intel lookup
  - `/export/navigator` - Navigator export
  - `/health` - Health check

### Code Quality
- Pre-compiled regex patterns in `_constants.py`
- Type hints added to all new modules
- `__future__` annotations import

### Testing
- Added `tests/test_logsentry.py` with pytest suite
- 30+ test cases covering parsers, detection, advanced features
- Test fixtures for temporary files

### Dependencies
- Updated `pyproject.toml` with optional groups:
  - `dev` - pytest, ruff, mypy
  - `server` - fastapi, uvicorn
  - `integrations` - stix2

## [0.1.0] - 2026-04-25

### Added
- Core log parsing (syslog, SSH, PAM, CloudTrail)
- MITRE ATT&CK mapping
- Real-time file watching
- Syslog listener (UDP/TCP)
- Threat intel providers (VirusTotal, AbuseIPDB, OTX, Shodan)
- Rule engine with YAML/JSON support
- Anomaly detection with z-score analysis
- ASCII dashboard visualization
- SIEM export (Elasticsearch, Splunk, Sumo Logic)
- Log generation scenarios (brute force, DDoS, MITM, etc.)
- AlertFlow ticket integration

---

## Migration Guide

### From 0.2.0 to 0.3.0

The engine mode replaces the file-based CLI workflow. Existing parsers and detection logic are preserved.

New required dependency: PostgreSQL.

To migrate:
```bash
# Install new dependencies
uv sync --extra dev

# Initialize the database
uv run main.py daemon --init-db

# Validate config
uv run main.py daemon --check
```

### From 0.1.0 to 0.2.0

New modules are auto-imported. No configuration changes required.

To use new integrations:
```bash
# Install optional dependencies
uv sync --extra server --extra integrations

# MISP
export MISP_URL="https://your-misp.com"
export MISP_API_KEY="your-key"

# TheHive  
export THEHIVE_URL="https://your-thehive.com"
export THEHIVE_API_KEY="your-key"

# TAXII
export TAXII_SERVER="https://taxii.example.com"
export TAXII_COLLECTION="your-collection-id"
```

To use new CLI commands:
```bash
uv run python cli_extended.py diff file1.log file2.log
uv run python cli_extended.py serve --port 8080
```
