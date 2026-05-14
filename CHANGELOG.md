# Changelog

All notable changes to LogSentry will be documented in this file.

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