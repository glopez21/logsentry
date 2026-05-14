# LogSentry

A security log parsing toolkit for SOC analysts and incident responders. LogSentry parses and normalizes common security log formats (syslog, SSH authentication, PAM auth, CloudTrail) into clean, analysis-ready data with built-in detection heuristics for faster triage.

## Features

### Core Features
- **Multi-format Support** - Auto-detects and parses syslog, SSH auth, PAM, and CloudTrail logs
- **Detection Checks** - Built-in failed login burst detection, suspicious IP flagging, MITRE ATT&CK mapping
- **Real-time Collection** - Watch log files or listen for syslog in real-time
- **Threat Intelligence** - IP enrichment via VirusTotal, AbuseIPDB, OTX, and Shodan
- **SIEM Export** - Export to Elasticsearch, Splunk HEC, and Sumo Logic

### Advanced Features (v0.2+)
- **Alert Suppression** - Reduce alert fatigue with intelligent grouping
- **Attack Timeline** - Kill chain reconstruction from MITRE tactics
- **MITRE Navigator Export** - Generate ATT&CK Navigator layer files
- **YARA Rules** - YARA-style pattern matching engine
- **Log Integrity** - Hash verification for forensic analysis
- **Baseline Storage** - Persistent baselines for anomaly detection
- **STIX/TAXII** - Threat intel feed integration

### Integrations
- **MISP** - Push IOCs to your Malware Information Sharing Platform
- **TheHive** - Create cases for incident response workflow
- **Sigma** - Convert detections to Sigma rule format
- **REST API** - FastAPI server for programmatic access

## Quick Start

```bash
# Install dependencies
uv sync

# Run with sample data
uv run main.py samples/sample_ssh_log.log

# Generate triage summary
uv run main.py samples/sample_ssh_log.log --triage-summary

# Export to CSV
uv run main.py samples/sample_ssh_log.log -o csv
```

## CLI Commands

### Parse Commands
```bash
uv run main.py parse logfile.log                  # Basic parsing
uv run main.py parse logfile.log --triage-summary # Triage summary
uv run main.py parse logfile.log --severity       # Severity scoring
uv run main.py parse logfile.log --mitre          # MITRE ATT&CK breakdown
uv run main.py parse logfile.log --dashboard      # ASCII dashboard
uv run main.py parse logfile.log --rules          # Rule engine
uv run main.py parse logfile.log --anomalies      # Anomaly detection
uv run main.py parse logfile.log --siem es        # SIEM export
uv run main.py parse logfile.log --yara           # YARA scan
uv run main.py parse logfile.log --suppress       # Alert suppression
uv run main.py parse logfile.log --attack-timeline# Attack chain
uv run main.py parse logfile.log --navigator out.json # Navigator export
uv run main.py parse logfile.log --integrity     # Integrity check
uv run main.py parse logfile.log --export-stix out.stix # STIX export
uv run main.py parse logfile.log --to-sigma       # Sigma rules
```

### Real-Time Commands
```bash
uv run main.py watch /var/log/auth.log           # File watcher
uv run main.py listen --port 514 --protocol udp  # Syslog listener
```

### Extended Commands
```bash
uv run main.py diff file1.log file2.log          # Compare logs
uv run main.py replay logfile.log --speed 10     # Time-compressed replay
uv run main.py schedule --command "python main.py watch auth.log" --interval 60
uv run main.py serve --port 8080                 # REST API server
```

### Threat Intel
```bash
uv run main.py lookup 185.220.101.45             # IP lookup (all providers)
uv run main.py lookup 185.220.101.45 --provider vt # Single provider
uv run main.py lookup 185.220.101.45 --json      # JSON output
uv run main.py lookup 185.220.101.45 --check-only # Quick check
```

## Scenario Generator

Generate realistic attack scenarios for SOC training:

```bash
# Generate specific scenarios
uv run generate_logs.py -s brute -o case_brute.csv --output-format csv
uv run generate_logs.py -s lateral -o case_lateral.csv --output-format csv
uv run generate_logs.py -s exfil -o case_exfil.csv --output-format csv

# Generate all scenarios
uv run generate_logs.py -s all --seed 42 -o combined.log

# Generate normal baseline
uv run generate_logs.py -s normal --count 2000 -o normal_day.log
```

| Scenario | Events | MITRE |
|----------|--------|-------|
| `brute` | 50+ | T1110, T1078 |
| `ddos` | 500+ | T1498 |
| `mitm` | 10 | T1557, T1040 |
| `scan` | 100+ | T1046 |
| `stuffing` | 10 | T1078 |
| `malware` | 8 | T1059, T1055 |
| `priv_esc` | 9 | T1068, T1098 |
| `lateral` | 10 | T1021, T1047 |
| `exfil` | 10 | T1048, T1041 |

## Environment Variables

### Threat Intel
```bash
export VT_API_KEY="your-key"
export ABUSEIPDB_API_KEY="your-key"
export OTX_API_KEY="your-key"
export SHODAN_API_KEY="your-key"
```

### SIEM Export
```bash
export ES_ENDPOINT="http://localhost:9200"
export ES_API_KEY="your-key"
export SPLUNK_ENDPOINT="https://localhost:8088/services/collector"
export SPLUNK_HEC_TOKEN="your-token"
export SUMO_ENDPOINT="https://endpoint.sumologic.com/..."
export SUMO_API_KEY="your-key"
```

### Integrations
```bash
export MISP_URL="https://your-misp.com"
export MISP_API_KEY="your-key"
export THEHIVE_URL="https://your-thehive.com"
export THEHIVE_API_KEY="your-key"
export TAXII_SERVER="https://taxii.example.com"
export TAXII_COLLECTION="collection-id"
```

## Project Structure

```
logsentry/
├── main.py              # CLI entry point
├── generate_logs.py      # Scenario generator
├── _constants.py        # Pre-compiled patterns
├── parsers/             # Log format parsers
│   ├── syslog_parser.py
│   ├── ssh_parser.py
│   ├── auth_parser.py
│   └── cloudtrail_parser.py
├── detection/           # Detection heuristics
├── output/              # Output formatters
├── threat_intel/       # Threat intelligence
├── siem/               # SIEM export
├── rules/              # Rule engine
├── analytics/          # Anomaly detection
├── dashboard/          # ASCII visualization
├── collector/          # Real-time collection
├── alerters/           # Alerting
├── alerts/            # Alert suppression
├── attack_timeline/    # Kill chain reconstruction
├── navigator/          # ATT&CK Navigator export
├── yara_rules/         # YARA-style rules
├── integrity/          # Log integrity
├── baselines/          # Baseline storage
├── integrations/       # External integrations
│   ├── misp.py
│   ├── thehive.py
│   ├── sigma.py
│   └── stix.py
├── tests/              # Test suite
└── samples/            # Sample data
```

## Requirements

- Python 3.11+
- pandas>=3.0.2
- rich>=15.0.0
- httpx>=0.27.0

Optional dependencies:
```bash
uv sync --extra server    # For REST API
uv sync --extra dev       # For testing (pytest, ruff, mypy)
uv sync --extra integrations # For STIX
```

## Documentation

- [README](README.md) - Overview and quick start
- [ARCHITECTURE.md](ARCHITECTURE.md) - Technical architecture
- [CHANGELOG.md](CHANGELOG.md) - Version history

---

*LogSentry - Build detection skills through practice.*