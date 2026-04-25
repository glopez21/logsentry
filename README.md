# LogSentry

A security log parsing toolkit for SOC analysts and incident responders. LogSentry parses and normalizes common security log formats (syslog, SSH authentication, PAM auth) into clean, analysis-ready data with built-in detection heuristics for faster triage.

I built LogSentry to practice analyzing security logs and develop detection skills in a structured way. Rather than just reading about brute force or lateral movement, I generated realistic log data for these scenarios to build pattern recognition. The MITRE ATT&CK tagging helped me understand the full attack lifecycle, not just individual events.  It generates realistic attack scenarios that mirror what SOC analysts encounter daily, helping me build pattern recognition and triage speed.

**What it demonstrates:**
- **Log analysis proficiency** - I can parse and interpret multiple log formats (syslog, SSH, PAM, CloudTrail)
- **Detection heuristic design** - I understand how to write detection logic for common attack patterns
- **MITRE ATT&CK framework** - I can map events to attack techniques and understand attacker behavior
- **Tool building for learning** - I create my own practice tools rather than relying solely on labs

**Use Case:** This toolkit is designed for SOC analyst interview practice and training. It generates realistic security log scenarios with MITRE ATT&CK mapping, and provides real-time log collection for live security monitoring.

## Features

- **Multi-format Support** - Auto-detects and parses syslog, SSH auth, and PAM authentication logs
- **Field Extraction** - Extracts timestamp, host, user, source IP, and event type
- **Detection Checks** - Built-in failed login burst detection, suspicious IP flagging, new account alerts
- **Flexible Output** - Rich table display, CSV, or JSON export
- **Triage Summary** - Generates concise summary for ticket documentation
- **Scenario Generator** - Creates realistic attack scenarios for practice
- **Real-time Collection** - Watch log files or listen for syslog in real-time
- **MITRE ATT&CK** - All scenarios tagged with techniques
- **Threat Intelligence** - Real-time IP enrichment via VirusTotal, AbuseIPDB, AlienVault OTX, and Shodan APIs
- **Rule Engine** - Custom detection rules with YAML/JSON support and pattern matching
- **Anomaly Detection** - Statistical analysis with baseline comparison and z-score detection
- **SIEM Export** - Direct export to Elasticsearch, Splunk HEC, and Sumo Logic
- **Dashboard** - ASCII visualization with attack chain mapping and charts

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

## Case Study Scenarios (SOC Practice)

Generate realistic attack scenarios for interview training:

```bash
# Generate a specific scenario as CSV
uv run generate_logs.py -s brute -o case_brute_force.csv --output-format csv
uv run generate_logs.py -s lateral -o case_lateral.csv --output-format csv
uv run generate_logs.py -s exfil -o case_exfil.csv --output-format csv

# Generate all scenarios combined
uv run generate_logs.py -s all --seed 42 -o combined.log
```

| Scenario | Events | Description | MITRE Technique |
|----------|--------|-------------|---------------|
| `brute` | 50+ | Brute force password attack | T1110, T1078 |
| `ddos` | 500+ | Distributed denial of service | T1498 |
| `mitm` | 10 | Man-in-the-middle attack | T1557, T1040 |
| `scan` | 100+ | Port scanning activity | T1046 |
| `stuffing` | 10 | Credential stuffing | T1078 |
| `malware` | 8 | Malware indicators | T1059, T1055, T1105 |
| `priv_esc` | 9 | Privilege escalation | T1068, T1098 |
| `lateral` | 10 | Lateral movement | T1021, T1047 |
| `exfil` | 10 | Data exfiltration | T1048, T1041 |

## Real-Time Collection

```bash
# Watch a log file in real-time (like tail -f)
uv run main.py watch /var/log/auth.log

# Watch and process existing lines first
uv run main.py watch /var/log/auth.log --once

# Listen for syslog messages (UDP)
uv run main.py listen --port 514 --protocol udp

# Listen on TCP
uv run main.py listen --port 514 --protocol tcp

# Create AlertFlow ticket
uv run main.py ticket "Brute force detected" -s critical
```
## Supported Log Formats

- **syslog** - Standard Linux syslog
- **ssh** - OpenSSH authentication logs
- **auth** - PAM/system authentication logs
- **cloudtrail** - AWS CloudTrail JSON logs

## Detection Features

- Failed login burst detection (default: 5+ attempts)
- Suspicious IP geography flagging (Tor exit nodes, known scanners)
- New account creation alerts
- Privilege escalation detection
- Lateral movement detection
- Data exfiltration detection
- Severity scoring (critical/high/medium/low/info)
- Event correlation
- **MITRE ATT&CK tactic mapping**

## Threat Intelligence

Real-time IP enrichment with multiple threat intelligence providers:

```bash
# Single IP lookup (all providers)
uv run main.py lookup 185.220.101.45

# Quick reputation check
uv run main.py lookup 185.220.101.45 --check-only

# Specific provider
uv run main.py lookup 185.220.101.45 --provider vt

# Enrich all IPs in log file
uv run main.py case.log --enrich-all
```

**Supported Providers:**
- **VirusTotal** - Detection ratios, tags
- **AbuseIPDB** - Abuse scores, Tor/Proxy/VPN detection
- **AlienVault OTX** - Pulse counts, threat categories
- **Shodan** - Host info, ISP data

**Setup (API keys via environment variables):**
```bash
export VT_API_KEY="your-key"
export ABUSEIPDB_API_KEY="your-key"
export OTX_API_KEY="your-key"
export SHODAN_API_KEY="your-key"
```

## Rule Engine

Custom detection rules with pattern matching:

```bash
# Run with built-in rules
uv run main.py case.log --rules

# With custom rules file
uv run main.py case.log --rules custom_rules.yaml
```

## Anomaly Detection

Statistical analysis with baseline comparison:

```bash
uv run main.py case.log --anomalies

# Compare against baseline
uv run main.py case.log --anomalies --baseline normal_day.log
```

## SIEM Export

Export to security platforms:

```bash
uv run main.py case.log --siem es        # Elasticsearch
uv run main.py case.log --siem splunk    # Splunk HEC
uv run main.py case.log --siem sumo      # Sumo Logic
```

## Dashboard

ASCII visualization dashboard:

```bash
uv run main.py case.log --dashboard
```

Displays: event timeline, severity distribution, top attackers, attack chain visualization.

## Project Structure

```
logsentry/
├── main.py              # CLI entry point
├── generate_logs.py     # Scenario generator
├── threat_intel/        # Threat intelligence providers
│   └── providers.py    # VT, AbuseIPDB, OTX, Shodan
├── siem/               # SIEM export
│   └── __init__.py    # Elasticsearch, Splunk, Sumo
├── rules/              # Rule engine
│   └── __init__.py    # Detection rules
├── analytics/          # Anomaly detection
│   └── __init__.py    # Statistical analysis
├── dashboard/          # Visualization
│   └── __init__.py    # ASCII charts
├── collector/          # Real-time collection
│   ├── file_tail.py   # File tail
│   └── syslog.py      # UDP/TCP listener
├── alerters/           # Alerting
│   ├── console.py    # Console output
│   └── ticket.py      # AlertFlow
├── parsers/            # Log parsers
│   ├── syslog_parser.py
│   ├── ssh_parser.py
│   └── auth_parser.py
├── detection/          # Detection heuristics
├── output/             # Output formatters
└── samples/            # Sample data
logsentry/
├── main.py              # CLI entry point
├── generate_logs.py    # Scenario generator
├── threat_intel/        # Threat intelligence providers
│   ├── __init__.py
│   └── providers.py    # VT, AbuseIPDB, OTX, Shodan
├── collector/           # Real-time collection
│   ├── __init__.py
│   ├── file_tail.py    # File tail implementation
│   └── syslog.py      # UDP/TCP listener
├── alerters/           # Alerting
│   ├── __init__.py
│   ├── console.py     # Console output
│   └── ticket.py      # AlertFlow integration
├── parsers/            # Log format parsers
│   ├── syslog_parser.py
│   ├── ssh_parser.py
│   └── auth_parser.py
├── detection/          # Detection heuristics
│   └── detection_checks.py
├── output/             # Output formatters
│   ├── formatter.py
│   └── advanced.py
└── samples/           # Sample case study files
```

## Requirements

- Python 3.11+
- pandas
- rich

Managed via `uv` - see `pyproject.toml` for version pins.

---

