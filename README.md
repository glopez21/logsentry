# LogSentry

A security log parsing toolkit for SOC analysts and incident responders. LogSentry parses and normalizes common security log formats (syslog, SSH authentication, PAM auth) into clean, analysis-ready data with built-in detection heuristics for faster triage.

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

## Quick Start

```bash
# Install dependencies
uv sync

# Run with sample data
uv run python main.py samples/sample_ssh_log.log

# Generate triage summary
uv run python main.py samples/sample_ssh_log.log --triage-summary

# Export to CSV
uv run python main.py samples/sample_ssh_log.log -o csv
```

## Case Study Scenarios (SOC Practice)

Generate realistic attack scenarios for interview training:

```bash
# Generate a specific scenario as CSV
uv run python generate_logs.py -s brute -o case_brute_force.csv --output-format csv
uv run python generate_logs.py -s lateral -o case_lateral.csv --output-format csv
uv run python generate_logs.py -s exfil -o case_exfil.csv --output-format csv

# Generate all scenarios combined
uv run python generate_logs.py -s all --seed 42 -o combined.log
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
uv run python main.py watch /var/log/auth.log

# Watch and process existing lines first
uv run python main.py watch /var/log/auth.log --once

# Listen for syslog messages (UDP)
uv run python main.py listen --port 514 --protocol udp

# Listen on TCP
uv run python main.py listen --port 514 --protocol tcp

# Create AlertFlow ticket
uv run python main.py ticket "Brute force detected" -s critical
```

## Usage

### Parse Commands

| Command | Description |
|---------|-------------|
| `uv run python main.py <logfile>` | Parse log file with auto-detection |
| `uv run python main.py <logfile> -f ssh` | Force SSH format parsing |
| `uv run python main.py <logfile> -o csv` | Export to CSV |
| `uv run python main.py <logfile> -o json` | Export to JSON |
| `uv run python main.py <logfile> --triage-summary` | Generate detection summary |
| `uv run python main.py <logfile> --severity` | Add severity scores to events |
| `uv run python main.py <logfile> --timeline` | Generate sorted event timeline |
| `uv run python main.py <logfile> --correlate` | Correlate related events |
| `uv run python main.py <logfile> --mitre` | Show MITRE ATT&CK tactics |
| `uv run python main.py <logfile> --report` | Generate Markdown incident report |
| `uv run python main.py <logfile> -i IP` | Enrich IP with threat intelligence |

### Watch Commands (Real-Time)

| Command | Description |
|---------|-------------|
| `uv run python main.py watch <logfile>` | Watch file in real-time |
| `uv run python main.py watch <logfile> --once` | Process existing lines first |
| `uv run python main.py watch <logfile> --severity-threshold high` | Only show high+ severity |

### Listen Commands (Syslog)

| Command | Description |
|---------|-------------|
| `uv run python main.py listen --port 514` | Listen on UDP (default) |
| `uv run python main.py listen --protocol tcp` | Listen on TCP |
| `uv run python main.py listen --bind 127.0.0.1` | Custom bind address |

### Ticket Commands

| Command | Description |
|---------|-------------|
| `uv run python main.py ticket "Title" -s critical` | Create ticket with severity |
| `uv run python main.py ticket "Title" -s high --webhook URL` | Using custom webhook |

## Advanced Analysis

```bash
# Severity scoring (critical/high/medium/low/info)
uv run python main.py case.log --severity

# Timeline sorted by severity
uv run python main.py case.log --timeline

# Attack correlation chains
uv run python main.py case.log --correlate

# MITRE ATT&CK tactics
uv run python main.py case.log --mitre

# Generate incident report
uv run python main.py case.log --report --report-title "My Incident"

# IP enrichment
uv run python main.py case.log -i 185.220.101.45
```

## Supported Log Formats

- **syslog** - Standard Linux syslog
- **ssh** - OpenSSH authentication logs
- **auth** - PAM/system authentication logs

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

## Project Structure

```
logsentry/
├── main.py              # CLI entry point
├── generate_logs.py    # Scenario generator
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