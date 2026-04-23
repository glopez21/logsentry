# LogSentry

A security log parsing toolkit for SOC analysts and incident responders. LogSentry parses and normalizes common security log formats (syslog, SSH authentication, PAM auth) into clean, analysis-ready data with built-in detection heuristics for faster triage.

**Use Case:** This toolkit is designed for SOC analyst interview practice and training. It generates realistic security log scenarios that simulate common attack patterns, enabling analysts to practice log analysis, threat identification, and incident investigation in a controlled environment.

## Features

- **Multi-format Support** - Auto-detects and parses syslog, SSH auth, and PAM authentication logs
- **Field Extraction** - Extracts timestamp, host, user, source IP, and event type
- **Detection Checks** - Built-in failed login burst detection, suspicious IP flagging, new account alerts
- **Flexible Output** - Rich table display, CSV, or JSON export
- **Triage Summary** - Generates concise summary for ticket documentation
- **Scenario Generator** - Creates realistic attack scenarios for practice

## Quick Start

```bash
# Run with sample data
python main.py samples/sample_ssh_log.log

# Generate triage summary
python main.py samples/sample_ssh_log.log --triage-summary

# Export to CSV
python main.py samples/sample_ssh_log.log -o csv
```

## Case Study Scenarios (SOC Practice)

Generate realistic attack scenarios for interview training:

```bash
# Generate a specific scenario as CSV
python generate_logs.py -s brute -o case_brute_force.csv --output-format csv
python generate_logs.py -s lateral -o case_lateral.csv --output-format csv
python generate_logs.py -s exfil -o case_exfil.csv --output-format csv

# Generate all scenarios combined
python generate_logs.py -s all --seed 42 -o combined.log
```

| Scenario | Events | Description |
|----------|--------|-------------|
| `brute` | 50+ | Brute force password attack |
| `ddos` | 500+ | Distributed denial of service |
| `mitm` | 10 | Man-in-the-middle attack |
| `scan` | 100+ | Port scanning activity |
| `stuffing` | 10 | Credential stuffing |
| `malware` | 8 | Malware indicators |
| `priv_esc` | 9 | Privilege escalation |
| `lateral` | 10 | Lateral movement |
| `exfil` | 10 | Data exfiltration |

## Installation

```bash
# Using uv (recommended)
uv sync

# Or manual
pip install -r requirements.txt
```

## Usage

| Command | Description |
|---------|-------------|
| `python main.py <logfile>` | Parse log file with auto-detection |
| `python main.py <logfile> -f ssh` | Force SSH format parsing |
| `python main.py <logfile> -o csv` | Export to CSV |
| `python main.py <logfile> -o json` | Export to JSON |
| `python main.py <logfile> --triage-summary` | Generate detection summary |
| `python main.py <logfile> --severity` | Add severity scores to events |
| `python main.py <logfile> --timeline` | Generate sorted event timeline |
| `python main.py <logfile> --correlate` | Correlate related events |
| `python main.py <logfile> --mitre` | Show MITRE ATT&CK tactics |
| `python main.py <logfile> --report` | Generate Markdown incident report |
| `python main.py <logfile> -i IP` | Enrich IP with threat intelligence |

## Advanced Analysis

```bash
# Severity scoring (critical/high/medium/low/info)
python main.py case.log --severity

# Timeline sorted by severity
python main.py case.log --timeline

# Attack correlation chains
python main.py case.log --correlate

# MITRE ATT&CK tactics
python main.py case.log --mitre

# Generate incident report
python main.py case.log --report --report-title "My Incident"

# IP enrichment
python main.py case.log -i 185.220.101.45
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

## MITRE ATT&CK Coverage

Each scenario is tagged with MITRE ATT&CK techniques:

| Scenario | Technique | Description |
|----------|----------|-------------|
| `brute` | T1110, T1078 | Initial Access, Valid Accounts |
| `ddos` | T1498 | Denial of Service |
| `mitm` | T1557, T1040 | Man-in-the-Middle, Network Sniffing |
| `scan` | T1046 | Service Discovery |
| `stuffing` | T1078 | Valid Accounts |
| `malware` | T1059, T1055, T1105 | Command injection, Process injection |
| `priv_esc` | T1068, T1098 | Privilege Escalation, Account Manipulation |
| `lateral` | T1021, T1047 | Remote Services, WMI |
| `exfil` | T1048, T1041, T1001 | Exfiltration |

**Usage with MITRE:**

```bash
# Generate log format with MITRE tags
python generate_logs.py -s brute -o case.log --output-format log

# Show MITRE ATT&CK breakdown
python main.py case.log --mitre

# Full incident report with tactics
python main.py case.log --report --report-title "Incident Report"
```

## Project Structure

```
logsentry/
├── main.py              # CLI entry point
├── generate_logs.py      # Scenario generator
├── parsers/             # Log format parsers
├── detection/          # Detection heuristics
├── output/             # Output formatters
└── samples/            # Sample case study files
```

## Requirements

- Python 3.11+
- pandas
- rich

See `pyproject.toml` for version pins.