# LogSentry

A security log parsing toolkit for SOC analysts and incident responders. LogSentry parses and normalizes common security log formats (syslog, SSH authentication, PAM auth) into clean, analysis-ready data with built-in detection heuristics for faster triage.

## Features

- **Multi-format Support** - Auto-detects and parses syslog, SSH auth, and PAM authentication logs
- **Field Extraction** - Extracts timestamp, host, user, source IP, and event type
- **Detection Checks** - Built-in failed login burst detection, suspicious IP flagging, new account alerts
- **Flexible Output** - Rich table display, CSV, or JSON export
- **Triage Summary** - Generates concise summary for ticket documentation

## Quick Start

```bash
# Run with sample data
python main.py samples/sample_ssh_log.log

# Generate triage summary
python main.py samples/sample_ssh_log.log --triage-summary

# Export to CSV
python main.py samples/sample_ssh_log.log -o csv
```

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

## Supported Log Formats

- **syslog** - Standard Linux syslog
- **ssh** - OpenSSH authentication logs
- **auth** - PAM/system authentication logs

## Detection Features

- Failed login burst detection (default: 5+ attempts)
- Suspicious IP geography flagging (Tor exit nodes, known scanners)
- New account creation alerts
- Event type categorization

## Project Structure

```
logsentry/
├── main.py              # CLI entry point
├── parsers/             # Log format parsers
├── detection/          # Detection heuristics
├── output/             # Output formatters
└── samples/            # Sample log files
```

## Requirements

- Python 3.11+
- pandas
- rich

See `pyproject.toml` for version pins.