# LogSentry - Development Notes

## Project Overview

- **Project Name**: LogSentry
- **Type**: CLI log parser and triage tool
- **Purpose**: Parse and normalize security logs for faster incident triage
- **Language**: Python 3.11+

## Architecture

### Directory Structure

```
logsentry/
├── main.py              # CLI entry point
├── parsers/             # Log format parsers
│   ├── syslog_parser.py
│   ├── ssh_parser.py
│   └── auth_parser.py
├── detection/         # Detection checks
│   └── detection_checks.py
├── output/            # Output formatting
│   └── formatter.py
├── samples/           # Sample log files
└── config/           # Configuration (reserved)
```

### Core Functionality

1. **Log Parsing**
   - Auto-detect log format from line content
   - Support syslog, SSH auth, and PAM auth formats
   - Extract: timestamp, host, user, source IP, event type

2. **Detection Checks**
   - Failed login burst detection (configurable threshold)
   - New account creation alerts
   - Suspicious IP geography detection (Tor exit nodes, known scanners)

3. **Output**
   - Rich table format (default)
   - CSV export
   - JSON export
   - Triage summary generation

## Development History

### Initial Build
- Created as "Log Triage Toolkit" - simple Python scripts for parsing SSH logs
- Added detection_checks.py for basic threat detection
- Auto-format detection between syslog, ssh, and auth formats

### Key Decisions
- Used `rich` for pretty table output
- Used `pandas` for data manipulation and CSV export
- Pattern-based IP extraction with regex
- Dictionary-based parser registry for extensibility

### Known Issues Fixed
- IP extraction regex was picking up partial IPs - fixed to capture full IPs
- Auto-detection wasn't working properly - improved detect_format() logic
- SSH parser regex needed "from =" or "from=" support

## Dependencies

```
pandas>=2.0
rich>=13.0
```

Managed via `uv` - see `pyproject.toml` and `uv.lock`

## Usage

```bash
# Parse SSH logs with auto-detection
python main.py samples/sample_ssh_log.log

# Generate triage summary
python main.py logs/auth.log --triage-summary

# Export to CSV
python main.py logs/auth.log -o csv
```

## Extending

### Adding a New Parser

1. Create `parsers/newformat_parser.py`
2. Implement `parse_newformat(line: str) -> dict|None`
3. Return dict with keys: timestamp, host, user, source_ip, event_type, raw_message
4. Add to LOG_PARSERS dict in main.py

### Adding Detection Checks

1. Add function to `detection/detection_checks.py`
2. Call from `run_detection_checks()`
3. Results automatically included in triage summary

## Future Improvements

- [ ] Add Windows Event Log parsing
- [ ] Add Suricata/Eve JSON parsing
- [ ] Add geoip enrichment via API
- [ ] Add YARA rule scanning
- [ ] Config file for thresholds
- [ ] Structured output for SIEM ingestion