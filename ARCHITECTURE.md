# LogSentry - Architecture Documentation

## Overview

LogSentry is a CLI security log parsing toolkit designed for SOC analysts and incident responders. It parses and normalizes common security log formats into analysis-ready data with built-in detection heuristics.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                           LogSentry                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐       │
│  │    CLI      │     │   Parser    │     │ Detection   │       │
│  │   (main)    │────▶│   Registry  │────▶│   Checks    │       │
│  └─────────────┘     └──────┬──────┘     └─────────────┘       │
│                             │                                  │
│         ┌───────────────────┼───────────────────┐              │
│         │                   │                   │              │
│  ┌──────▼──────┐  ┌────────▼───┐  ┌──────────▼─────┐         │
│  │   syslog    │  │    ssh     │  │     auth       │         │
│  │   parser    │  │   parser   │  │     parser     │         │
│  └─────────────┘  └────────────┘  └────────────────┘         │
│                                                                 │
│  ┌──────────────────────────────────────────────────────┐      │
│  │                   Output Module                       │      │
│  │  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────────┐  │      │
│  │  │ Table  │ │  CSV   │ │  JSON  │ │  Reports   │  │      │
│  │  └────────┘ └────────┘ └────────┘ └────────────┘  │      │
│  └──────────────────────────────────────────────────────┘      │
│                                                                 │
│  ┌──────────────────────────────────────────────────────┐      │
│  │                 Advanced Analysis                      │      │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐ │      │
│  │  │ Severity │ │ Timeline │ │ Correlation│ │Report  │ │      │
│  │  └──────────┘ └──────────┘ └──────────┘ └────────┘ │      │
│  └──────────────────────────────────────────────────────┘      │
│                                                                 │
│  ┌──────────────────────────────────────────────────────┐      │
│  │                   Modules (v0.2)                      │      │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐ │      │
│  │  │  Alerts  │ │  Attack   │ │ Navigator│ │  YARA  │ │      │
│  │  │Suppressor│ │Timeline   │ │ Export   │ │ Rules  │ │      │
│  │  └──────────┘ └──────────┘ └──────────┘ └────────┘ │      │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐ │      │
│  │  │Integrity │ │ Baselines│ │ Threat   │ │  SIEM  │ │      │
│  │  │  Verify  │ │  Store   │ │ Intel    │ │ Export │ │      │
│  │  └──────────┘ └──────────┘ └──────────┘ └────────┘ │      │
│  └──────────────────────────────────────────────────────┘      │
│                                                                 │
│  ┌──────────────────────────────────────────────────────┐      │
│  │                 Integrations                          │      │
│  │  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────────┐  │      │
│  │  │ MISP │ │TheHive│ │Sigma │ │ STIX │ │  REST    │  │      │
│  │  │      │ │      │ │      │ │/TAXII│ │  API     │  │      │
│  │  └──────┘ └──────┘ └──────┘ └──────┘ └──────────┘  │      │
│  └──────────────────────────────────────────────────────┘      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Module Descriptions

### Core Parsers (`parsers/`)

| Module | Description | Input Formats |
|--------|-------------|---------------|
| `syslog_parser.py` | Standard syslog format with MITRE tactic extraction | RFC 3164/5424 |
| `ssh_parser.py` | OpenSSH authentication logs | sshd format |
| `auth_parser.py` | PAM/system authentication | pam_unix, secure |
| `cloudtrail_parser.py` | AWS CloudTrail JSON | JSON |

### Detection (`detection/`)

- `detection_checks.py` - MITRE ATT&CK mapping, burst detection, geography checks

### Output (`output/`)

- `formatter.py` - Rich table formatting
- `advanced.py` - Severity scoring, timelines, reports

### Advanced Modules (v0.2)

| Module | Description |
|--------|-------------|
| `alerts/` | Alert suppression/grouping for fatigue reduction |
| `attack_timeline/` | Kill chain reconstruction from MITRE tactics |
| `navigator/` | MITRE ATT&CK Navigator layer export |
| `yara_rules/` | YARA-style pattern matching engine |
| `integrity/` | Log file hash verification |
| `baselines/` | Persistent baseline storage for anomaly detection |

### Integrations

| Module | Description | API Requirements |
|--------|-------------|-------------------|
| `integrations/misp.py` | Push IOCs to MISP | MISP_URL, MISP_API_KEY |
| `integrations/thehive.py` | Create cases in TheHive | THEHIVE_URL, THEHIVE_API_KEY |
| `integrations/sigma.py` | Convert to Sigma rules | - |
| `integrations/stix.py` | STIX bundle export, TAXII feed | TAXII_SERVER, TAXII_COLLECTION |

### CLI Extensions

- `main.py` - Core CLI (parse, watch, listen, ticket, lookup)
- `cli_extended.py` - Extended commands (diff, replay, schedule, serve)

## Data Flow

```
Log File → Parser Registry → Parsers → Detection → Advanced Analysis
                                                        ↓
                                              ┌─────────────┐
                                              │   Output    │
                                              └─────────────┘
                                                        ↓
                                              ┌─────────────┐
                                              │ Integrations│
                                              └─────────────┘
```

## Configuration

### Environment Variables

```bash
# Threat Intel
VT_API_KEY
ABUSEIPDB_API_KEY
OTX_API_KEY
SHODAN_API_KEY

# SIEM Export
ES_ENDPOINT, ES_API_KEY
SPLUNK_ENDPOINT, SPLUNK_HEC_TOKEN
SUMO_ENDPOINT, SUMO_API_KEY

# Integrations
MISP_URL, MISP_API_KEY
THEHIVE_URL, THEHIVE_API_KEY
TAXII_SERVER, TAXII_COLLECTION
```

## MITRE ATT&CK Coverage

| Tactic | Technique | Detection |
|--------|-----------|-----------|
| Initial Access | T1110 Brute Force | ✓ |
| Initial Access | T1078 Valid Accounts | ✓ |
| Execution | T1059 Command/Script | ✓ |
| Persistence | T1098 Account Manipulation | ✓ |
| Privilege Escalation | T1068 Exploitation | ✓ |
| Lateral Movement | T1021 Remote Services | ✓ |
| Collection | T1005 Data from Local | ✓ |
| Exfiltration | T1048 Exfil | ✓ |

## Performance Notes

- Regex patterns pre-compiled at module level
- IP extraction uses single pattern match
- Record processing is single-pass
- Large files can use pandas for batch reading

## Extension Points

1. **New Parser**: Add function to `parsers/` and register in `LOG_PARSERS`
2. **New Detection**: Add check to `detection_checks.py`
3. **New Integration**: Add module under `integrations/`
4. **New Rule**: Add to `rules/__init__.py` or `yara_rules/__init__.py`