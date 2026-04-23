#!/usr/bin/env python3
"""
Log Triage Toolkit - Parse and normalize common security log formats.
"""

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    import pandas as pd
except ImportError:
    print("Error: pandas required. Install with: pip install pandas")
    sys.exit(1)

from parsers.syslog_parser import parse_syslog
from parsers.ssh_parser import parse_ssh_log
from parsers.auth_parser import parse_auth_log
from detection.detection_checks import run_detection_checks
from output.formatter import format_output
from output.advanced import (
    score_records,
    generate_timeline,
    enrich_ip,
    correlate_events,
    generate_incident_report,
    get_severity
)


LOG_PARSERS = {
    "syslog": parse_syslog,
    "ssh": parse_ssh_log,
    "auth": parse_auth_log,
}


def detect_format(log_line: str) -> Optional[str]:
    """Auto-detect log format from line content."""
    if "sshd" in log_line and ("Accepted" in log_line or "Failed" in log_line or "Invalid" in log_line):
        return "ssh"
    if "ssh" in log_line.lower() and ("session" in log_line.lower() or "login" in log_line.lower()):
        return "ssh"
    if re.match(r"^\w{3}\s+\d+\s+\d+:\d+:\d+", log_line):
        if "session" in log_line.lower() or "password" in log_line.lower():
            return "auth"
        return "syslog"
    if re.search(r"(Failed|password|authentication|session)", log_line, re.I):
        return "auth"
    return None


def parse_log_file(filepath: str, format_type: str = "auto") -> list[dict]:
    """Parse log file and return normalized records."""
    records = []
    parser = LOG_PARSERS.get(format_type)

    if not parser and format_type == "auto":
        with open(filepath, "r") as f:
            lines = f.readlines()
        for line in lines:
            line = line.strip()
            if not line:
                continue
            detected = detect_format(line)
            if detected:
                parser = LOG_PARSERS.get(detected)
                if parser:
                    break

    if not parser:
        print(f"Error: Could not detect log format")
        sys.exit(1)

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                if format_type == "auto":
                    detected = detect_format(line)
                    current_parser = LOG_PARSERS.get(detected) if detected else parser
                else:
                    current_parser = parser
                record = current_parser(line)
                if record:
                    records.append(record)

    return records


def main():
    parser = argparse.ArgumentParser(description="Log Triage Toolkit")
    parser.add_argument("logfile", help="Path to log file")
    parser.add_argument("-f", "--format", choices=["auto", "syslog", "ssh", "auth"], default="auto")
    parser.add_argument("-o", "--output", choices=["csv", "json", "table"], default="table")
    parser.add_argument("--triage-summary", action="store_true", help="Generate triage summary")
    parser.add_argument("--severity", action="store_true", help="Add severity scores to events")
    parser.add_argument("--timeline", action="store_true", help="Generate event timeline")
    parser.add_argument("--correlate", action="store_true", help="Correlate related events")
    parser.add_argument("--report", action="store_true", help="Generate incident report (Markdown)")
    parser.add_argument("--report-title", default="Security Incident Report", help="Title for incident report")
    parser.add_argument("-i", "--ip-enrich", metavar="IP", help="Enrich a specific IP with threat intel")
    parser.add_argument("--mitre", action="store_true", help="Show MITRE ATT&CK tactic breakdown")
    args = parser.parse_args()

    records = parse_log_file(args.logfile, args.format)

    if not records:
        print("No records parsed")
        sys.exit(1)

    if args.severity:
        records = score_records(records)
        print("\nSeverity-scored events:")
        print("-" * 60)
        for r in records[:10]:
            print(f"[{r.get('severity', 'info').upper():8}] {r.get('timestamp', '')} {r.get('event_type', '')} - {r.get('source_ip', '')}")

    if args.timeline:
        timeline = generate_timeline(records)
        print("\nEvent Timeline (sorted by severity):")
        print("-" * 80)
        sorted_timeline = sorted(timeline, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x.get("severity"), 4))
        for e in sorted_timeline[:20]:
            print(f"[{e.get('severity', 'info').upper():8}] {e.get('timestamp', '')} | {e.get('event_type', '')} | {e.get('user', '')} | {e.get('message', '')[:40]}")

    if args.correlate:
        correlations = correlate_events(records)
        print("\nEvent Correlations:")
        print("=" * 60)
        for corr_type, events in correlations.items():
            if events:
                print(f"\n{corr_type.replace('_', ' ').title()}: {len(events)} events")
                for e in events[:5]:
                    if isinstance(e, dict):
                        print(f"  - {e.get('timestamp', '')}: {e.get('message', '')[:60]}")
                    else:
                        print(f"  - {e}")

    if args.ip_enrich:
        result = enrich_ip(args.ip_enrich)
        print(f"\nIP Enrichment: {args.ip_enrich}")
        print("-" * 40)
        for k, v in result.items():
            print(f"  {k}: {v}")

    if args.mitre:
        from detection.detection_checks import find_mitre_tactics
        mitre_results = find_mitre_tactics(records)
        print("\nMITRE ATT&CK Tactics:")
        print("=" * 50)
        print(f"Unique Tactics Detected: {mitre_results.get('unique_count', 0)}")
        print("\nTactic Breakdown:")
        for tactic, count in mitre_results.get('tactics', {}).items():
            print(f"  {tactic}: {count} events")
        print("\nSamples:")
        for sample in mitre_results.get('samples', []):
            print(f"  - {sample}")

    if args.report:
        report = generate_incident_report(records, args.report_title)
        report_file = "incident_report.md"
        with open(report_file, "w") as f:
            f.write(report)
        print(f"\nIncident report written to: {report_file}")

    if args.output == "csv":
        df = pd.DataFrame(records)
        df.to_csv("triage_output.csv", index=False)
        print("Output: triage_output.csv")
    elif args.output == "json":
        with open("triage_output.json", "w") as f:
            json.dump(records, f, indent=2, default=str)
        print("Output: triage_output.json")
    else:
        format_output(records)

    if args.triage_summary:
        checks = run_detection_checks(records)
        print("\n" + "="*50)
        print("TRIAGE SUMMARY")
        print("="*50)
        for check, result in checks.items():
            if isinstance(result, list):
                print(f"\n{check}: {len(result)} events")
                for r in result[:5]:
                    print(f"  - {r}")
            else:
                print(f"{check}: {result}")


if __name__ == "__main__":
    main()