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
        for line in Path(filepath).read_text().splitlines()[:10]:
            if detected := detect_format(line):
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
                record = parser(line)
                if record:
                    records.append(record)

    return records


def main():
    parser = argparse.ArgumentParser(description="Log Triage Toolkit")
    parser.add_argument("logfile", help="Path to log file")
    parser.add_argument("-f", "--format", choices=["auto", "syslog", "ssh", "auth"], default="auto")
    parser.add_argument("-o", "--output", choices=["csv", "json", "table"], default="table")
    parser.add_argument("--triage-summary", action="store_true", help="Generate triage summary")
    args = parser.parse_args()

    records = parse_log_file(args.logfile, args.format)

    if not records:
        print("No records parsed")
        sys.exit(1)

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