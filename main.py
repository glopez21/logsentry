#!/usr/bin/env python3
"""
Log Triage Toolkit - Parse and normalize common security log formats.
Includes real-time log collection and alerting.
"""

import argparse
import json
import re
import sys
import os
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
    parser = argparse.ArgumentParser(
        description="LogSentry - Security log parsing and real-time monitoring",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Parse a log file:
    python main.py sample.log --triage-summary
  
  Watch a file in real-time:
    python main.py watch /var/log/auth.log
  
  Listen for syslog:
    python main.py listen --port 514 --protocol udp
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Parse command (default)
    parse_parser = subparsers.add_parser("parse", help="Parse log file (default)")
    parse_parser.add_argument("logfile", help="Path to log file")
    parse_parser.add_argument("-f", "--format", choices=["auto", "syslog", "ssh", "auth"], default="auto")
    parse_parser.add_argument("-o", "--output", choices=["csv", "json", "table"], default="table")
    parse_parser.add_argument("--triage-summary", action="store_true", help="Generate triage summary")
    parse_parser.add_argument("--severity", action="store_true", help="Add severity scores")
    parse_parser.add_argument("--timeline", action="store_true", help="Event timeline")
    parse_parser.add_argument("--correlate", action="store_true", help="Correlate events")
    parse_parser.add_argument("--report", action="store_true", help="Incident report")
    parse_parser.add_argument("--report-title", default="Security Incident Report", help="Report title")
    parse_parser.add_argument("-i", "--ip-enrich", metavar="IP", help="IP enrichment")
    parse_parser.add_argument("--mitre", action="store_true", help="MITRE ATT&CK breakdown")
    
    # Watch command
    watch_parser = subparsers.add_parser("watch", help="Watch log file in real-time")
    watch_parser.add_argument("logfile", help="Path to log file to watch")
    watch_parser.add_argument("--daemon", action="store_true", help="Run as daemon")
    watch_parser.add_argument("--console", action="store_true", help="Console alerts (default)", default=True)
    watch_parser.add_argument("--log-file", help="Alert log file")
    watch_parser.add_argument("--severity-threshold", default="low", help="Severity threshold")
    watch_parser.add_argument("--once", action="store_true", help="Process existing lines first")
    
    # Listen command
    listen_parser = subparsers.add_parser("listen", help="Listen for syslog messages")
    listen_parser.add_argument("--port", type=int, default=514, help="Syslog port")
    listen_parser.add_argument("--protocol", choices=["udp", "tcp"], default="udp", help="Protocol")
    listen_parser.add_argument("--bind", default="0.0.0.0", help="Bind address")
    listen_parser.add_argument("--console", action="store_true", help="Console alerts", default=True)
    listen_parser.add_argument("--log-file", help="Alert log file")
    listen_parser.add_argument("--severity-threshold", default="low", help="Severity threshold")
    
    # Ticket command
    ticket_parser = subparsers.add_parser("ticket", help="Create AlertFlow ticket")
    ticket_parser.add_argument("title", help="Alert title")
    ticket_parser.add_argument("-m", "--message", help="Alert message")
    ticket_parser.add_argument("-s", "--severity", default="medium", help="Severity")
    ticket_parser.add_argument("--webhook", help="Webhook URL")
    ticket_parser.add_argument("--api-url", help="API URL")
    
    # Parse arguments
    if len(sys.argv) > 1 and sys.argv[1] not in ["parse", "watch", "listen", "ticket"]:
        # Default to parse command
        sys.argv.insert(1, "parse")
    
    args = parser.parse_args()
    
    if args.command == "parse":
        run_parse(args)
    elif args.command == "watch":
        run_watch(args)
    elif args.command == "listen":
        run_listen(args)
    elif args.command == "ticket":
        run_ticket(args)
    else:
        run_parse(args)


def run_parse(args):
    """Run parse command."""
    # Handle both 'parse' subcommand and default case
    logfile = getattr(args, 'logfile', None)
    if not logfile and len(sys.argv) > 1:
        # Try to get from sys.argv directly
        logfile = sys.argv[1] if not sys.argv[1].startswith('-') else sys.argv[2]
    
    if not logfile:
        print("Error: No log file specified")
        sys.exit(1)
    
    log_format = getattr(args, 'format', 'auto')
    records = parse_log_file(logfile, log_format)

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


def run_watch(args):
    """Run watch command - real-time file monitoring."""
    try:
        from collector.file_tail import FileTailCollector
        from alerters.console import ConsoleAlerter
        from output.advanced import get_severity
    except ImportError as e:
        print(f"Error: {e}")
        print("Install required: pip install rich")
        sys.exit(1)
    
    print(f"[*] Starting file watcher for: {args.logfile}")
    
    def on_line(line: str, record: Optional[dict]) -> None:
        """Callback for each new line."""
        if not record:
            return
        
        severity = record.get("severity", "info")
        if not args.console:
            return
        
        if severity in ["critical", "high", "medium"]:
            msg = record.get("raw_message", "") or record.get("message", "")
            print(f"[{severity.upper()}] {record.get('timestamp', '')} - {msg[:80]}")
    
    try:
        collector = FileTailCollector(
            filepath=args.logfile,
            parser=parse_log_line,
            callback=on_line
        )
        collector.start(process_existing=args.once)
    except KeyboardInterrupt:
        print("\n[*] Stopped.")
    except FileNotFoundError as e:
        print(f"Error: {e}")
        sys.exit(1)


def run_listen(args):
    """Run listen command - syslog listener."""
    try:
        from collector.syslog import SyslogListener
        from output.advanced import get_severity
    except ImportError as e:
        print(f"Error: {e}")
        sys.exit(1)
    
    print(f"[*] Starting syslog listener on {args.bind}:{args.port}/{args.protocol.upper()}")
    
    def on_message(line: str, record: Optional[dict], source: tuple) -> None:
        """Callback for each syslog message."""
        if not record:
            return
        
        severity = record.get("severity", "info")
        
        if args.console and severity in ["critical", "high", "medium"]:
            msg = record.get("raw_message", "") or record.get("message", "")
            print(f"[{severity.upper()}] {source[0]} - {msg[:80]}")
    
    try:
        listener = SyslogListener(
            port=args.port,
            protocol=args.protocol,
            parser=parse_log_line,
            callback=on_message,
            bind_address=args.bind
        )
        listener.start()
        
        # Keep running
        while listener.is_running():
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopped.")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def run_ticket(args):
    """Run ticket command - create AlertFlow ticket."""
    try:
        from alerters.ticket import TicketAlerter
    except ImportError as e:
        print(f"Error: {e}")
        sys.exit(1)
    
    alerter = TicketAlerter(
        webhook_url=args.webhook,
        api_url=args.api_url
    )
    
    result = alerter.alert(
        title=args.title,
        message=args.message or "",
        severity=args.severity
    )
    
    print(f"Ticket created: {result}")


def parse_log_line(line: str) -> Optional[dict]:
    """Parse a single log line."""
    detected = detect_format(line)
    if detected:
        parser = LOG_PARSERS.get(detected)
        if parser:
            return parser(line)
    
    # Fallback to syslog
    return parse_syslog(line)

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