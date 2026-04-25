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
from parsers.cloudtrail_parser import parse_cloudtrail, detect_cloudtrail
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
    "cloudtrail": parse_cloudtrail,
}


def detect_format(log_line: str) -> Optional[str]:
    """Auto-detect log format from line content."""
    # Check for CloudTrail JSON first
    if detect_cloudtrail(log_line):
        return "cloudtrail"
    
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
    parse_parser.add_argument("-f", "--format", choices=["auto", "syslog", "ssh", "auth", "cloudtrail"], default="auto")
    parse_parser.add_argument("-o", "--output", choices=["csv", "json", "table"], default="table")
    parse_parser.add_argument("--triage-summary", action="store_true", help="Generate triage summary")
    parse_parser.add_argument("--severity", action="store_true", help="Add severity scores")
    parse_parser.add_argument("--timeline", action="store_true", help="Event timeline")
    parse_parser.add_argument("--correlate", action="store_true", help="Correlate events")
    parse_parser.add_argument("--report", action="store_true", help="Incident report")
    parse_parser.add_argument("--report-title", default="Security Incident Report", help="Report title")
    parse_parser.add_argument("-i", "--ip-enrich", metavar="IP", help="IP enrichment")
    parse_parser.add_argument("--enrich-all", action="store_true", help="Enrich all source IPs in log file")
    parse_parser.add_argument("--mitre", action="store_true", help="MITRE ATT&CK breakdown")
    parse_parser.add_argument("--dashboard", action="store_true", help="Display ASCII dashboard")
    parse_parser.add_argument("--rules", nargs="?", const=True, metavar="FILE", help="Run rule engine (with optional rules file)")
    parse_parser.add_argument("--anomalies", action="store_true", help="Detect anomalies")
    parse_parser.add_argument("--siem", choices=["es", "splunk", "sumo"], help="Export to SIEM")
    parse_parser.add_argument("--baseline", metavar="FILE", help="Baseline file for anomaly detection")
    
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
    
    # Lookup command - Threat Intel
    lookup_parser = subparsers.add_parser("lookup", help="Threat intel lookup for IP")
    lookup_parser.add_argument("ip", help="IP address to lookup")
    lookup_parser.add_argument("--provider", choices=["vt", "abuseipdb", "otx", "shodan", "all"], default="all", help="Provider to use")
    lookup_parser.add_argument("--json", action="store_true", help="JSON output")
    lookup_parser.add_argument("--check-only", action="store_true", help="Quick reputation check only")
    
    # Parse arguments
    if len(sys.argv) > 1 and sys.argv[1] not in ["parse", "watch", "listen", "ticket", "lookup"]:
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
    elif args.command == "lookup":
        run_lookup(args)
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
        from threat_intel import enrich_ip as ti_enrich
        result = ti_enrich(args.ip_enrich)
        print(f"\nIP Enrichment: {args.ip_enrich}")
        print("-" * 40)
        print(f"Malicious: {result.get('is_malicious', False)}")
        print(f"Malicious Votes: {result.get('malicious_votes', 0)}")
        agg = result.get("aggregated", {})
        if isinstance(agg, dict):
            print(f"Country: {agg.get('country', 'N/A')}")
            print(f"ISP: {agg.get('isp', 'N/A')}")
            print(f"Tor: {agg.get('is_tor', False)}")
            print(f"VPN: {agg.get('is_vpn', False)}")
            print(f"Proxy: {agg.get('is_proxy', False)}")
    
    if args.enrich_all:
        from threat_intel import enrich_ip as ti_enrich
        unique_ips = set(r.get("source_ip", "") for r in records if r.get("source_ip"))
        print(f"\nEnriching {len(unique_ips)} unique IPs...")
        for ip in sorted(unique_ips):
            result = ti_enrich(ip)
            rep = "MALICIOUS" if result.get("is_malicious") else "clean"
            print(f"  {ip}: {rep}")

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
    
    if args.rules is not None:
        from rules import run_rule_engine
        rules_file = args.rules if isinstance(args.rules, str) else None
        rule_results = run_rule_engine(records, rules_file)
        print("\nRule Engine Results:")
        print("=" * 50)
        print(f"Rules Evaluated: {rule_results.get('rules_evaluated', 0)}")
        print(f"Matches Found: {rule_results.get('matches', 0)}")
        for r in rule_results.get('results', [])[:10]:
            print(f"  [{r.get('severity', '?').upper():8}] {r.get('rule_name', '?')} ({r.get('count', 0)} matches)")
    
    if args.anomalies:
        from analytics import detect_anomalies
        baseline_records = None
        if args.baseline:
            baseline_records = parse_log_file(args.baseline)
        anomaly_results = detect_anomalies(records, baseline_records)
        print("\nAnomaly Detection Results:")
        print("=" * 50)
        print(f"Anomalies Detected: {anomaly_results.get('anomalies_detected', 0)}")
        summary = anomaly_results.get('summary', {})
        print(f"  Critical: {summary.get('critical', 0)}")
        print(f"  High: {summary.get('high', 0)}")
        print(f"  Medium: {summary.get('medium', 0)}")
        print(f"  Low: {summary.get('low', 0)}")
        for a in anomaly_results.get('anomalies', [])[:10]:
            print(f"  [{a.get('severity', '?').upper():8}] {a.get('description', '?')}")
    
    if args.dashboard:
        from dashboard import generate_dashboard
        print(generate_dashboard(records))
    
    if args.siem:
        from siem import export_to_siem
        print(f"\nExporting to {args.siem.upper()}...")
        siem_map = {"es": "elasticsearch", "splunk": "splunk", "sumo": "sumologic"}
        result = export_to_siem(records, provider=siem_map[args.siem])
        if result.get("status") == "success":
            print(f"Exported {result.get('exported', 0)} events successfully")
        else:
            print(f"SIEM export: {result}")

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


def run_lookup(args):
    """Run lookup command - Threat intel IP lookup."""
    from threat_intel import (
        enrich_ip, check_ip_reputation,
        VirusTotalProvider, AbuseIPDBProvider,
        AlienVaultOTXProvider, ShodanProvider
    )
    
    ip = args.ip
    
    if args.check_only:
        rep = check_ip_reputation(ip)
        print(f"\n[*] IP Reputation Check: {ip}")
        print("-" * 40)
        print(f"Reputation: {rep.upper()}")
        return
    
    if args.provider == "all":
        result = enrich_ip(ip)
    else:
        provider_map = {
            "vt": VirusTotalProvider,
            "abuseipdb": AbuseIPDBProvider,
            "otx": AlienVaultOTXProvider,
            "shodan": ShodanProvider,
        }
        provider = provider_map[args.provider]()
        result = provider.lookup(ip)
    
    if args.json:
        import json
        print(json.dumps(result, indent=2, default=str))
        return
    
    print(f"\n[*] Threat Intel Lookup: {ip}")
    print("=" * 50)
    
    if result.get("providers_queried"):
        print(f"Providers queried: {', '.join(result['providers_queried'])}")
    if result.get("providers_available"):
        print(f"Providers available (no API key): {', '.join(result['providers_available'])}")
    
    print("-" * 50)
    print(f"Is Malicious: {result.get('is_malicious', False)}")
    print(f"Malicious Votes: {result.get('malicious_votes', 0)}")
    print(f"Max Confidence: {result.get('max_confidence', 0)}")
    
    agg = result.get("aggregated", {})
    if isinstance(agg, dict):
        print(f"Country: {agg.get('country', 'Unknown')}")
        print(f"ISP: {agg.get('isp', 'Unknown')}")
        print(f"Is Tor: {agg.get('is_tor', False)}")
        print(f"Is VPN: {agg.get('is_vpn', False)}")
        print(f"Is Proxy: {agg.get('is_proxy', False)}")
        print(f"Is Datacenter: {agg.get('is_datacenter', False)}")
    
    print("\n" + "=" * 50)
    print("Provider Details:")
    for detail in result.get("details", []):
        if "error" in detail:
            continue
        print(f"\n[{detail.get('provider', 'unknown')}]")
        print(f"  Malicious: {detail.get('is_malicious', False)}")
        print(f"  Confidence: {detail.get('confidence', 0)}")
        if detail.get("country"):
            print(f"  Country: {detail['country']}")
        if detail.get("tags"):
            print(f"  Tags: {', '.join(detail['tags'][:5])}")


def parse_log_line(line: str) -> Optional[dict]:
    """Parse a single log line."""
    detected = detect_format(line)
    if detected:
        parser = LOG_PARSERS.get(detected)
        if parser:
            return parser(line)
    
    # Fallback to syslog
    return parse_syslog(line)


if __name__ == "__main__":
    main()