#!/usr/bin/env python3
"""
Log Triage Toolkit - Parse and normalize common security log formats.
Includes real-time log collection and alerting.
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from typing import Any, Optional

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
    correlate_events,
    generate_incident_report
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
        print("Error: Could not detect log format")
        sys.exit(1)

    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                if format_type == "auto":
                    detected = detect_format(line)
                    current_parser = LOG_PARSERS.get(detected, parser) if detected else parser
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
    parse_parser.add_argument("--yara", nargs="?", const=True, metavar="FILE", help="Scan with YARA rules")
    parse_parser.add_argument("--suppress", action="store_true", help="Alert suppression")
    parse_parser.add_argument("--navigator", metavar="FILE", help="Export to ATT&CK Navigator (JSON file)")
    parse_parser.add_argument("--attack-timeline", action="store_true", help="Reconstruct attack timeline")
    parse_parser.add_argument("--integrity", action="store_true", help="Verify log file integrity")
    parse_parser.add_argument("--export-stix", metavar="FILE", help="Export to STIX bundle")
    parse_parser.add_argument("--to-sigma", action="store_true", help="Convert to Sigma rules")
    
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
    
    # Diff command
    diff_parser = subparsers.add_parser("diff", help="Compare two log files")
    diff_parser.add_argument("file1", help="First log file")
    diff_parser.add_argument("file2", help="Second log file")
    
    # Replay command
    replay_parser = subparsers.add_parser("replay", help="Replay log file at compressed speed")
    replay_parser.add_argument("file", help="Log file to replay")
    replay_parser.add_argument("--speed", type=float, default=10.0, help="Speed multiplier")
    replay_parser.add_argument("--limit", type=int, default=0, help="Limit events (0=all)")
    
    # Schedule command
    schedule_parser = subparsers.add_parser("schedule", help="Run periodic monitoring")
    schedule_parser.add_argument("--command", required=True, help="Command to run")
    schedule_parser.add_argument("--interval", type=int, default=60, help="Interval in minutes")
    
    # Serve command
    serve_parser = subparsers.add_parser("serve", help="Start REST API server")
    serve_parser.add_argument("--host", default="0.0.0.0", help="Bind address")
    serve_parser.add_argument("--port", type=int, default=8080, help="Port number")
    
    # Daemon command
    daemon_parser = subparsers.add_parser("daemon", help="Run LogSentry as a persistent daemon")
    daemon_parser.add_argument("-c", "--config", help="Path to config file")
    daemon_parser.add_argument("--init-db", action="store_true", help="Initialize database schema and exit")
    daemon_parser.add_argument("--check", action="store_true", help="Validate config and exit")

    # Gen-rsyslog command
    rsyslog_parser = subparsers.add_parser("gen-rsyslog", help="Generate rsyslog forwarder config")
    rsyslog_parser.add_argument("--host", default="logsentry", help="LogSentry engine hostname or IP")
    rsyslog_parser.add_argument("--port", type=int, default=514, help="LogSentry syslog port")
    rsyslog_parser.add_argument("--protocol", choices=["udp", "tcp"], default="udp", help="Transport protocol")
    rsyslog_parser.add_argument("--format", choices=["rfc3164", "rfc5424"], default="rfc5424", help="Syslog format")
    rsyslog_parser.add_argument("--facility", default="*.*", help="Facility.priority filter (default: all)")
    rsyslog_parser.add_argument("-o", "--output", help="Output file (default: stdout)")

    # Query command
    query_parser = subparsers.add_parser("query", help="Query stored logs from the database")
    query_parser.add_argument("--since", help="Start time (ISO format, e.g. 2026-05-20T00:00:00Z)")
    query_parser.add_argument("--until", help="End time")
    query_parser.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"], help="Filter by severity")
    query_parser.add_argument("--source-ip", help="Filter by source IP")
    query_parser.add_argument("--event-type", help="Filter by event type")
    query_parser.add_argument("--search", help="Full-text search in log messages")
    query_parser.add_argument("--labels", help="JSON label filter (e.g. '{\"host\":\"web01\"}')")
    query_parser.add_argument("--limit", type=int, default=50, help="Max results")
    query_parser.add_argument("--offset", type=int, default=0, help="Result offset")
    query_parser.add_argument("-o", "--output", choices=["table", "json", "csv"], default="table", help="Output format")
    query_parser.add_argument("-c", "--config", help="Path to config file")

    # Tail command
    tail_parser = subparsers.add_parser("tail", help="Live-tail logs from the engine via WebSocket")
    tail_parser.add_argument("--host", default="localhost", help="LogSentry engine host")
    tail_parser.add_argument("--port", type=int, default=8080, help="LogSentry API port")
    tail_parser.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"], help="Filter by severity")
    tail_parser.add_argument("--search", help="Filter by search term")
    tail_parser.add_argument("--api-key", help="API key for authenticated endpoints")

    # Ingest command
    ingest_parser = subparsers.add_parser("ingest", help="Bulk-ingest log files into the database")
    ingest_parser.add_argument("path", help="Log file or directory to ingest")
    ingest_parser.add_argument("--recursive", action="store_true", help="Walk directories recursively")
    ingest_parser.add_argument("--pattern", default="*.log", help="Glob pattern for file discovery (default: *.log)")
    ingest_parser.add_argument("--format", choices=["auto", "syslog", "ssh", "auth", "cloudtrail"], default="auto")
    ingest_parser.add_argument("--labels", help="JSON labels to attach (e.g. '{\"host\":\"web01\",\"app\":\"nginx\"}')")
    ingest_parser.add_argument("--dry-run", action="store_true", help="Count files and lines without inserting")
    ingest_parser.add_argument("-c", "--config", help="Path to config file")

    # Parse arguments
    if len(sys.argv) > 1 and sys.argv[1] not in ["parse", "watch", "listen", "ticket", "lookup", "daemon", "gen-rsyslog", "query", "ingest"]:
        # Default to parse command
        sys.argv.insert(1, "parse")
    
    args = parser.parse_args()
    
    if args.command == "daemon":
        run_daemon(args)
    elif args.command == "gen-rsyslog":
        run_gen_rsyslog(args)
    elif args.command == "query":
        run_query(args)
    elif args.command == "ingest":
        run_ingest(args)
    elif args.command == "tail":
        run_tail(args)
    elif args.command == "parse":
        run_parse(args)
    elif args.command == "watch":
        run_watch(args)
    elif args.command == "listen":
        run_listen(args)
    elif args.command == "ticket":
        run_ticket(args)
    elif args.command == "lookup":
        run_lookup(args)
    elif args.command == "diff":
        run_diff(args)
    elif args.command == "replay":
        run_replay(args)
    elif args.command == "schedule":
        run_schedule(args)
    elif args.command == "serve":
        run_serve(args)
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
        sorted_timeline = sorted(timeline, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x.get("severity", ""), 4))
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

    if args.yara:
        from yara_rules import scan_yara
        rules_file = args.yara if isinstance(args.yara, str) else None
        result = scan_yara(records, rules_file)
        print("\nYARA Scan Results:")
        print("="*50)
        print(f"Matches: {result.get('total_matches', 0)}")
        by_sev = result.get('by_severity', {})
        for sev in ['critical', 'high', 'medium', 'low']:
            if sev in by_sev:
                print(f"  {sev.upper()}: {by_sev[sev]}")

    if args.suppress:
        from alerts import suppress_alerts as do_suppress
        result = do_suppress(records)
        print("\nAlert Suppression:")
        print("="*50)
        summary = result.get('summary', {})
        print(f"Groups: {summary.get('total_groups', 0)}")
        print(f"Suppressed: {summary.get('suppressed', 0)}")
        print(f"Reduction: {summary.get('reduction_pct', 0):.1f}%")

    if args.navigator:
        from navigator import export_to_navigator, save_navigator_layer
        result = export_to_navigator(records)
        save_navigator_layer(result, args.navigator)
        print(f"\nNavigator layer exported to: {args.navigator}")

    if args.attack_timeline:
        from attack_timeline import reconstruct_attack, format_attack_timeline
        attack_tl = reconstruct_attack(records)
        print(format_attack_timeline(attack_tl))

    if args.integrity:
        from integrity import compute_log_hash
        result = compute_log_hash(logfile)
        print("\nLog File Integrity:")
        print("="*50)
        print(f"Algorithm: {result.get('algorithm', 'sha256')}")
        print(f"Hash: {result.get('hash', 'N/A')}")
        print(f"Size: {result.get('size', 0)} bytes")

    if args.export_stix:
        from integrations.stix import export_to_stix, save_stix_bundle
        result = export_to_stix(records)
        save_stix_bundle(result['bundle'], args.export_stix)
        print(f"\nSTIX bundle exported to: {args.export_stix}")

    if args.to_sigma:
        from integrations.sigma import convert_to_sigma
        result = convert_to_sigma(records)
        print(f"\nSigma Rules Generated: {result.get('rules_generated', 0)}")


def run_diff(args):
    """Compare two log files."""
    records_a = parse_log_file(args.file1)
    records_b = parse_log_file(args.file2)

    ips_a = set(r.get("source_ip", "") for r in records_a if r.get("source_ip"))
    ips_b = set(r.get("source_ip", "") for r in records_b if r.get("source_ip"))
    users_a = set(r.get("user", "") for r in records_a if r.get("user"))
    users_b = set(r.get("user", "") for r in records_b if r.get("user"))

    print("\n" + "="*60)
    print("LOG DIFF ANALYSIS")
    print("="*60)
    print(f"\nFile A: {args.file1} ({len(records_a)} events)")
    print(f"File B: {args.file2} ({len(records_b)} events)")

    new_ips = ips_b - ips_a
    print("\n--- NEW SOURCE IPs (in B but not A) ---")
    for ip in sorted(new_ips)[:20]:
        print(f"  + {ip}")

    removed_ips = ips_a - ips_b
    print("\n--- REMOVED SOURCE IPs (in A but not B) ---")
    for ip in sorted(removed_ips)[:20]:
        print(f"  - {ip}")

    new_users = users_b - users_a
    print("\n--- NEW USERS ---")
    for user in sorted(new_users)[:20]:
        print(f"  + {user}")


def run_replay(args):
    """Replay log file at compressed speed."""
    import time
    records = parse_log_file(args.file)

    if not records:
        print("No records to replay")
        return

    print(f"[*] Replaying {args.file} at {args.speed}x speed")
    delay = 1.0 / args.speed

    for i, record in enumerate(records):
        if args.limit and i >= args.limit:
            break
        ts = record.get("timestamp", "?")
        event = record.get("event_type", "?")
        msg = (record.get("raw_message", "") or record.get("message", ""))[:60]
        print(f"[{ts}] [{event}] {msg}")
        if i < len(records) - 1:
            time.sleep(delay)

    print(f"\n[*] Replayed {min(len(records), args.limit or len(records))} events")


def run_schedule(args):
    """Run periodic monitoring."""
    import time as time_module
    interval = args.interval / 60.0

    print(f"[*] Scheduling: {args.command} every {args.interval} minutes")

    while True:
        print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Running: {args.command}")
        import subprocess
        result = subprocess.run(args.command.split(), capture_output=True, text=True)
        if result.returncode == 0:
            print("  [OK]")
        else:
            print(f"  [ERROR] {result.stderr[:200]}")
        time_module.sleep(interval * 60)


def run_watch(args):
    """Run watch command - real-time file monitoring."""
    try:
        from collector.file_tail import FileTailCollector
        from alerters.console import ConsoleAlerter  # noqa: F401
        from output.advanced import get_severity  # noqa: F401
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
        from output.advanced import get_severity  # noqa: F401
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
        AlienVaultOTXProvider, ShodanProvider,
        ThreatIntelProvider,
    )
    
    ip = args.ip
    
    if args.check_only:
        rep = check_ip_reputation(ip)
        print(f"\n[*] IP Reputation Check: {ip}")
        print("-" * 40)
        print(f"Reputation: {rep.upper()}")
        return
    
    if args.provider == "all":
        result = dict(enrich_ip(ip))
    else:
        provider: ThreatIntelProvider
        if args.provider == "vt":
            provider = VirusTotalProvider()
        elif args.provider == "abuseipdb":
            provider = AbuseIPDBProvider()
        elif args.provider == "otx":
            provider = AlienVaultOTXProvider()
        else:
            provider = ShodanProvider()
        result = provider.lookup(ip).to_dict()
    
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


def run_daemon(args) -> None:
    """Run LogSentry as a persistent daemon."""
    from config import load_config
    from daemon import LogSentryDaemon

    config = load_config(args.config)

    if args.check:
        print("Config valid:")
        import json
        print(json.dumps(config, indent=2, default=str))
        return

    if args.init_db:
        from db import LogStore
        store = LogStore(dsn=config["storage"]["dsn"])
        store.connect()
        store.init_schema()
        store.close()
        print("Database schema initialized")
        return

    daemon = LogSentryDaemon(config)
    daemon.start()


def run_gen_rsyslog(args) -> None:
    """Generate rsyslog config to forward logs to a LogSentry engine."""
    host = args.host
    port = args.port
    proto = args.protocol
    fmt = args.format
    facility = args.facility

    config_lines = f"""# LogSentry rsyslog forwarder config
# Generated by: logsentry gen-rsyslog
# Target: {host}:{port}/{proto}
#
# Install:
#   1. Copy this file to /etc/rsyslog.d/90-logsentry.conf
#   2. Restart rsyslog: sudo systemctl restart rsyslog

{config_block(host, port, proto, fmt, facility)}
"""
    output = args.output
    if output:
        with open(output, "w") as f:
            f.write(config_lines)
        print(f"rsyslog config written to {output}")
        print(f"Install: sudo cp {output} /etc/rsyslog.d/90-logsentry.conf && sudo systemctl restart rsyslog")
    else:
        print(config_lines)


def config_block(host: str, port: int, proto: str, fmt: str, facility: str) -> str:
    """Build the rsyslog config block."""
    if fmt == "rfc5424":
        template = "RSYSLOG_SyslogProtocol23Format"
    else:
        template = "RSYSLOG_TraditionalFileFormat"

    if proto == "tcp":
        target = f"@@{host}:{port}"
    else:
        target = f"@{host}:{port}"

    return f"""# LogSentry remote forwarding
# Forward {facility} to LogSentry engine via {proto.upper()}
if $syslogfacility-text != 'local0' then {{
    {facility} {target};{template}
    stop
}}

# Local0 is reserved for LogSentry agent logs (not forwarded)
local0.* /var/log/logsentry-agent.log
"""


def run_query(args) -> None:
    """Query stored logs from the database."""
    from config import load_config
    from db import LogStore
    from datetime import datetime

    config = load_config(args.config)
    store = LogStore(dsn=config["storage"]["dsn"])
    store.connect()

    kwargs: dict[str, Any] = {}
    if args.since:
        try:
            kwargs["since"] = datetime.fromisoformat(args.since)
        except ValueError:
            print(f"Invalid --since: {args.since}")
            return
    if args.until:
        try:
            kwargs["until"] = datetime.fromisoformat(args.until)
        except ValueError:
            print(f"Invalid --until: {args.until}")
            return
    if args.severity:
        kwargs["severity"] = args.severity
    if args.source_ip:
        kwargs["source_ip"] = args.source_ip
    if args.event_type:
        kwargs["event_type"] = args.event_type
    if args.search:
        kwargs["search"] = args.search
    if args.labels:
        import json
        try:
            kwargs["labels"] = json.loads(args.labels)
        except json.JSONDecodeError:
            print(f"Invalid --labels JSON: {args.labels}")
            return
    kwargs["limit"] = args.limit
    kwargs["offset"] = args.offset

    try:
        results = store.query(**kwargs)  # type: ignore[arg-type]
    except Exception as e:
        print(f"Query error: {e}")
        return
    finally:
        store.close()

    if args.output == "json":
        import json
        print(json.dumps(results, indent=2, default=str))
    elif args.output == "csv":
        import pandas as pd
        df = pd.DataFrame(results)
        df.to_csv(sys.stdout, index=False)
    else:
        if not results:
            print("No results")
            return
        from rich.table import Table
        from rich.console import Console
        console = Console()
        table = Table(title=f"Logs ({len(results)} results)")
        table.add_column("Time", style="cyan")
        table.add_column("Severity", style="bold")
        table.add_column("Source IP")
        table.add_column("Event Type")
        table.add_column("Message", width=60)
        for r in results:
            sev = r.get("severity", "info")
            style = {"critical": "red bold", "high": "red", "medium": "yellow", "low": "green", "info": "blue"}.get(sev, "")
            table.add_row(
                str(r.get("timestamp", ""))[:19],
                f"[{style}]{sev.upper()}[/]" if style else sev.upper(),
                r.get("source_ip", "") or "-",
                r.get("event_type", "") or "-",
                (r.get("message", "") or "")[:60],
            )
        console.print(table)


def run_ingest(args) -> None:
    """Bulk-ingest log files into the database."""
    from config import load_config
    from db import LogStore
    import os
    import glob as glob_mod

    config = load_config(args.config)
    path = args.path
    files: list[str] = []

    if os.path.isfile(path):
        files.append(path)
    elif os.path.isdir(path):
        pattern = f"**/{args.pattern}" if args.recursive else args.pattern
        files = sorted(glob_mod.glob(os.path.join(path, pattern), recursive=args.recursive))
    else:
        print(f"Path not found: {path}")
        return

    if not files:
        print("No files found")
        return

    labels = {}
    if args.labels:
        import json
        try:
            labels = json.loads(args.labels)
        except json.JSONDecodeError:
            print(f"Invalid --labels JSON: {args.labels}")
            return

    if args.dry_run:
        total_lines = 0
        for fp in files:
            with open(fp) as f:
                line_count = sum(1 for _ in f)
            total_lines += line_count
            print(f"  {fp}: {line_count} lines")
        print(f"\nTotal: {len(files)} files, {total_lines} lines (dry run)")
        return

    # Connect to DB for actual ingest
    store = LogStore(dsn=config["storage"]["dsn"])
    store.connect()
    store.init_schema()

    total_parsed = 0
    total_inserted = 0

    for fp in files:
        print(f"Ingesting {fp}...", end=" ", flush=True)
        records = []
        try:
            with open(fp) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    record = parse_log_line(line)
                    if record:
                        record["labels"] = {**labels, "source": "ingest", "file": fp}
                        records.append(record)
        except Exception as e:
            print(f"error: {e}")
            continue

        if records:
            try:
                inserted = store.insert_logs_batch(records)
                total_parsed += len(records)
                total_inserted += inserted
                print(f"{len(records)} parsed, {inserted} stored")
            except Exception as e:
                print(f"db error: {e}")
        else:
            print("0 records parsed")

    store.close()
    print(f"\nDone: {total_parsed} parsed, {total_inserted} stored across {len(files)} files")


def run_tail(args) -> None:
    """Live-tail logs from the engine via WebSocket."""
    import asyncio
    import json

    try:
        import websockets  # type: ignore[import-not-found]
    except ImportError:
        print("Error: websockets required. Install with: pip install websockets")
        return

    uri = f"ws://{args.host}:{args.port}/api/v1/tail/ws"
    if args.api_key:
        uri += f"?api_key={args.api_key}"
    if args.severity:
        uri += f"{'&' if '?' in uri else '?'}severity={args.severity}"
    if args.search:
        uri += f"{'&' if '?' in uri else '?'}search={args.search}"

    async def _listen():
        async with websockets.connect(uri) as ws:
            print(f"[*] Connected to {uri}")
            print("[*] Waiting for logs... (Ctrl+C to stop)")
            async for message in ws:
                data = json.loads(message)
                sev = data.get("severity", "info").upper()
                ts = str(data.get("timestamp", ""))[:19]
                src = data.get("source_ip", "") or "-"
                msg = (data.get("message", "") or "")[:80]
                print(f"[{ts}] [{sev:8}] {src:15} {msg}")

    try:
        asyncio.run(_listen())
    except KeyboardInterrupt:
        print("\n[*] Stopped.")
    except websockets.exceptions.WebSocketException as e:
        print(f"Connection error: {e}")


def run_serve(args) -> None:
    """Start REST API server with storage backend."""
    from config import load_config

    config = load_config()
    store = None

    # Initialize DB if configured
    try:
        from db import LogStore
        store = LogStore(dsn=config["storage"]["dsn"])
        store.connect()
        store.init_schema()
    except Exception as e:
        print(f"Warning: DB not available, running without storage: {e}")

    try:
        from fastapi import FastAPI, Request, UploadFile, File
        from fastapi.responses import JSONResponse
        import uvicorn
    except ImportError:
        print("Error: Install server deps with: uv sync --extra server")
        sys.exit(1)

    app = FastAPI(title="LogSentry API")

    @app.post("/ingest")
    async def ingest_logs(file: UploadFile = File(...)) -> JSONResponse:
        """Ingest log file — parse, store, and return count."""
        content = await file.read()
        lines = content.decode("utf-8").splitlines()

        records = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            record = parse_log_line(line)
            if record:
                records.append(record)

        # Store in Postgres
        inserted = 0
        if store and records:
            try:
                inserted = store.insert_logs_batch(records)
            except Exception as e:
                return JSONResponse(
                    content={"status": "error", "message": str(e), "parsed": len(records)},
                    status_code=500,
                )

        return JSONResponse(content={
            "status": "success",
            "parsed": len(records),
            "stored": inserted,
        })

    @app.get("/api/v1/query")
    async def query_logs(
        since: str = "",
        until: str = "",
        severity: str = "",
        source_ip: str = "",
        event_type: str = "",
        search: str = "",
        limit: int = 100,
        offset: int = 0,
    ) -> JSONResponse:
        """Query stored logs."""
        if not store:
            return JSONResponse(
                content={"error": "Storage not available"},
                status_code=503,
            )

        query_kwargs: dict[str, Any] = {}
        if since:
            try:
                query_kwargs["since"] = datetime.fromisoformat(since)
            except ValueError:
                pass
        if until:
            try:
                query_kwargs["until"] = datetime.fromisoformat(until)
            except ValueError:
                pass
        if severity:
            query_kwargs["severity"] = severity
        if source_ip:
            query_kwargs["source_ip"] = source_ip
        if event_type:
            query_kwargs["event_type"] = event_type
        if search:
            query_kwargs["search"] = search
        query_kwargs["limit"] = min(limit, 1000)
        query_kwargs["offset"] = offset

        try:
            results = store.query(**query_kwargs)  # type: ignore[arg-type]
            return JSONResponse(content={"count": len(results), "results": results})
        except Exception as e:
            return JSONResponse(content={"error": str(e)}, status_code=500)

    @app.get("/api/v1/stats")
    async def engine_stats() -> JSONResponse:
        """Get engine statistics."""
        if not store:
            return JSONResponse(content={"error": "Storage not available"}, status_code=503)
        try:
            stats = store.get_stats()
            return JSONResponse(content=stats)
        except Exception as e:
            return JSONResponse(content={"error": str(e)}, status_code=500)

    @app.get("/lookup/{ip}")
    async def lookup_ip(ip: str) -> JSONResponse:
        """Threat intel lookup for IP (with DB caching)."""
        from threat_intel import enrich_ip

        # Check cache first
        cached = None
        if store:
            try:
                cached = store.get_threat_intel(ip)
            except Exception:
                pass

        if cached:
            return JSONResponse(content={"cached": True, **cached})

        result = enrich_ip(ip)

        # Cache result
        if store and "error" not in result:
            try:
                store.set_threat_intel(ip, result)
            except Exception:
                pass

        return JSONResponse(content=result)

    @app.get("/health")
    async def health() -> dict:
        """Health check endpoint."""
        db_status = "connected" if store else "disconnected"
        return {
            "status": "healthy",
            "service": "logsentry",
            "version": "0.2.0",
            "database": db_status,
            "logs_stored": store.get_stats().get("total_logs", 0) if store else 0,
        }

    @app.post("/export/navigator")
    async def export_navigator(file: UploadFile = File(...)) -> JSONResponse:
        """Export to MITRE ATT&CK Navigator format."""
        from navigator import export_to_navigator

        content = await file.read()
        lines = content.decode("utf-8").splitlines()

        records = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            record = parse_log_line(line)
            if record:
                records.append(record)

        result = export_to_navigator(records)
        return JSONResponse(content=result)

    # ── Prometheus /metrics ────────────────────────────────────────
    from fastapi.responses import PlainTextResponse

    @app.get("/metrics")
    async def metrics() -> PlainTextResponse:
        """Prometheus metrics endpoint (text format)."""
        total_logs = store.get_stats().get("total_logs", 0) if store else 0
        total_dets = store.get_stats().get("total_detections", 0) if store else 0
        dets_24h = store.get_stats().get("detections_24h", 0) if store else 0
        lines = [
            "# HELP logsentry_logs_total Total logs ingested",
            "# TYPE logsentry_logs_total counter",
            f"logsentry_logs_total {total_logs}",
            "# HELP logsentry_detections_total Total detections generated",
            "# TYPE logsentry_detections_total counter",
            f"logsentry_detections_total {total_dets}",
            "# HELP logsentry_detections_24h Detections in last 24 hours",
            "# TYPE logsentry_detections_24h gauge",
            f"logsentry_detections_24h {dets_24h}",
            "# HELP logsentry_up Daemon health (1=up)",
            "# TYPE logsentry_up gauge",
            f"logsentry_up {1 if store else 0}",
        ]
        if store:
            by_sev = store.get_stats().get("by_severity", {})
            for sev in ["critical", "high", "medium", "low", "info"]:
                count = by_sev.get(sev, 0)
                if count:
                    lines.append("# HELP logsentry_logs_by_severity Logs by severity")
                    lines.append("# TYPE logsentry_logs_by_severity gauge")
                    lines.append(f'logsentry_logs_by_severity{{severity="{sev}"}} {count}')
        return PlainTextResponse("\n".join(lines) + "\n")

    # ── Grafana SimpleJSON Datasource ──────────────────────────────

    @app.get("/grafana/")
    async def grafana_root() -> dict:
        """Grafana datasource discovery."""
        return {}

    @app.get("/grafana/search")
    async def grafana_search_get() -> list[str]:
        if not store:
            return []
        return ["critical", "high", "medium", "low", "info"]

    @app.post("/grafana/search")
    async def grafana_search() -> list[str]:
        """Return searchable fields (label values)."""
        if not store:
            return []
        return ["critical", "high", "medium", "low", "info"]

    @app.post("/grafana/query")
    async def grafana_query(body: dict) -> list[dict]:
        """Return time-series data for Grafana."""
        if not store:
            return []
        try:
            targets = body.get("targets", [{}])
            target = targets[0] if targets else {}
            target_str = target.get("target", "") if isinstance(target, dict) else ""

            # Parse interval range from body
            rng = body.get("range", {})
            since_str = rng.get("from", "") if isinstance(rng, dict) else ""
            until_str = rng.get("to", "") if isinstance(rng, dict) else ""

            kwargs: dict[str, Any] = {"limit": 500}
            if since_str:
                try:
                    kwargs["since"] = datetime.fromisoformat(since_str.replace("Z", "+00:00"))
                except (ValueError, AttributeError):
                    pass
            if until_str:
                try:
                    kwargs["until"] = datetime.fromisoformat(until_str.replace("Z", "+00:00"))
                except (ValueError, AttributeError):
                    pass
            if target_str in ("critical", "high", "medium", "low", "info"):
                kwargs["severity"] = target_str
            elif target_str:
                kwargs["search"] = target_str

            results = store.query(**kwargs)  # type: ignore[arg-type]

            # Group by severity for time-series
            from collections import defaultdict
            buckets: dict[str, list[list[Any]]] = defaultdict(list)
            for r in results:
                ts = r.get("timestamp")
                sev = r.get("severity", "info")
                if ts:
                    ts_float = ts.timestamp() if hasattr(ts, "timestamp") else 0
                    buckets[sev].append([ts_float * 1000, 1])

            series = []
            for sev, points in buckets.items():
                series.append({
                    "target": f"logs.{sev}",
                    "datapoints": points,
                })
            return series if series else [{"target": "logs.empty", "datapoints": []}]
        except Exception as e:
            return [{"target": "logs.error", "datapoints": [], "error": str(e)}]

    # ── Auth Middleware ────────────────────────────────────────────
    api_key = config.get("server", {}).get("api_key", "")

    @app.middleware("http")
    async def auth_middleware(request: Request, call_next):
        if not api_key:
            return await call_next(request)
        # Paths that don't require auth
        public_paths = {"/health", "/metrics", "/grafana/", "/grafana/search"}
        if request.url.path in public_paths:
            return await call_next(request)
        # WebSocket auth via query param
        if request.url.path.endswith("/tail/ws"):
            return await call_next(request)
        header_key = request.headers.get("Authorization", "").removeprefix("Bearer ")
        query_key = request.query_params.get("api_key", "")
        if header_key == api_key or query_key == api_key:
            return await call_next(request)
        from fastapi.responses import JSONResponse
        return JSONResponse(content={"error": "Unauthorized"}, status_code=401)

    # ── WebSocket Live Tail ────────────────────────────────────────
    import asyncio
    from fastapi import WebSocket, WebSocketDisconnect

    tail_clients: dict[WebSocket, dict[str, str]] = {}
    last_tail_check = datetime.now(timezone.utc)

    @app.websocket("/api/v1/tail/ws")
    async def tail_websocket(ws: WebSocket):
        await ws.accept()
        filters: dict[str, str] = {}
        sev_filter = ws.query_params.get("severity", "")
        search_filter = ws.query_params.get("search", "")
        if sev_filter:
            filters["severity"] = sev_filter
        if search_filter:
            filters["search"] = search_filter
        tail_clients[ws] = filters
        try:
            while True:
                await ws.receive_text()
        except WebSocketDisconnect:
            tail_clients.pop(ws, None)

    async def tail_broadcaster():
        nonlocal last_tail_check
        while True:
            await asyncio.sleep(1)
            if not tail_clients or not store:
                continue
            try:
                since = last_tail_check
                last_tail_check = datetime.now(timezone.utc)
                rows = store.query(since=since, limit=200)
                if not rows:
                    continue
                for ws, filters in list(tail_clients.items()):
                    try:
                        for row in rows:
                            sev = row.get("severity", "")
                            if filters.get("severity") and sev != filters["severity"]:
                                continue
                            if filters.get("search"):
                                msg = row.get("message", "") or ""
                                if filters["search"].lower() not in msg.lower():
                                    continue
                            import json as _json
                            await ws.send_text(_json.dumps(row, default=str))
                    except Exception:
                        tail_clients.pop(ws, None)
            except Exception:
                pass

    @app.on_event("startup")
    async def _start_tail_broadcaster():
        asyncio.create_task(tail_broadcaster())

    # ── API Key auth for tail CLI ──────────────────────────────────
    @app.get("/api/v1/tail/health")
    async def tail_health() -> dict:
        return {"status": "ok", "clients": len(tail_clients)}

    print(f"[*] Starting LogSentry API server on {args.host}:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port)


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