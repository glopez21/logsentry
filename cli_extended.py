#!/usr/bin/env python3
"""Additional CLI commands: diff, replay, schedule, serve."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime


def run_diff(args) -> None:
    """Compare two log files."""
    from output.advanced import get_severity
    
    def parse_file(filepath: str) -> list[dict]:
        from main import parse_log_file
        return parse_log_file(filepath)
    
    records_a = parse_file(args.file1)
    records_b = parse_file(args.file2)
    
    ips_a = set(r.get("source_ip", "") for r in records_a if r.get("source_ip"))
    ips_b = set(r.get("source_ip", "") for r in records_b if r.get("source_ip"))
    
    users_a = set(r.get("user", "") for r in records_a if r.get("user"))
    users_b = set(r.get("user", "") for r in records_b if r.get("user"))
    
    new_ips = ips_b - ips_a
    removed_ips = ips_a - ips_b
    new_users = users_b - users_a
    removed_users = users_a - users_b
    
    print("\n" + "=" * 60)
    print("LOG DIFF ANALYSIS")
    print("=" * 60)
    
    print(f"\nFile A: {args.file1} ({len(records_a)} events)")
    print(f"File B: {args.file2} ({len(records_b)} events)")
    
    print("\n--- NEW SOURCE IPs (in B but not A) ---")
    if new_ips:
        for ip in sorted(new_ips)[:20]:
            print(f"  + {ip}")
    else:
        print("  (none)")
    
    print("\n--- REMOVED SOURCE IPs (in A but not B) ---")
    if removed_ips:
        for ip in sorted(removed_ips)[:20]:
            print(f"  - {ip}")
    else:
        print("  (none)")
    
    print("\n--- NEW USERS (in B but not A) ---")
    if new_users:
        for user in sorted(new_users)[:20]:
            print(f"  + {user}")
    else:
        print("  (none)")
    
    print("\n--- REMOVED USERS (in A but not B) ---")
    if removed_users:
        for user in sorted(removed_users)[:20]:
            print(f"  - {user}")
    else:
        print("  (none)")
    
    severity_a = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    severity_b = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    
    for r in records_a:
        sev = get_severity(r.get("event_type", ""), r.get("message", ""))
        if sev in severity_a:
            severity_a[sev] += 1
    
    for r in records_b:
        sev = get_severity(r.get("event_type", ""), r.get("message", ""))
        if sev in severity_b:
            severity_b[sev] += 1
    
    print("\n--- SEVERITY COMPARISON ---")
    for sev in ["critical", "high", "medium", "low"]:
        diff = severity_b[sev] - severity_a[sev]
        sign = "+" if diff > 0 else ""
        print(f"  {sev.upper():8}: {severity_a[sev]:4} -> {severity_b[sev]:4} ({sign}{diff})")


def run_replay(args) -> None:
    """Replay log file at compressed time scale."""
    import time
    from main import parse_log_file
    
    print(f"[*] Replaying {args.file} at {args.speed}x speed")
    print("[*] Press Ctrl+C to stop")
    print()
    
    records = parse_log_file(args.file)
    
    if not records:
        print("No records to replay")
        return
    
    first_ts = None
    for r in records:
        if r.get("timestamp"):
            first_ts = r["timestamp"]
            break
    
    if not first_ts:
        print("No timestamps found in records")
        return
    
    delay = 1.0 / args.speed
    
    for i, record in enumerate(records):
        if i >= args.limit:
            break
        
        ts = record.get("timestamp", "?")
        event = record.get("event_type", "?")
        src = record.get("source_ip", "?")
        msg = (record.get("raw_message", "") or record.get("message", ""))[:60]
        
        print(f"[{ts}] [{event:15}] {src:15} {msg}")
        
        if i < len(records) - 1:
            time.sleep(delay)
    
    print(f"\n[*] Replayed {min(len(records), args.limit)} events")


def run_schedule(args) -> None:
    """Run periodic monitoring."""
    import time
    import schedule as sched
    
    print("[*] Scheduling monitoring job")
    print(f"[*] Command: {args.command}")
    print(f"[*] Interval: every {args.interval} minutes")
    
    sched.every(args.interval).minutes.do(run_scheduled_command, args.command)
    
    print("[*] Started. Press Ctrl+C to stop.")
    
    while True:
        sched.run_pending()
        time.sleep(10)


def run_scheduled_command(command: str) -> None:
    """Execute a scheduled command."""
    import subprocess
    
    print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Running: {command}")
    
    result = subprocess.run(
        command.split(),
        capture_output=True,
        text=True
    )
    
    if result.returncode == 0:
        print("  [OK] Completed")
    else:
        print(f"  [ERROR] {result.stderr[:200]}")


def run_serve(args) -> None:
    """Start REST API server."""
    try:
        from fastapi import FastAPI, UploadFile, File, HTTPException
        from fastapi.responses import JSONResponse
        import uvicorn
    except ImportError:
        print("Error: FastAPI required for server mode. Install with: pip install fastapi uvicorn")
        sys.exit(1)
    
    app = FastAPI(title="LogSentry API")
    
    @app.post("/parse")
    async def parse_logs(file: UploadFile = File(...)) -> JSONResponse:
        """Parse uploaded log file."""
        content = await file.read()
        
        try:
            lines = content.decode("utf-8").splitlines()
        except UnicodeDecodeError:
            raise HTTPException(status_code=400, detail="Invalid file encoding")
        
        from main import detect_format, LOG_PARSERS
        records = []
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            detected = detect_format(line)
            if detected:
                parser = LOG_PARSERS.get(detected)
                if parser:
                    record = parser(line)
                    if record:
                        records.append(record)
        
        return JSONResponse(content={"status": "success", "count": len(records), "records": records})
    
    @app.get("/lookup/{ip}")
    async def lookup_ip(ip: str) -> JSONResponse:
        """Threat intel lookup for IP."""
        from threat_intel import enrich_ip
        result = enrich_ip(ip)
        return JSONResponse(content=result)
    
    @app.get("/health")
    async def health() -> dict:
        """Health check endpoint."""
        return {"status": "healthy", "service": "logSentry", "version": "0.1.0"}
    
    @app.post("/export/navigator")
    async def export_navigator(file: UploadFile = File(...)) -> JSONResponse:
        """Export to MITRE ATT&CK Navigator format."""
        from navigator import export_to_navigator
        from main import detect_format, LOG_PARSERS
        
        content = await file.read()
        lines = content.decode("utf-8").splitlines()
        
        records = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            detected = detect_format(line)
            if detected:
                parser = LOG_PARSERS.get(detected)
                if parser:
                    record = parser(line)
                    if record:
                        records.append(record)
        
        result = export_to_navigator(records)
        return JSONResponse(content=result)
    
    print(f"[*] Starting LogSentry API server on {args.host}:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port)


def add_cli_commands(parser: argparse.ArgumentParser) -> None:
    """Add additional CLI commands to parser."""
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    diff_parser = subparsers.add_parser("diff", help="Compare two log files")
    diff_parser.add_argument("file1", help="First log file")
    diff_parser.add_argument("file2", help="Second log file")
    
    replay_parser = subparsers.add_parser("replay", help="Replay log file at compressed speed")
    replay_parser.add_argument("file", help="Log file to replay")
    replay_parser.add_argument("--speed", type=float, default=10.0, help="Speed multiplier (default: 10x)")
    replay_parser.add_argument("--limit", type=int, default=0, help="Limit events (0=all)")
    
    sched_parser = subparsers.add_parser("schedule", help="Run periodic monitoring")
    sched_parser.add_argument("--command", required=True, help="Command to run")
    sched_parser.add_argument("--interval", type=int, default=60, help="Interval in minutes")
    
    serve_parser = subparsers.add_parser("serve", help="Start REST API server")
    serve_parser.add_argument("--host", default="0.0.0.0", help="Bind address")
    serve_parser.add_argument("--port", type=int, default=8080, help="Port number")


def handle_command(args) -> None:
    """Route CLI commands to handlers."""
    if args.command == "diff":
        run_diff(args)
    elif args.command == "replay":
        run_replay(args)
    elif args.command == "schedule":
        run_schedule(args)
    elif args.command == "serve":
        run_serve(args)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LogSentry Extended CLI")
    add_cli_commands(parser)
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
    else:
        handle_command(args)