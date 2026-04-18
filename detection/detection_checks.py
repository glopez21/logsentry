#!/usr/bin/env python3
"""Detection-friendly checks for triage summary."""

import re
from collections import defaultdict
from datetime import datetime, timedelta


def run_detection_checks(records: list[dict]) -> dict:
    """Run detection checks on parsed records."""
    results = {
        "failed_logins": find_failed_login_bursts(records),
        "new_accounts": find_new_accounts(records),
        "suspicious_ips": find_suspicious_geographies(records),
        "unique_users": [],
        "unique_sources": [],
        "event_summary": {}
    }

    users = set()
    sources = set()
    event_counts = defaultdict(int)

    for r in records:
        if r.get("user"):
            users.add(r["user"])
        if r.get("source_ip"):
            sources.add(r["source_ip"])
        if r.get("event_type"):
            event_counts[r["event_type"]] += 1

    results["unique_users"] = list(users)
    results["unique_sources"] = list(sources)
    results["event_summary"] = dict(event_counts)

    return results


def find_failed_login_bursts(records: list[dict], threshold: int = 5, window_minutes: int = 10) -> list[str]:
    """Find failed login bursts from same source."""
    failed = [r for r in records if "fail" in r.get("event_type", "").lower()]
    bursts = []

    for i, record in enumerate(failed):
        src = record.get("source_ip", "") or record.get("user", "")
        if not src:
            continue

        burst_time = record.get("timestamp", "")
        count = 1

        for other in failed[i+1:]:
            if (other.get("source_ip", "") == record.get("source_ip", "") or
                other.get("user", "") == record.get("user", "")):
                count += 1

        if count >= threshold:
            bursts.append(f"{src}: {count} failed attempts")

    return list(set(bursts))[:10]


def find_new_accounts(records: list[dict]) -> list[str]:
    """Find new account creation events."""
    new_accounts = []
    for r in records:
        if r.get("event_type") in ("account_created", "new_account", "account_password"):
            new_accounts.append(f"{r.get('user', 'unknown')} created on {r.get('timestamp', '')}")
    return new_accounts


def find_suspicious_geographies(records: list[dict]) -> list[str]:
    """Check for IPs from suspicious geographies (basic check)."""
    suspicious = []
    suspicious_prefixes = ("185.220.", "91.121.", "103.", "45.", "77.")

    geo_map = {
        "185.220.101.": "Tor exit node",
        "91.121.": "Known scanner",
        "103.": "Dynamic/ISP",
        "45.": "Cloud provider",
        "77.": "Eastern Europe"
    }

    for r in records:
        ip = r.get("source_ip", "")
        if ip and ip.startswith(suspicious_prefixes):
            for prefix, geo in geo_map.items():
                if ip.startswith(prefix):
                    suspicious.append(f"{ip} ({geo})")
                    break

    return list(set(suspicious))


def is_internal_ip(ip: str) -> bool:
    """Check if IP is internal/private."""
    if not ip:
        return False
    return bool(re.match(r"^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)", ip))