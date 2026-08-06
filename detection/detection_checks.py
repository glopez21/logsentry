"""Detection-friendly checks for triage summary."""

import re
from collections import defaultdict

from _constants import MITRE_TACTICS


def run_detection_checks(records: list[dict]) -> dict:
    """Run detection checks on parsed records."""
    results = {
        "failed_logins": find_failed_login_bursts(records),
        "new_accounts": find_new_accounts(records),
        "suspicious_ips": find_suspicious_geographies(records),
        "privilege_escalation": find_privilege_escalation(records),
        "lateral_movement": find_lateral_movement(records),
        "data_exfiltration": find_data_exfiltration(records),
        "mitre_tactics": find_mitre_tactics(records),
        "unique_users": [],
        "unique_sources": [],
        "event_summary": {}
    }

    users = set()
    sources = set()
    event_counts: dict[str, int] = defaultdict(int)

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
    """Find failed login bursts from same source within a time window.

    Uses a sliding window per source IP/user to detect bursts. If timestamps
    are unparseable, falls back to total-count detection (no windowing).
    """
    from collections import Counter
    from datetime import datetime, timedelta

    failed = [r for r in records if "fail" in r.get("event_type", "").lower()]
    if not failed:
        return []

    def _parse_ts(ts_val: str) -> datetime | None:
        """Best-effort parse of timestamp string to datetime."""
        if isinstance(ts_val, datetime):
            return ts_val
        if not ts_val:
            return None
        for fmt in (
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%b %d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
        ):
            try:
                return datetime.strptime(ts_val, fmt)
            except ValueError:
                continue
        # Handle "Jan 15 10:30:00 2026" (ssh/syslog with year at end)
        try:
            dt = datetime.strptime(ts_val, "%b %d %H:%M:%S %Y")
            return dt
        except ValueError:
            pass
        return None

    # Attempt windowed detection — if no timestamps are parseable, fall back
    # to simple counter-based detection for backward compatibility.
    ip_events: dict[str, list[tuple[datetime, str]]] = {}
    user_events: dict[str, list[tuple[datetime, str]]] = {}
    any_parsed = False

    for r in failed:
        ts = _parse_ts(r.get("timestamp", ""))
        src_ip = r.get("source_ip", "")
        user = r.get("user", "")
        if ts and src_ip:
            ip_events.setdefault(src_ip, []).append((ts, user))
            any_parsed = True
        if ts and user:
            user_events.setdefault(user, []).append((ts, src_ip))
            any_parsed = True

    if not any_parsed:
        # Fallback: count all failures (no windowing)
        ip_counts: Counter = Counter()
        user_counts: Counter = Counter()
        for r in failed:
            src_ip = r.get("source_ip", "")
            user = r.get("user", "")
            if src_ip:
                ip_counts[src_ip] += 1
            if user:
                user_counts[user] += 1
        bursts: list[str] = []
        for src, count in ip_counts.most_common():
            if count >= threshold:
                bursts.append(f"{src}: {count} failed attempts")
        for user, count in user_counts.most_common():
            if count >= threshold:
                bursts.append(f"{user}: {count} failed attempts")
        return bursts[:10]

    window = timedelta(minutes=window_minutes)
    bursts = []

    # Sliding window burst detection per source IP
    for src, events in ip_events.items():
        events.sort(key=lambda x: x[0])
        for ts_start, _ in events:
            window_end = ts_start + window
            count = sum(1 for ts, _ in events if ts <= window_end)
            if count >= threshold:
                bursts.append(f"{src}: {count} failed attempts (within {window_minutes}m window)")
                break

    # Sliding window burst detection per user
    for user, events in user_events.items():
        events.sort(key=lambda x: x[0])
        for ts_start, _ in events:
            window_end = ts_start + window
            count = sum(1 for ts, _ in events if ts <= window_end)
            if count >= threshold:
                bursts.append(f"{user}: {count} failed attempts (within {window_minutes}m window)")
                break

    return bursts[:10]


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


def find_privilege_escalation(records: list[dict]) -> list[str]:
    """Find privilege escalation indicators."""
    priv_events = []
    for r in records:
        event_type = r.get("event_type", "").lower()
        msg = r.get("raw_message", "") or r.get("message", "")
        
        if any(x in event_type for x in ["priv_esc", "escalation"]) or any(
            x in msg.lower() for x in ["sudoers", "priv escalation", "old_priv", "new_priv", "permission", "wheel group", "/etc/shadow", "/etc/passwd"]
        ):
            priv_events.append(f"{r.get('timestamp', '?')} - {r.get('user', '?')} - {msg[:60]}")
    
    return priv_events


def find_lateral_movement(records: list[dict]) -> list[str]:
    """Find lateral movement indicators."""
    lateral_events = []
    for r in records:
        event_type = r.get("event_type", "").lower()
        msg = r.get("raw_message", "") or r.get("message", "")
        
        if any(x in event_type for x in ["lateral", "psexec", "wmi", "smb", "rdp"]) or any(
            x in msg.lower() for x in ["lateral", "smb session", "winrm", "rdp connection", "provider"]
        ):
            lateral_events.append(f"{r.get('timestamp', '?')} - {r.get('source_ip', '?')} -> {msg[:60]}")
    
    return lateral_events


def find_data_exfiltration(records: list[dict]) -> list[str]:
    """Find data exfiltration indicators."""
    exfil_events = []
    for r in records:
        event_type = r.get("event_type", "").lower()
        msg = r.get("raw_message", "") or r.get("message", "")
        
        if any(x in event_type for x in ["exfil", "exfiltration"]) or any(
            x in msg.lower() for x in ["exfil", "dns txt", "large file", "archive upload", "outbound connection"]
        ):
            src = r.get("source_ip", "")
            exfil_events.append(f"{r.get('timestamp', '?')} - {src} - {msg[:60]}")
    
    return exfil_events


def find_mitre_tactics(records: list[dict]) -> dict:
    """Find and summarize MITRE ATT&CK tactics."""
    tactics_found: dict[str, int] = defaultdict(int)
    tactic_details = []
    
    for r in records:
        tactic = r.get("mitre_tactic", "")
        if tactic:
            tactics_found[tactic] += 1
            technique = r.get("mitre_technique", MITRE_TACTICS.get(tactic, ""))
            if technique:
                tactic_details.append(f"{tactic}: {technique}")
    
    unique_tactics = dict(tactics_found)
    return {
        "unique_count": len(unique_tactics),
        "tactics": unique_tactics,
        "samples": tactic_details[:5]
    }