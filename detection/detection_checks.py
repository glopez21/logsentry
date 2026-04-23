#!/usr/bin/env python3
"""Detection-friendly checks for triage summary."""

import re
from collections import defaultdict
from datetime import datetime, timedelta


MITRE_TACTICS = {
    "T1078": "Valid Accounts",
    "T1110": "Initial Access",
    "T1190": "Exploitation for Privilege Escalation",
    "T1068": "Privilege Escalation",
    "T1083": "Discovery",
    "T1046": "Service Discovery", 
    "T1048": "Exfiltration",
    "T1005": "Masquerading",
    "T1082": "Lateral Movement",
    "T1021": "Remote Services",
    "T1072": "Execution",
    "T1059": "Command and Scripting Interpreter",
    "T1204": "User Execution",
    "T1047": "Windows Management Instrumentation",
    "T1027": "Obfuscated Files or Information",
    "T1080": "Exfiltration Over Alternative Protocol",
    "T1498": "Denial of Service",
    "T1557": "Man-in-the-Middle",
    "T1040": "Network Sniffing",
    "T1496": "Resource Hijacking",
    "T1071": "External Remote Services",
    "T1055": "Process Injection",
    "T1105": "Ingress Tool Transfer",
    "T1547": "Boot or Logon Autostart Execution",
    "T1004": "Execution Guardrails",
    "T1098": "Account Manipulation",
    "T1003": "OS Credential Dumping",
    "T1001": "Exfiltration Over DNS",
    "T1041": "Exfiltration Over C2 Channel",
    "T1112": "Archive Data",
}


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
    tactics_found = defaultdict(int)
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