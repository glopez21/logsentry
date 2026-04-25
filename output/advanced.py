#!/usr/bin/env python3
"""Severity scoring, timeline generation, and report generation."""

import re
from datetime import datetime
from typing import Any


def enrich_ip(ip: str) -> dict:
    """Enrich IP with threat intelligence. Uses real APIs if configured, falls back to local data."""
    try:
        from threat_intel import enrich_ip as real_enrich_ip
        result = real_enrich_ip(ip)
        return result
    except ImportError:
        pass
    
    result = {
        "ip": ip,
        "type": "unknown",
        "severity": "info",
        "reputation": "unknown"
    }
    
    if not ip:
        return result
    
    for prefix, data in THREAT_INTEL.items():
        if ip.startswith(prefix):
            result.update(data)
            break
    
    return result


SEVERITY_MAP = {
    "critical": [
        "priv_esc", "Privilege escalation", "lateral_movement detected", "data_exfiltration",
        "dcsync", "pass the hash", "golden ticket", "root account", "etc/shadow"
    ],
    "high": [
        "brute force", "max authentication attempts", "exceed", "credential_stuffing",
        "mitm", "man-in-the-middle", "arp spoofing", "ssl strip", "data exfiltration",
        "root password", "password reset for root", "sudoers"
    ],
    "medium": [
        "failed password", "failed login", "invalid user", "authentication failure",
        "port scan", "suspicious process", "process injection", "registry",
        "high cpu", "outbound connection", "unexpected"
    ],
    "low": [
        "session open", "session close", "disconnect", "new session",
        "password changed", "cron job", "accepted password"
    ],
    "info": [
        "normal", "heartbeat", "keepalive", "connection", "timeout"
    ]
}

THREAT_INTEL = {
    "185.220.101.": {"type": "Tor Exit Node", "severity": "high", "reputation": "malicious"},
    "91.121.": {"type": "Known Scanner", "severity": "high", "reputation": "suspicious"},
    "45.33.32.": {"type": "Proxy/ VPN", "severity": "medium", "reputation": "suspicious"},
    "103.45.67.": {"type": "Dynamic IP", "severity": "low", "reputation": "neutral"},
}


def get_severity(event_type: str = "", message: str = "") -> str:
    """Determine severity level for an event."""
    event_type = event_type.lower()
    message = message.lower()
    combined = f"{event_type} {message}"
    
    for severity, patterns in SEVERITY_MAP.items():
        for pattern in patterns:
            if pattern.lower() in combined:
                return severity
    
    return "info"


def score_records(records: list[dict]) -> list[dict]:
    """Add severity scores to all records."""
    scored = []
    for r in records:
        event_type = r.get("event_type", "")
        message = r.get("raw_message", "") or r.get("message", "")
        severity = get_severity(event_type, message)
        r["severity"] = severity
        scored.append(r)
    return scored


def generate_timeline(records: list[dict]) -> list[dict]:
    """Generate a chronological timeline of events."""
    timeline = []
    
    for r in records:
        event_type = r.get("event_type", "")
        message = r.get("raw_message", "") or r.get("message", "")
        severity = get_severity(event_type, message)
        
        timeline.append({
            "timestamp": r.get("timestamp", ""),
            "host": r.get("host", "unknown"),
            "source_ip": r.get("source_ip", ""),
            "user": r.get("user", ""),
            "event_type": event_type,
            "severity": severity,
            "message": message[:100]
        })
    
    return sorted(timeline, key=lambda x: x["timestamp"])


def correlate_events(records: list[dict]) -> dict:
    """Correlate related events."""
    correlations = {
        "brute_force_campaigns": [],
        "port_scan_campaigns": [],
        "privilege_escalation_attempts": [],
        "lateral_movement_chains": [],
        "exfiltration_campaigns": []
    }
    
    failed_logins = [r for r in records if "fail" in r.get("event_type", "").lower()]
    if failed_logins:
        sources = set(r.get("source_ip", "") for r in failed_logins if r.get("source_ip"))
        correlations["brute_force_campaigns"] = [
            {"ip": ip, "attempts": sum(1 for r in failed_logins if r.get("source_ip") == ip)}
            for ip in sources
        ]
    
    lateral = [r for r in records if "lateral" in r.get("event_type", "").lower()]
    if lateral:
        correlations["lateral_movement_chains"] = lateral[:10]
    
    priv = [r for r in records if "priv_esc" in r.get("event_type", "").lower()]
    if priv:
        correlations["privilege_escalation_attempts"] = priv[:10]
    
    exfil = [r for r in records if "exfil" in r.get("event_type", "").lower()]
    if exfil:
        correlations["exfiltration_campaigns"] = exfil[:10]
    
    return correlations


def generate_incident_report(records: list[dict], title: str = "Security Incident Report") -> str:
    """Generate a Markdown incident report."""
    timeline = generate_timeline(records)
    correlations = correlate_events(records)
    
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for e in timeline:
        severity_counts[e.get("severity", "info")] += 1
    
    unique_ips = set(r.get("source_ip", "") for r in records if r.get("source_ip"))
    unique_users = set(r.get("user", "") for r in records if r.get("user"))
    suspicious_ips = [enrich_ip(ip) for ip in unique_ips if ip]
    
    report = f"""# {title}

## Executive Summary

- **Generated**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
- **Total Events**: {len(records)}
- **Critical Events**: {severity_counts['critical']}
- **High Severity Events**: {severity_counts['high']}
- **Medium Severity Events**: {severity_counts['medium']}

## Affected Assets

- **Unique Source IPs**: {len(unique_ips)}
- **Unique Users**: {len(unique_users)}
- **Host**: {set(r.get('host', '') for r in records).pop() if records else 'unknown'}

## Threat Intelligence

"""
    
    if suspicious_ips:
        report += "| IP Address | Type | Severity | Reputation |\n"
        report += "|----------|------|----------|------------|\n"
        for ip_data in suspicious_ips:
            if ip_data.get("reputation") != "unknown":
                report += f"| {ip_data['ip']} | {ip_data['type']} | {ip_data['severity']} | {ip_data['reputation']} |\n"
    else:
        report += "No suspicious IPs detected.\n"
    
    report += """

## Attack Correlations

"""
    
    if correlations["brute_force_campaigns"]:
        report += "### Brute Force Campaigns\n\n"
        for campaign in correlations["brute_force_campaigns"]:
            report += f"- **{campaign['ip']}**: {campaign['attempts']} failed attempts\n"
    else:
        report += "### Brute Force\n\nNo brute force detected.\n"
    
    if correlations["lateral_movement_chains"]:
        report += "\n### Lateral Movement\n\n"
        for chain in correlations["lateral_movement_chains"][:5]:
            report += f"- {chain.get('timestamp', '')}: {chain.get('message', '')[:80]}\n"
    
    if correlations["privilege_escalation_attempts"]:
        report += "\n### Privilege Escalation\n\n"
        for attempt in correlations["privilege_escalation_attempts"][:5]:
            report += f"- {attempt.get('timestamp', '')}: {attempt.get('message', '')[:80]}\n"
    
    if correlations["exfiltration_campaigns"]:
        report += "\n### Data Exfiltration\n\n"
        for exfil in correlations["exfiltration_campaigns"][:5]:
            report += f"- {exfil.get('timestamp', '')}: {exfil.get('message', '')[:80]}\n"
    
    report += """

## MITRE ATT&CK Tactics

"""
    
    from detection.detection_checks import find_mitre_tactics
    mitre_results = find_mitre_tactics(records)
    unique_tactics = mitre_results.get("tactics", {})
    
    if unique_tactics:
        report += f"**Detected Tactics**: {mitre_results.get('unique_count', 0)}\n\n"
        report += "| Technique | Events | Description |\n"
        report += "|-----------|--------|-------------|\n"
        
        from detection.detection_checks import MITRE_TACTICS
        for tactic, count in sorted(unique_tactics.items()):
            desc = MITRE_TACTICS.get(tactic, "Unknown")
            report += f"| {tactic} | {count} | {desc} |\n"
    else:
        report += "No MITRE ATT&CK tactics detected.\n"
    
    report += """

## Event Timeline

| Timestamp | Severity | Event Type | Source IP | User | Message |
|-----------|----------|-----------|-----------|------|---------|
"""
    
    for event in timeline:
        severity = event.get("severity", "info")
        if severity in ["critical", "high"]:
            report += f"| {event.get('timestamp', '')} | **{severity.upper()}** | {event.get('event_type', '')} | {event.get('source_ip', '')} | {event.get('user', '')} | {event.get('message', '')[:50]} |\n"
        else:
            report += f"| {event.get('timestamp', '')} | {severity.upper()} | {event.get('event_type', '')} | {event.get('source_ip', '')} | {event.get('user', '')} | {event.get('message', '')[:50]} |\n"
    
    report += """

## Recommendations

1. **Immediate**: Block identified malicious IPs at perimeter firewall
2. **Short-term**: Reset credentials for compromised accounts
3. **Medium-term**: Review access logs and implement MFA
4. **Long-term**: Conduct full forensic investigation

---
*Report generated by LogSentry*
"""
    
    return report