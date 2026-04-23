#!/usr/bin/env python3
"""Syslog parser for standard syslog format."""

import re
from datetime import datetime


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


def parse_syslog(line: str) -> dict:
    """Parse a syslog line and extract key fields."""
    tactic_match = re.search(r'\[TACTIC:([A-Z0-9]+)\]', line)
    mitre_tactic = tactic_match.group(1) if tactic_match else ""
    
    clean_line = re.sub(r'\[TACTIC:[A-Z0-9]+\]', '', line)
    pattern = r"^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$"
    match = re.match(pattern, clean_line)

    if not match:
        return None

    timestamp, host, process, pid, message = match.groups()
    event_type = "syslog"
    src_ip = extract_ip(message, "src")
    dst_ip = extract_ip(message, "dst")

    return {
        "timestamp": timestamp,
        "host": host,
        "user": extract_user(message),
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "event_type": event_type,
        "process": process,
        "pid": pid,
        "raw_message": message.strip(),
        "mitre_tactic": mitre_tactic,
        "mitre_technique": MITRE_TACTICS.get(mitre_tactic, ""),
    }


def extract_ip(text: str, direction: str = "src") -> str:
    """Extract IP address from text."""
    pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    matches = re.findall(pattern, text)
    if not matches:
        return ""
    return matches[0] if direction == "src" else matches[-1]


def extract_user(message: str) -> str:
    """Extract username from message."""
    patterns = [
        r"user=(\S+)",
        r"for\s+(\S+)\s+from",
        r"=(\S+)\s+by",
    ]
    for pattern in patterns:
        match = re.search(pattern, message)
        if match:
            return match.group(1)
    return ""