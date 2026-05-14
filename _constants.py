#!/usr/bin/env python3
"""Pre-compiled regex patterns and constants for performance."""

import re
from typing import Final

IP_PATTERN: Final[re.Pattern] = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
TIMESTAMP_PATTERN: Final[re.Pattern] = re.compile(r"^(\w{3}\s+\d+\s+\d+:\d+:\d+)")
SYSLOG_PATTERN: Final[re.Pattern] = re.compile(r"^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$")
TACTIC_PATTERN: Final[re.Pattern] = re.compile(r'\[TACTIC:([A-Z0-9]+)\]')

SSH_ACCEPTED: Final[re.Pattern] = re.compile(r'Accepted', re.I)
SSH_FAILED: Final[re.Pattern] = re.compile(r'Failed', re.I)
SSH_INVALID: Final[re.Pattern] = re.compile(r'Invalid user', re.I)

USER_PATTERNS: Final[list[re.Pattern]] = [
    re.compile(r"user=(\S+)"),
    re.compile(r"for\s+(\S+)\s+from"),
    re.compile(r"=(\S+)\s+by"),
    re.compile(r"for\s+(\S+)\s+by"),
]

SUSPICIOUS_IP_PREFIXES: Final[tuple] = ("185.220.", "91.121.", "103.", "45.", "77.")

OFF_HOURS_START: Final[int] = 6
OFF_HOURS_END: Final[int] = 22

SEVERITY_THRESHOLDS: Final[dict] = {
    "critical": ["priv_esc", "Privilege escalation", "lateral_movement detected", "data_exfiltration",
                 "dcsync", "pass the hash", "golden ticket", "root account", "etc/shadow"],
    "high": ["brute force", "max authentication attempts", "exceed", "credential_stuffing",
             "mitm", "man-in-the-middle", "arp spoofing", "ssl strip", "data exfiltration",
             "root password", "password reset for root", "sudoers"],
    "medium": ["failed password", "failed login", "invalid user", "authentication failure",
               "port scan", "suspicious process", "process injection", "registry",
               "high cpu", "outbound connection", "unexpected"],
    "low": ["session open", "session close", "disconnect", "new session",
            "password changed", "cron job", "accepted password"],
    "info": ["normal", "heartbeat", "keepalive", "connection", "timeout"]
}

THREAT_INTEL_LOCAL: Final[dict] = {
    "185.220.101.": {"type": "Tor Exit Node", "severity": "high", "reputation": "malicious"},
    "91.121.": {"type": "Known Scanner", "severity": "high", "reputation": "suspicious"},
    "45.33.32.": {"type": "Proxy/VPN", "severity": "medium", "reputation": "suspicious"},
    "103.45.67.": {"type": "Dynamic IP", "severity": "low", "reputation": "neutral"},
}