#!/usr/bin/env python3
"""Syslog parser for standard syslog format."""

import re
from datetime import datetime


def parse_syslog(line: str) -> dict:
    """Parse a syslog line and extract key fields."""
    pattern = r"^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$"
    match = re.match(pattern, line)

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
        "raw_message": message.strip()
    }


def extract_ip(text: str, direction: str = "src") -> str:
    """Extract IP address from text."""
    pattern = r"(\d{1,3}\.){3}\d{1,3}"
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