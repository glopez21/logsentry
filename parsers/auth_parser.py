#!/usr/bin/env python3
"""Auth log parser for PAM/system auth logs."""

import re


def parse_auth_log(line: str) -> dict:
    """Parse authentication log line."""
    timestamp_match = re.match(r"^(\w{3}\s+\d+\s+\d+:\d+:\d+)", line)
    timestamp = timestamp_match.group(1) if timestamp_match else ""

    if "session opened" in line.lower():
        event_type = "session_open"
        user = re.search(r"for\s+(\S+)\s+by", line)
    elif "session closed" in line.lower():
        event_type = "session_close"
        user = re.search(r"for\s+(\S+)\s+by", line)
    elif "password changed" in line.lower():
        event_type = "password_change"
        user = re.search(r"for\s+(\S+)\s+by", line)
    elif "new password" in line.lower():
        event_type = "password_set"
        user = re.search(r"for\s+(\S+)\s+by", line)
    elif "account created" in line.lower() or "new account" in line.lower():
        event_type = "account_created"
        user = re.search(r"for\s+(\S+)\s+by", line)
    elif "account password" in line.lower():
        event_type = "account_password"
        user = re.search(r"for\s+(\S+)\s+by", line)
    else:
        return None

    return {
        "timestamp": timestamp,
        "host": "auth",
        "user": user.group(1) if user else "",
        "source_ip": re.search(r"(\d{1,3}\.){3}\d{1,3}", line).group(0) if re.search(r"(\d{1,3}\.){3}\d{1,3}", line) else "",
        "source_port": "",
        "destination_ip": "",
        "event_type": event_type,
        "raw_message": line.strip()
    }