#!/usr/bin/env python3
"""SSH auth log parser."""

import re
from datetime import datetime


def parse_ssh_log(line: str) -> dict:
    """Parse SSH log line and extract key fields."""
    timestamp_match = re.match(r"^(\w{3}\s+\d+\s+\d+:\d+:\d+)", line)
    timestamp = timestamp_match.group(1) if timestamp_match else ""

    if "Accepted" in line:
        event_type = "ssh_login_success"
        user = re.search(r"user=(\S+)", line)
        src_ip = re.search(r"from[ =](\S+)", line)
        src_port = re.search(r"port[ =](\d+)", line)
    elif "Failed" in line:
        event_type = "ssh_login_fail"
        user = re.search(r"user=(\S+)", line)
        src_ip = re.search(r"from[ =](\S+)", line)
        src_port = re.search(r"port[ =](\d+)", line)
    elif "Invalid user" in line:
        event_type = "ssh_invalid_user"
        user = re.search(r"Invalid user\s+(\S+)", line)
        src_ip = re.search(r"from[ =](\S+)", line)
        src_port = re.search(r"port[ =](\d+)", line)
    else:
        return None

    return {
        "timestamp": timestamp,
        "host": "sshd",
        "user": user.group(1) if user else "",
        "source_ip": src_ip.group(1) if src_ip else "",
        "source_port": src_port.group(1) if src_port else "",
        "destination_ip": "",
        "event_type": event_type,
        "raw_message": line.strip()
    }