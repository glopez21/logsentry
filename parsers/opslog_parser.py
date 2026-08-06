#!/usr/bin/env python3
"""opslog parser - parses opslog admin-activity log lines.

Example body:
    2026-08-05T12:23:52 admin ops: who is logged in [rc=0]
"""

import re

from parsers._common import split_syslog

_BODY_RE = re.compile(
    r'(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+ops:\s+(?P<action>.+?)\s+\[rc=(?P<rc>\d+)\]'
)


def parse_opslog(line: str) -> dict | None:
    """Parse an opslog line; tolerant of a leading syslog header."""
    body, _hts, header_host = split_syslog(line)
    m = _BODY_RE.search(body)
    if not m:
        return None
    g = m.groupdict()
    return {
        "timestamp": g["ts"],
        "host": header_host or g["host"],
        "user": g["host"],
        "source_ip": header_host or g["host"],
        "destination_ip": "",
        "event_type": "ops_action",
        "process": "opslog",
        "ops_action": g["action"],
        "ops_rc": int(g["rc"]),
        "severity": "info",
        "raw_message": line.strip(),
        "format": "opslog",
    }
