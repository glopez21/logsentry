#!/usr/bin/env python3
"""dnsgen parser - parses dnsgen DNS lookup log lines.

Example body:
    2026-08-05T12:24:19 query cloudflare.com -> NXDOMAIN
    2026-08-05T12:24:29 query pypi.org -> 151.101.0.223
"""

import re

from parsers._common import split_syslog

_BODY_RE = re.compile(
    r'(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\s+'
    r'query\s+(?P<query>\S+)\s+->\s+(?P<result>\S+)'
)


def parse_dnsgen(line: str) -> dict | None:
    """Parse a dnsgen line; tolerant of a leading syslog header."""
    body, _hts, host = split_syslog(line)
    m = _BODY_RE.search(body)
    if not m:
        return None
    g = m.groupdict()
    return {
        "timestamp": g["ts"],
        "host": host,
        "user": "",
        "source_ip": host or "",
        "destination_ip": "",
        "event_type": "dns_query",
        "process": "dnsgen",
        "query_name": g["query"],
        "dns_result": g["result"],
        "severity": "info",
        "raw_message": line.strip(),
        "format": "dnsgen",
    }
