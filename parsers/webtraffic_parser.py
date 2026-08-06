#!/usr/bin/env python3
"""webtraffic parser - parses webtraffic client log lines.

Example body:
    05/Aug/2026:12:23:53  "http://192.168.1.50:80/favicon.ico" 0 0 23ms ua=Mozilla/5.0
"""

import re
from urllib.parse import urlsplit

from parsers._common import split_syslog

_BODY_RE = re.compile(
    r'(?P<ts>\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})\s+'
    r'"(?P<url>https?://[^"]+)"\s+'
    r'(?P<status>\d+)\s+(?P<size>\d+)\s+'
    r'(?P<elapsed>\d+)ms\s+ua=(?P<ua>\S+)'
)


def parse_webtraffic(line: str) -> dict | None:
    """Parse a webtraffic line; tolerant of a leading syslog header."""
    body, _hts, host = split_syslog(line)
    m = _BODY_RE.search(body)
    if not m:
        return None
    g = m.groupdict()
    status = int(g["status"])
    if status == 0:
        severity = "warning"
    elif status >= 400:
        severity = "error"
    else:
        severity = "info"
    url = g["url"]
    try:
        dest = urlsplit(url).netloc
        dest_host, _, _port = dest.rpartition(":")
    except Exception:
        dest_host = dest = ""
    return {
        "timestamp": g["ts"],
        "host": host,
        "user": "",
        "source_ip": host or "",
        "destination_ip": dest_host,
        "event_type": "http_client_request",
        "process": "webtraffic",
        "http_url": url,
        "http_status": status,
        "http_size": int(g["size"]),
        "elapsed_ms": int(g["elapsed"]),
        "http_ua": g["ua"],
        "severity": severity,
        "raw_message": line.strip(),
        "format": "webtraffic",
    }
