#!/usr/bin/env python3
"""sysmetgen parser - parses sysmetgen system metrics log lines.

Example body:
    2026-08-05T12:25:02 sysmet client1 cpu=7.2 mem=31.5 disk=42.0 netrx_kb=512 nettx_kb=98
"""

import re

from parsers._common import split_syslog

_BODY_RE = re.compile(
    r'(?:(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\s+)?'
    r'sysmet\s+(?P<host>\S+)\s+'
    r'cpu=(?P<cpu>[-\d.]+)\s+'
    r'mem=(?P<mem>[-\d.]+)\s+'
    r'disk=(?P<disk>[-\d.]+)\s+'
    r'netrx_kb=(?P<netrx_kb>[-\d.]+)\s+'
    r'nettx_kb=(?P<nettx_kb>[-\d.]+)'
)


def parse_sysmetgen(line: str) -> dict | None:
    """Parse a sysmetgen line; tolerant of a leading syslog header."""
    body, hts, host = split_syslog(line)
    m = _BODY_RE.search(body)
    if not m:
        return None
    g = m.groupdict()
    ts = g["ts"] or hts
    if not ts:
        m2 = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line)
        ts = m2.group(1) if m2 else ""
    return {
        "timestamp": ts,
        "host": g["host"] or host,
        "user": "",
        "source_ip": g["host"] or "",
        "destination_ip": "",
        "event_type": "sys_metrics",
        "process": "sysmetgen",
        "cpu_pct": float(g["cpu"]),
        "mem_pct": float(g["mem"]),
        "disk_pct": float(g["disk"]),
        "net_rx_kb": float(g["netrx_kb"]),
        "net_tx_kb": float(g["nettx_kb"]),
        "severity": "info",
        "raw_message": line.strip(),
        "format": "sysmetgen",
    }
