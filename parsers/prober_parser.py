#!/usr/bin/env python3
"""prober parser - parses prober LAN recon log lines.

Example body:
    2026-08-05T12:23:44 probe 192.168.1.59: up
    2026-08-05T12:23:44 probe 192.168.1.59: open 22
    2026-08-05T12:23:44 probe 192.168.1.59: no open ports in [22, 80, 443, 8080]
"""

import re

from parsers._common import split_syslog

_BODY_RE = re.compile(
    r'(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\s+'
    r'probe\s+(?P<target>[\d.]+):\s+(?P<result>[^\n]+)'
)


def parse_prober(line: str) -> dict | None:
    """Parse a prober line; tolerant of a leading syslog header."""
    body, _hts, host = split_syslog(line)
    m = _BODY_RE.search(body)
    if not m:
        return None
    g = m.groupdict()
    result = g["result"].strip()
    open_ports = re.findall(r"\b(\d{1,5})\b", result.replace("no open ports", ""))
    if result.startswith("open"):
        severity = "warning"
        event_type = "port_scan"
    else:
        severity = "info"
        event_type = "network_probe"
    return {
        "timestamp": g["ts"],
        "host": host,
        "user": "",
        "source_ip": host or "",
        "destination_ip": g["target"],
        "event_type": event_type,
        "process": "prober",
        "probe_target": g["target"],
        "probe_result": result,
        "open_ports": open_ports,
        "severity": severity,
        "raw_message": line.strip(),
        "format": "prober",
    }
