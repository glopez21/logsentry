#!/usr/bin/env python3
"""weathergen parser - parses weathergen weather snapshot log lines.

Example body:
    2026-08-05T12:25:01 weather client1 41.90,-87.63 temp_c=22.4 hum=58 wind_kph=11.3 precip_mm=0.0 pressure=1015.2
"""

import re

from parsers._common import split_syslog

_BODY_RE = re.compile(
    r'(?:(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\s+)?'
    r'weather\s+(?P<host>\S+)\s+'
    r'(?P<location>\S+)\s+'
    r'temp_c=(?P<temp_c>[-\d.]+)\s+'
    r'hum=(?P<humidity>[-\d.]+)\s+'
    r'wind_kph=(?P<wind_kph>[-\d.]+)\s+'
    r'precip_mm=(?P<precip_mm>[-\d.]+)\s+'
    r'pressure=(?P<pressure>[-\d.]+)'
)


def parse_weathergen(line: str) -> dict | None:
    """Parse a weathergen line; tolerant of a leading syslog header."""
    body, hts, _host = split_syslog(line)
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
        "host": g["host"],
        "user": "",
        "source_ip": g["host"] or "",
        "destination_ip": "",
        "event_type": "weather_snapshot",
        "process": "weathergen",
        "location": g["location"],
        "temp_c": float(g["temp_c"]),
        "humidity": float(g["humidity"]),
        "wind_kph": float(g["wind_kph"]),
        "precip_mm": float(g["precip_mm"]),
        "pressure": float(g["pressure"]),
        "severity": "info",
        "raw_message": line.strip(),
        "format": "weathergen",
    }
