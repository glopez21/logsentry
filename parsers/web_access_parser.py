import re


COMBINED_RE = re.compile(
    r'^(?P<ip>\S+)\s+'
    r'\S+\s+'
    r'\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>\S+)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\S+)\s+'
    r'"(?P<referer>[^"]*)"\s+'
    r'"(?P<ua>[^"]*)"'
)
SHORT_RE = re.compile(
    r'^(?P<ip>\S+)\s+'
    r'\S+\s+'
    r'\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>\S+)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\S+)'
)


def parse_web_access(line: str) -> dict | None:
    m = COMBINED_RE.match(line)
    if not m:
        m = SHORT_RE.match(line)
    if not m:
        return None
    g = m.groupdict()
    user = ""
    status = int(g["status"])
    if status >= 500:
        sev = "error"
    elif status >= 400:
        sev = "warning"
    else:
        sev = "info"
    return {
        "timestamp": g["timestamp"],
        "host": "",
        "user": user,
        "source_ip": g["ip"],
        "destination_ip": "",
        "event_type": f"http_{g['method'].lower()}",
        "process": "httpd",
        "http_method": g["method"],
        "http_path": g["path"],
        "http_status": status,
        "http_proto": g.get("proto", ""),
        "http_referer": g.get("referer", ""),
        "http_ua": g.get("ua", ""),
        "severity": sev,
        "raw_message": line.strip(),
        "format": "web_access",
    }
