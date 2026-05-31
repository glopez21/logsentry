import re


APACHE_ERROR_RE = re.compile(
    r"^\[(?P<timestamp>\w{3}\s+\w{3}\s+\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+\d{4})\]"
    r"\s+\[(?P<module>[^\]]+?):(?P<severity>[^\]]+)\]"
    r"(?:\s+\[(?!client\b)[^\]]*\])*"
    r"(?:\s+\[client\s+(?P<client_ip>\S+)\])?\s*"
    r"(?P<msg>.*)$"
)

NGINX_ERROR_RE = re.compile(
    r"^(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"\[(?P<severity>\w+)\]\s+"
    r"(?P<pid>\d+)#(?P<tid>\d+):\s+"
    r"(\*(?P<conn_id>\d+)\s+)?"
    r"(?P<msg>.*)$"
)


def parse_web_error(line: str) -> dict | None:
    m = APACHE_ERROR_RE.match(line)
    fmt = "apache_error"
    if not m:
        m = NGINX_ERROR_RE.match(line)
        fmt = "nginx_error"
    if not m:
        return None
    g = m.groupdict()
    sev = g.get("severity", "error").lower()
    sev_map = {"warn": "warning", "emerg": "emerg", "crit": "critical", "alert": "alert", "notice": "notice", "debug": "debug"}
    sev = sev_map.get(sev, sev)
    return {
        "timestamp": g["timestamp"],
        "host": "",
        "user": "",
        "source_ip": g.get("client_ip", ""),
        "destination_ip": "",
        "event_type": "web_error",
        "process": fmt,
        "severity": sev,
        "raw_message": g["msg"].strip(),
        "format": fmt,
    }
