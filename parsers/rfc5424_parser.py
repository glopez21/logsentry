import re


RFC5424_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>"  
    r"(?P<version>\d+)"  
    r"\s+(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))"
    r"\s+(?P<host>\S+)"
    r"\s+(?P<appname>\S+)"
    r"\s+(?P<procid>\S+)"
    r"\s+(?P<msgid>\S+)"
    r"\s+(?P<structured>(?:\[.*?\]|-))"
    r"\s+(?P<msg>.*)$"
)


def parse_rfc5424(line: str) -> dict | None:
    m = RFC5424_RE.match(line)
    if not m:
        return None
    groups = m.groupdict()
    pri = int(groups["pri"])
    severity = pri & 0x07
    facility = pri >> 3
    sev_map = ["emerg", "alert", "crit", "error", "warning", "notice", "info", "debug"]
    return {
        "timestamp": groups["timestamp"],
        "host": groups["host"],
        "user": "",
        "source_ip": "",
        "destination_ip": "",
        "event_type": "syslog_rfc5424",
        "process": groups["appname"] or "",
        "pid": groups["procid"] or "",
        "facility": facility,
        "severity": sev_map[severity] if severity < len(sev_map) else "info",
        "raw_message": groups["msg"].strip(),
        "format": "rfc5424",
    }
