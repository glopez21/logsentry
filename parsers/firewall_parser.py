import re


IPTABLES_RE = re.compile(
    r"^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+kernel:\s*"
    r"(\[.*?\])?\s*(?P<body>.*)$"
)

FIREWALLD_RE = re.compile(
    r"^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+firewalld\[\d+\]:\s*(?P<body>.*)$"
)


def _extract_firewall_fields(body: str) -> dict:
    fields = {}
    for part in body.split():
        if "=" in part:
            k, v = part.split("=", 1)
            fields[k.lower()] = v.strip('"')
    return {
        "source_ip": fields.get("src", ""),
        "destination_ip": fields.get("dst", ""),
        "source_port": fields.get("spt", ""),
        "destination_port": fields.get("dpt", ""),
        "protocol": fields.get("proto", ""),
        "interface_in": fields.get("in", ""),
        "interface_out": fields.get("out", ""),
        "mac": fields.get("mac", ""),
        "action": "DROP" if "DROP" in body.upper() else "REJECT" if "REJECT" in body.upper() else "ACCEPT" if "ACCEPT" in body.upper() else "",
    }


def parse_firewall(line: str) -> dict | None:
    m = IPTABLES_RE.match(line)
    fmt = "iptables"
    body = ""
    timestamp = ""
    if not m:
        m = FIREWALLD_RE.match(line)
        fmt = "firewalld"
        if m:
            timestamp = m.group(1)
            body = m.group("body")
    else:
        timestamp = m.group(1)
        body = m.group("body")

    if not m:
        return None

    ef = _extract_firewall_fields(body)
    action = ef["action"]
    sev = "warning" if action in ("DROP", "REJECT") else "info"
    return {
        "timestamp": timestamp,
        "host": "",
        "user": "",
        "source_ip": ef["source_ip"],
        "destination_ip": ef["destination_ip"],
        "source_port": ef["source_port"],
        "destination_port": ef["destination_port"],
        "protocol": ef["protocol"],
        "action": action,
        "event_type": f"firewall_{action.lower()}" if action else "firewall_log",
        "process": fmt,
        "severity": sev,
        "raw_message": body.strip(),
        "format": fmt,
    }
