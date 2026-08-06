import re


MITRE_TACTICS = {
    "T1078": "Valid Accounts",
    "T1110": "Initial Access",
    "T1190": "Exploitation for Privilege Escalation",
    "T1068": "Privilege Escalation",
    "T1083": "Discovery",
    "T1046": "Service Discovery",
    "T1048": "Exfiltration",
    "T1005": "Masquerading",
    "T1082": "Lateral Movement",
    "T1021": "Remote Services",
    "T1072": "Execution",
    "T1059": "Command and Scripting Interpreter",
    "T1204": "User Execution",
    "T1047": "Windows Management Instrumentation",
    "T1027": "Obfuscated Files or Information",
    "T1080": "Exfiltration Over Alternative Protocol",
    "T1498": "Denial of Service",
    "T1557": "Man-in-the-Middle",
    "T1040": "Network Sniffing",
    "T1496": "Resource Hijacking",
    "T1071": "External Remote Services",
    "T1055": "Process Injection",
    "T1105": "Ingress Tool Transfer",
    "T1547": "Boot or Logon Autostart Execution",
    "T1004": "Execution Guardrails",
    "T1098": "Account Manipulation",
    "T1003": "OS Credential Dumping",
    "T1001": "Exfiltration Over DNS",
    "T1041": "Exfiltration Over C2 Channel",
    "T1112": "Archive Data",
}

RFC3164_RE = re.compile(
    r"^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$"
)
BARE_RFC5424_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))"
    r"\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$"
)
RFC5424_RE = re.compile(
    r"^<\d{1,3}>\d+\s+"
    r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))"
    r"\s+(\S+)"
    r"\s+(\S+)"
    r"\s+(\S+)"
    r"\s+(\S+)"
    r"\s+(?:\[.*?\]|-)\s+"
    r"(.*)$"
)


def parse_syslog(line: str) -> dict | None:
    tactic_match = re.search(r'\[TACTIC:([A-Z0-9]+)\]', line)
    mitre_tactic = tactic_match.group(1) if tactic_match else ""

    clean_line = re.sub(r'\[TACTIC:[A-Z0-9]+\]', '', line)
    m = RFC3164_RE.match(clean_line)
    if m:
        timestamp, host, process, pid, message = m.groups()
        return {
            "timestamp": timestamp,
            "host": host,
            "user": _extract_user(message),
            "source_ip": _extract_ip(message, "src"),
            "destination_ip": _extract_ip(message, "dst"),
            "event_type": "syslog",
            "process": process,
            "pid": pid or "",
            "raw_message": message.strip(),
            "mitre_tactic": mitre_tactic,
            "mitre_technique": MITRE_TACTICS.get(mitre_tactic, ""),
            "format": "syslog",
        }

    m = BARE_RFC5424_RE.match(clean_line)
    if m:
        timestamp, host, process, pid, message = m.groups()
        return {
            "timestamp": timestamp,
            "host": host,
            "user": _extract_user(message),
            "source_ip": _extract_ip(message, "src"),
            "destination_ip": _extract_ip(message, "dst"),
            "event_type": "syslog",
            "process": process,
            "pid": pid or "",
            "raw_message": message.strip(),
            "mitre_tactic": mitre_tactic,
            "mitre_technique": MITRE_TACTICS.get(mitre_tactic, ""),
            "format": "syslog",
        }

    m = RFC5424_RE.match(clean_line)
    if m:
        timestamp, host, appname, procid, msgid, message = m.groups()
        return {
            "timestamp": timestamp,
            "host": host,
            "user": _extract_user(message),
            "source_ip": _extract_ip(message, "src"),
            "destination_ip": _extract_ip(message, "dst"),
            "event_type": "syslog",
            "process": appname or "",
            "pid": procid or "",
            "raw_message": message.strip(),
            "mitre_tactic": mitre_tactic,
            "mitre_technique": MITRE_TACTICS.get(mitre_tactic, ""),
            "format": "syslog",
        }

    return None


def _extract_ip(text: str, direction: str = "src") -> str:
    pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    matches = re.findall(pattern, text)
    if not matches:
        return ""
    return matches[0] if direction == "src" else matches[-1]


def _extract_user(message: str) -> str:
    patterns = [
        r"user=(\S+)",
        r"for\s+(\S+)\s+from",
        r"=(\S+)\s+by",
    ]
    for pattern in patterns:
        match = re.search(pattern, message)
        if match:
            return match.group(1)
    return ""
