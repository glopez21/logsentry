"""Pre-compiled patterns, shared constants, and common dataclasses."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Final

# ── Regex Patterns ──────────────────────────────────────────────

IP_PATTERN: Final[re.Pattern] = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
TIMESTAMP_PATTERN: Final[re.Pattern] = re.compile(r"^(\w{3}\s+\d+\s+\d+:\d+:\d+)")
SYSLOG_PATTERN: Final[re.Pattern] = re.compile(r"^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$")
TACTIC_PATTERN: Final[re.Pattern] = re.compile(r'\[TACTIC:([A-Z0-9]+)\]')

SSH_ACCEPTED: Final[re.Pattern] = re.compile(r'Accepted', re.I)
SSH_FAILED: Final[re.Pattern] = re.compile(r'Failed', re.I)
SSH_INVALID: Final[re.Pattern] = re.compile(r'Invalid user', re.I)

USER_PATTERNS: Final[list[re.Pattern]] = [
    re.compile(r"user=(\S+)"),
    re.compile(r"for\s+(\S+)\s+from"),
    re.compile(r"=(\S+)\s+by"),
    re.compile(r"for\s+(\S+)\s+by"),
]

SUSPICIOUS_IP_PREFIXES: Final[tuple[str, ...]] = ("185.220.", "91.121.", "103.", "45.", "77.")

OFF_HOURS_START: Final[int] = 6
OFF_HOURS_END: Final[int] = 22

# ── MITRE ATT&CK ────────────────────────────────────────────────

MITRE_TACTICS: Final[dict[str, str]] = {
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
    "T1136": "Create Account",
    "T1486": "Data Encrypted for Impact",
    "T1567": "Exfiltration Over Web Service",
    "T1210": "Exploitation of Remote Services",
    "T1552": "Unsecured Credentials",
    "T1562": "Impair Defenses",
    "T1070": "Indicator Removal",
    "T1543": "Create or Modify System Process",
    "T1053": "Scheduled Task/Job",
    "T1189": "Drive-by Compromise",
    "T1133": "External Remote Services",
}

MITRE_KILL_CHAIN: Final[list[dict[str, Any]]] = [
    {"phase": "reconnaissance", "tactics": ["T1595", "T1590", "T1589", "T1598"], "description": "Gathering info on target"},
    {"phase": "resource_development", "tactics": ["T1583", "T1586", "T1587"], "description": "Acquiring infrastructure"},
    {"phase": "initial_access", "tactics": ["T1189", "T1190", "T1133", "T1569", "T1078", "T0852", "T0860"], "description": "Gaining foothold"},
    {"phase": "execution", "tactics": ["T1059", "T1053", "T1609", "T1204"], "description": "Running malicious code"},
    {"phase": "persistence", "tactics": ["T1098", "T1543", "T1547", "T1505"], "description": "Maintaining access"},
    {"phase": "privilege_escalation", "tactics": ["T1068", "T1055"], "description": "Gaining higher privileges"},
    {"phase": "defense_evasion", "tactics": ["T1562", "T1070", "T1027"], "description": "Avoiding detection"},
    {"phase": "credential_access", "tactics": ["T1110", "T1552", "T1003"], "description": "Stealing credentials"},
    {"phase": "discovery", "tactics": ["T1046", "T1082", "T1083"], "description": "Exploring environment"},
    {"phase": "lateral_movement", "tactics": ["T1021", "T1210"], "description": "Moving through systems"},
    {"phase": "collection", "tactics": ["T1005", "T1560"], "description": "Gathering data"},
    {"phase": "exfiltration", "tactics": ["T1041", "T1048", "T1567"], "description": "Stealing data"},
    {"phase": "impact", "tactics": ["T1486", "T1484", "T1490"], "description": "Causing damage"},
]

ATTACK_MATRIX: Final[dict[str, list[str]]] = {
    "reconnaissance": ["T1595", "T1590", "T1589", "T1598", "T1597", "T1596", "T1594", "T1593", "T1592", "T1591"],
    "resource_development": ["T1583", "T1586", "T1587", "T1584", "T1585", "T1588"],
    "initial_access": ["T1189", "T1190", "T1133", "T1569", "T1078", "T0852", "T0860", "T0881", "T0837"],
    "execution": ["T1059", "T1053", "T1609", "T1204", "T1050", "T1072", "T1570"],
    "persistence": ["T1098", "T1543", "T1547", "T1505", "T1136", "T1546", "T1554", "T1525", "T1542"],
    "privilege_escalation": ["T1068", "T1055", "T1066", "T1067", "T1069", "T1053"],
    "defense_evasion": ["T1562", "T1070", "T1027", "T1564", "T1574", "T1556", "T1078"],
    "credential_access": ["T1110", "T1552", "T1003", "T1556", "T1558", "T1606"],
    "discovery": ["T1046", "T1082", "T1083", "T1018", "T1057", "T1010", "T1033", "T1005"],
    "lateral_movement": ["T1021", "T1210", "T1570", "T1028", "T1029", "T1071"],
    "collection": ["T1005", "T1560", "T1074", "T1114", "T1039", "T1054"],
    "command_and_control": ["T1071", "T1095", "T1105", "T1104", "T1573", "T1568"],
    "exfiltration": ["T1041", "T1048", "T1567", "T1046", "T1052"],
    "impact": ["T1486", "T1484", "T1490", "T1529", "T1485"],
}

# ── Severity / Threat Intel ─────────────────────────────────────

SEVERITY_THRESHOLDS: Final[dict[str, list[str]]] = {
    "critical": ["priv_esc", "Privilege escalation", "lateral_movement detected", "data_exfiltration",
                 "dcsync", "pass the hash", "golden ticket", "root account", "etc/shadow"],
    "high": ["brute force", "max authentication attempts", "exceed", "credential_stuffing",
             "mitm", "man-in-the-middle", "arp spoofing", "ssl strip", "data exfiltration",
             "root password", "password reset for root", "sudoers"],
    "medium": ["failed password", "failed login", "invalid user", "authentication failure",
               "port scan", "suspicious process", "process injection", "registry",
               "high cpu", "outbound connection", "unexpected"],
    "low": ["session open", "session close", "disconnect", "new session",
            "password changed", "cron job", "accepted password"],
    "info": ["normal", "heartbeat", "keepalive", "connection", "timeout"],
}

THREAT_INTEL_LOCAL: Final[dict[str, dict[str, str]]] = {
    "185.220.101.": {"type": "Tor Exit Node", "severity": "high", "reputation": "malicious"},
    "91.121.": {"type": "Known Scanner", "severity": "high", "reputation": "suspicious"},
    "45.33.32.": {"type": "Proxy/VPN", "severity": "medium", "reputation": "suspicious"},
    "103.45.67.": {"type": "Dynamic IP", "severity": "low", "reputation": "neutral"},
}

# ── Common Dataclasses ──────────────────────────────────────────

SEVERITY_ORDER: Final[list[str]] = ["critical", "high", "medium", "low", "info"]
SEVERITY_SORT: Final[dict[str, int]] = {s: i for i, s in enumerate(SEVERITY_ORDER)}
SEVERITY_MAP_SCORE: Final[dict[str, int]] = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}


@dataclass
class Baseline:
    """Statistical baseline for metric comparison."""
    metric: str
    mean: float = 0.0
    std_dev: float = 0.0
    min_val: float = 0.0
    max_val: float = 0.0
    median: float = 0.0
    p95: float = 0.0
    p99: float = 0.0
    sample_count: int = 0
    name: str = ""
    created_at: str = ""
    period_start: str = ""
    period_end: str = ""
    values: list[float] = field(default_factory=list)

    def __post_init__(self):
        if not self.name:
            self.name = self.metric

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "metric": self.metric,
            "mean": self.mean,
            "std_dev": self.std_dev,
            "min": self.min_val,
            "max": self.max_val,
            "median": self.median,
            "p95": self.p95,
            "p99": self.p99,
            "sample_count": self.sample_count,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Baseline:
        return cls(
            name=data.get("name", data.get("metric", "")),
            metric=data["metric"],
            mean=data.get("mean", 0.0),
            std_dev=data.get("std_dev", 0.0),
            min_val=data.get("min", 0.0),
            max_val=data.get("max", 0.0),
            median=data.get("median", 0.0),
            p95=data.get("p95", 0.0),
            p99=data.get("p99", 0.0),
            sample_count=data.get("sample_count", 0),
            created_at=data.get("created_at", ""),
            values=data.get("values", []),
        )

    def compare(self, value: float) -> dict[str, Any]:
        """Compare a value against this baseline."""
        if self.std_dev == 0:
            z_score = 999.0 if value > self.mean * 2 else 0.0
        else:
            z_score = (value - self.mean) / self.std_dev

        is_anomaly = abs(z_score) > 2.0
        return {
            "value": value,
            "z_score": round(z_score, 2),
            "is_anomaly": is_anomaly,
            "severity": "high" if abs(z_score) > 3 else "medium" if is_anomaly else "normal",
            "deviation": value - self.mean,
        }
