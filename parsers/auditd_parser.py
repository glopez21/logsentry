import re


AUDIT_RE = re.compile(
    r"^type=(?P<type>\S+)\s+"
    r"msg=audit\((?P<unix_ts>\d+)(?:\.\d+)?:(?P<serial>\d+)\):\s*"
    r"(?P<body>.*)$"
)

KEY_MAP = {
    "SYSCALL": "audit_syscall",
    "USER_AUTH": "audit_user_auth",
    "USER_LOGIN": "audit_user_login",
    "USER_CMD": "audit_user_cmd",
    "USER_END": "audit_user_end",
    "USER_ACCT": "audit_user_acct",
    "CRED_ACQ": "audit_cred_acq",
    "CRED_DISP": "audit_cred_disp",
    "LOGIN": "audit_login",
    "ANOM_ABEND": "audit_anom_abend",
    "ANOM_LOGIN_FAILURES": "audit_anom_login",
    "EXECVE": "audit_execve",
    "PROCTITLE": "audit_proctitle",
    "CWD": "audit_cwd",
    "PATH": "audit_path",
}


def parse_auditd(line: str) -> dict | None:
    m = AUDIT_RE.match(line)
    if not m:
        return None
    g = m.groupdict()
    audit_type = g["type"]
    unix_ts = g["unix_ts"]
    from datetime import datetime, timezone
    ts = datetime.fromtimestamp(int(unix_ts), tz=timezone.utc).isoformat()
    body = g["body"]
    src_ip = ""
    user = ""
    m_ip = re.search(r"(?:addr|src)=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", body)
    if m_ip:
        src_ip = m_ip.group(1)
    m_user = re.search(r"(?:uid|auid|acct)=(\S+)", body)
    if m_user:
        user = m_user.group(1)
    return {
        "timestamp": ts,
        "host": "",
        "user": user,
        "source_ip": src_ip,
        "destination_ip": "",
        "event_type": KEY_MAP.get(audit_type, f"audit_{audit_type.lower()}"),
        "process": audit_type,
        "severity": "info",
        "raw_message": body.strip(),
        "format": "auditd",
    }
