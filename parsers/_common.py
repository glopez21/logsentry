"""Shared helpers for parsers."""

import re

_HEADER_RE = re.compile(
    r"^<\d{1,3}>\s*"
    r"(?P<ts>(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})|(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?))"
    r"\s+(?P<host>[\w.-]+)"
    r"\s+(?P<tag>[\w.-]+(?:\[\d+\])?):"
)


def split_syslog(line: str) -> tuple[str, str, str]:
    """Strip a leading syslog header.

    Returns (body, header_timestamp, host). When the line has no syslog
    header (already a raw body) the line is returned unchanged.
    """
    m = _HEADER_RE.match(line)
    if m:
        return line[m.end():].strip(), m.group("ts"), m.group("host")
    return line.strip(), "", ""
