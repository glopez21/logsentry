#!/usr/bin/env python3
"""LogSentry Collector - Real-time log monitoring module."""

from .file_tail import FileTailCollector
from .syslog import SyslogListener

__all__ = ["FileTailCollector", "SyslogListener"]