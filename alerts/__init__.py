#!/usr/bin/env python3
"""Alert suppression and grouping to reduce alert fatigue."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional
from collections import defaultdict


@dataclass
class AlertGroup:
    """Grouped alerts with suppression metadata."""
    source_ip: str
    event_type: str
    count: int = 1
    first_seen: str = ""
    last_seen: str = ""
    severity: str = "medium"
    records: list[dict] = field(default_factory=list)
    suppressed: bool = False

    def to_dict(self) -> dict:
        return {
            "source_ip": self.source_ip,
            "event_type": self.event_type,
            "count": self.count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "severity": self.severity,
            "suppressed": self.suppressed,
            "sample_records": self.records[:3],
        }


class AlertSuppressor:
    """Suppress redundant alerts through grouping."""

    def __init__(self, window_seconds: int = 60, threshold: int = 5):
        self.window_seconds = window_seconds
        self.threshold = threshold
        self._groups: dict[str, AlertGroup] = {}

    def _get_key(self, record: dict) -> str:
        ip = record.get("source_ip", "unknown")
        event_type = record.get("event_type", "unknown")
        return f"{ip}:{event_type}"

    def _get_severity(self, records: list[dict]) -> str:
        severity_order = ["critical", "high", "medium", "low", "info"]
        for r in records:
            sev = r.get("severity", "info")
            if sev in severity_order:
                return sev
        return "medium"

    def add_alert(self, record: dict) -> Optional[AlertGroup]:
        key = self._get_key(record)
        
        if key in self._groups:
            group = self._groups[key]
            group.count += 1
            group.records.append(record)
            
            if group.count >= self.threshold:
                group.suppressed = True
            
            return group
        
        severity = self._get_severity([record])
        group = AlertGroup(
            source_ip=record.get("source_ip", "unknown"),
            event_type=record.get("event_type", "unknown"),
            first_seen=record.get("timestamp", ""),
            last_seen=record.get("timestamp", ""),
            severity=severity,
            records=[record]
        )
        self._groups[key] = group
        return group

    def process_records(self, records: list[dict]) -> list[AlertGroup]:
        groups = []
        for record in records:
            group = self.add_alert(record)
            if group:
                groups.append(group)
        return groups

    def get_suppressed(self) -> list[AlertGroup]:
        return [g for g in self._groups.values() if g.suppressed]

    def get_active(self) -> list[AlertGroup]:
        return [g for g in self._groups.values() if not g.suppressed]

    def get_summary(self) -> dict:
        return {
            "total_groups": len(self._groups),
            "suppressed": len(self.get_suppressed()),
            "active": len(self.get_active()),
            "total_alerts": sum(g.count for g in self._groups.values()),
            "reduction_pct": (
                sum(g.count - 1 for g in self.get_suppressed()) / 
                sum(g.count for g in self._groups.values()) * 100 
                if self._groups else 0
            )
        }


def suppress_alerts(records: list[dict], window_seconds: int = 60, threshold: int = 5) -> dict:
    """Suppress alerts by grouping similar events."""
    suppressor = AlertSuppressor(window_seconds, threshold)
    groups = suppressor.process_records(records)
    
    return {
        "status": "success",
        "groups": [g.to_dict() for g in groups],
        "summary": suppressor.get_summary(),
        "suppressed_count": len(suppressor.get_suppressed()),
        "active_count": len(suppressor.get_active()),
    }


def group_by_severity(groups: list[AlertGroup]) -> dict[str, list[AlertGroup]]:
    """Group alerts by severity level."""
    result = defaultdict(list)
    for group in groups:
        result[group.severity].append(group)
    return dict(result)


def format_suppression_report(groups: list[AlertGroup]) -> str:
    """Format suppression report as readable text."""
    lines = []
    lines.append("\n" + "=" * 60)
    lines.append("ALERT SUPPRESSION REPORT")
    lines.append("=" * 60)
    
    suppressed = [g for g in groups if g.suppressed]
    active = [g for g in groups if not g.suppressed]
    
    lines.append(f"\nSuppressed: {len(suppressed)} groups")
    lines.append(f"Active: {len(active)} groups")
    
    if suppressed:
        lines.append("\n--- SUPPRESSED ALERTS ---")
        for g in suppressed[:10]:
            lines.append(f"  [{g.severity.upper():8}] {g.source_ip}:{g.event_type} ({g.count} events)")
    
    if active:
        lines.append("\n--- ACTIVE ALERTS ---")
        for g in active[:10]:
            lines.append(f"  [{g.severity.upper():8}] {g.source_ip}:{g.event_type} ({g.count} events)")
    
    return "\n".join(lines)