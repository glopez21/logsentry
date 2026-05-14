#!/usr/bin/env python3
"""Sigma rule converter - convert detection rules to Sigma format."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class SigmaRule:
    """Sigma rule representation."""
    title: str
    id: str
    status: str = "stable"
    description: str = ""
    author: str = "LogSentry"
    date: str = ""
    modified: str = ""
    tags: list[str] = None
    logsource: dict = None
    detection: dict = None
    level: str = "medium"

    def __post_init__(self):
        from datetime import date
        today = date.today().isoformat()
        if not self.date:
            self.date = today
        if not self.modified:
            self.modified = today
        if self.tags is None:
            self.tags = ["attack.t1110", "attack.credential_access"]
        if not self.logsource:
            self.logsource = {"product": "linux", "service": "auth"}

    def to_sigma_yaml(self) -> str:
        """Convert to Sigma YAML format."""
        lines = []
        lines.append(f"title: {self.title}")
        lines.append(f"id: {self.id}")
        lines.append(f"status: {self.status}")
        lines.append(f"description: {self.description}")
        lines.append(f"author: {self.author}")
        lines.append(f"date: {self.date}")
        lines.append(f"modified: {self.modified}")
        lines.append("tags:")
        for tag in self.tags:
            lines.append(f"  - {tag}")
        
        if self.logsource:
            lines.append("logsource:")
            for key, val in self.logsource.items():
                lines.append(f"    {key}: {val}")
        
        if self.detection:
            lines.append("detection:")
            for key, val in self.detection.items():
                if isinstance(val, list):
                    lines.append(f"  {key}:")
                    for item in val:
                        lines.append(f"    - '{item}'")
                else:
                    lines.append(f"  {key}: {val}")
        
        lines.append(f"level: {self.level}")
        
        return "\n".join(lines)


class SigmaConverter:
    """Convert LogSentry rules to Sigma format."""

    MITRE_TO_SIGMA = {
        "T1110": {"level": "high", "tags": ["attack.credential_access", "attack.t1110"]},
        "T1078": {"level": "medium", "tags": ["attack.privilege_escalation", "attack.t1078"]},
        "T1068": {"level": "high", "tags": ["attack.privilege_escalation", "attack.t1068"]},
        "T1021": {"level": "high", "tags": ["attack.lateral_movement", "attack.t1021"]},
        "T1048": {"level": "critical", "tags": ["attack.exfiltration", "attack.t1048"]},
        "T1059": {"level": "critical", "tags": ["attack.execution", "attack.t1059"]},
    }

    def convert_from_rules(self, rules: list[dict]) -> list[SigmaRule]:
        """Convert LogSentry rules to Sigma format."""
        sigma_rules = []
        
        for rule in rules:
            sigma_rule = SigmaRule(
                title=f"LogSentry: {rule.get('name', rule.get('id', 'Unknown'))}",
                id=self._generate_id(rule.get('name', '')),
                description=rule.get('description', ''),
                level=self._map_level(rule.get('severity', 'medium')),
                tags=self._map_tags(rule.get('mitre_tactic', '')),
            )
            
            patterns = rule.get('patterns', [])
            if patterns:
                sigma_rule.detection = {
                    "selection": patterns,
                    "condition": "selection"
                }
            
            sigma_rules.append(sigma_rule)
        
        return sigma_rules

    def convert_from_records(self, records: list[dict]) -> list[SigmaRule]:
        """Convert detected patterns to Sigma rules."""
        event_types: dict[str, list[dict]] = {}
        
        for r in records:
            et = r.get("event_type", "unknown")
            if et not in event_types:
                event_types[et] = []
            event_types[et].append(r)
        
        sigma_rules = []
        
        for event_type, recs in event_types.items():
            if len(recs) < 3:
                continue
            
            patterns = self._extract_patterns(recs)
            if not patterns:
                continue
            
            tactic = recs[0].get("mitre_tactic", "")
            sigma_rule = SigmaRule(
                title=f"LogSentry Detected: {event_type}",
                id=self._generate_id(event_type),
                description=f"Detected {len(recs)} occurrences of {event_type}",
                level="medium",
                tags=self._map_tags(tactic),
            )
            sigma_rule.detection = {"selection": patterns[:5], "condition": "selection"}
            
            sigma_rules.append(sigma_rule)
        
        return sigma_rules

    def _generate_id(self, name: str) -> str:
        """Generate Sigma rule ID."""
        clean = re.sub(r'[^a-zA-Z0-9]', '', name)
        return f"logSentry-{clean[:20]}-{abs(hash(name)) % 10000:04d}"

    def _map_level(self, severity: str) -> str:
        """Map severity to Sigma level."""
        return {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}.get(severity, "medium")

    def _map_tags(self, tactic: str) -> list[str]:
        """Map MITRE tactic to Sigma tags."""
        if tactic in self.MITRE_TO_SIGMA:
            return self.MITRE_TO_SIGMA[tactic]["tags"]
        return [f"attack.{tactic.lower()}"] if tactic else ["attack.misc"]

    def _extract_patterns(self, records: list[dict]) -> list[str]:
        """Extract common patterns from records."""
        patterns = set()
        
        for r in records:
            msg = r.get("raw_message", "") or r.get("message", "")
            if "Failed" in msg:
                patterns.add("Failed")
            if "password" in msg.lower():
                patterns.add("password")
            if "ssh" in msg.lower():
                patterns.add("ssh")
            if "from" in msg:
                patterns.add("from")
        
        return list(patterns)


def convert_to_sigma(records: list[dict]) -> dict:
    """Convert detection results to Sigma rules."""
    converter = SigmaConverter()
    sigma_rules = converter.convert_from_records(records)
    
    return {
        "status": "success",
        "rules_generated": len(sigma_rules),
        "rules": [{"title": r.title, "id": r.id, "yaml": r.to_sigma_yaml()} for r in sigma_rules]
    }


def save_sigma_rules(rules: list[SigmaRule], directory: str = "sigma_rules") -> dict:
    """Save Sigma rules to directory."""
    from pathlib import Path
    
    path = Path(directory)
    path.mkdir(exist_ok=True)
    
    saved = []
    for rule in rules:
        filename = f"{rule.id}.yml"
        filepath = path / filename
        
        with open(filepath, "w") as f:
            f.write(rule.to_sigma_yaml())
        
        saved.append(str(filepath))
    
    return {
        "status": "success",
        "count": len(saved),
        "files": saved
    }