#!/usr/bin/env python3
"""YARA-style rule engine for pattern matching."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class YaraRule:
    """YARA-style detection rule."""
    name: str
    description: str = ""
    severity: str = "medium"
    patterns: list[str] = field(default_factory=list)
    condition: str = ""
    threshold: int = 1
    mitre_tactic: str = ""
    mitre_technique: str = ""
    enabled: bool = True

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "patterns": self.patterns,
            "condition": self.condition,
            "threshold": self.threshold,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "enabled": self.enabled,
        }


@dataclass
class YaraMatch:
    """Result of a YARA-style rule match."""
    rule_name: str
    matched_text: str
    position: int
    severity: str
    record: dict

    def to_dict(self) -> dict:
        return {
            "rule_name": self.rule_name,
            "matched_text": self.matched_text[:50],
            "position": self.position,
            "severity": self.severity,
            "timestamp": self.record.get("timestamp", ""),
            "source_ip": self.record.get("source_ip", ""),
        }


class YaraEngine:
    """YARA-style pattern matching engine."""

    BUILT_IN_RULES: list[YaraRule] = [
        YaraRule(
            name="SSH_BruteForce",
            description="Multiple SSH authentication failures",
            severity="high",
            patterns=[r"Failed.*password", r"Invalid user"],
            condition="count > 5",
            threshold=6,
            mitre_tactic="T1110"
        ),
        YaraRule(
            name="Suspicious_IP_Connection",
            description="Connection from known bad IP range",
            severity="high",
            patterns=[r"185\.220\.", r"91\.121\.", r"Tor"],
            mitre_tactic="T1078"
        ),
        YaraRule(
            name="Privilege_Escalation",
            description="Privilege escalation attempt",
            severity="critical",
            patterns=[r"sudo.*root", r"su:.*AUTHFAIL", r"/etc/shadow", r"/etc/passwd"],
            threshold=1,
            mitre_tactic="T1068"
        ),
        YaraRule(
            name="Data_Exfiltration",
            description="Potential data exfiltration",
            severity="critical",
            patterns=[r"archive.*upload", r"exfil.*connection", r"large.*file.*access"],
            threshold=1,
            mitre_tactic="T1048"
        ),
        YaraRule(
            name="Malware_Execution",
            description="Suspicious process execution",
            severity="high",
            patterns=[r"powershell.*-enc", r"cmd\.exe.*/c", r"base64.*decode"],
            mitre_tactic="T1059"
        ),
        YaraRule(
            name="Lateral_Movement",
            description="Lateral movement indicators",
            severity="high",
            patterns=[r"smb.*session", r"rdp.*connection", r"winrm.*remote"],
            threshold=2,
            mitre_tactic="T1021"
        ),
        YaraRule(
            name="Tor_Exit_Node",
            description="Connection from Tor exit node",
            severity="high",
            patterns=[r"185\.220\.101\."],
            threshold=1,
            mitre_tactic="T1078"
        ),
        YaraRule(
            name="Password_Spray",
            description="Single password tried across many users",
            severity="medium",
            patterns=[r"Failed.*from", r"authentication.*fail"],
            condition="multiple_users",
            mitre_tactic="T1110"
        ),
    ]

    def __init__(self, rules: list[YaraRule] | None = None):
        self.rules = rules or self.BUILT_IN_RULES.copy()
        self._compiled: dict[str, list[re.Pattern]] = {}
        self._compile_rules()

    def _compile_rules(self):
        for rule in self.rules:
            compiled = []
            for pattern in rule.patterns:
                try:
                    compiled.append(re.compile(pattern, re.IGNORECASE))
                except re.error:
                    compiled.append(re.compile(re.escape(pattern), re.IGNORECASE))
            self._compiled[rule.name] = compiled

    def scan_record(self, record: dict) -> list[YaraMatch]:
        """Scan a single record against all rules."""
        matches = []
        text = (record.get("raw_message", "") + " " + record.get("message", "")).lower()
        
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            compiled_patterns = self._compiled.get(rule.name, [])
            for pattern in compiled_patterns:
                match = pattern.search(text)
                if match:
                    matches.append(YaraMatch(
                        rule_name=rule.name,
                        matched_text=match.group(0),
                        position=match.start(),
                        severity=rule.severity,
                        record=record
                    ))
                    break
        
        return matches

    def scan_records(self, records: list[dict]) -> list[YaraMatch]:
        """Scan all records against all rules."""
        all_matches = []
        for record in records:
            all_matches.extend(self.scan_record(record))
        return all_matches

    def apply_thresholds(self, matches: list[YaraMatch]) -> list[YaraMatch]:
        """Filter matches based on thresholds."""
        rule_counts: dict[str, int] = {}
        
        for match in matches:
            rule_counts[match.rule_name] = rule_counts.get(match.rule_name, 0) + 1
        
        filtered = []
        for match in matches:
            rule = next((r for r in self.rules if r.name == match.rule_name), None)
            if rule and rule_counts[match.rule_name] >= rule.threshold:
                filtered.append(match)
        
        return filtered


def scan_yara(records: list[dict], rules_file: str | None = None) -> dict:
    """Scan records with YARA-style rules."""
    engine = YaraEngine()
    
    if rules_file:
        engine = YaraEngine(load_rules_from_file(rules_file))
    
    matches = engine.scan_records(records)
    matches = engine.apply_thresholds(matches)
    
    by_severity: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_rule: dict[str, int] = {}
    
    for m in matches:
        by_severity[m.severity] = by_severity.get(m.severity, 0) + 1
        by_rule[m.rule_name] = by_rule.get(m.rule_name, 0) + 1
    
    return {
        "status": "success",
        "total_matches": len(matches),
        "by_severity": by_severity,
        "by_rule": by_rule,
        "matches": [m.to_dict() for m in matches[:50]],
    }


def load_rules_from_file(filepath: str) -> list[YaraRule]:
    """Load YARA-style rules from file."""
    import json
    import yaml
    
    path = filepath
    if filepath.endswith(".yaml") or filepath.endswith(".yml"):
        with open(filepath) as f:
            data = yaml.safe_load(f)
    elif filepath.endswith(".json"):
        with open(filepath) as f:
            data = json.load(f)
    else:
        return []
    
    rules = []
    rules_data = data if isinstance(data, list) else data.get("rules", [])
    
    for r in rules_data:
        rules.append(YaraRule(
            name=r.get("name", "Unknown"),
            description=r.get("description", ""),
            severity=r.get("severity", "medium"),
            patterns=r.get("patterns", []),
            threshold=r.get("threshold", 1),
            mitre_tactic=r.get("mitre_tactic", ""),
            mitre_technique=r.get("mitre_technique", ""),
            enabled=r.get("enabled", True),
        ))
    
    return rules


def create_sample_yara_file(path: str = "rules_yara.yaml") -> dict:
    """Create a sample YARA-style rules file."""
    content = """rules:
  - name: Custom_Rule
    description: Example YARA-style rule
    severity: high
    patterns:
      - "failed.*login"
      - "suspicious.*connection"
    threshold: 3
    mitre_tactic: T1110
"""
    with open(path, "w") as f:
        f.write(content)
    return {"status": "created", "path": path}