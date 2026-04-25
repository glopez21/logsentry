#!/usr/bin/env python3
"""Rule engine for custom detection rules."""

import re
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path


@dataclass
class DetectionRule:
    """A detection rule definition."""
    id: str
    name: str
    description: str
    severity: str = "medium"
    condition: str = ""
    patterns: list[str] = field(default_factory=list)
    threshold: int = 1
    time_window: int = 0
    mitre_tactic: str = ""
    mitre_technique: str = ""
    enabled: bool = True
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "condition": self.condition,
            "patterns": self.patterns,
            "threshold": self.threshold,
            "time_window": self.time_window,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "enabled": self.enabled,
        }


@dataclass
class RuleMatch:
    """A match from a detection rule."""
    rule_id: str
    rule_name: str
    severity: str
    records: list[dict] = field(default_factory=list)
    count: int = 0
    message: str = ""
    mitre_tactic: str = ""
    mitre_technique: str = ""
    
    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "count": self.count,
            "message": self.message,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "sample_records": self.records[:3],
        }


class RuleEngine:
    """Engine for evaluating detection rules against log records."""
    
    BUILT_IN_RULES = [
        DetectionRule(
            id="R001",
            name="Multiple Failed Logins",
            description="Detects brute force attempts",
            severity="high",
            patterns=["failed", "fail", "invalid"],
            threshold=5,
            time_window=600,
            mitre_tactic="Credential Access",
            mitre_technique="T1110",
        ),
        DetectionRule(
            id="R002",
            name="SSH Root Login",
            description="SSH login as root user",
            severity="high",
            patterns=["sshd", "root"],
            mitre_tactic="Initial Access",
            mitre_technique="T1078",
        ),
        DetectionRule(
            id="R003",
            name="Privilege Escalation",
            description="Sudo or privilege escalation attempt",
            severity="critical",
            patterns=["sudo", "su ", " privilege", "escalat"],
            mitre_tactic="Privilege Escalation",
            mitre_technique="T1068",
        ),
        DetectionRule(
            id="R004",
            name="Suspicious IP Range",
            description="Login from known suspicious IP",
            severity="high",
            condition="source_ip_starts_with",
            threshold=1,
        ),
        DetectionRule(
            id="R005",
            name="New Account Created",
            description="New user account creation",
            severity="medium",
            patterns=["new user", "user created", "account created", "adduser"],
            mitre_tactic="Persistence",
            mitre_technique="T1136",
        ),
        DetectionRule(
            id="R006",
            name="Failed Root Login",
            description="Failed root login attempts",
            severity="medium",
            patterns=["failed", "root"],
            mitre_tactic="Credential Access",
            mitre_technique="T1110",
        ),
        DetectionRule(
            id="R007",
            name="Tor Exit Node",
            description="Connection from Tor exit node",
            severity="high",
            condition="ip_is_tor",
        ),
        DetectionRule(
            id="R008",
            name="Unusual Port",
            description="Connection on unusual port",
            severity="low",
            patterns=["port 22", "port 23", "port 3389"],
        ),
        DetectionRule(
            id="R009",
            name="Lateral Movement",
            description="Indicators of lateral movement",
            severity="high",
            patterns=[" lateral ", "smb", "psexec", "winrm", "rdp"],
            mitre_tactic="Lateral Movement",
            mitre_technique="T1021",
        ),
        DetectionRule(
            id="R010",
            name="Data Exfiltration",
            description="Potential data exfiltration",
            severity="critical",
            patterns=["exfil", "large upload", "archive", "outbound"],
            mitre_tactic="Exfiltration",
            mitre_technique="T1041",
        ),
    ]
    
    def __init__(self, rules: list[DetectionRule] = None):
        self.rules = rules or self.BUILT_IN_RULES.copy()
        self._compiled_patterns: dict[str, re.Pattern] = {}
        self._compile_patterns()
    
    def _compile_patterns(self):
        for rule in self.rules:
            for pattern in rule.patterns:
                if pattern not in self._compiled_patterns:
                    try:
                        self._compiled_patterns[pattern] = re.compile(pattern, re.IGNORECASE)
                    except re.error:
                        self._compiled_patterns[pattern] = re.compile(re.escape(pattern), re.IGNORECASE)
    
    def evaluate(self, records: list[dict]) -> list[RuleMatch]:
        """Evaluate all rules against records."""
        matches = []
        
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            matched_records = self._match_rule(rule, records)
            
            if matched_records:
                match = RuleMatch(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    records=matched_records,
                    count=len(matched_records),
                    message=f"{rule.name}: {len(matched_records)} matches",
                    mitre_tactic=rule.mitre_tactic,
                    mitre_technique=rule.mitre_technique,
                )
                matches.append(match)
        
        return sorted(matches, key=lambda m: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(m.severity, 4))
    
    def _match_rule(self, rule: DetectionRule, records: list[dict]) -> list[dict]:
        matched = []
        
        for record in records:
            if self._record_matches_rule(rule, record):
                matched.append(record)
        
        return matched
    
    def _record_matches_rule(self, rule: DetectionRule, record: dict) -> bool:
        message = (record.get("raw_message", "") or record.get("message", "")).lower()
        event_type = record.get("event_type", "").lower()
        source_ip = record.get("source_ip", "")
        user = record.get("user", "")
        
        if rule.condition == "source_ip_starts_with":
            suspicious_prefixes = ("185.220.", "91.121.", "103.", "45.", "77.")
            return any(source_ip.startswith(p) for p in suspicious_prefixes)
        
        if rule.condition == "ip_is_tor":
            return source_ip.startswith("185.220.")
        
        if rule.patterns:
            for pattern in rule.patterns:
                compiled = self._compiled_patterns.get(pattern)
                if compiled:
                    if compiled.search(message) or compiled.search(event_type):
                        return True
        
        return False
    
    def add_rule(self, rule: DetectionRule):
        """Add a custom rule."""
        self.rules.append(rule)
        for pattern in rule.patterns:
            if pattern not in self._compiled_patterns:
                try:
                    self._compiled_patterns[pattern] = re.compile(pattern, re.IGNORECASE)
                except re.error:
                    self._compiled_patterns[pattern] = re.compile(re.escape(pattern), re.IGNORECASE)
    
    def load_rules_from_file(self, filepath: str):
        """Load rules from YAML or JSON file."""
        import json
        path = Path(filepath)
        
        if path.suffix in (".yaml", ".yml"):
            try:
                import yaml
                with open(path) as f:
                    data = yaml.safe_load(f)
                self._load_rules_from_dict(data)
            except ImportError:
                return {"status": "error", "message": "PyYAML not installed"}
        elif path.suffix == ".json":
            with open(path) as f:
                data = json.load(f)
            self._load_rules_from_dict(data)
        else:
            return {"status": "error", "message": "Unsupported file format"}
        
        return {"status": "loaded", "count": len(self.rules)}
    
    def _load_rules_from_dict(self, data: dict):
        rules_data = data.get("rules", [data] if "id" in data else [])
        for r in rules_data:
            rule = DetectionRule(
                id=r.get("id", f"R{len(self.rules):03d}"),
                name=r.get("name", "Custom Rule"),
                description=r.get("description", ""),
                severity=r.get("severity", "medium"),
                patterns=r.get("patterns", []),
                threshold=r.get("threshold", 1),
                time_window=r.get("time_window", 0),
                mitre_tactic=r.get("mitre_tactic", ""),
                mitre_technique=r.get("mitre_technique", ""),
                enabled=r.get("enabled", True),
            )
            if not any(existing.id == rule.id for existing in self.rules):
                self.add_rule(rule)


def run_rule_engine(records: list[dict], rules_file: str = None) -> dict:
    """Run rule engine on records."""
    engine = RuleEngine()
    
    if rules_file:
        result = engine.load_rules_from_file(rules_file)
        if result.get("status") == "error":
            return result
    
    matches = engine.evaluate(records)
    
    return {
        "status": "success",
        "rules_evaluated": len(engine.rules),
        "matches": len(matches),
        "critical": sum(1 for m in matches if m.severity == "critical"),
        "high": sum(1 for m in matches if m.severity == "high"),
        "medium": sum(1 for m in matches if m.severity == "medium"),
        "low": sum(1 for m in matches if m.severity == "low"),
        "results": [m.to_dict() for m in matches],
    }


def create_sample_rules_file(path: str = "rules.yaml"):
    """Create a sample rules file."""
    sample_rules = """
rules:
  - id: R101
    name: Custom Brute Force
    description: Custom brute force detection
    severity: high
    patterns:
      - "failed"
      - "password"
    threshold: 3
    mitre_tactic: "Credential Access"
    mitre_technique: "T1110"
    
  - id: R102
    name: Suspicious Time
    description: Activity outside business hours
    severity: medium
    patterns:
      - "login"
      - "access"
    enabled: true
"""
    with open(path, "w") as f:
        f.write(sample_rules)
    return {"status": "created", "path": path}