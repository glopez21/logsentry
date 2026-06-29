#!/usr/bin/env python3
"""Attack timeline reconstruction from MITRE ATT&CK kill chain."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
from collections import defaultdict

from _constants import MITRE_KILL_CHAIN


@dataclass
class AttackStage:
    """A single stage in the attack timeline."""
    phase: str
    description: str
    techniques: list[str] = field(default_factory=list)
    records: list[dict] = field(default_factory=list)
    start_time: str = ""
    end_time: str = ""
    severity: str = "medium"

    def to_dict(self) -> dict:
        return {
            "phase": self.phase,
            "description": self.description,
            "techniques": self.techniques,
            "event_count": len(self.records),
            "start_time": self.start_time,
            "end_time": self.end_time,
            "severity": self.severity,
        }


@dataclass
class AttackTimeline:
    """Complete attack chain reconstruction."""
    stages: list[AttackStage] = field(default_factory=list)
    duration_seconds: int = 0
    unique_techniques: list[str] = field(default_factory=list)
    confidence_score: float = 0.0

    def to_dict(self) -> dict:
        return {
            "stages": [s.to_dict() for s in self.stages],
            "stage_count": len(self.stages),
            "duration_seconds": self.duration_seconds,
            "unique_techniques": self.unique_techniques,
            "confidence_score": self.confidence_score,
        }


def _find_phase_for_tactic(tactic: str) -> Optional[dict]:
    """Find the kill chain phase for a MITRE tactic."""
    for entry in MITRE_KILL_CHAIN:
        if tactic in entry["tactics"]:
            return entry
    return None


def reconstruct_attack(records: list[dict]) -> AttackTimeline:
    """Reconstruct attack chain from log records."""
    tactic_to_records: dict[str, list[dict]] = defaultdict(list)
    
    for record in records:
        tactic = record.get("mitre_tactic", "")
        if tactic:
            tactic_to_records[tactic].append(record)
    
    stages_dict: dict[str, list[dict]] = defaultdict(list)
    
    for tactic, recs in tactic_to_records.items():
        phase_info = _find_phase_for_tactic(tactic)
        if phase_info:
            stages_dict[phase_info["phase"]].extend(recs)
    
    timeline = AttackTimeline()
    
    for phase_entry in MITRE_KILL_CHAIN:
        phase = phase_entry["phase"]
        if phase not in stages_dict:
            continue
        
        recs = stages_dict[phase]
        techniques = list(set(r.get("mitre_tactic", "") for r in recs))
        
        timestamps = [r.get("timestamp", "") for r in recs if r.get("timestamp")]
        
        stage = AttackStage(
            phase=phase,
            description=phase_entry["description"],
            techniques=techniques,
            records=recs,
            start_time=timestamps[0] if timestamps else "",
            end_time=timestamps[-1] if timestamps else "",
            severity=_get_stage_severity(recs)
        )
        timeline.stages.append(stage)
    
    all_tactics = set()
    for stage in timeline.stages:
        all_tactics.update(stage.techniques)
    timeline.unique_techniques = sorted(all_tactics)
    
    timeline.confidence_score = _calculate_confidence(timeline.stages)
    
    return timeline


def _get_stage_severity(records: list[dict]) -> str:
    """Get severity for a stage based on records."""
    severities = [r.get("severity", "medium") for r in records]
    if "critical" in severities:
        return "critical"
    if "high" in severities:
        return "high"
    return "medium"


def _calculate_confidence(stages: list[AttackStage]) -> float:
    """Calculate confidence score for reconstruction."""
    if not stages:
        return 0.0
    
    sequential_bonus = min(len(stages) * 0.1, 0.5)
    technique_bonus = min(len(set(t for s in stages for t in s.techniques)) * 0.05, 0.3)
    
    return min(sequential_bonus + technique_bonus + 0.2, 1.0)


def format_attack_timeline(timeline: AttackTimeline) -> str:
    """Format attack timeline as readable text."""
    lines = []
    lines.append("\n" + "=" * 70)
    lines.append("ATTACK CHAIN RECONSTRUCTION")
    lines.append("=" * 70)
    
    lines.append(f"\nConfidence: {timeline.confidence_score:.0%}")
    lines.append(f"Stages Detected: {len(timeline.stages)}")
    lines.append(f"Unique Techniques: {len(timeline.unique_techniques)}")
    
    if timeline.unique_techniques:
        lines.append(f"Mitre ATT&CK: {', '.join(timeline.unique_techniques)}")
    
    lines.append("\n" + "-" * 70)
    lines.append(f"{'Phase':<25} {'Techniques':<15} {'Events':<8} {'Severity':<10}")
    lines.append("-" * 70)
    
    for stage in timeline.stages:
        tech_str = ",".join(stage.techniques[:2])
        if len(stage.techniques) > 2:
            tech_str += f" +{len(stage.techniques)-2}"
        lines.append(f"{stage.phase:<25} {tech_str:<15} {len(stage.records):<8} {stage.severity:<10}")
    
    return "\n".join(lines)