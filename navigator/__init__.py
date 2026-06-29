#!/usr/bin/env python3
"""MITRE ATT&CK Navigator layer export for visualization."""

from __future__ import annotations

from dataclasses import dataclass, field

from collections import Counter

from _constants import SEVERITY_MAP_SCORE


@dataclass
class NavigatorLayer:
    """MITRE ATT&CK Navigator layer format."""
    name: str
    versions: dict = field(default_factory=lambda: {"attack": "15", "navigator": "4.9.1", "layer": "4.5"})
    domain: str = "mitre-enterprise"
    metadata: list = field(default_factory=list)
    filters: dict = field(default_factory=lambda: {"platforms": ["Linux", "Windows", "macOS"]})
    sorting: int = 0
    hideDisabled: bool = False
    showTacticRowBackground: bool = True
    legendBars: list = field(default_factory=list)
    techniques: list[dict] = field(default_factory=list)
    gradient: dict = field(default_factory=lambda: {
        "colors": ["#ffffff", "#ff6666"],
        "minValue": 0,
        "maxValue": 100
    })
    label: str = ""
    layerColor: str = ""
    description: str = ""
    tintOpacity: float = 0.0
    backgroundColor: str = "#ffffff00"
    metadataId: str = "main"
    showID: bool = False
    showName: bool = False
    showAggregateScores: bool = False


def export_to_navigator(records: list[dict]) -> dict:
    """Export records as MITRE ATT&CK Navigator layer."""
    tactic_counts: Counter = Counter()
    technique_scores: dict[str, float] = {}
    
    for record in records:
        severity = record.get("severity", "info")
        score: float = SEVERITY_MAP_SCORE.get(severity, 0)
        
        tactic = record.get("mitre_tactic", "")
        if tactic:
            tactic_counts[tactic] += 1
            technique_scores[tactic] = technique_scores.get(tactic, 0) + score
    
    techniques = []
    for tactic, score in technique_scores.items():
        if score > 0:
            technique_id = tactic
            count = tactic_counts[tactic]
            avg_score = score / count
            score_pct = min(avg_score * 10, 100)
            
            techniques.append({
                "techniqueID": technique_id,
                "score": int(score_pct),
                "metadata": [
                    {"name": "count", "value": count},
                    {"name": "avg_severity", "value": avg_score}
                ],
                "enabled": True,
                "comment": "",
                "showSubtechniques": False
            })
    
    layer = NavigatorLayer(
        name="LogSentry Analysis",
        description="Generated from security log analysis",
        techniques=techniques
    )
    
    return {
        "status": "success",
        "layer": layer.__dict__,
        "summary": {
            "total_techniques": len(techniques),
            "total_events": sum(tactic_counts.values()),
            "tactics": dict(tactic_counts)
        }
    }


def save_navigator_layer(layer_data: dict, filepath: str) -> dict:
    """Save navigator layer to JSON file."""
    import json
    try:
        with open(filepath, "w") as f:
            json.dump(layer_data["layer"], f, indent=2)
        return {"status": "success", "path": filepath}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def format_navigator_summary(layer_data: dict) -> str:
    """Format navigator export summary."""
    summary = layer_data.get("summary", {})
    lines = []
    lines.append("\n" + "=" * 50)
    lines.append("MITRE ATT&CK NAVIGATOR EXPORT")
    lines.append("=" * 50)
    lines.append(f"\nTechniques Detected: {summary.get('total_techniques', 0)}")
    lines.append(f"Total Events: {summary.get('total_events', 0)}")
    
    tactics = summary.get("tactics", {})
    if tactics:
        lines.append("\nTactics Breakdown:")
        for tactic, count in sorted(tactics.items(), key=lambda x: -x[1])[:10]:
            lines.append(f"  {tactic}: {count} events")
    
    return "\n".join(lines)