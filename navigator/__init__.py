#!/usr/bin/env python3
"""MITRE ATT&CK Navigator layer export for visualization."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
from collections import Counter


ATTACK_MATRIX: dict[str, list[str]] = {
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
        severity_map = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
        severity = record.get("severity", "info")
        score = severity_map.get(severity, 0)
        
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