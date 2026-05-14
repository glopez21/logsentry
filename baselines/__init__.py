#!/usr/bin/env python3
"""Baseline storage system for anomaly detection."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional
import statistics


@dataclass
class Baseline:
    """Statistical baseline for metrics."""
    name: str
    created_at: str
    metric: str
    mean: float = 0.0
    std_dev: float = 0.0
    min_val: float = 0.0
    max_val: float = 0.0
    median: float = 0.0
    p95: float = 0.0
    p99: float = 0.0
    sample_count: int = 0
    values: list[float] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "created_at": self.created_at,
            "metric": self.metric,
            "mean": self.mean,
            "std_dev": self.std_dev,
            "min": self.min_val,
            "max": self.max_val,
            "median": self.median,
            "p95": self.p95,
            "p99": self.p99,
            "sample_count": self.sample_count,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Baseline:
        return cls(
            name=data["name"],
            created_at=data["created_at"],
            metric=data["metric"],
            mean=data["mean"],
            std_dev=data["std_dev"],
            min_val=data["min"],
            max_val=data["max"],
            median=data["median"],
            p95=data["p95"],
            p99=data["p99"],
            sample_count=data["sample_count"],
            values=data.get("values", [])
        )

    def compare(self, value: float) -> dict:
        """Compare a value against this baseline."""
        if self.std_dev == 0:
            z_score = 999 if value > self.mean * 2 else 0
        else:
            z_score = (value - self.mean) / self.std_dev
        
        is_anomaly = abs(z_score) > 2.0
        
        return {
            "value": value,
            "z_score": round(z_score, 2),
            "is_anomaly": is_anomaly,
            "severity": "high" if abs(z_score) > 3 else "medium" if is_anomaly else "normal",
            "deviation": value - self.mean,
        }


class BaselineStore:
    """Persistent storage for baselines."""

    def __init__(self, storage_dir: str = ".baselines"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(exist_ok=True)
        self._baselines: dict[str, Baseline] = {}
        self._load_index()

    def _load_index(self):
        """Load all baseline files."""
        for f in self.storage_dir.glob("*.json"):
            try:
                with open(f) as fp:
                    data = json.load(fp)
                    baseline = Baseline.from_dict(data)
                    self._baselines[baseline.name] = baseline
            except Exception:
                pass

    def save_baseline(self, baseline: Baseline) -> dict:
        """Save a baseline to disk."""
        filepath = self.storage_dir / f"{baseline.name}.json"
        with open(filepath, "w") as f:
            json.dump(baseline.to_dict(), f, indent=2)
        self._baselines[baseline.name] = baseline
        return {"status": "saved", "name": baseline.name, "path": str(filepath)}

    def load_baseline(self, name: str) -> Baseline | None:
        """Load a baseline by name."""
        return self._baselines.get(name)

    def delete_baseline(self, name: str) -> dict:
        """Delete a baseline."""
        filepath = self.storage_dir / f"{name}.json"
        if filepath.exists():
            filepath.unlink()
        if name in self._baselines:
            del self._baselines[name]
        return {"status": "deleted", "name": name}

    def list_baselines(self) -> list[dict]:
        """List all stored baselines."""
        return [b.to_dict() for b in self._baselines.values()]

    def compare_value(self, name: str, value: float) -> dict:
        """Compare a value against a stored baseline."""
        baseline = self.load_baseline(name)
        if not baseline:
            return {"error": f"Baseline '{name}' not found"}
        return baseline.compare(value)


def create_baseline(records: list[dict], name: str, metric: str) -> Baseline:
    """Create a baseline from records for a specific metric."""
    values = extract_metric_values(records, metric)
    
    if not values:
        return Baseline(name=name, created_at=datetime.now().isoformat(), metric=metric)
    
    sorted_vals = sorted(values)
    return Baseline(
        name=name,
        created_at=datetime.now().isoformat(),
        metric=metric,
        mean=statistics.mean(values),
        std_dev=statistics.stdev(values) if len(values) > 1 else 0,
        min_val=min(values),
        max_val=max(values),
        median=statistics.median(values),
        p95=sorted_vals[int(len(sorted_vals) * 0.95)] if sorted_vals else 0,
        p99=sorted_vals[int(len(sorted_vals) * 0.99)] if sorted_vals else 0,
        sample_count=len(values),
        values=values[:1000]
    )


def extract_metric_values(records: list[dict], metric: str) -> list[float]:
    """Extract metric values from records."""
    values = []
    
    for r in records:
        if metric == "failed_logins":
            if "fail" in r.get("event_type", "").lower():
                values.append(1)
        elif metric == "auth_failures":
            msg = (r.get("raw_message", "") + r.get("message", "")).lower()
            if "fail" in msg or "invalid" in msg or "denied" in msg:
                values.append(1)
        elif metric == "unique_ips":
            if r.get("source_ip"):
                values.append(hash(r["source_ip"]) % 1000)
        elif metric == "unique_users":
            if r.get("user"):
                values.append(hash(r["user"]) % 1000)
        elif metric == "events_per_minute":
            values.append(1)
        else:
            val = r.get(metric, 0)
            if val:
                try:
                    values.append(float(val))
                except (ValueError, TypeError):
                    pass
    
    return values


def save_baseline_to_file(baseline: Baseline, name: str | None = None) -> dict:
    """Save baseline using global store."""
    store = BaselineStore()
    target_name = name or baseline.name
    baseline.name = target_name
    return store.save_baseline(baseline)


def load_baseline_from_file(name: str) -> Baseline | None:
    """Load baseline from global store."""
    store = BaselineStore()
    return store.load_baseline(name)