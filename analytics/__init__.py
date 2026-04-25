#!/usr/bin/env python3
"""Anomaly detection using statistical analysis."""

from dataclasses import dataclass, field
from typing import Optional
from collections import defaultdict
from datetime import datetime, timedelta
import statistics


@dataclass
class Baseline:
    """Statistical baseline for comparison."""
    metric: str
    mean: float = 0.0
    std_dev: float = 0.0
    min_val: float = 0.0
    max_val: float = 0.0
    median: float = 0.0
    p95: float = 0.0
    p99: float = 0.0
    sample_count: int = 0
    period_start: str = ""
    period_end: str = ""


@dataclass
class Anomaly:
    """Detected anomaly."""
    metric: str
    value: float
    expected_range: tuple[float, float]
    deviation: float
    z_score: float
    severity: str
    description: str
    timestamp: str = ""


@dataclass 
class AnomalyReport:
    """Full anomaly detection report."""
    baseline: dict[str, Baseline]
    anomalies: list[Anomaly] = field(default_factory=list)
    summary: dict = field(default_factory=dict)


class AnomalyDetector:
    """Statistical anomaly detection for log data."""
    
    def __init__(self, sensitivity: float = 2.0):
        self.sensitivity = sensitivity
        self.baselines: dict[str, Baseline] = {}
    
    def compute_baseline(self, records: list[dict], metric: str) -> Baseline:
        """Compute baseline statistics for a metric."""
        values = []
        
        for r in records:
            if metric == "failed_logins":
                if "fail" in r.get("event_type", "").lower():
                    values.append(1)
            elif metric == "unique_ips":
                if r.get("source_ip"):
                    values.append(hash(r["source_ip"]) % 1000)
            elif metric == "unique_users":
                if r.get("user"):
                    values.append(hash(r["user"]) % 1000)
            elif metric == "events_per_minute":
                pass
            elif metric == "auth_failures":
                msg = (r.get("raw_message", "") or r.get("message", "")).lower()
                if "fail" in msg or "invalid" in msg or "denied" in msg:
                    values.append(1)
            else:
                val = r.get(metric, 0)
                if val:
                    try:
                        values.append(float(val))
                    except (ValueError, TypeError):
                        pass
        
        if not values:
            return Baseline(metric=metric)
        
        mean = statistics.mean(values) if values else 0
        std = statistics.stdev(values) if len(values) > 1 else 0
        
        sorted_vals = sorted(values)
        median = statistics.median(values)
        p95 = sorted_vals[int(len(sorted_vals) * 0.95)] if sorted_vals else 0
        p99 = sorted_vals[int(len(sorted_vals) * 0.99)] if sorted_vals else 0
        
        baseline = Baseline(
            metric=metric,
            mean=mean,
            std_dev=std,
            min_val=min(values) if values else 0,
            max_val=max(values) if values else 0,
            median=median,
            p95=p95,
            p99=p99,
            sample_count=len(values),
        )
        
        self.baselines[metric] = baseline
        return baseline
    
    def compute_all_baselines(self, records: list[dict]) -> dict[str, Baseline]:
        """Compute baselines for all common metrics."""
        metrics = ["failed_logins", "auth_failures", "unique_ips", "unique_users"]
        for metric in metrics:
            if metric not in self.baselines:
                self.compute_baseline(records, metric)
        return self.baselines
    
    def detect_anomalies(self, current_records: list[dict], baseline_records: list[dict] = None) -> AnomalyReport:
        """Detect anomalies by comparing current data against baselines."""
        if baseline_records:
            self.compute_all_baselines(baseline_records)
        elif not self.baselines:
            self.compute_all_baselines(current_records[:len(current_records)//2] if len(current_records) > 10 else current_records)
        
        anomalies = []
        current_baselines = self.compute_all_baselines(current_records)
        
        for metric, baseline in current_baselines.items():
            if baseline.sample_count == 0:
                continue
            
            if metric == "failed_logins":
                count = sum(1 for r in current_records if "fail" in r.get("event_type", "").lower())
                self._check_anomaly(metric, count, baseline, anomalies)
            
            elif metric == "auth_failures":
                count = sum(1 for r in current_records 
                           if any(x in (r.get("raw_message", "") + r.get("message", "")).lower() 
                                 for x in ["fail", "invalid", "denied"]))
                self._check_anomaly(metric, count, baseline, anomalies)
            
            elif metric == "unique_ips":
                unique_ips = set(r.get("source_ip") for r in current_records if r.get("source_ip"))
                count = len(unique_ips)
                self._check_anomaly(metric, count, baseline, anomalies)
        
        self._analyze_time_based_anomalies(current_records, anomalies)
        self._analyze_ip_based_anomalies(current_records, anomalies)
        
        report = AnomalyReport(
            baseline={k: v for k, v in current_baselines.items()},
            anomalies=anomalies,
            summary=self._generate_summary(anomalies)
        )
        
        return report
    
    def _check_anomaly(self, metric: str, value: float, baseline: Baseline, anomalies: list[Anomaly]):
        """Check if value is anomalous given baseline."""
        if baseline.std_dev == 0:
            if value > baseline.mean * 2:
                anomalies.append(Anomaly(
                    metric=metric,
                    value=value,
                    expected_range=(0, baseline.mean * 2),
                    deviation=value - baseline.mean,
                    z_score=999,
                    severity="high",
                    description=f"Value {value} is significantly higher than baseline mean {baseline.mean:.1f}"
                ))
            return
        
        z_score = (value - baseline.mean) / baseline.std_dev if baseline.std_dev else 0
        
        if abs(z_score) > self.sensitivity:
            severity = "critical" if abs(z_score) > 4 else "high" if abs(z_score) > 3 else "medium"
            expected = (baseline.mean - baseline.std_dev * self.sensitivity,
                       baseline.mean + baseline.std_dev * self.sensitivity)
            
            anomalies.append(Anomaly(
                metric=metric,
                value=value,
                expected_range=expected,
                deviation=value - baseline.mean,
                z_score=z_score,
                severity=severity,
                description=f"Value {value:.1f} is {abs(z_score):.1f} std devs from baseline"
            ))
    
    def _analyze_time_based_anomalies(self, records: list[dict], anomalies: list[Anomaly]):
        """Detect time-based anomalies (off-hours activity, bursts)."""
        hour_counts = defaultdict(int)
        
        for r in records:
            ts = r.get("timestamp", "")
            if ts:
                try:
                    hour = int(ts.split(":")[0].split()[-1]) if ":" in ts else 0
                    hour_counts[hour] += 1
                except (ValueError, IndexError):
                    pass
        
        if hour_counts:
            avg_per_hour = statistics.mean(hour_counts.values()) if hour_counts else 0
            std_per_hour = statistics.stdev(hour_counts.values()) if len(hour_counts) > 1 else 0
            
            for hour, count in hour_counts.items():
                if hour < 6 or hour > 22:
                    if count > avg_per_hour * 1.5:
                        anomalies.append(Anomaly(
                            metric="off_hours_activity",
                            value=count,
                            expected_range=(0, avg_per_hour * 1.5),
                            deviation=count - avg_per_hour,
                            z_score=(count - avg_per_hour) / std_per_hour if std_per_hour else 0,
                            severity="medium",
                            description=f"Unusual activity at {hour}:00 (off hours)"
                        ))
    
    def _analyze_ip_based_anomalies(self, records: list[dict], anomalies: list[Anomaly]):
        """Detect IP-based anomalies (single source flooding)."""
        ip_counts = defaultdict(int)
        
        for r in records:
            if ip := r.get("source_ip"):
                ip_counts[ip] += 1
        
        if ip_counts:
            max_count = max(ip_counts.values())
            avg_count = statistics.mean(ip_counts.values()) if ip_counts else 0
            
            if avg_count > 0 and max_count > avg_count * 5:
                top_ip = max(ip_counts, key=ip_counts.get)
                anomalies.append(Anomaly(
                    metric="single_source_flood",
                    value=max_count,
                    expected_range=(0, avg_count * 5),
                    deviation=max_count - avg_count,
                    z_score=999,
                    severity="high",
                    description=f"IP {top_ip} responsible for {max_count} events (avg: {avg_count:.1f})"
                ))
    
    def _generate_summary(self, anomalies: list[Anomaly]) -> dict:
        """Generate summary of anomalies."""
        return {
            "total_anomalies": len(anomalies),
            "critical": sum(1 for a in anomalies if a.severity == "critical"),
            "high": sum(1 for a in anomalies if a.severity == "high"),
            "medium": sum(1 for a in anomalies if a.severity == "medium"),
            "low": sum(1 for a in anomalies if a.severity == "low"),
            "metrics_affected": list(set(a.metric for a in anomalies)),
        }


def detect_anomalies(records: list[dict], baseline_records: list[dict] = None, sensitivity: float = 2.0) -> dict:
    """Detect anomalies in log records."""
    detector = AnomalyDetector(sensitivity=sensitivity)
    report = detector.detect_anomalies(records, baseline_records)
    
    return {
        "status": "success",
        "anomalies_detected": len(report.anomalies),
        "summary": report.summary,
        "baselines": {k: {
            "mean": v.mean,
            "std_dev": v.std_dev,
            "median": v.median,
            "p95": v.p95,
        } for k, v in report.baseline.items()},
        "anomalies": [{
            "metric": a.metric,
            "value": a.value,
            "severity": a.severity,
            "description": a.description,
            "z_score": round(a.z_score, 2),
        } for a in report.anomalies],
    }