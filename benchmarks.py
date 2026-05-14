#!/usr/bin/env python3
"""Performance benchmarks for LogSentry."""

import time
from pathlib import Path

from generate_logs import LogGenerator


def benchmark_parsing(log_size: int = 10000) -> dict:
    """Benchmark log parsing performance."""
    from main import parse_log_file
    
    gen = LogGenerator(seed=42)
    records = gen.generate_all_scenarios()
    
    while len(records) < log_size:
        records.extend(records)
    
    records = records[:log_size]
    
    log_file = Path("/tmp/benchmark_logs.txt")
    with open(log_file, "w") as f:
        for r in records:
            ts = r.get("timestamp", "")
            msg = r.get("message", "")
            f.write(f"{ts} localhost sshd: {msg}\n")
    
    start = time.perf_counter()
    parsed = parse_log_file(str(log_file))
    elapsed = time.perf_counter() - start
    
    log_file.unlink()
    
    return {
        "test": "parsing",
        "records": len(parsed),
        "time_seconds": round(elapsed, 4),
        "records_per_second": int(len(parsed) / elapsed)
    }


def benchmark_detection(records: int = 1000) -> dict:
    """Benchmark detection checks performance."""
    from detection.detection_checks import run_detection_checks
    
    gen = LogGenerator(seed=42)
    records_list = gen.generate_all_scenarios()
    records_list = records_list[:records]
    
    start = time.perf_counter()
    results = run_detection_checks(records_list)
    elapsed = time.perf_counter() - start
    
    return {
        "test": "detection",
        "records": len(records_list),
        "time_seconds": round(elapsed, 4),
        "records_per_second": int(len(records_list) / elapsed),
        "checks": len(results)
    }


def benchmark_yara(records: int = 1000) -> dict:
    """Benchmark YARA rule scanning."""
    from yara_rules import YaraEngine
    
    gen = LogGenerator(seed=42)
    records_list = gen.generate_all_scenarios()
    records_list = records_list[:records]
    
    engine = YaraEngine()
    
    start = time.perf_counter()
    matches = engine.scan_records(records_list)
    elapsed = time.perf_counter() - start
    
    return {
        "test": "yara_scan",
        "records": len(records_list),
        "matches": len(matches),
        "time_seconds": round(elapsed, 4),
        "records_per_second": int(len(records_list) / elapsed)
    }


def benchmark_suppression(records: int = 1000) -> dict:
    """Benchmark alert suppression."""
    from alerts import AlertSuppressor
    
    gen = LogGenerator(seed=42)
    records_list = gen.generate_all_scenarios()
    records_list = records_list[:records]
    
    suppressor = AlertSuppressor(threshold=5)
    
    start = time.perf_counter()
    groups = suppressor.process_records(records_list)
    elapsed = time.perf_counter() - start
    
    return {
        "test": "alert_suppression",
        "records": len(records_list),
        "groups": len(groups),
        "time_seconds": round(elapsed, 4),
        "records_per_second": int(len(records_list) / elapsed)
    }


def run_benchmarks(iterations: int = 3) -> dict:
    """Run all benchmarks."""
    print("=" * 60)
    print("LogSentry Performance Benchmarks")
    print("=" * 60)
    
    results = []
    
    print("\n[*] Benchmarking log parsing...")
    for _ in range(iterations):
        result = benchmark_parsing()
        results.append(result)
        print(f"    {result['records']} records @ {result['records_per_second']} r/s")
    
    print("\n[*] Benchmarking detection checks...")
    for _ in range(iterations):
        result = benchmark_detection()
        results.append(result)
        print(f"    {result['records']} records @ {result['records_per_second']} r/s")
    
    print("\n[*] Benchmarking YARA scanning...")
    for _ in range(iterations):
        result = benchmark_yara()
        results.append(result)
        print(f"    {result['records']} records @ {result['records_per_second']} r/s")
    
    print("\n[*] Benchmarking alert suppression...")
    for _ in range(iterations):
        result = benchmark_suppression()
        results.append(result)
        print(f"    {result['records']} records @ {result['records_per_second']} r/s")
    
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    
    for test in ["parsing", "detection", "yara_scan", "alert_suppression"]:
        test_results = [r for r in results if r["test"] == test]
        if test_results:
            avg_rps = sum(r["records_per_second"] for r in test_results) // len(test_results)
            avg_time = sum(r["time_seconds"] for r in test_results) / len(test_results)
            print(f"{test:20} avg: {avg_time:.4f}s ({avg_rps} records/s)")
    
    return {"results": results}


if __name__ == "__main__":
    run_benchmarks()