#!/usr/bin/env python3
"""Log integrity verification for forensic analysis."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path



@dataclass
class IntegrityRecord:
    """Record of file integrity state."""
    filepath: str
    hash_algorithm: str
    hash_value: str
    timestamp: str
    file_size: int
    line_count: int

    def to_dict(self) -> dict:
        return {
            "filepath": self.filepath,
            "algorithm": self.hash_algorithm,
            "hash": self.hash_value,
            "timestamp": self.timestamp,
            "file_size": self.file_size,
            "line_count": self.line_count,
        }


class IntegrityTracker:
    """Track and verify log file integrity."""

    def __init__(self, algorithm: str = "sha256"):
        self.algorithm = algorithm
        self.known_hashes: dict[str, IntegrityRecord] = {}

    def compute_hash(self, filepath: str) -> str:
        """Compute hash of file contents."""
        h = hashlib.new(self.algorithm)
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    def compute_content_hash(self, records: list[dict]) -> str:
        """Compute hash of parsed log records."""
        content = json.dumps(records, sort_keys=True, default=str)
        return hashlib.sha256(content.encode()).hexdigest()

    def record_integrity(self, filepath: str, records: list[dict] | None = None) -> IntegrityRecord:
        """Record current state of a file."""
        path = Path(filepath)
        hash_value = self.compute_hash(filepath)
        
        line_count = 0
        if path.exists():
            with open(filepath) as f:
                line_count = sum(1 for _ in f)
        
        record = IntegrityRecord(
            filepath=filepath,
            hash_algorithm=self.algorithm,
            hash_value=hash_value,
            timestamp=datetime.now().isoformat(),
            file_size=path.stat().st_size if path.exists() else 0,
            line_count=line_count
        )
        
        self.known_hashes[filepath] = record
        return record

    def verify_integrity(self, filepath: str) -> dict:
        """Verify file integrity against known hash."""
        if filepath not in self.known_hashes:
            current_hash = self.compute_hash(filepath)
            return {
                "filepath": filepath,
                "status": "unknown",
                "message": "File not previously recorded",
                "current_hash": current_hash,
            }
        
        known = self.known_hashes[filepath]
        current_hash = self.compute_hash(filepath)
        current_size = Path(filepath).stat().st_size if Path(filepath).exists() else 0
        
        if current_hash != known.hash_value:
            return {
                "filepath": filepath,
                "status": "modified",
                "message": "File has been modified since last recording",
                "previous_hash": known.hash_value,
                "current_hash": current_hash,
                "size_change": current_size - known.file_size,
            }
        
        return {
            "filepath": filepath,
            "status": "verified",
            "message": "File integrity verified",
            "hash": known.hash_value,
        }

    def save_state(self, path: str) -> dict:
        """Save integrity records to JSON file."""
        data = {
            "timestamp": datetime.now().isoformat(),
            "records": [r.to_dict() for r in self.known_hashes.values()]
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        return {"status": "success", "path": path}

    def load_state(self, path: str) -> dict:
        """Load integrity records from JSON file."""
        with open(path) as f:
            data = json.load(f)
        
        for rec_data in data.get("records", []):
            self.known_hashes[rec_data["filepath"]] = IntegrityRecord(**rec_data)
        
        return {
            "status": "loaded",
            "count": len(self.known_hashes),
            "timestamp": data.get("timestamp"),
        }


def compute_log_hash(filepath: str, algorithm: str = "sha256") -> dict:
    """Compute hash of a log file."""
    tracker = IntegrityTracker(algorithm)
    try:
        hash_value = tracker.compute_hash(filepath)
        size = Path(filepath).stat().st_size
        return {
            "status": "success",
            "filepath": filepath,
            "algorithm": algorithm,
            "hash": hash_value,
            "size": size,
        }
    except FileNotFoundError:
        return {"status": "error", "message": f"File not found: {filepath}"}


def verify_integrity(filepath: str, expected_hash: str, algorithm: str = "sha256") -> dict:
    """Verify file against expected hash."""
    tracker = IntegrityTracker(algorithm)
    current_hash = tracker.compute_hash(filepath)
    
    matches = current_hash == expected_hash
    return {
        "filepath": filepath,
        "verified": matches,
        "expected": expected_hash,
        "actual": current_hash,
        "status": "verified" if matches else "mismatch",
    }


def verify_records_hash(records: list[dict], expected_hash: str) -> dict:
    """Verify hash of parsed records."""
    tracker = IntegrityTracker()
    actual_hash = tracker.compute_content_hash(records)
    
    return {
        "verified": actual_hash == expected_hash,
        "expected": expected_hash,
        "actual": actual_hash,
        "record_count": len(records),
    }