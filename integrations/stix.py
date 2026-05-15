#!/usr/bin/env python3
"""STIX/TAXII integration for threat intelligence feeds."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass
class STIXConfig:
    """STIX/TAXII configuration."""
    server_url: str
    collection: str
    username: str = ""
    password: str = ""
    api_key: str = ""
    verify_ssl: bool = True


class TAXIIClient:
    """Client for TAXII 2.x threat intelligence feeds."""

    def __init__(self, config: STIXConfig | None = None):
        self.config = config or STIXConfig(
            server_url=os.getenv("TAXII_SERVER", ""),
            collection=os.getenv("TAXII_COLLECTION", ""),
            username=os.getenv("TAXII_USERNAME", ""),
            password=os.getenv("TAXII_PASSWORD", ""),
            api_key=os.getenv("TAXII_API_KEY", ""),
        )
        self._cache: list[dict] = []
        self._last_fetch: datetime | None = None

    def is_configured(self) -> bool:
        """Check if client is configured."""
        return bool(self.config.server_url and self.config.collection)

    def fetch_indicators(self, days: int = 7, indicator_types: list[str] | None = None) -> dict:
        """Fetch indicators from TAXII server."""
        if not self.is_configured():
            return {"status": "not_configured", "message": "TAXII server not configured"}

        try:
            import httpx
            
            headers = {"Accept": "application/taxii+json"}
            if self.config.api_key:
                headers["Authorization"] = f"Bearer {self.config.api_key}"
            
            cutoff = datetime.now() - timedelta(days=days)
            
            params: dict[str, str | int] = {
                "match_date": cutoff.isoformat(),
                "limit": 1000
            }
            
            if indicator_types:
                params["type"] = ",".join(indicator_types)
            
            response = httpx.get(
                f"{self.config.server_url}/taxii2/collections/{self.config.collection}/objects",
                headers=headers,
                params=params,
                verify=self.config.verify_ssl,
                timeout=60
            )
            
            if response.status_code == 200:
                data = response.json()
                objects = data.get("objects", [])
                
                self._cache = objects
                self._last_fetch = datetime.now()
                
                return {
                    "status": "success",
                    "count": len(objects),
                    "objects": objects[:100]
                }
            else:
                return {"status": "error", "message": f"HTTP {response.status_code}: {response.text}"}
                
        except ImportError:
            return {"status": "error", "message": "httpx not installed"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def check_ip(self, ip: str) -> dict:
        """Check an IP against cached STIX indicators."""
        if not self._cache:
            return {"status": "no_data", "message": "No indicators loaded"}
        
        ip_indicators = []
        
        for obj in self._cache:
            if obj.get("type") == "indicator":
                pattern = obj.get("pattern", "")
                if ip in pattern:
                    ip_indicators.append({
                        "id": obj.get("id"),
                        "name": obj.get("name", ""),
                        "description": obj.get("description", ""),
                        "valid_from": obj.get("valid_from", ""),
                        "pattern": pattern
                    })
        
        return {
            "ip": ip,
            "match_count": len(ip_indicators),
            "indicators": ip_indicators,
            "cached_at": self._last_fetch.isoformat() if self._last_fetch else None
        }

    def get_cached_count(self) -> int:
        """Get number of cached indicators."""
        return len(self._cache)


class STIXBuilder:
    """Build STIX 2.1 bundles from LogSentry records."""

    def __init__(self):
        self._objects: list[dict] = []
        self._identity = {
            "type": "identity",
            "spec_version": "2.1",
            "id": "identity--logSentry",
            "created_by_ref": "identity--logSentry",
            "name": "LogSentry",
            "identity_class": "organization"
        }
        self._objects.append(self._identity)

    def add_indicator(self, indicator_type: str, pattern: str, name: str,
                     description: str = "", labels: list[str] | None = None) -> str:
        """Add an indicator to the bundle."""
        indicator_id = f"indicator--{self._generate_id()}"
        
        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": datetime.now().isoformat(),
            "modified": datetime.now().isoformat(),
            "name": name,
            "description": description,
            "pattern": pattern,
            "pattern_type": "stix",
            "indicator_types": labels or ["malicious-activity"],
            "valid_from": datetime.now().isoformat(),
            "labels": labels or ["malicious-activity"],
            "created_by_ref": "identity--logSentry",
            "confidence": "high"
        }
        
        self._objects.append(indicator)
        return indicator_id

    def add_ip_indicator(self, ip: str, description: str = "") -> str:
        """Add IP address as STIX indicator."""
        pattern = f"[ipv4-addr:value = '{ip}']"
        return self.add_indicator(
            indicator_type="ip",
            pattern=pattern,
            name=f"LogSentry: Malicious IP {ip}",
            description=description or "IP detected by LogSentry analysis"
        )

    def add_domain_indicator(self, domain: str, description: str = "") -> str:
        """Add domain as STIX indicator."""
        pattern = f"[domain-name:value = '{domain}']"
        return self.add_indicator(
            indicator_type="domain",
            pattern=pattern,
            name=f"LogSentry: Malicious Domain {domain}",
            description=description or "Domain detected by LogSentry"
        )

    def build_bundle(self) -> dict:
        """Build final STIX bundle."""
        return {
            "type": "bundle",
            "id": f"bundle--{self._generate_id()}",
            "spec_version": "2.1",
            "objects": self._objects
        }

    def _generate_id(self) -> str:
        """Generate unique ID."""
        import uuid
        return str(uuid.uuid4())


def fetch_taxii_feed(days: int = 7) -> dict:
    """Fetch and cache TAXII indicators."""
    client = TAXIIClient()
    
    if not client.is_configured():
        return {
            "status": "skipped",
            "reason": "TAXII not configured. Set TAXII_SERVER, TAXII_COLLECTION environment variables."
        }
    
    return client.fetch_indicators(days=days)


def check_ip_threat_intel(ip: str) -> dict:
    """Check IP against TAXII feeds."""
    client = TAXIIClient()
    
    if not client.is_configured():
        return {"status": "skipped", "reason": "TAXII not configured"}
    
    return client.check_ip(ip)


def export_to_stix(records: list[dict]) -> dict:
    """Export records as STIX bundle."""
    builder = STIXBuilder()
    
    ips = set()
    
    for r in records:
        if ip := r.get("source_ip"):
            if ip and not ip.startswith(("192.168.", "10.", "172.")):
                ips.add(ip)
    
    for ip in ips:
        builder.add_ip_indicator(ip, "Malicious IP from LogSentry analysis")
    
    bundle = builder.build_bundle()
    
    return {
        "status": "success",
        "indicators_created": len(ips),
        "bundle": bundle
    }


def save_stix_bundle(bundle: dict, filepath: str) -> dict:
    """Save STIX bundle to file."""
    import json
    
    try:
        with open(filepath, "w") as f:
            json.dump(bundle, f, indent=2)
        return {"status": "success", "path": filepath}
    except Exception as e:
        return {"status": "error", "message": str(e)}