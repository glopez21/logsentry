#!/usr/bin/env python3
"""MISP integration for IOC push."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class MISPConfig:
    """MISP server configuration."""
    url: str
    api_key: str
    ssl_verify: bool = True


class MISPClient:
    """Client for MISP (Malware Information Sharing Platform)."""

    def __init__(self, url: str | None = None, api_key: str | None = None):
        self.url = url or os.getenv("MISP_URL", "")
        self.api_key = api_key or os.getenv("MISP_API_KEY", "")
        self.ssl_verify = os.getenv("MISP_SSL_VERIFY", "true").lower() != "false"

    def is_configured(self) -> bool:
        """Check if client is properly configured."""
        return bool(self.url and self.api_key)

    def push_ip(self, ip: str, comment: str = "", tags: list[str] | None = None) -> dict:
        """Push IP address as IOC to MISP."""
        if not self.is_configured():
            return {"status": "not_configured", "message": "MISP not configured"}

        try:
            import httpx
            headers = {
                "Authorization": self.api_key,
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
            
            event_data = {
                "Event": {
                    "info": f"LogSentry IOC: {ip}",
                    "threat_level_id": 2,
                    "published": False,
                    "attributes": [
                        {
                            "type": "ip-dst",
                            "value": ip,
                            "comment": comment,
                            "to_ids": True,
                            "distribution": 4,
                        }
                    ],
                    "Tag": [{"name": tag} for tag in (tags or ["logSentry", "automated"])]
                }
            }
            
            response = httpx.post(
                f"{self.url}/events",
                json=event_data,
                headers=headers,
                verify=self.ssl_verify,
                timeout=30
            )
            
            if response.status_code in (200, 201):
                return {"status": "success", "event_id": response.json().get("Event", {}).get("id")}
            else:
                return {"status": "error", "message": response.text}
                
        except ImportError:
            return {"status": "error", "message": "httpx not installed"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def push_domain(self, domain: str, comment: str = "", tags: list[str] | None = None) -> dict:
        """Push domain as IOC."""
        if not self.is_configured():
            return {"status": "not_configured"}

        try:
            import httpx
            headers = {"Authorization": self.api_key, "Content-Type": "application/json"}
            
            event_data = {
                "Event": {
                    "info": f"LogSentry IOC: {domain}",
                    "threat_level_id": 2,
                    "attributes": [{
                        "type": "domain",
                        "value": domain,
                        "comment": comment,
                        "to_ids": True,
                        "distribution": 4
                    }],
                    "Tag": [{"name": tag} for tag in (tags or ["logSentry"])]
                }
            }
            
            response = httpx.post(
                f"{self.url}/events",
                json=event_data,
                headers=headers,
                verify=self.ssl_verify,
                timeout=30
            )
            
            return {"status": "success" if response.status_code in (200, 201) else "error"}
            
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def push_hashes(self, hashes: dict[str, str], comment: str = "") -> dict:
        """Push file hashes as IOCs."""
        if not self.is_configured():
            return {"status": "not_configured"}

        attributes = []
        for hash_type, hash_val in hashes.items():
            type_map = {"md5": "md5", "sha1": "sha1", "sha256": "sha256"}
            if hash_type in type_map:
                attributes.append({
                    "type": type_map[hash_type],
                    "value": hash_val,
                    "comment": comment,
                    "to_ids": True
                })

        try:
            import httpx
            headers = {"Authorization": self.api_key, "Content-Type": "application/json"}
            
            event_data = {
                "Event": {
                    "info": "LogSentry IOC: File Hashes",
                    "threat_level_id": 2,
                    "attributes": attributes
                }
            }
            
            response = httpx.post(
                f"{self.url}/events",
                json=event_data,
                headers=headers,
                verify=self.ssl_verify,
                timeout=30
            )
            
            return {"status": "success" if response.status_code in (200, 201) else "error"}
            
        except Exception as e:
            return {"status": "error", "message": str(e)}


def push_to_misp(ip: str | None = None, domain: str | None = None, hashes: dict | None = None,
                 comment: str = "", tags: list[str] | None = None) -> dict:
    """Push IOCs to MISP."""
    client = MISPClient()
    
    if not client.is_configured():
        return {
            "status": "skipped",
            "reason": "MISP not configured. Set MISP_URL and MISP_API_KEY environment variables."
        }
    
    results = []
    
    if ip:
        results.append(client.push_ip(ip, comment, tags))
    if domain:
        results.append(client.push_domain(domain, comment, tags))
    if hashes:
        results.append(client.push_hashes(hashes, comment))
    
    return {
        "status": "completed",
        "results": results,
        "ioc_count": len(results)
    }


def export_records_to_misp(records: list[dict]) -> dict:
    """Export all IOCs from records to MISP."""
    ips = set()
    
    for r in records:
        if ip := r.get("source_ip"):
            if ip and not ip.startswith(("192.168.", "10.", "172.")):
                ips.add(ip)
    
    if not ips:
        return {"status": "no_ips", "message": "No external IPs found"}
    
    client = MISPClient()
    results = []
    
    for ip in ips:
        result = client.push_ip(ip, "LogSentry automated export", ["logSentry", "automated"])
        results.append({"ip": ip, "result": result})
    
    return {
        "status": "completed",
        "ips_pushed": len(ips),
        "results": results
    }