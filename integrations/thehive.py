#!/usr/bin/env python3
"""TheHive integration for case creation."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime


@dataclass
class TheHiveConfig:
    """TheHive server configuration."""
    url: str
    api_key: str
    case_template: str = "Default"


class TheHiveClient:
    """Client for TheHive case management."""

    def __init__(self, url: str | None = None, api_key: str | None = None):
        self.url = url or os.getenv("THEHIVE_URL", "")
        self.api_key = api_key or os.getenv("THEHIVE_API_KEY", "")
        self.case_template = os.getenv("THEHIVE_CASE_TEMPLATE", "Default")

    def is_configured(self) -> bool:
        """Check if client is properly configured."""
        return bool(self.url and self.api_key)

    def create_case(self, title: str, description: str, severity: int = 2,
                    tags: list[str] | None = None, observables: list[dict] | None = None) -> dict:
        """Create a case in TheHive."""
        if not self.is_configured():
            return {"status": "not_configured", "message": "TheHive not configured"}

        try:
            import httpx
            
            case = {
                "title": title,
                "description": description,
                "severity": severity,
                "owner": "",
                "tags": tags or ["logSentry", "automated"],
                "caseTemplate": self.case_template,
                "status": "Open"
            }
            
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            response = httpx.post(
                f"{self.url}/api/v1/case",
                json=case,
                headers=headers,
                timeout=30
            )
            
            if response.status_code in (200, 201):
                result = response.json()
                case_id = result.get("id", result.get("_id", ""))
                
                if observables and case_id:
                    self._add_observables(case_id, observables)
                
                return {"status": "success", "case_id": case_id, "case": result}
            else:
                return {"status": "error", "message": response.text}
                
        except ImportError:
            return {"status": "error", "message": "httpx not installed"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def _add_observables(self, case_id: str, observables: list[dict]) -> dict:
        """Add observables to a case."""
        try:
            import httpx
            headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
            
            data = [{"type": obs.get("type", "ip"), "value": obs.get("value", "")} for obs in observables]
            
            response = httpx.post(
                f"{self.url}/api/v1/case/{case_id}/observable",
                json=data,
                headers=headers,
                timeout=30
            )
            
            return {"status": "success" if response.status_code in (200, 201) else "error"}
            
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def add_alert(self, title: str, description: str, severity: int = 2,
                  source: str = "logSentry") -> dict:
        """Create an alert in TheHive."""
        if not self.is_configured():
            return {"status": "not_configured"}

        try:
            import httpx
            headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
            
            alert = {
                "title": title,
                "description": description,
                "severity": severity,
                "source": source,
                "sourceRef": f"logSentry-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                "type": "external",
                "tags": ["logSentry"]
            }
            
            response = httpx.post(
                f"{self.url}/api/v1/alert",
                json=alert,
                headers=headers,
                timeout=30
            )
            
            return {"status": "success" if response.status_code in (200, 201) else "error"}
            
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def update_case_status(self, case_id: str, status: str) -> dict:
        """Update case status."""
        if not self.is_configured():
            return {"status": "not_configured"}

        try:
            import httpx
            headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
            
            response = httpx.patch(
                f"{self.url}/api/v1/case/{case_id}",
                json={"status": status},
                headers=headers,
                timeout=30
            )
            
            return {"status": "success" if response.status_code == 200 else "error"}
            
        except Exception as e:
            return {"status": "error", "message": str(e)}


def create_case(title: str, description: str, severity: int = 2,
                ips: list[str] | None = None, domains: list[str] | None = None) -> dict:
    """Create a case from log analysis."""
    client = TheHiveClient()
    
    if not client.is_configured():
        return {
            "status": "skipped",
            "reason": "TheHive not configured. Set THEHIVE_URL and THEHIVE_API_KEY."
        }
    
    observables = []
    if ips:
        for ip in ips:
            if ip and not ip.startswith(("192.168.", "10.", "172.")):
                observables.append({"type": "ip", "value": ip})
    if domains:
        for domain in domains:
            observables.append({"type": "domain", "value": domain})
    
    return client.create_case(title, description, severity, observables=observables)


def create_case_from_records(records: list[dict], title: str | None = None) -> dict:
    """Create a case from parsed log records."""
    severity_map = {"critical": 3, "high": 2, "medium": 2, "low": 1, "info": 1}
    
    max_severity = "info"
    for r in records:
        sev = r.get("severity", "info")
        if sev in ("critical", "high"):
            max_severity = sev
            if sev == "critical":
                break
    
    severity = severity_map.get(max_severity, 2)
    
    unique_ips = list(set(r.get("source_ip", "") for r in records if r.get("source_ip")))
    
    if not title:
        title = f"Security Incident: {max_severity.upper()} severity"
    
    description = "LogSentry incident analysis\n\n"
    description += f"Events: {len(records)}\n"
    description += f"Unique IPs: {len(unique_ips)}\n"
    description += f"Severity: {max_severity}\n\n"
    description += "Source IPs:\n" + "\n".join(f"  - {ip}" for ip in unique_ips[:20])
    
    return create_case(title, description, severity, ips=unique_ips)