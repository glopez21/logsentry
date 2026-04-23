#!/usr/bin/env python3
"""
Ticket Alerter - Creates tickets in external systems (AlertFlow, etc.)
"""

import json
import os
from typing import Optional, Dict, Any
from datetime import datetime


try:
    import httpx
except ImportError:
    httpx = None


class TicketAlerter:
    """Creates tickets in external systems."""
    
    def __init__(
        self,
        webhook_url: Optional[str] = None,
        api_url: Optional[str] = None,
        api_key: Optional[str] = None,
        default_priority: str = "P3",
        default_assignee: str = ""
    ):
        self.webhook_url = webhook_url or os.environ.get("LOGSENTRY_WEBHOOK_URL")
        self.api_url = api_url or os.environ.get("LOGSENTRY_API_URL")
        self.api_key = api_key or os.environ.get("LOGSENTRY_API_KEY", "")
        self.default_priority = default_priority
        self.default_assignee = default_assignee
        
        self._client = None
        if httpx:
            self._client = httpx.Client(timeout=10.0)
    
    def alert(
        self,
        title: str,
        message: str,
        severity: str = "medium",
        source_ip: str = "",
        user: str = "",
        tags: Optional[list] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Create a ticket/alert."""
        payload = self._build_payload(
            title=title,
            message=message,
            severity=severity,
            source_ip=source_ip,
            user=user,
            tags=tags or []
        )
        
        if self.webhook_url:
            return self._send_webhook(payload)
        elif self.api_url:
            return self._send_api(payload)
        else:
            return {"status": "no_endpoint", "message": "No webhook or API configured"}
    
    def _build_payload(
        self,
        title: str,
        message: str,
        severity: str,
        source_ip: str,
        user: str,
        tags: list
    ) -> dict:
        """Build the ticket payload."""
        priority_map = {
            "critical": "P1",
            "high": "P2", 
            "medium": "P3",
            "low": "P4",
            "info": "P4"
        }
        
        return {
            "title": title,
            "description": message,
            "severity": severity.upper(),
            "priority": priority_map.get(severity.lower(), self.default_priority),
            "source_ip": source_ip,
            "user": user,
            "tags": ["logsentry"] + tags,
            "timestamp": datetime.now().isoformat()
        }
    
    def _send_webhook(self, payload: dict) -> Dict[str, Any]:
        """Send to webhook."""
        if not self._client or not self.webhook_url:
            return {"status": "error", "message": "Webhook not configured"}
        
        try:
            response = self._client.post(
                self.webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            return {"status": "success", "response": response.status_code}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def _send_api(self, payload: dict) -> Dict[str, Any]:
        """Send to API endpoint."""
        if not self._client or not self.api_url:
            return {"status": "error", "message": "API not configured"}
        
        headers = {"Authorization": f"Bearer {self.api_key}"}
        
        try:
            response = self._client.post(
                f"{self.api_url}/alerts",
                json=payload,
                headers=headers
            )
            return {"status": "success", "response": response.status_code}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def close(self) -> None:
        """Close HTTP client."""
        if self._client:
            self._client.close()


class AlertFlowAlerter(TicketAlerter):
    """AlertFlow-specific ticket creation."""
    
    def alert(
        self,
        title: str,
        message: str,
        severity: str = "medium",
        source_ip: str = "",
        user: str = "",
        tags: Optional[list] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Create AlertFlow ticket."""
        payload = self._build_payload(
            title=title,
            message=message,
            severity=severity,
            source_ip=source_ip,
            user=user,
            tags=tags or ["logsentry"]
        )
        
        # Add AlertFlow-specific fields
        payload.update({
            "source": "logsentry",
            "category": self._categorize(severity),
            "status": "open"
        })
        
        return self._send_api(payload)
    
    def _categorize(self, severity: str) -> str:
        """Map severity to category."""
        categories = {
            "critical": "security_incident",
            "high": "security_incident", 
            "medium": "securityAlert",
            "low": "informational",
            "info": "informational"
        }
        return categories.get(severity.lower(), "other")


def create_alerter(
    url: Optional[str] = None,
    alerter_type: str = "webhook"
) -> TicketAlerter:
    """Factory function to create alerter."""
    if alerter_type == "alertflow":
        return AlertFlowAlerter(webhook_url=url)
    return TicketAlerter(webhook_url=url)