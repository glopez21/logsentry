"""ThreatPulse integration client.

Pushes LogSentry detection events and engine telemetry into the ThreatPulse
platform through its SIEM webhook ingest endpoint:

    POST {api_url}/webhooks

The SIEM app stores each event as a log entry (source=logsentry) and feeds the
ThreatPulse detection/correlation pipeline. `api_url` must point at the SIEM
API base — e.g. the ThreatPulse frontend nginx route that proxies `/api/siem`
to `siem-app` (`http://127.0.0.1:8081/api/siem/api/v1`).

Auth is optional: a webhook secret (HMAC-SHA256 `X-Webhook-Signature`) is used
by the receiver only when configured; if the platform requires one, provide the
shared secret via `api_key` and the client signs the body.

This client is intentionally small and synchronous; the daemon schedules calls
from async contexts as needed. Failures are swallowed with debug logging to
avoid impacting the hot path.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone
from typing import Any

import httpx

logger = logging.getLogger("logsentry.threatpulse")

# Map LogSentry severities to SIEM log levels.
_LEVEL_MAP = {
    "critical": "critical",
    "high": "error",
    "medium": "warning",
    "low": "warning",
    "info": "info",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ThreatPulseClient:
    def __init__(self, api_url: str, api_key: str = "", timeout: float = 5.0):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self._headers = {"Content-Type": "application/json"}
        if api_key:
            self._headers["Authorization"] = f"Bearer {api_key}"

    def _post_webhook(self, *, event: str, payload: dict[str, Any]) -> bool:
        url = f"{self.api_url}/webhooks"
        headers = {
            "X-Webhook-Source": "logsentry",
            "X-Webhook-Event": event,
            **self._headers,
        }
        try:
            body = json.dumps(payload, default=str).encode("utf-8")
            if self.api_key:
                sig = hmac.new(self.api_key.encode(), body, hashlib.sha256).hexdigest()
                headers["X-Webhook-Signature"] = sig
            resp = httpx.post(url, content=body, headers=headers, timeout=self.timeout)
            if not resp.is_success:
                logger.debug("ThreatPulse webhook rejected (%s): %s", resp.status_code, resp.text[:200])
                return False
            return True
        except Exception as e:
            logger.debug("ThreatPulse webhook push failed: %s", e)
            return False

    def push_event(
        self,
        *,
        rule_name: str,
        severity: str,
        description: str,
        source_ip: str = "",
        event_type: str = "",
        timestamp: str = "",
        tags: list[str] | None = None,
    ) -> bool:
        """Send a detection event to the ThreatPulse SIEM."""
        payload = {
            "timestamp": timestamp or _now(),
            "level": _LEVEL_MAP.get(severity, "info"),
            "source": "logsentry",
            "source_ip": source_ip or "",
            "user": "",
            "message": (f"LogSentry: {rule_name} — {description}")[:500],
            "summary": (description or "")[:500],
            "category": event_type or "detection",
            "rule": rule_name,
            "severity": severity,
            "tags": tags or ["logsentry", rule_name, severity],
        }
        return self._post_webhook(event="detection", payload=payload)

    def push_telemetry(self, metrics: dict[str, Any]) -> bool:
        """Send periodic engine stats to the ThreatPulse SIEM."""
        payload = {
            "timestamp": _now(),
            "level": "info",
            "source": "logsentry",
            "source_ip": "",
            "user": "",
            "message": "LogSentry engine telemetry",
            "summary": "engine telemetry",
            "category": "telemetry",
            "raw_data": {"metrics": metrics},
        }
        return self._post_webhook(event="telemetry", payload=payload)
