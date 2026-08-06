import os
import time
import uuid
import json
import threading
from typing import Any

import httpx


class AugurClient:
    def __init__(
        self,
        hub_url: str | None = None,
        agent_id: str | None = None,
        agent_name: str | None = None,
        agent_type: str | None = None,
        api_key: str | None = None,
        heartbeat_interval: int = 30,
    ):
        self.hub_url = (hub_url or os.getenv("AUGUR_URL", "")).rstrip("/")
        self.agent_id = agent_id or os.getenv("AUGUR_AGENT_ID", "")
        self.agent_name = agent_name or os.getenv("AUGUR_AGENT_NAME", "")
        self.agent_type = agent_type or os.getenv("AUGUR_AGENT_TYPE", "")
        self.api_key = api_key or os.getenv("AUGUR_API_KEY", "")
        self.auth_token = os.getenv("AUGUR_AUTH_TOKEN", "")
        self.heartbeat_interval = int(os.getenv("AUGUR_HEARTBEAT_INTERVAL", str(heartbeat_interval)))
        self._heartbeat_thread: threading.Thread | None = None
        self._running = False
        # Optional multi-tenant header support
        self.tenant_id = os.getenv("AUGUR_TENANT_ID", "")

    @property
    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        token = self.auth_token or self.api_key
        if token:
            h["Authorization"] = f"Bearer {token}"
        if self.tenant_id:
            h["X-Tenant-ID"] = self.tenant_id
        return h

    def register(self, name: str | None = None, agent_type: str | None = None, version: str = "", hostname: str = "", ip_address: str = "") -> dict:
        payload = {
            "name": name or self.agent_name,
            "agent_type": agent_type or self.agent_type,
            "version": version,
            "hostname": hostname or os.uname().nodename if hasattr(os, "uname") else "",
            "ip_address": ip_address,
        }
        resp = httpx.post(f"{self.hub_url}/api/v1/agents/register", json=payload, headers=self._headers, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        self.agent_id = data.get("id", self.agent_id)
        self.auth_token = data.get("auth_token") or self.auth_token
        return data

    def heartbeat(self) -> dict:
        if not self.agent_id:
            raise RuntimeError("Agent not registered — call register() first")
        resp = httpx.post(
            f"{self.hub_url}/api/v1/agents/heartbeat",
            json={"agent_id": self.agent_id, "status": "online"},
            headers=self._headers,
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()

    def push_event(self, event_type: str, severity: str, source: str, title: str = "", payload: dict | None = None, context: dict | None = None, tags: list[str] | None = None) -> dict:
        data: dict[str, Any] = {
            "event_type": event_type,
            "severity": severity,
            "source": source,
            "agent_id": self.agent_id,
            "title": title,
        }
        if payload:
            data["payload"] = payload
        if context:
            data["context"] = context
        if tags:
            data["tags"] = tags
        resp = httpx.post(f"{self.hub_url}/api/v1/events", json=data, headers=self._headers, timeout=10)
        resp.raise_for_status()
        return resp.json()

    def push_events(self, events: list[dict]) -> dict:
        for e in events:
            e.setdefault("agent_id", self.agent_id)
        resp = httpx.post(f"{self.hub_url}/api/v1/events/batch", json=events, headers=self._headers, timeout=15)
        resp.raise_for_status()
        return resp.json()

    def pull_config(self) -> dict:
        if not self.agent_id:
            raise RuntimeError("Agent not registered — call register() first")
        resp = httpx.get(f"{self.hub_url}/api/v1/agents/{self.agent_id}/config", headers=self._headers, timeout=10)
        resp.raise_for_status()
        return resp.json()

    def start_heartbeat(self):
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            return
        self._running = True

        def _loop():
            while self._running:
                try:
                    self.heartbeat()
                except httpx.HTTPStatusError as e:
                    if e.response.status_code == 404:
                        print("[augur-client] Agent not found — re-registering...")
                        try:
                            self.register()
                            print(f"[augur-client] Re-registered, agent_id={self.agent_id}")
                        except Exception as re:
                            print(f"[augur-client] Re-registration failed: {re}")
                    else:
                        print(f"[augur-client] heartbeat failed: {e}")
                except Exception as e:
                    print(f"[augur-client] heartbeat failed: {e}")
                time.sleep(self.heartbeat_interval)

        self._heartbeat_thread = threading.Thread(target=_loop, daemon=True)
        self._heartbeat_thread.start()

    def stop_heartbeat(self):
        self._running = False
