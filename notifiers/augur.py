"""Augur hub notifier — push alerts to the Augur SOC platform."""

from __future__ import annotations

import logging
from typing import Any

from .base import AlertMessage, Notifier

logger = logging.getLogger("logsentry.augur")


class AugurNotifier(Notifier):
    """Push LogSentry alerts to the Augur hub as events."""

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self._client: Any = None
        self._init_client()

    def _init_client(self) -> None:
        try:
            from augur_client import AugurClient

            self._client = AugurClient(
                hub_url=self.config.get("hub_url", ""),
                agent_name=self.config.get("agent_name", "logsentry"),
                agent_type=self.config.get("agent_type", "logsentry"),
                api_key=self.config.get("api_key", ""),
                heartbeat_interval=self.config.get("heartbeat_interval", 30),
            )
            logger.info("Augur client initialized (hub: %s)", self.config.get("hub_url", ""))
        except ImportError:
            logger.warning("augur-client not installed — install with: pip install 'logsentry[augur]'")
            self._client = None
        except Exception as e:
            logger.warning("Augur client init failed: %s", e)
            self._client = None

    def send(self, alert: AlertMessage) -> bool:
        if not self._client:
            return False
        try:
            self._client.push_event(
                event_type=alert.rule_name or alert.event_type or "alert",
                severity=alert.severity,
                source="logsentry",
                title=alert.title,
                payload={
                    "description": alert.description[:500],
                    "source_ip": alert.source_ip,
                    "event_type": alert.event_type,
                    "rule_name": alert.rule_name,
                    **alert.fields,
                },
                tags=["logsentry", alert.rule_name, alert.severity],
            )
            return True
        except Exception as e:
            logger.debug("Augur push failed: %s", e)
            return False
