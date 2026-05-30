"""Discord webhook notifier."""

from __future__ import annotations

from typing import Any

from .base import AlertMessage, Notifier

COLORS = {
    "critical": 15548997,
    "high": 16711680,
    "medium": 16776960,
    "low": 5763719,
    "info": 3447003,
}


class DiscordNotifier(Notifier):
    """Sends alerts to a Discord channel via webhook."""

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.webhook_url = (
            self.config.get("webhook_url")
            or self.config.get("discord_webhook")
            or ""
        )

    def send(self, alert: AlertMessage) -> bool:
        if not self.webhook_url:
            return False

        import httpx

        color = COLORS.get(alert.severity, COLORS["info"])
        fields: list[dict[str, Any]] = []
        if alert.source_ip:
            fields.append({"name": "Source IP", "value": alert.source_ip, "inline": True})
        if alert.event_type:
            fields.append({"name": "Event Type", "value": alert.event_type, "inline": True})
        if alert.rule_name:
            fields.append({"name": "Rule", "value": alert.rule_name, "inline": True})
        for k, v in alert.fields.items():
            fields.append({"name": str(k), "value": str(v)[:500], "inline": True})

        embed: dict[str, Any] = {
            "title": alert.title or alert.rule_name or "LogSentry Alert",
            "description": alert.description[:2000] if alert.description else "",
            "color": color,
            "fields": fields,
            "timestamp": alert.timestamp or None,
        }

        payload = {
            "username": "LogSentry",
            "avatar_url": "",
            "embeds": [embed],
        }

        try:
            resp = httpx.post(self.webhook_url, json=payload, timeout=10)
            return resp.status_code == 204
        except Exception:
            return False
