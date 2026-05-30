"""Slack webhook notifier."""

from __future__ import annotations

from typing import Any

from .base import AlertMessage, Notifier

LEVEL_EMOJI = {
    "critical": ":rotating_light:",
    "high": ":red_circle:",
    "medium": ":warning:",
    "low": ":large_green_circle:",
    "info": ":information_source:",
}


class SlackNotifier(Notifier):
    """Sends alerts to a Slack channel via webhook."""

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.webhook_url = (
            self.config.get("webhook_url")
            or self.config.get("slack_webhook")
            or ""
        )

    def send(self, alert: AlertMessage) -> bool:
        if not self.webhook_url:
            return False

        import httpx

        emoji = LEVEL_EMOJI.get(alert.severity, ":grey_question:")
        title = alert.title or alert.rule_name or "LogSentry Alert"
        blocks: list[dict[str, Any]] = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{emoji} {title}"},
            },
        ]

        if alert.description:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": alert.description[:2000]},
            })

        fields = []
        if alert.severity:
            fields.append({"type": "mrkdwn", "text": f"*Severity:*\n{alert.severity.upper()}"})
        if alert.source_ip:
            fields.append({"type": "mrkdwn", "text": f"*Source IP:*\n{alert.source_ip}"})
        if alert.event_type:
            fields.append({"type": "mrkdwn", "text": f"*Event Type:*\n{alert.event_type}"})
        if alert.rule_name:
            fields.append({"type": "mrkdwn", "text": f"*Rule:*\n{alert.rule_name}"})

        if fields:
            blocks.append({"type": "section", "fields": fields})

        for k, v in alert.fields.items():
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*{k}:* {str(v)[:500]}"},
            })

        payload = {"blocks": blocks}

        try:
            resp = httpx.post(self.webhook_url, json=payload, timeout=10)
            return resp.status_code == 200
        except Exception:
            return False
