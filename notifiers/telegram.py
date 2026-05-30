"""Telegram bot notifier."""

from __future__ import annotations

from typing import Any

from .base import AlertMessage, Notifier

LEVEL_ICONS = {
    "critical": "\u26a0\ufe0f",
    "high": "\U0001f534",
    "medium": "\U0001f7e1",
    "low": "\U0001f7e2",
    "info": "\u2139\ufe0f",
}


class TelegramNotifier(Notifier):
    """Sends alerts via Telegram bot."""

    def __init__(self, config: dict[str, Any] | None = None):
        super().__init__(config)
        self.bot_token = self.config.get("bot_token") or self.config.get("telegram_token") or ""
        self.chat_id = self.config.get("chat_id") or self.config.get("telegram_chat_id") or ""

    def send(self, alert: AlertMessage) -> bool:
        if not self.bot_token or not self.chat_id:
            return False

        import httpx

        icon = LEVEL_ICONS.get(alert.severity, "")
        title = alert.title or alert.rule_name or "LogSentry Alert"

        lines = [f"{icon} *{title}*"]
        if alert.description:
            lines.append(f"\n{alert.description[:2000]}")
        lines.append("")
        lines.append(f"*Severity:* {alert.severity.upper()}")
        if alert.source_ip:
            lines.append(f"*Source IP:* {alert.source_ip}")
        if alert.event_type:
            lines.append(f"*Event Type:* {alert.event_type}")
        if alert.rule_name:
            lines.append(f"*Rule:* {alert.rule_name}")
        if alert.timestamp:
            lines.append(f"*Time:* {alert.timestamp}")

        for k, v in alert.fields.items():
            lines.append(f"*{k}:* {str(v)[:500]}")

        payload = {
            "chat_id": self.chat_id,
            "text": "\n".join(lines),
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }

        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"

        try:
            resp = httpx.post(url, json=payload, timeout=10)
            return resp.status_code == 200
        except Exception:
            return False
