"""Notification backends for LogSentry alerts."""

from .base import Notifier
from .discord import DiscordNotifier
from .slack import SlackNotifier
from .telegram import TelegramNotifier

try:
    from .augur import AugurNotifier
except ImportError:
    AugurNotifier = None  # type: ignore[assignment,misc]

__all__ = ["Notifier", "DiscordNotifier", "SlackNotifier", "TelegramNotifier", "AugurNotifier"]
