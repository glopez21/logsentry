"""Base notifier interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AlertMessage:
    title: str = ""
    description: str = ""
    severity: str = "medium"
    source_ip: str = ""
    event_type: str = ""
    rule_name: str = ""
    timestamp: str = ""
    fields: dict[str, Any] = field(default_factory=dict)


class Notifier(ABC):
    """Base class for alert notification backends."""

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}

    @abstractmethod
    def send(self, alert: AlertMessage) -> bool:
        """Send a notification. Returns True on success."""
        ...

    def alert(self, alert: AlertMessage) -> bool:
        """Alias for send()."""
        return self.send(alert)
