"""Configuration loader for LogSentry Engine."""

from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import yaml

DEFAULT_PATHS: list[str] = [
    "/etc/logsentry/logsentry.yaml",
    "./logsentry.yaml",
    "~/.config/logsentry/logsentry.yaml",
]

DEFAULT_CONFIG = {
    "engine": {
        "mode": "cli",
        "log_level": "info",
        "detection_interval": 30,
        "stats_interval": 60,
    },
    "storage": {
        "dsn": os.environ.get(
            "LOGSENTRY_DSN",
            "postgresql://logsentry:logsentry@localhost:5432/logsentry",
        ),
        "pool_min": 2,
        "pool_max": 10,
        "retention_days": 90,
        "batch_size": 500,
        "flush_interval": 5,
    },
    "ingest": {
        "syslog": {"enabled": False, "bind": "0.0.0.0", "port": 514, "protocol": "udp"},
        "http": {"enabled": True},
        "file_watchers": {"enabled": False, "paths": ["/var/log"]},
        # Parser overrides to pin formats for specific sources.
        # Examples:
        #   - {source_ip: "10.0.0.5", parser: "web_access"}
        #   - {contains: "nginx:", parser: "web_error"}
        "overrides": [],
    },
    "detection": {
        "enabled": True,
        "rules": [],
        "alerts": {
            "stdout": True,
            "webhook": "",
            "discord": {"webhook_url": ""},
            "slack": {"webhook_url": ""},
            "telegram": {"bot_token": "", "chat_id": ""},
        },
    },
    "server": {
        "host": "0.0.0.0",
        "port": 8080,
        # Optional API key to protect /ingest and /api endpoints. If empty, auth is disabled.
        "api_key": os.environ.get("LOGSENTRY_API_KEY", ""),
    },
    "schemas": ["logsentry", "alertflow", "threatpulse", "shared"],
    "augur": {
        "enabled": bool(os.environ.get("AUGUR_URL")),
        "hub_url": os.environ.get("AUGUR_URL", ""),
        "agent_name": os.environ.get("AUGUR_AGENT_NAME", "logsentry"),
        "agent_type": os.environ.get("AUGUR_AGENT_TYPE", "logsentry"),
        "api_key": os.environ.get("AUGUR_API_KEY", ""),
        "heartbeat_interval": int(os.environ.get("AUGUR_HEARTBEAT_INTERVAL", "30")),
    },
    "threatpulse": {
        # Auto-enable if THREATPULSE_URL is present in the environment
        "enabled": bool(os.environ.get("THREATPULSE_URL")),
        "api_url": os.environ.get("THREATPULSE_URL", ""),
        "api_key": os.environ.get("THREATPULSE_API_KEY", ""),
        "timeout": float(os.environ.get("THREATPULSE_TIMEOUT", "5.0")),
    },
}


def find_config() -> str | None:
    """Search standard paths for a config file."""
    for path_str in DEFAULT_PATHS:
        path = Path(path_str).expanduser().resolve()
        if path.exists() and path.is_file():
            return str(path)
    return None


def load_config(path: str | None = None) -> dict[str, Any]:
    """Load config from file, falling back to defaults.

    Environment variables override file values:
      - LOGSENTRY_DSN overrides storage.dsn
      - LOGSENTRY_MODE overrides engine.mode
    """
    config: dict[str, Any] = copy.deepcopy(DEFAULT_CONFIG)

    config_path = path or find_config()
    if config_path:
        with open(config_path) as f:
            file_config = yaml.safe_load(f) or {}
        _deep_merge(config, file_config)

    # Env overrides
    if os.environ.get("LOGSENTRY_DSN"):
        config["storage"]["dsn"] = os.environ["LOGSENTRY_DSN"]
    if os.environ.get("LOGSENTRY_MODE"):
        config["engine"]["mode"] = os.environ["LOGSENTRY_MODE"]
    # Env presence means explicit operator intent: enable + point the
    # integration, even if the YAML shipped with `enabled: false`.
    if os.environ.get("AUGUR_URL"):
        config["augur"]["enabled"] = True
        config["augur"]["hub_url"] = os.environ["AUGUR_URL"]
    if os.environ.get("THREATPULSE_URL"):
        config["threatpulse"]["enabled"] = True
        config["threatpulse"]["api_url"] = os.environ["THREATPULSE_URL"]

    return config


def _deep_merge(base: dict, overlay: dict) -> None:
    """Recursively merge overlay into base."""
    for key, value in overlay.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
