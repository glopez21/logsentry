"""Bridge: LogSentry detection alerts → n3xusDB event_outbox."""

import asyncio
import logging

from n3xuslib import N3xusClient
from n3xuslib.config import N3xusConfig

logger = logging.getLogger("logsentry.n3xus")


def emit_alert(
    *,
    source_instance: str = "",
    rule_name: str,
    severity: str,
    description: str,
    source_ip: str = "",
    event_type: str = "",
    loop: asyncio.AbstractEventLoop | None = None,
) -> str | None:
    config = N3xusConfig.from_env()

    async def _emit() -> str | None:
        try:
            async with N3xusClient(config) as client:
                return await client.emit(
                    source="logsentry",
                    source_instance=source_instance or config.source_instance,
                    event_type=rule_name,
                    severity=severity,
                    title=f"LogSentry: {rule_name}",
                    payload={
                        "description": description[:500],
                        "source_ip": source_ip,
                        "event_type": event_type,
                        "rule": rule_name,
                    },
                    tags=["logsentry", rule_name, severity],
                )
        except Exception as e:
            logger.debug("n3xuslib emit failed: %s", e)
            return None

    # If a running event loop is provided (daemon mode), schedule on it
    # instead of calling asyncio.run() which would create a conflicting loop.
    if loop is not None and loop.is_running():
        asyncio.run_coroutine_threadsafe(_emit(), loop)
        return None

    # Check if we're already inside a running event loop (shouldn't happen
    # from daemon callbacks, but handle defensively).
    try:
        running = asyncio.get_running_loop()
    except RuntimeError:
        running = None

    if running is not None and running.is_running():
        asyncio.run_coroutine_threadsafe(_emit(), running)
        return None

    return asyncio.run(_emit())
