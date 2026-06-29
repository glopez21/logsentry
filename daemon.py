"""LogSentry Engine Daemon — async-first persistent log ingestion, storage, and detection."""

from __future__ import annotations

import asyncio
import logging
import os
import signal
from datetime import datetime, timezone
from typing import Any, Optional

from db.store import LogStore, AsyncLogStore
from notifiers import DiscordNotifier, SlackNotifier, TelegramNotifier
from notifiers.base import AlertMessage

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    force=True,
)
logger = logging.getLogger("logsentry.daemon")


class LogSentryDaemon:
    """Main engine loop with asyncio orchestration and optional asyncpg."""

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self._running = False
        self._tasks: list[asyncio.Task] = []
        self._loop: asyncio.AbstractEventLoop | None = None

        storage_cfg = config["storage"]
        use_async = storage_cfg.get("async", False)

        if use_async:
            self.store: LogStore | AsyncLogStore = AsyncLogStore(
                dsn=storage_cfg["dsn"],
                min_conn=storage_cfg.get("pool_min", 2),
                max_conn=storage_cfg.get("pool_max", 10),
                batch_size=storage_cfg.get("batch_size", 500),
                flush_interval=storage_cfg.get("flush_interval", 5),
            )
        else:
            self.store = LogStore(
                dsn=storage_cfg["dsn"],
                min_conn=storage_cfg.get("pool_min", 2),
                max_conn=storage_cfg.get("pool_max", 10),
                batch_size=storage_cfg.get("batch_size", 500),
                flush_interval=storage_cfg.get("flush_interval", 5),
            )

        self._syslog_listener: Any = None
        self._http_server: Any = None
        self._file_watchers: list[Any] = []

        self._detection_interval = config["engine"].get("detection_interval", 30)
        self._stats_interval = config["engine"].get("stats_interval", 60)
        self._alert_rules: list[dict] = config["detection"].get("rules", []) or []

        self._notifiers: list[Any] = []
        alert_cfg = config["detection"].get("alerts", {})
        if alert_cfg.get("discord", {}).get("webhook_url"):
            self._notifiers.append(DiscordNotifier(alert_cfg["discord"]))
        if alert_cfg.get("slack", {}).get("webhook_url"):
            self._notifiers.append(SlackNotifier(alert_cfg["slack"]))
        if alert_cfg.get("telegram", {}).get("bot_token") and alert_cfg.get("telegram", {}).get("chat_id"):
            self._notifiers.append(TelegramNotifier(alert_cfg["telegram"]))
        if self._notifiers:
            logger.info("Initialized %s notifiers", len(self._notifiers))

        self._augur_client: Any = None
        augur_cfg = config.get("augur", {})
        if augur_cfg.get("enabled") and augur_cfg.get("hub_url"):
            try:
                from augur_client import AugurClient
                self._augur_client = AugurClient(
                    hub_url=augur_cfg["hub_url"],
                    agent_name=augur_cfg.get("agent_name", "logsentry"),
                    agent_type=augur_cfg.get("agent_type", "logsentry"),
                    api_key=augur_cfg.get("api_key", ""),
                    heartbeat_interval=augur_cfg.get("heartbeat_interval", 30),
                )
                logger.info("Augur hub client initialized (hub: %s)", augur_cfg["hub_url"])
            except ImportError:
                logger.warning("augur-client not installed — install with: pip install 'logsentry[augur]'")
            except Exception as e:
                logger.warning("Augur client init failed: %s", e)

    # ── Lifecycle ─────────────────────────────────────────────────

    def start(self) -> None:
        """Run the daemon — starts the asyncio event loop."""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        # Install signal handlers
        def _make_handler(sig_num: int):
            return lambda: self._signal_handler(sig_num, None)
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                self._loop.add_signal_handler(sig, _make_handler(sig))
            except (ValueError, NotImplementedError):
                signal.signal(sig, lambda s, f: self._signal_handler(s, f))

        try:
            self._loop.run_until_complete(self._async_start())
        except KeyboardInterrupt:
            pass
        finally:
            self._loop.run_until_complete(self._async_stop())
            self._loop.close()

    async def _async_start(self) -> None:
        """Async start routine."""
        self._running = True
        self._tasks = []

        # 1. Connect to Postgres
        logger.info("Connecting to Postgres...")
        if isinstance(self.store, AsyncLogStore):
            await self.store.connect()
        else:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self.store.connect)

        # 2. Initialize schema
        logger.info("Initializing schema...")
        if isinstance(self.store, AsyncLogStore):
            await self.store.init_schema()
        else:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self.store.init_schema)

        # 3. Enforce retention
        retention = self.config["storage"].get("retention_days", 90)
        if isinstance(self.store, AsyncLogStore):
            dropped = await self.store.enforce_retention(retention)
        else:
            loop = asyncio.get_event_loop()
            dropped = await loop.run_in_executor(
                None, self.store.enforce_retention, retention
            )
        if dropped:
            logger.info("Cleaned %s old partitions", dropped)

        # 4. Start ingest collectors
        await self._start_ingest()

        # 5. Register with Augur hub
        if self._augur_client:
            try:
                self._augur_client.register(
                    name=self._augur_client.agent_name,
                    agent_type=self._augur_client.agent_type,
                )
                self._augur_client.start_heartbeat()
                logger.info("Registered with Augur hub, heartbeat started")
            except Exception as e:
                logger.warning("Augur registration failed: %s", e)

        # 6. Stats reporter task
        self._tasks.append(asyncio.create_task(self._stats_loop()))

        # 7. Detection pipeline task
        if self.config["detection"].get("enabled", True):
            self._tasks.append(asyncio.create_task(self._detection_loop()))

        logger.info("Daemon started — ingesting, storing, detecting")

        # 8. Keep running
        await self._wait_for_shutdown()

    async def _wait_for_shutdown(self) -> None:
        """Wait until stop is requested."""
        while self._running:
            await asyncio.sleep(1)

    def stop(self) -> None:
        """Request graceful shutdown."""
        self._running = False
        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)

    async def _async_stop(self) -> None:
        """Async shutdown."""
        logger.info("Shutting down...")

        # Cancel background tasks
        for t in self._tasks:
            t.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

        # Stop Augur heartbeat
        if self._augur_client:
            try:
                self._augur_client.stop_heartbeat()
            except Exception:
                pass

        # Stop syslog listener
        if self._syslog_listener:
            try:
                self._syslog_listener.stop()
            except Exception:
                pass

        # Close DB
        try:
            if isinstance(self.store, AsyncLogStore):
                await self.store.close()
            else:
                await asyncio.get_event_loop().run_in_executor(None, self.store.close)
        except Exception:
            pass

        logger.info("Daemon stopped")

    def _signal_handler(self, signum, frame) -> None:
        """Handle shutdown signals."""
        print()
        logger.info("Received signal %s, shutting down...", signum)
        self.stop()

    # ── Ingest ────────────────────────────────────────────────────

    async def _start_ingest(self) -> None:
        """Start configured ingest sources."""
        ingest_cfg = self.config["ingest"]

        if ingest_cfg.get("syslog", {}).get("enabled"):
            await self._start_syslog(ingest_cfg["syslog"])

        file_cfg = ingest_cfg.get("file_watchers", {})
        if file_cfg.get("enabled") and file_cfg.get("paths"):
            await self._start_file_watchers(file_cfg["paths"])

    async def _start_syslog(self, cfg: dict) -> None:
        """Start syslog listener in executor thread."""
        from collector.syslog import SyslogListener

        listener = SyslogListener(
            port=cfg.get("port", 514),
            protocol=cfg.get("protocol", "udp"),
            parser=self._parse_line,
            callback=self._syslog_callback,
            bind_address=cfg.get("bind", "0.0.0.0"),
        )

        loop = asyncio.get_event_loop()
        self._tasks.append(
            asyncio.ensure_future(loop.run_in_executor(None, listener.start))
        )
        self._syslog_listener = listener
        logger.info(
            "Syslog listener started: %s:%s/%s",
            cfg.get("bind", "0.0.0.0"), cfg.get("port", 514), cfg.get("protocol", "udp"),
        )

    async def _start_file_watchers(self, paths: list[str]) -> None:
        """Watch directories for .log files via executor."""
        from collector.file_tail import FileTailCollector

        def discover_log_files(base_dirs: list[str]) -> list[str]:
            files = []
            for base in base_dirs:
                if os.path.isdir(base):
                    for root, _dirs, fnames in os.walk(base):
                        for fname in fnames:
                            if fname.endswith(".log"):
                                files.append(os.path.join(root, fname))
            return sorted(files)

        log_files = discover_log_files(paths)
        loop = asyncio.get_event_loop()

        for fp in log_files[:50]:
            collector = FileTailCollector(
                filepath=fp,
                parser=self._parse_line,
                callback=self._file_watcher_callback,
            )
            self._tasks.append(
                asyncio.ensure_future(loop.run_in_executor(None, collector.start, False))
            )
            self._file_watchers.append(collector)

        logger.info("Watching %s log files", len(log_files))

    def _parse_line(self, line: str) -> Optional[dict]:
        from main import detect_format, LOG_PARSERS

        detected = detect_format(line)
        if detected:
            parser = LOG_PARSERS.get(detected)
            if parser:
                try:
                    return parser(line)
                except Exception:
                    pass
        return None

    def _syslog_callback(self, message: str, record: Optional[dict], source: tuple) -> None:
        self._store_record(record, message, source="syslog", host=source[0] if source else "")

    def _file_watcher_callback(self, line: str, record: Optional[dict]) -> None:
        self._store_record(record, line, source="file")

    def _store_record(
        self, record: Optional[dict], raw_message: str, source: str = "syslog", host: str = ""
    ) -> None:
        """Parse and store a log record to Postgres. Runs synchronously from collector callbacks."""
        try:
            if record:
                if isinstance(self.store, AsyncLogStore):
                    # Schedule async insert from sync callback
                    asyncio.run_coroutine_threadsafe(
                        self._async_store_record(record, raw_message, source, host),
                        self._loop or asyncio.get_event_loop(),
                    )
                else:
                    self._sync_store_record(record, raw_message, source, host)
        except Exception as e:
            logger.warning("Failed to store log: %s", e)

    def _sync_store_record(self, record: dict, raw_message: str, source: str, host: str) -> None:
        self.store.insert_log(
            timestamp=record.get("timestamp", datetime.now(timezone.utc)),
            message=record.get("message", "") or raw_message,
            labels={"source": source, "host": host or record.get("host", "unknown")},
            source=source,
            format=record.get("format", "syslog"),
            host=host or record.get("host", ""),
            source_ip=record.get("source_ip", ""),
            user_name=record.get("user", ""),
            event_type=record.get("event_type", ""),
            severity=record.get("severity", "info"),
            parsed=record,
            mitre_id=(
                [record["mitre_tactic"]] if record.get("mitre_tactic") else []
            ),
            raw_message=raw_message,
        )
        hostname = host or record.get("host", "")
        src_ip = record.get("source_ip", "")
        if hostname:
            try:
                self.store.upsert_host(
                    hostname=hostname,
                    ip_address=src_ip,
                    role="",
                    labels={"source": source, "auto_discovered": "true"},
                )
            except Exception:
                pass

    async def _async_store_record(self, record: dict, raw_message: str, source: str, host: str) -> None:
        store = self.store
        if not isinstance(store, AsyncLogStore):
            return
        await store.insert_log(
            timestamp=record.get("timestamp", datetime.now(timezone.utc)),
            message=record.get("message", "") or raw_message,
            labels={"source": source, "host": host or record.get("host", "unknown")},
            source=source,
            format=record.get("format", "syslog"),
            host=host or record.get("host", ""),
            source_ip=record.get("source_ip", ""),
            user_name=record.get("user", ""),
            event_type=record.get("event_type", ""),
            severity=record.get("severity", "info"),
            parsed=record,
            mitre_id=(
                [record["mitre_tactic"]] if record.get("mitre_tactic") else []
            ),
            raw_message=raw_message,
        )
        hostname = host or record.get("host", "")
        src_ip = record.get("source_ip", "")
        if hostname:
            try:
                await store.upsert_host(
                    hostname=hostname,
                    ip_address=src_ip,
                    role="",
                    labels={"source": source, "auto_discovered": "true"},
                )
            except Exception:
                pass

    # ── Detection Pipeline ────────────────────────────────────────

    async def _detection_loop(self) -> None:
        """Periodically run detection on recent logs (async)."""
        last_check = datetime.now(timezone.utc)

        while self._running:
            try:
                now = datetime.now(timezone.utc)
                if isinstance(self.store, AsyncLogStore):
                    recent = await self.store.query(since=last_check, limit=5000)
                else:
                    loop = asyncio.get_event_loop()
                    recent = await loop.run_in_executor(
                        None, self.store.query, last_check, None, None, None, None, None, None, 5000, 0
                    )
                if recent:
                    await self._run_detections(recent)
                last_check = now
                await asyncio.sleep(self._detection_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Detection loop error: %s", e)
                await asyncio.sleep(self._detection_interval)

    async def _run_detections(self, records: list[dict]) -> None:
        """Apply detection rules to a batch of records."""
        from detection.detection_checks import run_detection_checks

        try:
            results = run_detection_checks(records)

            for check_name, findings in results.items():
                if not findings:
                    continue
                if isinstance(findings, list):
                    for finding in findings[:10]:
                        severity = "medium"
                        if "fail" in check_name:
                            severity = "high"
                        elif "suspicious" in check_name:
                            severity = "medium"
                        elif "exfil" in check_name:
                            severity = "critical"

                        if isinstance(self.store, AsyncLogStore):
                            await self.store.insert_detection(
                                log_id=None, rule_name=check_name,
                                severity=severity, description=str(finding),
                                rule_type="builtin",
                            )
                        else:
                            loop = asyncio.get_event_loop()
                            await loop.run_in_executor(
                                None, self.store.insert_detection,
                                None, check_name, severity, str(finding), "builtin", None, None, None,
                            )

                        await self._send_alert(
                            rule_name=check_name, severity=severity,
                            description=str(finding),
                        )
                elif isinstance(findings, dict):
                    description = (
                        f"{check_name}: {findings.get('unique_count', 0)} tactics, "
                        f"{list(findings.get('tactics', {}).keys())}"
                    )
                    if isinstance(self.store, AsyncLogStore):
                        await self.store.insert_detection(
                            log_id=None, rule_name=check_name,
                            severity="medium", description=description[:500],
                            rule_type="builtin",
                        )
                    else:
                        loop = asyncio.get_event_loop()
                        await loop.run_in_executor(
                            None, self.store.insert_detection,
                            None, check_name, "medium", description[:500], "builtin", None, None, None,
                        )
                    await self._send_alert(
                        rule_name=check_name, severity="medium",
                        description=description[:500],
                    )

            for rule in self._alert_rules:
                await self._evaluate_rule(rule, records)

        except Exception as e:
            logger.error("Detection error: %s", e)

    async def _evaluate_rule(self, rule: dict, records: list[dict]) -> None:
        """Evaluate a single custom alert rule against records."""
        name = rule.get("name", "unknown")
        condition = rule.get("condition", {})
        event_type = condition.get("event_type")
        user = condition.get("user")
        source_ip = condition.get("source_ip")
        threshold = condition.get("threshold", 1)
        severity = rule.get("severity", "medium")

        matches = []
        for r in records:
            if event_type and r.get("event_type") != event_type:
                continue
            if user and r.get("user") != user:
                continue
            if source_ip and r.get("source_ip") != source_ip:
                continue
            matches.append(r)

        if len(matches) >= threshold:
            desc = rule.get("description", "")
            if isinstance(self.store, AsyncLogStore):
                await self.store.insert_detection(
                    log_id=None, rule_name=name,
                    severity=severity, description=desc,
                    rule_type="custom",
                )
            else:
                loop = asyncio.get_event_loop()
                await loop.run_in_executor(
                    None, self.store.insert_detection,
                    None, name, severity, desc, "custom", None, None, None,
                )
            await self._send_alert(
                rule_name=name, severity=severity,
                description=rule.get("description", ""),
                source_ip=matches[0].get("source_ip", ""),
                event_type=matches[0].get("event_type", ""),
                timestamp=str(matches[0].get("timestamp", "")),
            )

    async def _send_alert(
        self,
        rule_name: str,
        severity: str,
        description: str,
        source_ip: str = "",
        event_type: str = "",
        timestamp: str = "",
    ) -> None:
        """Send alert to all configured notifiers."""
        alert_cfg = self.config["detection"].get("alerts", {})

        if alert_cfg.get("stdout", True):
            logger.warning("ALERT [%s] %s: %s", severity.upper(), rule_name, description)

        webhook = alert_cfg.get("webhook", "")
        if webhook:
            try:
                import httpx
                httpx.post(webhook, json={
                    "rule": rule_name, "severity": severity,
                    "description": description, "source_ip": source_ip,
                }, timeout=5)
            except Exception:
                pass

        msg = AlertMessage(
            title=f"LogSentry: {rule_name}",
            description=description,
            severity=severity,
            source_ip=source_ip,
            event_type=event_type,
            rule_name=rule_name,
            timestamp=timestamp,
        )
        for notifier in self._notifiers:
            try:
                notifier.send(msg)
            except Exception as e:
                logger.debug("Notifier error: %s", e)

        if self._augur_client:
            try:
                self._augur_client.push_event(
                    event_type=rule_name,
                    severity=severity,
                    source="logsentry",
                    title=f"LogSentry: {rule_name}",
                    payload={
                        "description": description[:500],
                        "source_ip": source_ip,
                        "event_type": event_type,
                    },
                    tags=["logsentry", rule_name, severity],
                )
            except Exception as e:
                logger.debug("Augur push failed: %s", e)

        from n3xus import emit_alert
        instance = self.config.get("engine", {}).get("instance", "")
        emit_alert(
            source_instance=instance,
            rule_name=rule_name,
            severity=severity,
            description=description,
            source_ip=source_ip,
            event_type=event_type,
        )

    # ── Stats ─────────────────────────────────────────────────────

    async def _stats_loop(self) -> None:
        """Periodically log ingestion statistics."""
        while self._running:
            try:
                if isinstance(self.store, AsyncLogStore):
                    stats = await self.store.get_stats()
                else:
                    loop = asyncio.get_event_loop()
                    stats = await loop.run_in_executor(None, self.store.get_stats)
                if stats and "error" not in stats:
                    logger.info(
                        "Stats | logs: %s | detections: %s (24h: %s) | by severity: %s",
                        stats.get("total_logs", 0),
                        stats.get("total_detections", 0),
                        stats.get("detections_24h", 0),
                        stats.get("by_severity", {}),
                    )
                await asyncio.sleep(self._stats_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug("Stats error: %s", e)
                await asyncio.sleep(self._stats_interval)
