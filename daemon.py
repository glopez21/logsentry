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


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge *override* into *base* in place.

    - Dict values are merged recursively.
    - Non-dict values in *override* replace those in *base*.
    - Keys present only in *override* are added to *base*.
    """
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
    return base


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

        self._syslog_listeners: list[Any] = []
        self._http_server: Any = None
        self._file_watchers: list[Any] = []

        self._detection_interval = config["engine"].get("detection_interval", 30)
        self._stats_interval = config["engine"].get("stats_interval", 60)
        self._alert_rules: list[dict] = config["detection"].get("rules", []) or []
        self._parser_overrides: list[dict] = config.get("ingest", {}).get("overrides", []) or []

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

        # ThreatPulse client (optional)
        self._tp_client: Any = None
        tp_cfg = config.get("threatpulse", {})
        if tp_cfg.get("enabled") and tp_cfg.get("api_url"):
            try:
                from integrations.threatpulse import ThreatPulseClient
                self._tp_client = ThreatPulseClient(
                    api_url=tp_cfg["api_url"],
                    api_key=tp_cfg.get("api_key", ""),
                    timeout=float(tp_cfg.get("timeout", 5.0)),
                )
                logger.info("ThreatPulse client initialized (%s)", tp_cfg["api_url"])
            except Exception as e:
                logger.warning("ThreatPulse client init failed: %s", e)

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
            self._loop.add_signal_handler(signal.SIGHUP, lambda: self._reload_config())
        except (ValueError, NotImplementedError, AttributeError):
            signal.signal(signal.SIGHUP, lambda s, f: self._reload_config())

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

        # Stop syslog listener(s)
        for listener in (self._syslog_listeners or []):
            try:
                listener.stop()
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

    def _reload_config(self) -> None:
        """SIGHUP handler — reload configuration without restart."""
        import yaml
        config_path = os.environ.get("LOGSENTRY_CONFIG", "logsentry.yaml")
        try:
            if os.path.exists(config_path):
                with open(config_path) as f:
                    new_config = yaml.safe_load(f) or {}
                _deep_merge(self.config, new_config)
                self._alert_rules = self.config.get("detection", {}).get("rules", []) or []
                logger.info("Configuration reloaded from %s", config_path)
        except Exception as e:
            logger.warning("Config reload failed: %s", e)

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
        """Start syslog listener(s) in executor threads.

        `protocol` may be "udp", "tcp", or "both" to listen on both transports
        on the same port (e.g. so UDP and TCP rsyslog forwarders both work).
        """
        from collector.syslog import SyslogListener

        protocol = cfg.get("protocol", "udp")
        protocols = ["udp", "tcp"] if protocol == "both" else [protocol]

        loop = asyncio.get_event_loop()
        self._syslog_listeners = []
        for proto in protocols:
            listener = SyslogListener(
                port=cfg.get("port", 514),
                protocol=proto,
                parser=self._parse_line,
                callback=self._syslog_callback,
                bind_address=cfg.get("bind", "0.0.0.0"),
                rate_limit=cfg.get("rate_limit", 100.0),
                rate_burst=cfg.get("rate_burst", 200),
                register_signals=False,
            )
            self._tasks.append(
                asyncio.ensure_future(loop.run_in_executor(None, listener.start))
            )
            self._syslog_listeners.append(listener)
            logger.info(
                "Syslog listener started: %s:%s/%s",
                cfg.get("bind", "0.0.0.0"), cfg.get("port", 514), proto,
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
                register_signals=False,
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
        # Apply parser override if configured
        try:
            source_ip = source[0] if source else ""
        except Exception:
            source_ip = ""
        forced = self._choose_parser_override(message, source_ip)
        if forced:
            try:
                from main import LOG_PARSERS
                parser = LOG_PARSERS.get(forced)
                if parser:
                    rec2 = parser(message)
                    if rec2:
                        record = rec2
            except Exception:
                pass
        self._store_record(record, message, source="syslog", host=source_ip)

    def _file_watcher_callback(self, line: str, record: Optional[dict]) -> None:
        # For file watcher, only 'contains' overrides apply
        forced = self._choose_parser_override(line, "")
        if forced:
            try:
                from main import LOG_PARSERS
                parser = LOG_PARSERS.get(forced)
                if parser:
                    rec2 = parser(line)
                    if rec2:
                        record = rec2
            except Exception:
                pass
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

    def _choose_parser_override(self, message: str, source_ip: str) -> Optional[str]:
        """Return a parser name if any override matches this message/source.

        Supports two simple match modes for minimal risk:
          - source_ip exact match: {"source_ip": "1.2.3.4", "parser": "web_access"}
          - substring match in raw line: {"contains": "nginx:", "parser": "web_error"}
        """
        for rule in self._parser_overrides:
            try:
                parser = rule.get("parser")
                if not parser:
                    continue
                if rule.get("source_ip") and source_ip and rule["source_ip"] == source_ip:
                    return parser
                if rule.get("contains") and rule["contains"] and rule["contains"] in message:
                    return parser
            except Exception:
                continue
        return None

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
        from datetime import datetime, timedelta

        name = rule.get("name", "unknown")
        condition = rule.get("condition", {})
        event_type = condition.get("event_type")
        user = condition.get("user")
        source_ip = condition.get("source_ip")
        threshold = condition.get("threshold", 1)
        severity = rule.get("severity", "medium")

        # Parse window (e.g. "5m", "1h", "30s") — defaults to None (no windowing)
        window_str = condition.get("window")
        window: timedelta | None = None
        if window_str:
            try:
                value = int(window_str[:-1])
                unit = window_str[-1].lower()
                if unit == "s":
                    window = timedelta(seconds=value)
                elif unit == "m":
                    window = timedelta(minutes=value)
                elif unit == "h":
                    window = timedelta(hours=value)
                elif unit == "d":
                    window = timedelta(days=value)
            except (ValueError, IndexError):
                pass

        matches = []
        for r in records:
            if event_type and r.get("event_type") != event_type:
                continue
            if user and r.get("user") != user:
                continue
            if source_ip and r.get("source_ip") != source_ip:
                continue
            matches.append(r)

        # Apply time window: only count matches within the most recent window
        if window and matches:
            def _parse_ts(ts_val: str) -> datetime | None:
                if isinstance(ts_val, datetime):
                    return ts_val
                if not ts_val:
                    return None
                for fmt in (
                    "%Y-%m-%dT%H:%M:%S",
                    "%Y-%m-%dT%H:%M:%S.%f",
                    "%Y-%m-%dT%H:%M:%SZ",
                    "%Y-%m-%dT%H:%M:%S%z",
                    "%Y-%m-%dT%H:%M:%S.%f%z",
                    "%b %d %H:%M:%S",
                    "%Y/%m/%d %H:%M:%S",
                ):
                    try:
                        return datetime.strptime(ts_val, fmt)
                    except ValueError:
                        continue
                return None

            # Find the most recent timestamp among matches
            timestamps = [_parse_ts(m.get("timestamp", "")) for m in matches]
            valid_ts = [t for t in timestamps if t is not None]
            if valid_ts:
                latest = max(valid_ts)
                cutoff = latest - window
                windowed = []
                for m, ts in zip(matches, timestamps):
                    if ts is None or ts >= cutoff:
                        windowed.append(m)
                matches = windowed

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

        stdout_cfg = alert_cfg.get("stdout", {})
        if isinstance(stdout_cfg, dict):
            if stdout_cfg.get("enabled", True):
                if stdout_cfg.get("format", "text") == "json":
                    import json as _json
                    logger.warning("ALERT %s", _json.dumps({
                        "severity": severity, "rule": rule_name,
                        "description": description, "source_ip": source_ip,
                        "event_type": event_type, "timestamp": timestamp,
                    }))
                else:
                    logger.warning("ALERT [%s] %s: %s", severity.upper(), rule_name, description)
        elif stdout_cfg:
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

        # Forward to ThreatPulse if configured
        if self._tp_client:
            try:
                self._tp_client.push_event(
                    rule_name=rule_name,
                    severity=severity,
                    description=description,
                    source_ip=source_ip,
                    event_type=event_type,
                    timestamp=timestamp,
                    tags=["logsentry", rule_name, severity],
                )
            except Exception as e:
                logger.debug("ThreatPulse push failed: %s", e)

        from n3xus import emit_alert
        instance = self.config.get("engine", {}).get("instance", "")
        emit_alert(
            source_instance=instance,
            rule_name=rule_name,
            severity=severity,
            description=description,
            source_ip=source_ip,
            event_type=event_type,
            loop=self._loop,
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
                    # Push lightweight telemetry to ThreatPulse if configured
                    if self._tp_client:
                        try:
                            self._tp_client.push_telemetry({
                                "total_logs": stats.get("total_logs", 0),
                                "total_detections": stats.get("total_detections", 0),
                                "detections_24h": stats.get("detections_24h", 0),
                            })
                        except Exception:
                            pass
                await asyncio.sleep(self._stats_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug("Stats error: %s", e)
                await asyncio.sleep(self._stats_interval)
