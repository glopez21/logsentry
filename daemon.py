"""LogSentry Engine Daemon — persistent log ingestion, storage, and detection."""

from __future__ import annotations

import logging
import os
import signal
import threading
import time
from datetime import datetime, timezone
from typing import Any, Optional

from db import LogStore
from notifiers import DiscordNotifier, SlackNotifier, TelegramNotifier
from notifiers.base import AlertMessage

logger = logging.getLogger("logsentry.daemon")


class LogSentryDaemon:
    """Main engine loop: ingest → store → detect."""

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self._running = False
        self._threads: list[threading.Thread] = []

        # Storage
        storage_cfg = config["storage"]
        self.store = LogStore(
            dsn=storage_cfg["dsn"],
            min_conn=storage_cfg.get("pool_min", 2),
            max_conn=storage_cfg.get("pool_max", 10),
            batch_size=storage_cfg.get("batch_size", 500),
            flush_interval=storage_cfg.get("flush_interval", 5),
        )

        # Ingest components (lazy init)
        self._syslog_listener: Any = None
        self._http_server: Any = None
        self._file_watchers: list[Any] = []

        # Detection pipeline
        self._detection_interval = config["engine"].get("detection_interval", 30)
        self._stats_interval = config["engine"].get("stats_interval", 60)

        # Alert rules
        self._alert_rules: list[dict] = config["detection"].get("rules", []) or []

        # Notifiers
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

        # Augur hub integration
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

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    # ── Lifecycle ─────────────────────────────────────────────────

    def start(self) -> None:
        """Start the daemon — connect DB, start ingest, run pipeline."""
        self._running = True

        # 1. Connect to Postgres
        logger.info("Connecting to Postgres...")
        self.store.connect()

        # 2. Initialize schema
        logger.info("Initializing schema...")
        self.store.init_schema()

        # 3. Enforce retention on startup
        retention = self.config["storage"].get("retention_days", 90)
        dropped = self.store.enforce_retention(retention)
        if dropped:
            logger.info("Cleaned %s old partitions", dropped)

        # 4. Start ingest collectors
        self._start_ingest()

        # 5. Register with Augur hub and start heartbeat
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

        # 6. Start stats reporter
        t = threading.Thread(target=self._stats_loop, daemon=True)
        t.start()
        self._threads.append(t)

        # 7. Start detection pipeline
        if self.config["detection"].get("enabled", True):
            t = threading.Thread(target=self._detection_loop, daemon=True)
            t.start()
            self._threads.append(t)

        logger.info("Daemon started — ingesting, storing, detecting")

        # 8. Block until signal
        while self._running:
            time.sleep(1)

    def stop(self) -> None:
        """Graceful shutdown."""
        logger.info("Shutting down...")
        self._running = False

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
            self.store.close()
        except Exception:
            pass

        logger.info("Daemon stopped")

    def _signal_handler(self, signum, frame) -> None:
        """Handle shutdown signals."""
        print()  # clear ^C line
        self.stop()

    # ── Ingest ────────────────────────────────────────────────────

    def _start_ingest(self) -> None:
        """Start configured ingest sources."""
        ingest_cfg = self.config["ingest"]

        # Syslog listener
        syslog_cfg = ingest_cfg.get("syslog", {})
        if syslog_cfg.get("enabled"):
            self._start_syslog(syslog_cfg)

        # File watchers (if paths configured)
        file_cfg = ingest_cfg.get("file_watchers", {})
        if file_cfg.get("enabled") and file_cfg.get("paths"):
            self._start_file_watchers(file_cfg["paths"])

    def _start_syslog(self, cfg: dict) -> None:
        """Start syslog UDP/TCP listener in a thread."""
        from collector.syslog import SyslogListener

        listen_port = cfg.get("port", 514)
        listen_proto = cfg.get("protocol", "udp")
        listen_bind = cfg.get("bind", "0.0.0.0")

        listener = SyslogListener(
            port=listen_port,
            protocol=listen_proto,
            parser=self._parse_line,
            callback=self._syslog_callback,
            bind_address=listen_bind,
        )

        t = threading.Thread(target=listener.start, daemon=True)
        t.start()
        self._syslog_listener = listener
        logger.info(
            "Syslog listener started: %s:%s/%s", listen_bind, listen_port, listen_proto
        )

    def _start_file_watchers(self, paths: list[str]) -> None:
        """Watch directories for .log files."""
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
        for fp in log_files[:50]:  # limit to prevent overload
            collector = FileTailCollector(
                filepath=fp,
                parser=self._parse_line,
                callback=self._file_watcher_callback,
            )
            t = threading.Thread(target=collector.start, args=(False,), daemon=True)
            t.start()
            self._file_watchers.append(collector)

        logger.info("Watching %s log files", len(log_files))

    def _parse_line(self, line: str) -> Optional[dict]:
        """Parse a single log line (inline to avoid circular import)."""
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
        """Callback for syslog messages — store in DB."""
        self._store_record(record, message, source="syslog", host=source[0] if source else "")

    def _file_watcher_callback(self, line: str, record: Optional[dict]) -> None:
        """Callback for file watcher — store in DB."""
        self._store_record(record, line, source="file")

    def _store_record(
        self, record: Optional[dict], raw_message: str, source: str = "syslog", host: str = ""
    ) -> None:
        """Parse and store a log record to Postgres."""
        try:
            if record:
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
                        [record["mitre_tactic"]]
                        if record.get("mitre_tactic")
                        else []
                    ),
                    raw_message=raw_message,
                )

                # Auto-register host
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
            else:
                # Store raw unparsed line
                self.store.insert_log(
                    timestamp=datetime.now(timezone.utc),
                    message=raw_message,
                    labels={"source": source, "host": host or "unknown"},
                    source=source,
                    format="raw",
                    raw_message=raw_message,
                )
        except Exception as e:
            logger.warning("Failed to store log: %s", e)

    # ── Detection Pipeline ────────────────────────────────────────

    def _detection_loop(self) -> None:
        """Periodically run detection on recent logs."""
        last_check = datetime.now(timezone.utc)

        while self._running:
            try:
                now = datetime.now(timezone.utc)
                recent = self.store.query(
                    since=last_check,
                    limit=5000,
                )
                if recent:
                    self._run_detections(recent)
                last_check = now
                time.sleep(self._detection_interval)
            except Exception as e:
                logger.error("Detection loop error: %s", e)
                time.sleep(self._detection_interval)

    def _run_detections(self, records: list[dict]) -> None:
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

                        self.store.insert_detection(
                            log_id=None,
                            rule_name=check_name,
                            severity=severity,
                            description=str(finding),
                            rule_type="builtin",
                        )

                        self._send_alert(
                            rule_name=check_name,
                            severity=severity,
                            description=str(finding),
                        )
                elif isinstance(findings, dict):
                    description = (
                        f"{check_name}: {findings.get('unique_count', 0)} tactics, "
                        f"{list(findings.get('tactics', {}).keys())}"
                    )
                    self.store.insert_detection(
                        log_id=None,
                        rule_name=check_name,
                        severity="medium",
                        description=description[:500],
                        rule_type="builtin",
                    )
                    self._send_alert(
                        rule_name=check_name,
                        severity="medium",
                        description=description[:500],
                    )

            # Evaluate custom alert rules
            for rule in self._alert_rules:
                self._evaluate_rule(rule, records)

            if results:
                logger.debug("Detection run: %s checks matched", len(results))
        except Exception as e:
            logger.error("Detection error: %s", e)

    def _evaluate_rule(self, rule: dict, records: list[dict]) -> None:
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
            self.store.insert_detection(
                log_id=None,
                rule_name=name,
                severity=severity,
                description=rule.get("description", ""),
                rule_type="custom",
            )
            self._send_alert(
                rule_name=name,
                severity=severity,
                description=rule.get("description", ""),
                source_ip=matches[0].get("source_ip", ""),
                event_type=matches[0].get("event_type", ""),
                timestamp=str(matches[0].get("timestamp", "")),
            )

    def _send_alert(
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

        # Stdout
        if alert_cfg.get("stdout", True):
            logger.warning("ALERT [%s] %s: %s", severity.upper(), rule_name, description)

        # Webhook
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

        # Notifier backends
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

        # Push to Augur hub
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

        # Emit to n3xusDB event_outbox via n3xuslib
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

    def _stats_loop(self) -> None:
        """Periodically log ingestion statistics."""
        while self._running:
            try:
                stats = self.store.get_stats()
                if stats and "error" not in stats:
                    logger.info(
                        "Stats | logs: %s | detections: %s (24h: %s) | by severity: %s",
                        stats.get("total_logs", 0),
                        stats.get("total_detections", 0),
                        stats.get("detections_24h", 0),
                        stats.get("by_severity", {}),
                    )
                time.sleep(self._stats_interval)
            except Exception as e:
                logger.debug("Stats error: %s", e)
                time.sleep(self._stats_interval)
