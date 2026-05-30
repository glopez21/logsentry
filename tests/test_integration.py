"""Integration tests for LogSentry Engine — store, query, detection, API."""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ── Fixtures ───────────────────────────────────────────────────────

@pytest.fixture
def mock_conn():
    """Mock psycopg2 connection with cursor."""
    conn = MagicMock()
    cur = MagicMock()
    cur.__enter__.return_value = cur
    conn.cursor.return_value = cur
    return conn, cur


@pytest.fixture
def store(mock_conn):
    """LogStore with mocked connection pool."""
    conn, cur = mock_conn

    class FakePool:
        maxconn = 10
        minconn = 2
        def getconn(self):
            return conn
        def putconn(self, c):
            pass
        def closeall(self):
            pass

    with patch("psycopg2.pool.ThreadedConnectionPool", return_value=FakePool()):
        from db import LogStore
        s = LogStore(dsn="postgresql://test:test@localhost:5432/test")
        s._pool = FakePool()
        yield s
        s.close()


# ── Store Tests ────────────────────────────────────────────────────

class TestLogStore:
    def test_insert_log(self, store, mock_conn):
        mock_conn, cur = mock_conn
        cur.fetchone.return_value = [42]
        row_id = store.insert_log(
            timestamp=datetime.now(timezone.utc),
            message="Failed password for root from 10.0.0.1",
            labels={"host": "web01"},
            source="syslog",
            format="ssh",
            host="web01",
            source_ip="10.0.0.1",
            user_name="root",
            event_type="failed_login",
            severity="high",
        )
        assert row_id == 42
        assert mock_conn.commit.called

    def test_query_with_results(self, store, mock_conn):
        mock_conn, cur = mock_conn
        cur.fetchall.return_value = [
            {"id": 1, "message": "test", "severity": "high", "timestamp": datetime.now(timezone.utc)}
        ]
        results = store.query(severity="high", limit=10)
        assert len(results) == 1
        assert results[0]["severity"] == "high"

    def test_query_empty(self, store, mock_conn):
        mock_conn, cur = mock_conn
        cur.fetchall.return_value = []
        results = store.query(limit=10)
        assert results == []

    def test_insert_detection(self, store, mock_conn):
        mock_conn, cur = mock_conn
        cur.fetchone.return_value = [99]
        det_id = store.insert_detection(
            log_id=1,
            rule_name="brute_force_test",
            severity="high",
            description="Test detection",
        )
        assert det_id == 99
        assert mock_conn.commit.called

    def test_upsert_host(self, store, mock_conn):
        conn, _ = mock_conn
        store.upsert_host(hostname="web01", ip_address="10.0.0.1", role="web")
        assert conn.commit.called

    def test_get_threat_intel_cache_miss(self, store, mock_conn):
        _, cur = mock_conn
        cur.fetchone.return_value = None
        result = store.get_threat_intel("10.0.0.1")
        assert result is None

    def test_get_threat_intel_cache_hit(self, store, mock_conn):
        _, cur = mock_conn
        cur.fetchone.return_value = {"data": '{"is_malicious": true, "score": 85}'}
        result = store.get_threat_intel("10.0.0.1")
        assert result is not None
        assert result["is_malicious"] is True

    def test_set_threat_intel(self, store, mock_conn):
        conn, _ = mock_conn
        store.set_threat_intel("10.0.0.1", {"is_malicious": True}, ttl=3600)
        assert conn.commit.called

    def test_get_stats(self, store, mock_conn):
        _, cur = mock_conn
        cur.fetchone.side_effect = [
            {"total": 100},
            {"total_detections": 15},
            {"total_detections": 5},
        ]
        cur.fetchall.return_value = [{"severity": "high", "cnt": 30}]
        stats = store.get_stats()
        assert stats["total_logs"] == 100
        assert stats["total_detections"] == 15
        assert stats["by_severity"] == {"high": 30}

    def test_enforce_retention(self, store, mock_conn):
        _, cur = mock_conn
        cur.fetchone.return_value = [3]
        dropped = store.enforce_retention(90)
        assert dropped == 3


# ── Detection Tests ────────────────────────────────────────────────

class TestDetectionPipeline:
    def test_failed_login_burst_detection(self):
        from detection.detection_checks import find_failed_login_bursts
        records = [
            {"event_type": "failed_login", "source_ip": "10.0.0.1", "user": "root"},
            {"event_type": "failed_login", "source_ip": "10.0.0.1", "user": "root"},
            {"event_type": "failed_login", "source_ip": "10.0.0.1", "user": "root"},
            {"event_type": "failed_login", "source_ip": "10.0.0.1", "user": "root"},
            {"event_type": "failed_login", "source_ip": "10.0.0.1", "user": "root"},
        ]
        bursts = find_failed_login_bursts(records, threshold=3)
        assert len(bursts) > 0
        assert "10.0.0.1" in bursts[0]

    def test_no_false_positive_on_normal(self):
        from detection.detection_checks import find_failed_login_bursts, find_new_accounts
        records = [
            {"event_type": "ssh_login", "source_ip": "10.0.0.1", "user": "alice"},
            {"event_type": "ssh_login", "source_ip": "10.0.0.2", "user": "bob"},
        ]
        bursts = find_failed_login_bursts(records, threshold=5)
        assert bursts == []
        accounts = find_new_accounts(records)
        assert accounts == []

    def test_mitre_tactic_extraction(self):
        from detection.detection_checks import find_mitre_tactics
        records = [
            {"event_type": "failed_login", "mitre_tactic": "T1110"},
            {"event_type": "privilege_escalation", "mitre_tactic": "T1068"},
            {"event_type": "failed_login", "mitre_tactic": "T1110"},
        ]
        result = find_mitre_tactics(records)
        assert result["unique_count"] == 2
        assert result["tactics"]["T1110"] == 2

    def test_mitre_tactic_no_data(self):
        from detection.detection_checks import find_mitre_tactics
        records = [{"event_type": "unknown"}]
        result = find_mitre_tactics(records)
        assert result["unique_count"] == 0


# ── Parser Tests ───────────────────────────────────────────────────

class TestParsers:
    def test_parse_ssh_failed(self):
        from main import parse_log_line
        line = "Mar 15 10:30:00 web01 sshd[1234]: Failed password for root from 10.0.0.1 port 22 ssh2"
        result = parse_log_line(line)
        assert result is not None
        assert result["event_type"] == "ssh_login_fail"
        assert result["source_ip"] == "10.0.0.1"
        assert result["user"] == "root"

    def test_parse_ssh_accepted(self):
        from main import parse_log_line
        line = "Mar 15 10:30:00 web01 sshd[1234]: Accepted password for alice from 10.0.0.2 port 22 ssh2"
        result = parse_log_line(line)
        assert result is not None
        assert result["event_type"] == "ssh_login_success"
        assert result["user"] == "alice"

    def test_parse_syslog(self):
        from main import parse_log_line
        line = "Mar 15 10:30:00 web01 kernel: [123456.789] CPU0: Core temperature above threshold"
        result = parse_log_line(line)
        assert result is not None
        assert "host" in result

    def test_parse_empty_line(self):
        from main import parse_log_line
        assert parse_log_line("") is None
        assert parse_log_line("   ") is None


# ── Daemon Tests ───────────────────────────────────────────────────

class TestDaemon:
    def test_alert_rule_evaluation(self):
        from daemon import LogSentryDaemon
        config = {
            "engine": {"detection_interval": 30, "stats_interval": 60},
            "storage": {"dsn": "", "pool_min": 2, "pool_max": 10, "batch_size": 500, "flush_interval": 5, "retention_days": 90},
            "detection": {
                "enabled": True, "rules": [
                    {"name": "test_rule", "severity": "high", "description": "Test",
                     "condition": {"event_type": "failed_login", "threshold": 2}}
                ],
                "alerts": {"stdout": False, "webhook": "", "discord": {"webhook_url": ""}, "slack": {"webhook_url": ""}, "telegram": {"bot_token": "", "chat_id": ""}},
            },
            "ingest": {"syslog": {"enabled": False}, "http": {"enabled": True}, "file_watchers": {"enabled": False, "paths": []}},
            "server": {"host": "0.0.0.0", "port": 8080},
            "schemas": [],
        }
        with patch.object(LogSentryDaemon, "_send_alert") as mock_send:
            daemon = LogSentryDaemon(config)
            daemon.store = MagicMock()
            records = [
                {"event_type": "failed_login", "source_ip": "10.0.0.1", "timestamp": datetime.now(timezone.utc)},
                {"event_type": "failed_login", "source_ip": "10.0.0.1", "timestamp": datetime.now(timezone.utc)},
            ]
            daemon._evaluate_rule(config["detection"]["rules"][0], records)  # type: ignore[index]
            assert daemon.store.insert_detection.called
            assert mock_send.called

    def test_send_alert_with_notifier(self):
        from daemon import LogSentryDaemon
        config = {
            "engine": {"detection_interval": 30, "stats_interval": 60},
            "storage": {"dsn": "", "pool_min": 2, "pool_max": 10, "batch_size": 500, "flush_interval": 5, "retention_days": 90},
            "detection": {
                "enabled": True, "rules": [],
                "alerts": {"stdout": False, "webhook": "", "discord": {"webhook_url": ""}, "slack": {"webhook_url": ""}, "telegram": {"bot_token": "", "chat_id": ""}},
            },
            "ingest": {"syslog": {"enabled": False}, "http": {"enabled": True}, "file_watchers": {"enabled": False, "paths": []}},
            "server": {"host": "0.0.0.0", "port": 8080},
            "schemas": [],
        }
        daemon = LogSentryDaemon(config)
        daemon.store = MagicMock()
        daemon._send_alert(rule_name="test", severity="high", description="test")
        # Should not raise and notifier should not be called (no URL configured)


# ── Config Tests ───────────────────────────────────────────────────

class TestConfig:
    def test_load_config_defaults(self):
        from config import load_config
        # Ensure env vars are not set
        os.environ.pop("LOGSENTRY_DSN", None)
        os.environ.pop("LOGSENTRY_MODE", None)
        cfg = load_config()
        assert "engine" in cfg
        assert "storage" in cfg
        assert "detection" in cfg
        assert cfg["storage"]["dsn"].startswith("postgresql://")

    def test_env_override(self):
        from config import load_config
        os.environ["LOGSENTRY_DSN"] = "postgresql://override:test@localhost:5432/test"
        cfg = load_config()
        assert cfg["storage"]["dsn"] == "postgresql://override:test@localhost:5432/test"
        del os.environ["LOGSENTRY_DSN"]

    def test_load_yaml_config(self):
        from config import load_config
        os.environ.pop("LOGSENTRY_DSN", None)
        cfg = load_config()
        assert cfg["engine"]["mode"] in ("cli", "daemon")
