#!/usr/bin/env python3
"""Test suite for LogSentry."""

import pytest


class TestParsers:
    """Tests for log parsers."""

    def test_syslog_parser_valid(self):
        from parsers.syslog_parser import parse_syslog
        line = "Apr 23 12:34:56 hostname sshd[1234]: Failed password for admin from 192.168.1.10"
        result = parse_syslog(line)
        assert result is not None
        assert result["source_ip"] == "192.168.1.10"
        assert result["user"] == "admin"
        assert result["timestamp"] == "Apr 23 12:34:56"

    def test_syslog_parser_invalid(self):
        from parsers.syslog_parser import parse_syslog
        line = "invalid log line"
        result = parse_syslog(line)
        assert result is None

    def test_ssh_parser_accepted(self):
        from parsers.ssh_parser import parse_ssh_log
        line = "Apr 23 12:34:56 host sshd: Accepted password for admin from 192.168.1.10 port 22 ssh2"
        result = parse_ssh_log(line)
        assert result is not None
        assert result["event_type"] == "ssh_login_success"
        assert result["user"] == "admin"
        assert result["source_ip"] == "192.168.1.10"

    def test_ssh_parser_failed(self):
        from parsers.ssh_parser import parse_ssh_log
        line = "Apr 23 12:34:56 host sshd: Failed password for admin from 10.0.0.1 port 54321 ssh2"
        result = parse_ssh_log(line)
        assert result is not None
        assert result["event_type"] == "ssh_login_fail"
        assert result["source_ip"] == "10.0.0.1"

    def test_ssh_parser_invalid_user(self):
        from parsers.ssh_parser import parse_ssh_log
        line = "Apr 23 12:34:56 host sshd: Invalid user webmaster from 8.8.8.8 port 22 ssh2"
        result = parse_ssh_log(line)
        assert result is not None
        assert result["event_type"] == "ssh_invalid_user"
        assert result["user"] == "webmaster"

    def test_auth_parser_session(self):
        from parsers.auth_parser import parse_auth_log
        line = "Apr 23 12:34:56 auth pam: session opened for user admin by (uid=0)"
        result = parse_auth_log(line)
        assert result is not None
        assert result["event_type"] == "session_open"
        assert result["user"] == "admin"

    def test_cloudtrail_parser(self):
        from parsers.cloudtrail_parser import parse_cloudtrail, detect_cloudtrail
        line = '{"eventVersion":"1.08","eventTime":"2024-04-23T12:34:56Z","eventName":"ConsoleLogin","userIdentity":{"userName":"admin"},"sourceIPAddress":"192.168.1.10"}'
        assert detect_cloudtrail(line) is True
        result = parse_cloudtrail(line)
        assert result is not None
        assert result["user"] == "admin"
        assert result["source_ip"] == "192.168.1.10"


class TestDetection:
    """Tests for detection checks."""

    def test_failed_login_bursts(self):
        from detection.detection_checks import find_failed_login_bursts
        records = [
            {"event_type": "ssh_login_fail", "source_ip": "185.220.101.45", "timestamp": "t1"},
            {"event_type": "ssh_login_fail", "source_ip": "185.220.101.45", "timestamp": "t2"},
            {"event_type": "ssh_login_fail", "source_ip": "185.220.101.45", "timestamp": "t3"},
            {"event_type": "ssh_login_fail", "source_ip": "185.220.101.45", "timestamp": "t4"},
            {"event_type": "ssh_login_fail", "source_ip": "185.220.101.45", "timestamp": "t5"},
            {"event_type": "ssh_login_fail", "source_ip": "185.220.101.45", "timestamp": "t6"},
        ]
        bursts = find_failed_login_bursts(records)
        assert len(bursts) > 0

    def test_suspicious_ips(self):
        from detection.detection_checks import find_suspicious_geographies
        records = [
            {"source_ip": "185.220.101.45"},
            {"source_ip": "91.121.87.200"},
            {"source_ip": "192.168.1.10"},
        ]
        suspicious = find_suspicious_geographies(records)
        assert len(suspicious) >= 2

    def test_mitre_tactics(self):
        from detection.detection_checks import find_mitre_tactics
        records = [
            {"mitre_tactic": "T1110", "mitre_technique": "Brute Force"},
            {"mitre_tactic": "T1110", "mitre_technique": "Brute Force"},
            {"mitre_tactic": "T1078", "mitre_technique": "Valid Accounts"},
        ]
        result = find_mitre_tactics(records)
        assert result["unique_count"] == 2
        assert "T1110" in result["tactics"]
        assert result["tactics"]["T1110"] == 2


class TestAdvanced:
    """Tests for advanced output features."""

    def test_severity_scoring(self):
        from output.advanced import score_records
        records = [
            {"event_type": "ssh_login_fail", "message": "Failed password attempt"},
            {"event_type": "priv_esc", "message": "Privilege escalation detected"},
            {"event_type": "session_open", "message": "Normal session"},
        ]
        scored = score_records(records)
        severities = [r.get("severity") for r in scored]
        assert "medium" in severities
        assert "critical" in severities
        assert "low" in severities

    def test_timeline_generation(self):
        from output.advanced import generate_timeline
        records = [
            {"timestamp": "t1", "event_type": "event1", "message": "First"},
            {"timestamp": "t2", "event_type": "event2", "message": "Second"},
        ]
        timeline = generate_timeline(records)
        assert len(timeline) == 2

    def test_correlate_events(self):
        from output.advanced import correlate_events
        records = [
            {"event_type": "ssh_login_fail", "source_ip": "1.2.3.4"},
            {"event_type": "ssh_login_fail", "source_ip": "1.2.3.4"},
            {"event_type": "lateral_alert", "source_ip": "5.6.7.8"},
        ]
        correlations = correlate_events(records)
        assert "brute_force_campaigns" in correlations
        assert "lateral_movement_chains" in correlations


class TestAlertSuppression:
    """Tests for alert suppression module."""

    def test_suppress_alerts(self):
        from alerts import AlertSuppressor
        suppressor = AlertSuppressor(threshold=3)
        
        records = [
            {"source_ip": "1.2.3.4", "event_type": "ssh_login_fail", "timestamp": "t1"},
            {"source_ip": "1.2.3.4", "event_type": "ssh_login_fail", "timestamp": "t2"},
            {"source_ip": "1.2.3.4", "event_type": "ssh_login_fail", "timestamp": "t3"},
        ]
        
        groups = suppressor.process_records(records)
        assert len(groups) == 3
        suppressed = suppressor.get_suppressed()
        assert len(suppressed) == 1
        assert suppressed[0].count == 3

    def test_alert_grouping(self):
        from alerts import suppress_alerts
        records = [
            {"source_ip": "1.2.3.4", "event_type": "fail", "timestamp": "t1"},
            {"source_ip": "1.2.3.4", "event_type": "fail", "timestamp": "t2"},
            {"source_ip": "5.6.7.8", "event_type": "success", "timestamp": "t3"},
        ]
        result = suppress_alerts(records, threshold=2)
        assert result["status"] == "success"
        assert result["suppressed_count"] >= 0


class TestYaraRules:
    """Tests for YARA-style rules."""

    def test_yara_scan(self):
        from yara_rules import scan_yara
        records = [
            {"raw_message": "Failed password for admin from 185.220.101.45", "message": ""},
            {"raw_message": "Another failed attempt", "message": ""},
        ]
        result = scan_yara(records)
        assert result["status"] == "success"
        assert result["total_matches"] >= 1

    def test_tor_detection(self):
        from yara_rules import YaraEngine
        engine = YaraEngine()
        
        record = {"raw_message": "Connection from 185.220.101.45", "message": ""}
        matches = engine.scan_record(record)
        
        tor_match = any("Tor" in m.rule_name for m in matches)
        assert tor_match or len(matches) > 0


class TestIntegrity:
    """Tests for integrity verification."""

    def test_compute_hash(self, tmp_path):
        from integrity import compute_log_hash
        
        test_file = tmp_path / "test.log"
        test_file.write_text("test log content\n")
        
        result = compute_log_hash(str(test_file))
        assert result["status"] == "success"
        assert "hash" in result

    def test_verify_integrity(self, tmp_path):
        from integrity import compute_log_hash, verify_integrity
        
        test_file = tmp_path / "test.log"
        test_file.write_text("original content\n")
        
        result = compute_log_hash(str(test_file))
        original_hash = result["hash"]
        
        verify_result = verify_integrity(str(test_file), original_hash)
        assert verify_result["verified"] is True
        
        test_file.write_text("modified content\n")
        
        verify_result = verify_integrity(str(test_file), original_hash)
        assert verify_result["verified"] is False


class TestBaseline:
    """Tests for baseline storage."""

    def test_create_baseline(self):
        from baselines import create_baseline
        records = [
            {"event_type": "ssh_login_fail"},
            {"event_type": "ssh_login_fail"},
            {"event_type": "ssh_login_success"},
            {"event_type": "ssh_login_fail"},
            {"event_type": "ssh_login_success"},
        ]
        baseline = create_baseline(records, "test_baseline", "failed_logins")
        assert baseline.name == "test_baseline"
        assert baseline.sample_count == 2

    def test_baseline_comparison(self):
        from baselines import Baseline
        baseline = Baseline(
            name="test",
            created_at="2024-01-01",
            metric="test",
            mean=10.0,
            std_dev=2.0
        )
        result = baseline.compare(15.0)
        assert result["value"] == 15.0
        assert result["z_score"] == 2.5


class TestSigmaRules:
    """Tests for Sigma rule conversion."""

    def test_convert_to_sigma(self):
        from sigma import convert_to_sigma
        records = [
            {"event_type": "ssh_login_fail", "mitre_tactic": "T1110", "raw_message": "Failed password"},
            {"event_type": "ssh_login_fail", "mitre_tactic": "T1110", "raw_message": "Failed password"},
            {"event_type": "ssh_login_fail", "mitre_tactic": "T1110", "raw_message": "Failed password"},
        ]
        result = convert_to_sigma(records)
        assert result["status"] == "success"
        assert result["rules_generated"] >= 0


class TestNavigatorExport:
    """Tests for MITRE ATT&CK Navigator export."""

    def test_export_navigator(self):
        from navigator import export_to_navigator
        records = [
            {"mitre_tactic": "T1110", "severity": "high"},
            {"mitre_tactic": "T1078", "severity": "medium"},
            {"mitre_tactic": "T1110", "severity": "critical"},
        ]
        result = export_to_navigator(records)
        assert result["status"] == "success"
        assert "layer" in result
        assert result["summary"]["total_techniques"] == 2


class TestAttackTimeline:
    """Tests for attack timeline reconstruction."""

    def test_reconstruct_attack(self):
        from attack_timeline import reconstruct_attack
        records = [
            {"mitre_tactic": "T1110", "timestamp": "t1"},
            {"mitre_tactic": "T1078", "timestamp": "t2"},
            {"mitre_tactic": "T1068", "timestamp": "t3"},
        ]
        timeline = reconstruct_attack(records)
        assert timeline.confidence_score >= 0
        assert len(timeline.unique_techniques) == 3


class TestGenerators:
    """Tests for log generation."""

    def test_brute_force_scenario(self):
        from generate_logs import LogGenerator
        gen = LogGenerator(seed=42)
        records = gen.generate_brute_force()
        assert len(records) > 0
        assert any("Failed" in str(r.get("message", "")) for r in records)

    def test_normal_day_scenario(self):
        from generate_logs import LogGenerator
        gen = LogGenerator(seed=42)
        records = gen.generate_normal_day(hours=1)
        assert len(records) > 0

    def test_all_scenarios(self):
        from generate_logs import LogGenerator
        gen = LogGenerator(seed=42)
        records = gen.generate_all_scenarios()
        assert len(records) > 100


if __name__ == "__main__":
    pytest.main([__file__, "-v"])