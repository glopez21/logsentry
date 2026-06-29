// ─────────────────────────────────────────────────────────────────
// sentry-detect: On-Agent Detection Engine
//
// DetectionEngine evaluates LogEntry values and produces Alert
// values when suspicious activity is detected. It implements a
// sliding-window counter for burst detection (e.g., "more than
// 10 SSH failures from the same IP in 60 seconds").
//
// Architecture:
//
//   LogEntry → DetectionEngine.evaluate() → Vec<Alert>
//
// The engine is stateful — it tracks counters per IP/user and
// last-alert timestamps to avoid alert flooding (cooldown).
// State is kept in memory only; no persistence across restarts.
//
// Design decisions:
//   - SlidingCounter uses VecDeque (double-ended queue) for O(1)
//     push/pop from both ends. Old timestamps are removed from the
//     front as they fall outside the window.
//   - HashMap<String, SlidingCounter> maps source IPs or users to
//     their counters. The string key is cloned from the LogEntry.
//   - Cooldown prevents the same alert from firing more than once
//     per 60 seconds for the same rule + event combination.
//   - Alert keys include a prefix of the raw log text to
//     distinguish different triggering events even for the same
//     rule.
// ─────────────────────────────────────────────────────────────────

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use chrono::Utc;
use sentry_core::{Alert, LogEntry, Severity};

// ── SlidingCounter ──────────────────────────────────────────────
//
// A simple time-windowed event counter. Tracks timestamps of
// recent events and reports whether the count exceeds a threshold.
//
// Generic in purpose — used for both IP-based and user-based
// counters.
//
// Performance: VecDeque with with_capacity avoids reallocation
// during normal operation. In the worst case (all events within
// the window), we allocate max_entries + 1 slots.

struct SlidingCounter {
    window: Duration,           // How far back to look (e.g., 60 seconds)
    max_entries: usize,         // Maximum allowed events in the window
    timestamps: VecDeque<Instant>,  // Sorted event timestamps (oldest first)
}

impl SlidingCounter {
    fn new(window_secs: u64, max_entries: usize) -> Self {
        SlidingCounter {
            window: Duration::from_secs(window_secs),
            max_entries,
            // Pre-allocate to avoid resizing on each push
            timestamps: VecDeque::with_capacity(max_entries + 1),
        }
    }

    // ── record ────────────────────────────────────────────────
    //
    // Records a new event at the current time. Then evicts events
    // outside the window. Returns true if the threshold is
    // exceeded AFTER recording.
    //
    // The threshold check is "strictly greater than" — if
    // max_entries = 10, the 11th event triggers.

    fn record(&mut self) -> bool {
        let now = Instant::now();
        self.timestamps.push_back(now);

        // Slide window: remove timestamps older than `window`
        while let Some(&t) = self.timestamps.front() {
            if now.duration_since(t) > self.window {
                self.timestamps.pop_front();
            } else {
                break;  // Timestamps are ordered, so we can stop
            }
        }

        // Check if threshold exceeded
        self.timestamps.len() > self.max_entries
    }
}

// ── DetectionEngine ─────────────────────────────────────────────
//
// The main detection orchestrator. Holds:
//   - ip_counters: Map<source_ip, SlidingCounter> for brute force
//   - user_counters: Map<user, SlidingCounter> for lateral movement
//   - suspicious_ips: Static list of known bad IPs
//   - last_alert: Map<alert_key, Instant> for cooldown tracking
//   - alert_cooldown: Minimum time between identical alerts

pub struct DetectionEngine {
    ip_counters: HashMap<String, SlidingCounter>,
    user_counters: HashMap<String, SlidingCounter>,
    suspicious_ips: Vec<String>,
    last_alert: HashMap<String, Instant>,
    alert_cooldown: Duration,
}

impl DetectionEngine {
    pub fn new(suspicious_ips: Vec<String>) -> Self {
        DetectionEngine {
            ip_counters: HashMap::new(),
            user_counters: HashMap::new(),
            suspicious_ips,
            last_alert: HashMap::new(),
            alert_cooldown: Duration::from_secs(60),  // 1 minute between repeats
        }
    }

    // ── evaluate ─────────────────────────────────────────────
    //
    // Evaluate a single LogEntry and return any Alerts that fire.
    // This is called for every ingested event. Returns an empty
    // Vec for most events — only a tiny fraction trigger alerts.
    //
    // Each alert includes:
    //   - A human-readable description
    //   - MITRE ATT&CK ID for mapping to the framework
    //   - Severity level matching the threat
    //   - The original context (IP, user, host)

    pub fn evaluate(&mut self, entry: &LogEntry) -> Vec<Alert> {
        let mut alerts = Vec::new();
        let now = Instant::now();

        // Closure to generate a unique key for cooldown tracking.
        // Includes the first 20 chars of the raw log to distinguish
        // different triggering events for the same rule.
        let alert_key = |rule: &str| -> String {
            // .get(0..20) returns Option<&str> for the first 20
            // chars. unwrap_or provides fallback if raw is shorter.
            format!("{}-{}", rule, entry.raw.get(0..20).unwrap_or(""))
        };

        // ── 1. Suspicious IP Match ────────────────────────────
        //
        // If the source IP is in the known-bad list, fire
        // immediately. No threshold needed — one match is enough.
        // MITRE T1078: Valid Accounts (using compromised credentials)

        if let Some(ref ip) = entry.source_ip {
            if self.suspicious_ips.contains(ip) {
                let key = alert_key("suspicious_ip");
                if self.can_alert(&key, now) {
                    alerts.push(Alert {
                        rule_name: "suspicious_ip_match".to_string(),
                        severity: Severity::High,
                        description: format!("Connection from known malicious IP: {}", ip),
                        source_ip: Some(ip.clone()),
                        user: entry.user.clone(),
                        event_type: entry.event_type.clone(),
                        host: Some(entry.host.clone()),
                        timestamp: Utc::now(),
                        mitre_id: Some("T1078".to_string()),
                    });
                    self.last_alert.insert(key, now);
                }
            }
        }

        // ── 2. SSH Brute Force ────────────────────────────────
        //
        // Count failed SSH attempts per source IP. If more than
        // 10 in 60 seconds, fire CRITICAL alert.
        // MITRE T1110: Brute Force

        if entry.format == "ssh" && entry.severity >= Severity::Medium {
            if let Some(ref ip) = entry.source_ip {
                let counter = self.ip_counters.entry(ip.clone())
                    .or_insert_with(|| SlidingCounter::new(60, 10));

                if counter.record() {
                    let key = alert_key("ssh_brute");
                    if self.can_alert(&key, now) {
                        alerts.push(Alert {
                            rule_name: "ssh_brute_force".to_string(),
                            severity: Severity::Critical,
                            description: format!("SSH brute force from {}", ip),
                            source_ip: Some(ip.clone()),
                            user: entry.user.clone(),
                            event_type: Some("brute_force".to_string()),
                            host: Some(entry.host.clone()),
                            timestamp: Utc::now(),
                            mitre_id: Some("T1110".to_string()),
                        });
                        self.last_alert.insert(key, now);
                    }
                }
            }
        }

        // ── 3. Privilege Escalation ───────────────────────────
        //
        // Sudo failures suggest an attacker trying to escalate.
        // MITRE T1548: Abuse Elevation Control Mechanism

        if entry.format == "auth" && entry.raw.to_lowercase().contains("sudo") {
            if let Some(ref user) = entry.user {
                let key = alert_key("priv_esc");
                if self.can_alert(&key, now) {
                    alerts.push(Alert {
                        rule_name: "privilege_escalation".to_string(),
                        severity: Severity::High,
                        description: format!("Sudo failure for user {}", user),
                        source_ip: entry.source_ip.clone(),
                        user: Some(user.clone()),
                        event_type: Some("privilege_escalation".to_string()),
                        host: Some(entry.host.clone()),
                        timestamp: Utc::now(),
                        mitre_id: Some("T1548".to_string()),
                    });
                    self.last_alert.insert(key, now);
                }
            }
        }

        // ── 4. Lateral Movement ───────────────────────────────
        //
        // Successful SSH logins to different hosts suggest
        // lateral movement. If a user logs in more than 5 times
        // in 1 hour, flag it.
        // MITRE T1021: Remote Services

        if entry.format == "ssh" && entry.raw.contains("Accepted") {
            if let Some(ref user) = entry.user {
                let counter = self.user_counters.entry(user.clone())
                    .or_insert_with(|| SlidingCounter::new(3600, 5));  // 1 hour window

                if counter.record() {
                    let key = alert_key("lateral_move");
                    if self.can_alert(&key, now) {
                        alerts.push(Alert {
                            rule_name: "potential_lateral_movement".to_string(),
                            severity: Severity::High,
                            description: format!(
                                "Multiple SSH logins for {} — possible lateral movement", user
                            ),
                            source_ip: entry.source_ip.clone(),
                            user: Some(user.clone()),
                            event_type: Some("lateral_movement".to_string()),
                            host: Some(entry.host.clone()),
                            timestamp: Utc::now(),
                            mitre_id: Some("T1021".to_string()),
                        });
                        self.last_alert.insert(key, now);
                    }
                }
            }
        }

        // ── 5. Exfiltration ───────────────────────────────────
        //
        // Large POST requests over web could indicate data
        // exfiltration. This is a simplified heuristic — in prod,
        // you'd also check Content-Length against a baseline.
        // MITRE T1041: Exfiltration Over C2 Channel

        if entry.format == "web" && entry.raw.contains("POST") {
            if entry.severity >= Severity::Medium {
                let key = alert_key("exfil");
                if self.can_alert(&key, now) {
                    alerts.push(Alert {
                        rule_name: "potential_exfiltration".to_string(),
                        severity: Severity::Medium,
                        description: "Large POST request — possible data exfiltration".to_string(),
                        source_ip: entry.source_ip.clone(),
                        user: entry.user.clone(),
                        event_type: Some("exfiltration".to_string()),
                        host: Some(entry.host.clone()),
                        timestamp: Utc::now(),
                        mitre_id: Some("T1041".to_string()),
                    });
                    self.last_alert.insert(key, now);
                }
            }
        }

        alerts
    }

    // ── can_alert ─────────────────────────────────────────────
    //
    // Cooldown check: has the same alert key fired within the
    // last 60 seconds? Prevents alert storms.
    //
    // Closure returns .map(|&t| ...).unwrap_or(true):
    //   - If key exists: compare elapsed time against cooldown
    //   - If key doesn't exist (first time): return true (allow)

    fn can_alert(&self, key: &str, now: Instant) -> bool {
        self.last_alert
            .get(key)
            .map(|&t| now.duration_since(t) > self.alert_cooldown)
            .unwrap_or(true)  // true if no previous alert (first time)
    }
}
