// ─────────────────────────────────────────────────────────────────
// sentry-core: Shared Types, Config, and Error Definitions
//
// This is the "hub" crate — every other crate depends on it. It
// contains no logic, only data structures. The idea is that if
// you want to understand what kinds of data flow through the
// agent, you start here.
//
// Key Rust concepts illustrated:
//   - #[derive(Debug, Clone, Serialize, Deserialize)] —
//     Rust's derive macros auto-implement traits. Debug = "{:?}",
//     Clone = .clone(), Serialize/Deserialize = serde JSON/YAML.
//   - enum — algebraic data types with optional payload per variant.
//   - #[serde(tag = "type")] — serde's internally-tagged enum
//     representation for JSON (like a discriminator field).
//   - impl blocks for adding methods to types defined elsewhere.
//   - #[derive(thiserror::Error)] — generate std::error::Error impls.
//   - #[from] — auto-generate From<source> for your error type
//     so the ? operator works seamlessly.
// ─────────────────────────────────────────────────────────────────

use std::collections::HashMap;

use chrono::{DateTime, Utc};

use serde::{Deserialize, Serialize};

// ── LogEntry ────────────────────────────────────────────────────
//
// This is THE core data type — every event the agent ingests,
// detects, stores, and sends becomes a LogEntry.
//
// Rust ownership notes:
//   String = owned, heap-allocated UTF-8 (like Python str but
//     owned, not borrowed).
//   Option<String> = may or may not be present — the agent might
//     not be able to extract a source IP from every line.
//   DateTime<Utc> = chrono's timezone-aware datetime. The <Utc>
//     is a generic parameter indicating UTC timezone.
//   Vec<String> = a growable array of strings.
//   Severity = our custom enum defined below.
//
// Every field is pub because this is a data-transfer object (DTO)
// and there's no benefit to encapsulation here.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,           // When the log was generated (or ingested)
    pub host: String,                        // Hostname where the event originated
    pub source: String,                      // Ingestion method: "file", "syslog", "journald", "http"
    pub format: String,                      // Detected log format: "ssh", "auth", "firewall", "web", "auditd", "syslog"
    pub raw: String,                         // The original, unmodified log line
    pub source_ip: Option<String>,           // Extracted source IP address, if any
    pub user: Option<String>,                // Extracted username, if any
    pub event_type: Option<String>,          // Classification like "brute_force", "exfiltration"
    pub mitre_tactic: Option<String>,        // MITRE ATT&CK tactic ID (e.g., "TA0001")
    pub mitre_technique: Option<String>,     // MITRE ATT&CK technique ID (e.g., "T1110")
    pub severity: Severity,                  // Assessed severity level
    pub tags: Vec<String>,                   // Free-form tags for categorization
}

// ── Severity ────────────────────────────────────────────────────
//
// Rust enums are "algebraic data types" — each variant can carry
// data (though here none do). The PartialOrd derive lets us
// compare them: Severity::Critical > Severity::Info.
//
// PartialEq = can compare with ==
// Eq = full equivalence (all fields are equal-comparable)
// PartialOrd = can compare with <, > (ordering)
// Ord = total ordering (Critical > High > Medium > Low > Info)
//
// The derives generate correct ordering because variants are
// declared in descending priority.

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Critical,  // highest — immediate threat
    High,
    Medium,
    Low,
    Info,      // lowest — informational
}

// The Display trait controls how Severity appears when formatted
// with {} or in format!() / println!(). Without this, Rust would
// use Debug ({:?}) output which includes the enum variant name.

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // match is exhaustive — Rust forces us to handle every variant
            Severity::Critical => write!(f, "critical"),
            Severity::High => write!(f, "high"),
            Severity::Medium => write!(f, "medium"),
            Severity::Low => write!(f, "low"),
            Severity::Info => write!(f, "info"),
        }
    }
}

// Inherent impl — methods that live directly on Severity (not via
// a trait). We define a from_str constructor to parse a severity
// from a string like config files.

impl Severity {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            // _ is the catch-all / default pattern. Since we return
            // early for known strings, anything else maps to Info.
            _ => Severity::Info,
        }
    }
}

// ── Alert ───────────────────────────────────────────────────────
//
// Generated by sentry-detect when a detection rule fires. Alerts
// are stored as LogEntry values in the event queue (with
// source="detection" and format="alert") so they flow through the
// same pipeline as ingested events.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub rule_name: String,               // Which rule triggered (e.g. "ssh_brute_force")
    pub severity: Severity,               // How bad is this alert?
    pub description: String,              // Human-readable explanation
    pub source_ip: Option<String>,        // The IP that triggered the alert
    pub user: Option<String>,             // The user involved
    pub event_type: Option<String>,       // MITRE category like "brute_force"
    pub host: Option<String>,             // Affected host
    pub timestamp: DateTime<Utc>,         // When the alert fired
    pub mitre_id: Option<String>,         // MITRE ATT&CK ID (e.g., "T1110")
}

// ── ContainerInfo ───────────────────────────────────────────────
//
// Represents a container discovered on the host. Generated by
// sentry-containers during periodic discovery scans.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerInfo {
    pub container_id: String,
    pub name: String,
    pub image: String,
    pub status: String,
    pub ports: Vec<String>,
    pub labels: HashMap<String, String>,
    pub created: String,
    pub runtime: String,
    pub pid: Option<i32>,
}

// ── TaskEnvelope ──────────────────────────────────────────────
//
// Wraps a RemoteTask with the task ID assigned by the Augur hub.
// The Augur API returns tasks as { id, task_type, params, ... }
// where task_type maps to the RemoteTask variant and params
// contains the variant's fields. This struct preserves the ID
// so the agent can ack and submit results for the correct task.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskEnvelope {
    pub id: String,
    pub task_type: String,
    pub params: serde_json::Value,
}

impl TaskEnvelope {
    pub fn to_remote_task(&self) -> Result<RemoteTask, SentryError> {
        let p = &self.params;
        match self.task_type.as_str() {
            "run_script" => Ok(RemoteTask::RunScript {
                script: p.get("script").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                interpreter: p.get("interpreter").and_then(|v| v.as_str()).unwrap_or("/bin/sh").to_string(),
                timeout_secs: p.get("timeout_secs").and_then(|v| v.as_u64()).unwrap_or(30) as u32,
            }),
            "run_command" => Ok(RemoteTask::RunCommand {
                command: p.get("command").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                args: p.get("args").and_then(|v| v.as_array()).map(|a| {
                    a.iter().filter_map(|v| v.as_str().map(String::from)).collect()
                }).unwrap_or_default(),
                timeout_secs: p.get("timeout_secs").and_then(|v| v.as_u64()).unwrap_or(30) as u32,
            }),
            "collect_file" => Ok(RemoteTask::CollectFile {
                path: p.get("path").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                max_bytes: p.get("max_bytes").and_then(|v| v.as_u64()).unwrap_or(10_485_760),
            }),
            "acquire_memory" => Ok(RemoteTask::AcquireMemory {
                tool: p.get("tool").and_then(|v| v.as_str()).unwrap_or("avml").to_string(),
                output_path: p.get("output_path").and_then(|v| v.as_str()).unwrap_or("/tmp/memory.dump").to_string(),
            }),
            other => Err(SentryError::Parse(format!("unknown task type: {}", other))),
        }
    }
}

// ── RemoteTask ─────────────────────────────────────────────────
//
// The hub can instruct the agent to execute tasks remotely.
// This enum represents the different types of tasks. Serde's
// #[serde(tag = "type")] means the JSON representation looks like:
//
//   {"type": "RunCommand", "command": "whoami", ...}
//
// Serde reads the "type" field to determine which variant to
// deserialize into. This is called "internally tagged" enum
// representation.

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RemoteTask {
    RunScript {
        script: String,         // The script content to execute
        interpreter: String,    // e.g., "/bin/bash", "/usr/bin/python3"
        timeout_secs: u32,      // Max execution time before abort
    },
    CollectFile {
        path: String,           // Absolute path to the file
        max_bytes: u64,         // Max bytes to read (truncation guard)
    },
    RunCommand {
        command: String,        // The binary to execute
        args: Vec<String>,      // Command-line arguments
        timeout_secs: u32,
    },
    AcquireMemory {
        tool: String,           // Which memory acquisition tool: "avml", "lime", "dumpmem"
        output_path: String,    // Where to write the memory dump
    },
}

// The result of executing a RemoteTask, sent back to the hub.
// stdout/stderr are Option because the task might time out before
// producing output.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResult {
    pub task_id: String,
    pub status: TaskStatus,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub exit_code: Option<i32>,  // None if timeout (process didn't exit)
    pub artifacts: Vec<String>,  // File paths created during execution
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TaskStatus {
    Completed,  // Process exited successfully (exit code 0)
    Failed,     // Process ran but exited non-zero
    Timeout,    // Process was killed after timeout_secs
}

// ── AgentConfig ─────────────────────────────────────────────────
//
// Deserialized from sentryd.yaml. All fields map directly to YAML
// keys. Serde's rename attribute maps Rust's snake_case to the
// config file format (e.g., agent_type → # YAML key "type").

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub agent: AgentSection,
    pub hub: HubSection,
    pub ingest: IngestSection,
    pub detection: DetectionSection,
    pub store: StoreSection,
    pub discovery: DiscoveryConfig,
}

// Note the #[serde(rename = "type")] — "type" is a Rust keyword
// so we can't name a field `type`. But the YAML config has
// `agent.type: "endpoint"`. Serde maps between them.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSection {
    pub name: String,
    #[serde(rename = "type")]
    pub agent_type: String,  // Matches YAML key "type", stored as agent_type in Rust
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubSection {
    pub url: String,
    pub api_key: String,
    pub heartbeat_interval: u64,
    pub ws_enabled: bool,
    pub ws_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestSection {
    pub syslog: SyslogConfig,
    pub file_watchers: FileWatcherConfig,
    pub journald: JournaldConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyslogConfig {
    pub enabled: bool,
    pub bind: String,        // IP to bind (e.g., "0.0.0.0")
    pub port: u16,           // Port to listen on (e.g., 514)
    pub protocol: String,    // "udp" or "tcp"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileWatcherConfig {
    pub enabled: bool,
    pub paths: Vec<String>,      // Directories to watch
    pub patterns: Vec<String>,   // Glob patterns like "/var/log/auth.log"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournaldConfig {
    pub enabled: bool,
    pub units: Vec<String>,      // Systemd units to follow
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionSection {
    pub enabled: bool,
    pub rules: Vec<DetectionRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRule {
    pub name: String,
    pub event_type: String,   // Which log format to apply this rule to
    pub threshold: u32,       // Event count to trigger
    pub window: String,       // Time window as string (e.g., "60s")
    pub severity: String,     // Severity level string
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreSection {
    pub path: String,
    pub retention_days: u32,
    pub max_pending: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    pub enabled: bool,
    pub interval: u64,
    pub runtimes: Vec<String>,
}

// ── SentryError ─────────────────────────────────────────────────
//
// A custom error enum using thiserror. Each variant maps to a
// category of error the agent can encounter.
//
// #[from] on Io means thiserror auto-generates:
//   impl From<std::io::Error> for SentryError { ... }
// This lets you use ? on io::Result without manual mapping.

#[derive(Debug, thiserror::Error)]
pub enum SentryError {
    // The strings in #[error("...")] become the Display output of
    // the error. {0} references the first field of the variant.
    #[error("config error: {0}")]
    Config(String),

    // #[from] auto-generates From<std::io::Error>
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("db error: {0}")]
    Db(String),

    #[error("http error: {0}")]
    Http(String),

    #[error("parse error: {0}")]
    Parse(String),

    #[error("{0}")]
    Other(String),
}

// We also bridge anyhow::Error into SentryError so interop works
// both ways. The binary crate uses anyhow, libraries use
// SentryError — this From impl lets them coexist.
impl From<anyhow::Error> for SentryError {
    fn from(e: anyhow::Error) -> Self {
        SentryError::Other(e.to_string())
    }
}
