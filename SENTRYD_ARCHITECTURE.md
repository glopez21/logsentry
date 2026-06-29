# LogSentry Rust Agent — `sentryd`

> A lightweight, cross-platform log collection and telemetry agent written in Rust.
> Replaces the Python daemon on target machines. Sends to Augur hub + ThreatPulse.

---

## Why Rust for the Agent (Not Python)

| Requirement | Python daemon problem | Rust solution |
|-------------|----------------------|---------------|
| Run on target VMs/VPS (minimal deps) | Requires Python 3.10+, pip, venv, C extensions | Single static binary, no deps |
| Low resource footprint | 50-100MB RSS per process | 5-10MB RSS, no GC pauses |
| Cross-compile for Linux ARM/x86 | Complex with `manylinux` / Docker | `cross` or `cargo build --target` |
| File tailing under high throughput | GIL limits parallel parsing | Zero-cost async, parallel parsing |
| Run as system service (systemd) | Wrapper scripts needed | Native daemon with systemd notify |
| Remote command execution | Subprocess with shell injection risk | Controlled `Command` API with timeouts |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                       sentryd (Rust)                               │
│                                                                    │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐   │
│  │  Log Ingest  │  │   Detect    │  │     Augur Protocol      │   │
│  │             │  │   Engine    │  │                         │   │
│  │  • file_tail │  │  • patterns │  │  • register/heartbeat   │   │
│  │  • syslog    │──▶• thresholds │──▶• push_event batch      │   │
│  │  • journald  │  │  • mitre    │  │  • pull_config          │   │
│  │  • http      │  │             │  │  • remote_task          │   │
│  │             │  │             │  │                         │   │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘   │
│         │                │                      │                  │
│         ▼                ▼                      ▼                  │
│  ┌──────────────────────────────────────────────────────┐        │
│  │              Task Executor (remote)                    │        │
│  │  • run_script — run Python/Shell scripts on host     │        │
│  │  • collect_file — upload file to Augur                │        │
│  │  • run command — controlled subprocess with timeout   │        │
│  │  • acquire_memory — trigger LiME/avml dump           │        │
│  └──────────────────────────────────────────────────────┘        │
└──────────────────────────────────────────────────────────────────┘
         │                      │
         ▼                      ▼
  ┌─────────────┐      ┌────────────────┐
  │  Local cache │      │  Augur Hub      │
  │  (SQLite)    │      │  (REST API)     │
  └─────────────┘      └────────────────┘
```

---

## Crate Structure

```
sentryd/
├── Cargo.toml                  # workspace root
├── crates/
│   ├── sentry-core/            # types, config, errors (shared by all crates)
│   ├── sentry-ingest/          # log collection: file_tail, syslog, journald
│   ├── sentry-detect/          # detection engine: patterns, thresholds, mitre
│   ├── sentry-agent/           # augur protocol client, heartbeat, registration
│   ├── sentry-exec/            # remote task execution (run_script, collect_file)
│   ├── sentry-store/           # local SQLite cache for offline buffering
│   └── sentryd/                # main binary: CLI + daemon mode
```

---

## Key Design Decisions

### 1. Protocol: Reuse Existing Augur REST API

The Python `augur_client` already defines the protocol. `sentry-agent` speaks the same API:

```
POST /api/v1/agents/register    — register with hub
POST /api/v1/agents/heartbeat   — keep alive
POST /api/v1/events             — push single event
POST /api/v1/events/batch       — push batch events
GET  /api/v1/agents/{id}/config — pull agent config
POST /api/v1/agents/{id}/task   — receive remote task
```

This means Augur/ThreatPulse don't change — they see the agent as another HTTP client.

### 2. Log Collection: Three Ingest Methods

| Source | Crate | Method |
|--------|-------|--------|
| **File tail** | `sentry-ingest` | `inotify` on Linux, poll on others, keep track of inode/position |
| **Syslog** | `sentry-ingest` | UDP listener on port 514, TCP listener, parse RFC 3164 |
| **Journald** | `sentry-ingest` | Read from `systemd-journald` via `journalctl --follow` or `libsystemd` |

Each source produces the same `LogEntry` struct:

```rust
struct LogEntry {
    timestamp: DateTime<Utc>,
    host: String,
    source: String,          // "file", "syslog", "journald", "http"
    format: String,          // "syslog", "ssh", "auth", "firewall", "web"
    raw: String,
    source_ip: Option<String>,
    user: Option<String>,
    event_type: Option<String>,
    mitre_tactic: Option<String>,
    mitre_technique: Option<String>,
    severity: Severity,       // critical, high, medium, low, info
}
```

### 3. Detection Engine: Port LogSentry's Python Logic

The existing `detection_checks.py` has straightforward logic:
- Count failed logins per IP → burst detection
- Check IP against known suspicious prefixes
- Pattern match for privilege escalation, lateral movement, exfiltration

Port directly as Rust pattern matching + simple counters. No need for ML.

```rust
// sentry-detect/src/checks.rs
pub fn check_failed_login_bursts(entries: &[LogEntry], threshold: u32, window: Duration) -> Vec<Alert>
pub fn check_suspicious_ips(entries: &[LogEntry]) -> Vec<Alert>
pub fn check_privilege_escalation(entries: &[LogEntry]) -> Vec<Alert>
pub fn check_lateral_movement(entries: &[LogEntry]) -> Vec<Alert>
pub fn check_data_exfiltration(entries: &[LogEntry]) -> Vec<Alert>
```

### 4. Remote Task Execution: Augur → Agent

The hub can push tasks to the agent. The agent polls `GET /tasks` on heartbeat or accepts pushed tasks.

```rust
enum RemoteTask {
    RunScript {
        script: String,       // inline script content
        interpreter: String,  // "bash", "python3", "powershell"
        timeout_secs: u32,
    },
    CollectFile {
        path: String,         // /var/log/syslog
        max_bytes: u64,
    },
    RunCommand {
        command: String,      // "df -h"
        args: Vec<String>,
        timeout_secs: u32,
    },
    AcquireMemory {
        tool: String,         // "lime", "avml", "winpmem"
        output_path: String,
    },
}

struct TaskResult {
    task_id: String,
    status: TaskStatus,       // completed, failed, timeout
    stdout: Option<String>,
    stderr: Option<String>,
    exit_code: Option<i32>,
    artifacts: Vec<String>,   // paths to uploaded files
}
```

### 5. Offline Buffering: SQLite Local Cache

When the agent loses connectivity to the hub, it buffers events locally:

```rust
// sentry-store/src/lib.rs
pub struct LocalStore {
    conn: rusqlite::Connection,
}

impl LocalStore {
    fn push_event(&self, event: &LogEntry) -> Result<()>
    fn pop_unsent(&self, batch_size: u32) -> Result<Vec<LogEntry>>
    fn count_pending(&self) -> Result<u64>
}
```

On reconnect, `sentry-agent` drains the queue via `POST /api/v1/events/batch`.

---

## Mapping to Existing LogSentry Python Code

| Python Module | Rust Crate | Reuse Strategy |
|--------------|------------|----------------|
| `parsers/*.py` | `sentry-ingest` | Rewrite regex parsers in Rust (`regex` crate) |
| `detection/detection_checks.py` | `sentry-detect` | Port logic directly (counters + patterns) |
| `collector/syslog.py` | `sentry-ingest` | Rewrite UDP/TCP listener using `tokio` |
| `collector/file_tail.py` | `sentry-ingest` | Rewrite using `notify` (inotify) crate |
| `notifiers/*.py` | `sentry-agent` | Replace with direct Augur API calls |
| `integrations/*.py` | (n/a) | Keep Python LogSentry for deep analysis, Rust agent is for collection |
| `daemon.py` | `sentryd` | Replace entirely — Rust handles lifecycle |
| `n3xus.py` | `sentry-agent` | Replace with native HTTP to Augur |
| `logsentry.yaml` | `sentry-core` | Parse same YAML format with `serde_yaml` |

---

## CLI Interface

```bash
# Start daemon (systemd service)
sentryd daemon --config /etc/sentryd/config.yaml

# One-shot: parse a log file and print alerts
sentryd parse /var/log/auth.log --format ssh

# One-shot: send event directly to Augur
sentryd send --hub http://augur:8001 --event-type security_alert --severity high

# Run remote task (from hub's perspective)
sentryd exec --command "df -h" --timeout 10

# Status
sentryd status

# Validate config
sentryd check-config /etc/sentryd/config.yaml
```

---

## Config (YAML — same format as existing logsentry.yaml)

```yaml
agent:
  name: sentryd-webserver-01
  type: sentryd

hub:
  url: "http://augur:8001"
  api_key: ""
  heartbeat_interval: 30

ingest:
  syslog:
    enabled: true
    bind: 0.0.0.0
    port: 514
    protocol: udp

  file_watchers:
    enabled: true
    paths:
      - /var/log
    patterns:
      - "*.log"
      - "*.syslog"

  journald:
    enabled: false
    units:
      - sshd
      - nginx

detection:
  enabled: true
  rules:
    - name: brute_force_burst
      event_type: failed_login
      threshold: 5
      window: 5m
      severity: high

store:
  path: /var/lib/sentryd/cache.db
  retention_days: 7
  max_pending: 10000
```

---

---

## ML Feature Pipeline — `sentry-learn`

> *"The LogSentry DB is not just ops storage — it's your training data factory."*

### Concept

Every structured log record stored by LogSentry is a labeled timestamped observation. Aggregated over time, these form **feature vectors** per entity (IP, user, host, process). Use them to train:

1. **Anomaly detector** — catches what static rules miss (beaconing, DGA, privilege escalation chains)
2. **Triage classifier** — predicts severity + recommended playbook from alert + context
3. **IOC predictor** — scores new IPs/hashes/domains based on similarity to past confirmed IOCs

### Architecture

```
                    ┌──────────────────────┐
                    │   LogSentry DB        │
                    │   (PostgreSQL)        │
                    └──────┬───────────────┘
                           │
                           ▼
              ┌────────────────────────────┐
              │  Feature Pipeline           │
              │  (Python: pandas/polars)    │
              │                             │
              │  Queries DB → time-bucket    │
              │  aggregates → feature       │
              │  vectors → training dataset │
              └────────┬───────────────────┘
                       │
              ┌────────┴────────┐
              ▼                  ▼
  ┌──────────────────┐  ┌──────────────────┐
  │  Anomaly Model    │  │  Triage Model    │
  │  (autoencoder)    │  │  (XGBoost/LLM)   │
  │                   │  │                  │
  │  Trained on       │  │  Trained on      │
  │  normal-behavior  │  │  analyst-labeled │
  │  baselines per    │  │  alerts from     │
  │  host/user/source │  │  LogSentry DB    │
  └────────┬──────────┘  └────────┬─────────┘
           │                      │
           ▼                      ▼
  ┌───────────────────────────────────────────┐
  │           Inference API                    │
  │  (FastAPI sidecar or embedded in Augur)    │
  │                                            │
  │  POST /api/v1/score/ip      → anomaly 0.92│
  │  POST /api/v1/classify      → {severity,  │
  │  POST /api/v1/predict-ioc     playbook}   │
  └───────────────────────────────────────────┘
```

### Feature Engineering: What the Pipeline Produces

Each row corresponds to one entity over one time window (e.g. `{ip: "45.33.32.156", window_5m}`):

| Feature Group | Features | Source Columns |
|--------------|----------|---------------|
| **Velocity** | login_fail_count, login_success_count, connection_count, unique_user_count | `event_type`, `source_ip` |
| **Temporal** | event_hour, is_weekend, interarrival_mean_ms, interarrival_std_ms | `timestamp` grouped by source |
| **Spatial** | geo_distance_km_from_baseline, is_tor_exit, is_proxy, is_datacenter | `source_ip` geolocation |
| **Behavioral** | unique_ports_scanned, unique_destinations, protocol_count | `destination_port`, `protocol` |
| **Content** | user_length, contains_sql_keywords, contains_encoded_payload | `raw_message` text features |
| **Historical** | days_since_first_seen, total_events_24h, prior_alert_count | aggregate from DB |

### Training Pipeline

```python
# logsentry/learn/features.py  — extracts features from LogSentry DB
# logsentry/learn/train.py     — trains anomaly + triage models
# logsentry/learn/inference.py — loads model, serves predictions
# logsentry/learn/models/      — model architectures (autoencoder, xgb, llm)

class FeaturePipeline:
    def extract(
        self,
        db: LogStore,
        entity_type: str,     # "ip", "user", "host", "process"
        window_minutes: int,  # 5, 15, 60
        since: datetime,
        until: datetime,
    ) -> pd.DataFrame:
        """Query LogSentry DB and return feature vectors."""

    def extract_labels(
        self,
        db: LogStore,
        since: datetime,
        until: datetime,
    ) -> pd.DataFrame:
        """Pull analyst-labeled detections for supervised training.
        
        Each row: {detection_id, rule_name, severity, description,
                   source_ip, user, host, 
                   analyst_action: "escalate"/"close"/"false_positive",
                   analyst_notes, playbook_used}
        """

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Normalize, encode, impute missing values."""
```

### Agentic Triage Workflow (LLM + Retrieval)

```
Alert arrives (from sentryd or correlation engine)
    │
    ▼
Context Retriever — queries LogSentry DB for:
  • Past 24h events from same source_ip
  • Past detections involving same user/host
  • Historical baseline for this entity type
  • Similar past incidents (embedding similarity on alert text)
    │
    ▼
Classifier — two paths:
  │
  ├── XGBoost path (<500ms, 80% accuracy):
  │     Feature vector → predict severity + playbook
  │     Used for known alert types, high volume
  │
  └── LLM path (2-5s, handles edge cases):
        Alert + context → structured prompt → reasoning + recommendation
        Used for novel / low-volume alerts
    │
    ▼
Action — playbook recommended, routed to Augur/ThreatPulse:
  • Auto-execute (low severity, high confidence)
  • Suggest with context (medium)
  • Escalate to analyst (high severity, low confidence)
    │
    ▼
Analyst feedback loops back → retrains classifier
```

### Where This Lives

Keep it in Python as part of LogSentry (`logsentry/learn/`):

```
logsentry/
├── learn/
│   ├── __init__.py
│   ├── features.py       # Feature pipeline (reads LogSentry DB)
│   ├── train.py          # Training loops (autoencoder + xgboost)
│   ├── inference.py      # Inference API (FastAPI sidecar)
│   ├── models/
│   │   ├── anomaly.py    # PyTorch autoencoder
│   │   ├── triage.py     # XGBoost classifier
│   │   └── agent.py      # LLM agent (LangChain / custom prompt)
│   ├── retriever.py      # Context retriever (queries DB + embedding)
│   └── schemas.py        # Pydantic models for feature vectors
```

The Rust `sentryd` focuses on collection + basic detection. The Python `logsentry/learn/` handles ML because:

1. PyTorch/scikit-learn ecosystem is not viable in Rust for this use case
2. Training runs on the SOC workstation, not on target VMs
3. Inference can be deployed as a lightweight FastAPI sidecar that Augur calls

### Data Flow End-to-End

```
sentryd (vm-01) ──logs──► Augur DB ──► LogSentry DB ──► Feature Pipeline
                                                              │
sentryd (vps-02) ──logs──► Augur DB ──► LogSentry DB ────────┤
                                                              │
sentryd (lxc-03) ──logs──► Augur DB ──► LogSentry DB ────────┤
                                                              │
                                                              ▼
                                                     Trained Model
                                                          │
                                              ◄────────────┤
                                              │
                                        Anomaly Score
                                        Triage Class
                                        IOC Prediction
                                              │
                                              ▼
                                        Augur Alert
                                              │
                                              ▼
                                        Playbook Executor
```

The LogSentry DB is the central spine. Everything reads from it and writes to it. The feedback loop closes when an analyst triages an alert — that decision becomes training data for the next model iteration.

---



## Build & Deploy

```bash
# Build static binary
cd sentryd
cargo build --release --target x86_64-unknown-linux-musl
# → target/x86_64-unknown-linux-musl/release/sentryd (single binary, ~8MB)

# Cross-compile for ARM VPS
cargo build --release --target aarch64-unknown-linux-musl

# Install on target
scp sentryd root@target:/usr/local/bin/
scp config.yaml root@target:/etc/sentryd/
sentryd daemon --config /etc/sentryd/config.yaml

# systemd unit
cat > /etc/systemd/system/sentryd.service <<EOF
[Unit]
Description=LogSentry Rust Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sentryd daemon --config /etc/sentryd/config.yaml
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload && systemctl enable --now sentryd
```

---

## Integration with Existing Python LogSentry

The Python LogSentry stays as the **analysis workstation** tool:
- Deep log analysis (full parser suite, correlation, timelines)
- Incident report generation
- Integration with MISP, TheHive, STIX/TAXII
- Sigma rule conversion

The Rust `sentryd` is the **lightweight collector** deployed on every target:
- Forward logs to the hub
- Run basic detection (bursts, suspicious IPs)
- Execute remote tasks from the hub
- Buffer offline

```
┌──────────────────┐     ┌──────────────┐     ┌──────────────────────┐
│  Target VM/VPS   │     │  Augur Hub   │     │  SOC Workstation     │
│  (runs sentryd)  │────▶│  (REST API)  │◀────│  (Python LogSentry)  │
│                  │     │              │     │                      │
│  • tails logs    │     │  • agg events│     │  • deep analysis     │
│  • syslog listen │     │  • push to TP│     │  • incident reports  │
│  • basic detect  │     │  • task queue│     │  • MISP/TheHive sync │
│  • exec tasks    │     │  • coverage  │     │  • Sigma generation  │
└──────────────────┘     └──────────────┘     └──────────────────────┘
```

---

## Dependencies

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_yaml = "0.9"
serde_json = "1"
reqwest = { version = "0.12", features = ["json", "rustls-tls"] }
tracing = "0.1"
tracing-subscriber = "0.3"
clap = { version = "4", features = ["derive"] }
anyhow = "1"
thiserror = "2"
chrono = { version = "0.4", features = ["serde"] }
rusqlite = { version = "0.31", features = ["bundled"] }
notify = "6"         # inotify file watching
regex = "1"
uuid = { version = "1", features = ["v4"] }
glob = "0.3"
# syslog UDP listener — built on tokio::net::UdpSocket (stdlib, no extra dep)
# journald — optional, reads from systemd-journald socket
```

---

## What This Unlocks

1. **Single binary deployment** — scp to any Linux VM/VPS, runs immediately
2. **Offline resilience** — buffers events locally, drains on reconnect
3. **Remote task execution** — Augur can push forensic collection / script execution to any agent
4. **Same config format** — reuses `logsentry.yaml` schema so ops team doesn't learn a new format
5. **Coexists with Python LogSentry** — Python stays for analysis, Rust handles collection
