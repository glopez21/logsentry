// ─────────────────────────────────────────────────────────────────
// sentry-agent: Augur Hub REST Client
//
// This crate implements the agent side of the Augur protocol.
// The hub (Augur) is a central SOC management server that receives
// events, stores them, and can issue remote tasks to agents.
//
// Architecture:
//
//   1. Registration — agent sends its name, type, version, and
//      hostname. Hub returns a unique agent_id.
//
//   2. Heartbeat loop — a tokio task periodically POSTs to the
//      hub. If the hub returns 404, the agent needs re-registration
//      (hub was restarted and lost its state).
//
//   3. Event push — each ingested/detected event is sent to the
//      hub via POST. If the push fails (hub unreachable), the
//      event remains in the local SQLite queue (sent=0).
//
//   4. Queue drain — on each heartbeat tick (and after reconnect),
//      the agent pops unsent events from the store and pushes them
//      in batch.
//
//   5. Remote task polling — periodically check for tasks assigned
//      by the hub, execute them, and submit results.
//
// Key Rust concepts:
//   - reqwest::Client — async HTTP client. Built once, reused for
//     all requests (connection pooling, DNS caching).
//   - serde_json::json!{} — ergonomic JSON construction macro.
//   - tokio::select! — await multiple futures, first one to
//     complete wins. Used for the heartbeat loop with shutdown.
//   - Watch channel — tokio::sync::watch for shutdown signaling.
//     One sender, many receivers. Each receiver sees the latest
//     value.
// ─────────────────────────────────────────────────────────────────

use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use sentry_core::{Alert, LogEntry, RemoteTask, SentryError, TaskResult};
use sentry_store::LocalStore;
use tokio::time;

// ── AugurClient ─────────────────────────────────────────────────
//
// The store is Option<Arc<LocalStore>> — if the agent is running
// in ephemeral mode (no persistence), it can work without a store.
// Arc (Atomic Reference Counting) enables shared ownership across
// the heartbeat loop task and the main task.

pub struct AugurClient {
    hub_url: String,                          // Base URL of Augur hub
    api_key: String,                          // Bearer token for auth
    agent_name: String,                       // Our display name
    agent_type: String,                       // "endpoint", "server", "network"
    agent_id: Option<String>,                 // Assigned by hub during registration
    http: Client,                             // Shared HTTP client (connection pool)
    store: Option<Arc<LocalStore>>,           // Optional persistent queue
    heartbeat_interval: Duration,             // Seconds between heartbeats
}

impl AugurClient {
    // ── new ───────────────────────────────────────────────────
    //
    // Builds the client. reqwest::Client::builder() follows the
    // builder pattern — configure, then .build(). expect() is a
    // shortcut: unwrap with a panic message. This is acceptable
    // here because Client::builder() only fails with impossible
    // config errors.

    pub fn new(
        hub_url: &str,
        api_key: &str,
        agent_name: &str,
        agent_type: &str,
        heartbeat_interval_secs: u64,
        store: Option<Arc<LocalStore>>,
    ) -> Self {
        AugurClient {
            hub_url: hub_url.trim_end_matches('/').to_string(),
            api_key: api_key.to_string(),
            agent_name: agent_name.to_string(),
            agent_type: agent_type.to_string(),
            agent_id: None,
            http: Client::builder()
                .timeout(Duration::from_secs(15))       // Per-request timeout
                .build()
                .expect("reqwest client builder failed"),
            store,
            heartbeat_interval: Duration::from_secs(heartbeat_interval_secs),
        }
    }

    // ── headers ───────────────────────────────────────────────
    //
    // Builds standard HTTP headers for every request.
    // If api_key is empty, we skip the Authorization header.

    fn headers(&self) -> reqwest::header::HeaderMap {
        let mut h = reqwest::header::HeaderMap::new();
        h.insert("Content-Type", "application/json".parse().unwrap());
        if !self.api_key.is_empty() {
            h.insert(
                "Authorization",
                format!("Bearer {}", self.api_key).parse().unwrap(),
            );
        }
        h
    }

    // ── register ──────────────────────────────────────────────
    //
    // POST /api/v1/agents/register
    //
    // The hub responds with a JSON body containing an "id" field.
    // We store it in self.agent_id for subsequent requests.
    //
    // The env!("CARGO_PKG_VERSION") macro embeds the crate version
    // from Cargo.toml at compile time — no runtime cost.
    //
    // Note: &mut self is required because we modify agent_id.
    // Registration happens once at startup.

    pub async fn register(&mut self) -> Result<(), SentryError> {
        let body = serde_json::json!({
            "name": self.agent_name,
            "agent_type": self.agent_type,
            "version": env!("CARGO_PKG_VERSION"),
            "hostname": hostname(),
        });

        let resp = self.http
            .post(format!("{}/api/v1/agents/register", self.hub_url))
            .headers(self.headers())
            .json(&body)    // Serializes body to JSON, sets Content-Type
            .send()
            .await         // .await = non-blocking HTTP call
            .map_err(|e| SentryError::Http(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(SentryError::Http(format!(
                "register returned {}",
                resp.status()
            )));
        }

        // Deserialize response body as generic JSON Value.
        // We only care about the "id" field.
        let data: serde_json::Value = resp.json().await
            .map_err(|e| SentryError::Http(e.to_string()))?;

        // and_then chains Option operations:
        //   data.get("id") -> Option<&Value>
        //   .and_then(|v| v.as_str()) -> Option<&str>
        //   .map(String::from) -> Option<String>
        self.agent_id = data.get("id")
            .and_then(|v| v.as_str())
            .map(String::from);

        tracing::info!("registered with Augur hub, agent_id={:?}", self.agent_id);
        Ok(())
    }

    // ── heartbeat ──────────────────────────────────────────────
    //
    // POST /api/v1/agents/heartbeat
    //
    // Simple keepalive. Returns 404 if the hub doesn't know about
    // this agent (e.g., after hub restart).

    pub async fn heartbeat(&self) -> Result<(), SentryError> {
        let agent_id = self.agent_id.as_deref()  // Option<String> → Option<&str>
            .ok_or_else(|| SentryError::Http(
                "not registered — call register() first".to_string()
            ))?;

        let resp = self.http
            .post(format!("{}/api/v1/agents/heartbeat", self.hub_url))
            .headers(self.headers())
            .json(&serde_json::json!({
                "agent_id": agent_id,
                "status": "online",
            }))
            .send()
            .await
            .map_err(|e| SentryError::Http(e.to_string()))?;

        if resp.status() == 404 {
            tracing::warn!("agent not found on hub — needs re-registration");
            return Err(SentryError::Http("agent not found".into()));
        }
        Ok(())
    }

    // ── push_event ─────────────────────────────────────────────
    //
    // POST /api/v1/events — single event push.
    //
    // The JSON payload follows the Augur event schema. We extract
    // fields from LogEntry and map them to the hub's expected
    // format. The raw log text is truncated to 1000 chars to avoid
    // oversized requests.

    pub async fn push_event(&self, event: &LogEntry) -> Result<(), SentryError> {
        let agent_id = self.agent_id.as_deref()
            .ok_or_else(|| SentryError::Http("not registered".to_string()))?;

        let body = serde_json::json!({
            "agent_id": agent_id,
            "event_type": event.event_type.as_deref().unwrap_or("log"),
            "severity": event.severity.to_string(),
            "source": "sentryd",
            "title": format!("{} event from {}", event.format, event.host),
            "payload": {
                "host": event.host,
                "source": event.source,
                "format": event.format,
                "source_ip": event.source_ip,
                "user": event.user,
                "mitre_tactic": event.mitre_tactic,
                "mitre_technique": event.mitre_technique,
                "tags": event.tags,
                "raw": truncate(&event.raw, 1000),
            },
            "timestamp": event.timestamp.to_rfc3339(),
        });

        let resp = self.http
            .post(format!("{}/api/v1/events", self.hub_url))
            .headers(self.headers())
            .json(&body)
            .send()
            .await
            .map_err(|e| SentryError::Http(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(SentryError::Http(format!(
                "push_event returned {}", resp.status()
            )));
        }
        Ok(())
    }

    // ── push_events_batch ──────────────────────────────────────
    //
    // POST /api/v1/events/batch — multiple events in one HTTP
    // request. This is more efficient than one request per event.

    pub async fn push_events_batch(&self, events: &[LogEntry]) -> Result<(), SentryError> {
        let agent_id = self.agent_id.as_deref()
            .ok_or_else(|| SentryError::Http("not registered".to_string()))?;

        // Map each LogEntry to the JSON format the hub expects.
        // collect() builds a Vec<serde_json::Value>.
        let batch: Vec<serde_json::Value> = events
            .iter()
            .map(|e| {
                serde_json::json!({
                    "agent_id": agent_id,
                    "event_type": e.event_type.as_deref().unwrap_or("log"),
                    "severity": e.severity.to_string(),
                    "source": "sentryd",
                    "title": format!("{} event from {}", e.format, e.host),
                    "payload": {
                        "host": e.host,
                        "source": e.source,
                        "format": e.format,
                        "source_ip": e.source_ip,
                        "user": e.user,
                        "mitre_tactic": e.mitre_tactic,
                        "mitre_technique": e.mitre_technique,
                        "tags": e.tags,
                        "raw": truncate(&e.raw, 1000),
                    },
                    "timestamp": e.timestamp.to_rfc3339(),
                })
            })
            .collect();

        let resp = self.http
            .post(format!("{}/api/v1/events/batch", self.hub_url))
            .headers(self.headers())
            .json(&batch)
            .send()
            .await
            .map_err(|e| SentryError::Http(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(SentryError::Http(format!(
                "batch push returned {}", resp.status()
            )));
        }
        Ok(())
    }

    // ── push_alert ─────────────────────────────────────────────
    //
    // Same as push_event but specifically for detection alerts.
    // Tags include "sentryd" + rule name for easy filtering.

    pub async fn push_alert(&self, alert: &Alert) -> Result<(), SentryError> {
        let agent_id = self.agent_id.as_deref()
            .ok_or_else(|| SentryError::Http("not registered".to_string()))?;

        let body = serde_json::json!({
            "agent_id": agent_id,
            "event_type": "detection",
            "severity": alert.severity.to_string(),
            "source": "sentryd",
            "title": format!("sentryd: {}", alert.rule_name),
            "payload": {
                "rule_name": alert.rule_name,
                "description": alert.description,
                "source_ip": alert.source_ip,
                "user": alert.user,
                "host": alert.host,
                "mitre_id": alert.mitre_id,
                "event_type": alert.event_type,
            },
            "tags": ["sentryd", &alert.rule_name, &alert.severity.to_string()],
            "timestamp": alert.timestamp.to_rfc3339(),
        });

        let resp = self.http
            .post(format!("{}/api/v1/events", self.hub_url))
            .headers(self.headers())
            .json(&body)
            .send()
            .await
            .map_err(|e| SentryError::Http(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(SentryError::Http(format!(
                "push_alert returned {}", resp.status()
            )));
        }
        Ok(())
    }

    // ── pull_config ────────────────────────────────────────────
    //
    // GET /api/v1/agents/:id/config
    //
    // Pulls remote config overrides from the hub. Returns generic
    // JSON — the caller decides how to merge it with local config.

    pub async fn pull_config(&self) -> Result<serde_json::Value, SentryError> {
        let agent_id = self.agent_id.as_deref()
            .ok_or_else(|| SentryError::Http("not registered".to_string()))?;

        let resp = self.http
            .get(format!("{}/api/v1/agents/{}/config", self.hub_url, agent_id))
            .headers(self.headers())
            .send()
            .await
            .map_err(|e| SentryError::Http(e.to_string()))?;

        let data: serde_json::Value = resp.json().await
            .map_err(|e| SentryError::Http(e.to_string()))?;
        Ok(data)
    }

    // ── poll_tasks ─────────────────────────────────────────────
    //
    // GET /api/v1/agents/:id/tasks
    //
    // Returns a list of RemoteTask values. Because RemoteTask uses
    // #[serde(tag = "type")], the JSON discriminator field
    // determines which variant is deserialized.

    pub async fn poll_tasks(&self) -> Result<Vec<RemoteTask>, SentryError> {
        let agent_id = self.agent_id.as_deref()
            .ok_or_else(|| SentryError::Http("not registered".to_string()))?;

        let resp = self.http
            .get(format!("{}/api/v1/agents/{}/tasks", self.hub_url, agent_id))
            .headers(self.headers())
            .send()
            .await
            .map_err(|e| SentryError::Http(e.to_string()))?;

        let tasks: Vec<RemoteTask> = resp.json().await
            .map_err(|e| SentryError::Http(e.to_string()))?;
        Ok(tasks)
    }

    // ── submit_task_result ─────────────────────────────────────
    //
    // POST /api/v1/agents/:id/tasks/result
    //
    // Reports the outcome of a remote task execution back to the
    // hub.

    pub async fn submit_task_result(&self, result: &TaskResult) -> Result<(), SentryError> {
        let agent_id = self.agent_id.as_deref()
            .ok_or_else(|| SentryError::Http("not registered".to_string()))?;

        let body = serde_json::json!({
            "agent_id": agent_id,
            "task_result": result,
        });

        let resp = self.http
            .post(format!("{}/api/v1/agents/{}/tasks/result", self.hub_url, agent_id))
            .headers(self.headers())
            .json(&body)
            .send()
            .await
            .map_err(|e| SentryError::Http(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(SentryError::Http(format!(
                "submit result returned {}", resp.status()
            )));
        }
        Ok(())
    }

    // ── Heartbeat Loop ─────────────────────────────────────────
    //
    // Runs forever (or until shutdown signal). Every heartbeat
    // interval:
    //   1. Send heartbeat POST
    //   2. If hub returns 404, log a warning (re-register needed)
    //   3. Drain the local store queue
    //
    // tokio::select! waits for either the timer or the shutdown
    // signal. This is cooperative cancellation — the loop checks
    // shutdown_rx after the select.

    pub async fn start_heartbeat_loop(&self, mut shutdown_rx: tokio::sync::watch::Receiver<bool>) {
        loop {
            // race between timer and shutdown signal
            tokio::select! {
                _ = time::sleep(self.heartbeat_interval) => {}
                _ = shutdown_rx.changed() => break,   // shutdown_rx changed = signal sent
            }

            // Double-check — break if shutdown is true
            if *shutdown_rx.borrow() {
                break;
            }

            // Send heartbeat, handle errors gracefully
            match self.heartbeat().await {
                Ok(()) => {}  // all good
                Err(ref e) => {
                    match e {
                        // 404 from hub — needs re-registration
                        SentryError::Http(msg) if msg == "agent not found" => {
                            tracing::warn!("hub lost track of us — re-registration needed");
                        }
                        _ => tracing::warn!("heartbeat failed: {}", e),
                    }
                }
            }

            // Try to drain the queue on each tick
            if let Some(ref store) = self.store {
                self.drain_queue(store).await;
            }
        }
    }

    // ── drain_queue ────────────────────────────────────────────
    //
    // Pops up to 100 unsent events and pushes them in batch.
    // On success, marks them as sent in the store.

    async fn drain_queue(&self, store: &LocalStore) {
        match store.pop_unsent(100) {
            Ok(events) if !events.is_empty() => {
                // Push batch to hub
                match self.push_events_batch(&events).await {
                    Ok(()) => {
                        // Mark as sent only on success
                        if let Err(e) = store.mark_sent(events.len() as u32) {
                            tracing::warn!("failed to mark events sent: {}", e);
                        }
                        tracing::debug!("drained {} events to hub", events.len());
                    }
                    Err(e) => tracing::warn!("drain failed (will retry): {}", e),
                }
            }
            Ok(_) => {}     // No pending events
            Err(e) => tracing::warn!("drain pop failed: {}", e),
        }
    }
}

// ── Helper: hostname ────────────────────────────────────────────
//
// Tries $HOSTNAME env var, then /etc/hostname, falls back to
// "unknown". Used during registration.

fn hostname() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| {
        std::fs::read_to_string("/etc/hostname")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    })
}

// ── Helper: truncate ────────────────────────────────────────────
//
// Truncates a string to `max` characters, appending "..." if
// truncated. Prevents sending multi-megabyte log lines.

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}
