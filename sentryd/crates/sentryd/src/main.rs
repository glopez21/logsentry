// ─────────────────────────────────────────────────────────────────
// sentryd — Main Binary
//
// This is the entry point for the sentryd agent binary. It
// defines the CLI using clap (derive mode), then dispatches to
// the appropriate handler based on the subcommand.
//
// Two execution modes:
//   1. Interactive/CLI — parse, send, exec, status, check-config
//      These are one-shot commands that do one thing and exit.
//   2. Daemon — the main event loop that runs forever, ingesting
//      logs, running detection, storing locally, and sending to
//      the hub.
//
// Daemon mode lifecycle:
//   1. Load config from YAML file
//   2. Open/create the SQLite store
//   3. Build the Augur HTTP client
//   4. Register with the hub (get agent_id)
//   5. Start heartbeat loop (spawned as a tokio task)
//   6. Start file watchers (spawned as a tokio task)
//   7. Enter main loop:
//        - Receive LogEntry from file watcher channel
//        - Push to local SQLite store
//        - Run detection engine
//        - If alert generated, store as event too
//   8. On SIGINT/SIGTERM (ctrl-c): signal shutdown, join tasks
//
// tokio::spawn creates concurrent tasks on the same thread pool.
// The watch channel (tokio::sync::watch) provides one-shot
// broadcast for shutdown signaling.
// ─────────────────────────────────────────────────────────────────

// This lint denies common Rust 2018 migration issues at compile
// time. We use it as a safety net to enforce best practices.
#![deny(rust_2018_idioms)]

use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use clap::{Parser, Subcommand};
use sentry_agent::AugurClient;
use sentry_core::{AgentConfig, LogEntry, RemoteTask};
use sentry_detect::DetectionEngine;
use sentry_exec::execute_task;
use sentry_ingest::FileTail;
use sentry_store::LocalStore;
use tracing_subscriber::EnvFilter;

// ── CLI Definition ──────────────────────────────────────────────
//
// clap's derive API: the struct is annotated with #[derive(Parser)]
// and fields become CLI arguments. Nested enums (Subcommand)
// define subcommands.
//
// #[command(...)] sets metadata for --help output.
// #[arg(...)] configures individual arguments (short/long flags,
//   default values, required/optional).

#[derive(Parser)]
#[command(name = "sentryd", about = "Lightweight SOC agent", version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Path to config file
    #[arg(short, long, default_value = "/etc/sentryd/sentryd.yaml")]
    config: PathBuf,
}

#[derive(Subcommand)]
enum Commands {
    /// Run as daemon (default)
    Daemon,
    /// Parse a single log line or file
    Parse {
        line: Option<String>,
        #[arg(short, long)]
        file: Option<PathBuf>,
    },
    /// Send a line to the hub
    Send {
        #[arg(required = true)]
        message: String,
    },
    /// Run a single remote task locally
    Exec {
        #[arg(required = true)]
        task_json: String,
    },
    /// Show agent status
    Status,
    /// Validate config file
    CheckConfig,
    /// Send SIGHUP to running daemon to reload config
    Reload,
}

// ── main ────────────────────────────────────────────────────────
//
// #[tokio::main] transforms the async main function into the
// actual synchronous entry point that initializes the tokio
// runtime and runs the async body.
//
// The return type is anyhow::Result<()> — this lets us use ?
// everywhere and prints the error + backtrace on failure.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ── Initialize logging ───────────────────────────────────
    //
    // tracing_subscriber::fmt() with EnvFilter: logs are printed
    // to stderr with timestamps and levels. The RUST_LOG env var
    // controls verbosity (e.g., RUST_LOG=debug sentryd daemon).
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    let config_path = cli.config.clone();
    let config = Arc::new(RwLock::new(load_config(&cli.config)?));

    // Dispatch to subcommand handler
    match cli.command {
        Commands::Daemon => run_daemon(config, config_path).await,
        Commands::Parse { line, file } => cmd_parse(config, line, file).await,
        Commands::Send { message } => cmd_send(config, message).await,
        Commands::Exec { task_json } => cmd_exec(task_json).await,
        Commands::Status => cmd_status(config).await,
        Commands::CheckConfig => {
            println!("config valid: {} entries ok", 1);
            Ok(())
        }
        Commands::Reload => {
            let pid_path = "/var/run/sentryd.pid";
            let pid_str = std::fs::read_to_string(pid_path)
                .map_err(|e| anyhow::anyhow!("cannot read {}: {}", pid_path, e))?;
            let pid: i32 = pid_str.trim().parse()
                .map_err(|e| anyhow::anyhow!("invalid pid in {}: {}", pid_path, e))?;
            // Send SIGHUP via kill command
            let status = std::process::Command::new("kill")
                .arg("-HUP")
                .arg(pid.to_string())
                .status()
                .map_err(|e| anyhow::anyhow!("failed to send SIGHUP: {}", e))?;
            if !status.success() {
                return Err(anyhow::anyhow!("kill -HUP {} failed", pid));
            }
            println!("sent SIGHUP to pid {}", pid);
            Ok(())
        }
    }
}

// ── load_config ────────────────────────────────────────────────
//
// Reads and parses the YAML config file. Uses serde_yaml to
// deserialize into AgentConfig (defined in sentry-core).
// Returns anyhow::Error on failure — the caller (main) will
// print it and exit.

fn load_config(path: &PathBuf) -> anyhow::Result<AgentConfig> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("cannot read config {}: {}", path.display(), e))?;
    let config: AgentConfig = serde_yaml::from_str(&contents)
        .map_err(|e| anyhow::anyhow!("invalid config {}: {}", path.display(), e))?;
    Ok(config)
}

// ── cmd_parse ──────────────────────────────────────────────────
//
// Parses one or more log lines and prints the structured LogEntry
// as JSON. Three input modes:
//   1. `-l "line"` — parse a single string argument
//   2. `-f /path/to/file` — parse an entire file
//   3. No args — read lines from stdin (pipe mode)
//
// This is useful for debugging the parser without running the
// full daemon.

async fn cmd_parse(_config: Arc<RwLock<AgentConfig>>, line: Option<String>, file: Option<PathBuf>) -> anyhow::Result<()> {
    let entries: Vec<LogEntry> = if let Some(line) = line {
        // Mode 1: single line from CLI argument
        let tail = FileTail::new("/dev/null");
        vec![tail.parse_line(&line)?]
    } else if let Some(path) = file {
        // Mode 2: file path
        let tail = FileTail::new(path.to_str().unwrap_or("/dev/null"));
        let (entries, _pos) = tail.tail_from_start()?;
        entries
    } else {
        // Mode 3: stdin (pipe)
        use std::io::BufRead;
        let stdin = std::io::stdin();
        let tail = FileTail::new("/dev/stdin");
        let mut entries = Vec::new();
        for line in stdin.lock().lines() {
            let line = line?;
            if let Ok(entry) = tail.parse_line(&line) {
                entries.push(entry);
            }
        }
        entries
    };

    // Print each entry as pretty-printed JSON to stdout
    for entry in &entries {
        println!("{}", serde_json::to_string_pretty(entry)?);
    }
    Ok(())
}

// ── cmd_send ───────────────────────────────────────────────────
//
// Parses a single line and pushes it to the hub. Useful for
// testing hub connectivity.
// Note: this opens the store but doesn't use it for queueing.

async fn cmd_send(config: Arc<RwLock<AgentConfig>>, message: String) -> anyhow::Result<()> {
    let cfg = &*config.read().unwrap();
    let store = Arc::new(open_store(cfg)?);
    let client = make_client(cfg, Some(store));
    let tail = FileTail::new("/dev/null");
    let entry = tail.parse_line(&message)?;
    client.push_event(&entry).await?;
    println!("sent: {}", entry.raw);
    Ok(())
}

// ── cmd_exec ───────────────────────────────────────────────────
//
// Parses a JSON string as a RemoteTask and executes it locally.
// Prints the resulting TaskResult as JSON.
// JSON input example:
//   '{"type":"RunCommand","command":"echo","args":["hello"],"timeout_secs":5}'

async fn cmd_exec(task_json: String) -> anyhow::Result<()> {
    let task: RemoteTask = serde_json::from_str(&task_json)?;
    let result = execute_task(task).await;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

// ── cmd_status ─────────────────────────────────────────────────
//
// Opens the local store and prints diagnostic information:
// agent name, hub URL, pending event count, watchers, detection
// status.

async fn cmd_status(config: Arc<RwLock<AgentConfig>>) -> anyhow::Result<()> {
    let cfg = &*config.read().unwrap();
    let store = open_store(cfg)?;
    let pending = store.count_pending()?;
    println!("agent:      {}", cfg.agent.name);
    println!("hub:        {}", cfg.hub.url);
    println!("pending:    {} events", pending);
    println!("watchers:   {} paths", cfg.ingest.file_watchers.paths.len());
    println!("detection:  {}", if cfg.detection.enabled { "enabled" } else { "disabled" });
    println!("config:     /etc/sentryd/sentryd.yaml (SIGHUP to reload)");
    Ok(())
}

// ═════════════════════════════════════════════════════════════════
// DAEMON MODE
// ═════════════════════════════════════════════════════════════════
//
// The daemon is the main operational mode. It runs until killed
// by SIGINT/SIGTERM (ctrl-c).

async fn run_daemon(config: Arc<RwLock<AgentConfig>>, config_path: PathBuf) -> anyhow::Result<()> {
    let cfg = &*config.read().unwrap();
    tracing::info!("starting sentryd daemon for agent '{}'", cfg.agent.name);

    // ── Write PID file ─────────────────────────────────────────
    std::fs::write("/var/run/sentryd.pid", format!("{}", std::process::id()))
        .map_err(|e| tracing::warn!("cannot write pid file: {}", e))
        .ok();

    // ── Open SQLite store ─────────────────────────────────────
    let store_arc = Arc::new(open_store(cfg)?);

    // ── Build Augur client and register ───────────────────────
    let mut client_init = make_client(cfg, Some(store_arc.clone()));
    client_init.register().await?;
    let client = Arc::new(client_init);

    // Drop the read lock — config reloads from SIGHUP will use
    // the RwLock going forward.
    let _ = cfg;

    // ── Shutdown channel ──────────────────────────────────────
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // ── Heartbeat loop (spawned task) ─────────────────────────
    let hb_client = client.clone();
    let hb_shutdown = shutdown_rx.clone();
    let hb_handle = tokio::spawn(async move {
        hb_client.start_heartbeat_loop(hb_shutdown).await;
    });

    // ── SIGHUP handler (config reload) ────────────────────────
    let sighup_config = config.clone();
    let sighup_path = config_path.clone();
    let mut sighup_shutdown = shutdown_rx.clone();
    let sighup_handle = tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sig = match signal(SignalKind::hangup()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("cannot register SIGHUP handler: {}", e);
                    return;
                }
            };
            loop {
                tokio::select! {
                    _ = sig.recv() => {
                        match load_config(&sighup_path) {
                            Ok(new_cfg) => {
                                match sighup_config.write() {
                                    Ok(mut guard) => *guard = new_cfg,
                                    Err(e) => tracing::error!("config lock poisoned: {}", e),
                                }
                                tracing::info!("config reloaded from {}", sighup_path.display());
                            }
                            Err(e) => tracing::error!("config reload failed: {}", e),
                        }
                    }
                    _ = sighup_shutdown.changed() => break,
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = sighup_shutdown.changed().await;
        }
    });

    // ── Remote config pull loop ───────────────────────────────
    let remote_client = client.clone();
    let remote_cfg = config.clone();
    let mut remote_shutdown = shutdown_rx.clone();
    let remote_handle = tokio::spawn(async move {
        let mut tick = 0u64;
        loop {
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {}
                _ = remote_shutdown.changed() => break,
            }
            if *remote_shutdown.borrow() { break; }
            tick += 1;
            // Only pull config every 5 minutes (5th tick)
            if tick % 5 != 0 { continue; }
            match remote_client.pull_config().await {
                Ok(remote) => {
                    if let Ok(mut guard) = remote_cfg.write() {
                        if let Some(hub_url) = remote.get("hub_url").and_then(|v| v.as_str()) {
                            guard.hub.url = hub_url.to_string();
                        }
                        if let Some(interval) = remote.get("heartbeat_interval").and_then(|v| v.as_u64()) {
                            guard.hub.heartbeat_interval = interval;
                        }
                        tracing::info!("applied remote config overrides from hub");
                    }
                }
                Err(e) => tracing::debug!("remote config pull failed (non-fatal): {}", e),
            }
        }
    });

    // ── File watcher (spawned task) ───────────────────────────
    let (ingest_tx, mut ingest_rx) = tokio::sync::mpsc::unbounded_channel();
    let ingest_shutdown = shutdown_rx.clone();
    let ingest_config = config.clone();
    let ingest_handle = tokio::spawn(async move {
        let patterns = {
            let cfg = &*ingest_config.read().unwrap();
            cfg.ingest.file_watchers.patterns.clone()
        };
        if let Err(e) = sentry_ingest::watch_files(patterns, ingest_tx, ingest_shutdown).await {
            tracing::error!("file watcher error: {}", e);
        }
    });

    // ── Detection engine ──────────────────────────────────────
    let mut engine = DetectionEngine::new(vec![]);
    let mut det_shutdown = shutdown_rx.clone();
    let det_config = config.clone();

    // ── Main event loop ───────────────────────────────────────
    let main_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(entry) = ingest_rx.recv() => {
                    tracing::debug!(
                        "event: {} | {} | {}",
                        entry.format,
                        entry.severity,
                        entry.raw.get(0..80).unwrap_or("..."),
                    );

                    if let Err(e) = store_arc.push_event(&entry) {
                        tracing::warn!("store push failed: {}", e);
                    }

                    let detection_enabled = det_config.read()
                        .map(|g| g.detection.enabled)
                        .unwrap_or(false);
                    if detection_enabled {
                        let alerts = engine.evaluate(&entry);
                        for alert in alerts {
                            tracing::warn!(
                                "ALERT: {} | {} | {}",
                                alert.rule_name,
                                alert.severity,
                                alert.description,
                            );

                            let alert_entry = LogEntry {
                                timestamp: alert.timestamp,
                                host: alert.host.clone().unwrap_or_default(),
                                source: "detection".to_string(),
                                format: "alert".to_string(),
                                raw: alert.description.clone(),
                                source_ip: alert.source_ip.clone(),
                                user: alert.user.clone(),
                                event_type: Some(alert.rule_name.clone()),
                                mitre_tactic: None,
                                mitre_technique: None,
                                severity: alert.severity.clone(),
                                tags: vec!["alert".to_string()],
                            };
                            let _ = store_arc.push_event(&alert_entry);
                        }
                    }
                }
                _ = det_shutdown.changed() => break,
            }
        }
    });

    // ── Wait for shutdown signal ──────────────────────────────
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down...");

    let _ = shutdown_tx.send(true);
    let _ = tokio::join!(sighup_handle, remote_handle, hb_handle, ingest_handle, main_handle);
    let _ = std::fs::remove_file("/var/run/sentryd.pid");

    tracing::info!("sentryd stopped");
    Ok(())
}

// ── Helper Functions ──────────────────────────────────────────

/// Opens the local SQLite store from the configured path.
fn open_store(config: &AgentConfig) -> anyhow::Result<LocalStore> {
    let path = PathBuf::from(&config.store.path);
    Ok(LocalStore::open(
        &path,
        config.store.max_pending,
        config.store.retention_days,
    )?)
}

/// Builds an AugurClient using config values.
fn make_client(config: &AgentConfig, store: Option<Arc<LocalStore>>) -> AugurClient {
    AugurClient::new(
        &config.hub.url,
        &config.hub.api_key,
        &config.agent.name,
        &config.agent.agent_type,
        config.hub.heartbeat_interval,
        store,
    )
}
