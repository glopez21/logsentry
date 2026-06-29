// ─────────────────────────────────────────────────────────────────
// sentry-ingest: File Tailing, Log Parsing, and File Watching
//
// This is where raw log lines become structured LogEntry values.
// The pipeline is:
//
//   File (on disk) → FileTail (read + parse) → LogEntry
//                                                      ↓
//   inotify event  → FileTail (read new content) → LogEntry
//                                                      ↓
//                                              tokio channel
//                                                      ↓
//                                           sentryd main loop
//                                              → store + detect
//
// The crate is structured as a library because sentryd binary
// calls into it. The watch_files() async function is the main
// entry point for daemon mode.
//
// Error handling: we use anyhow::Result (dynamic error type)
// because this crate deals with many different error sources
// (I/O, regex, glob) and it's not important for callers to
// distinguish between them.
// ─────────────────────────────────────────────────────────────────

use anyhow::anyhow;
use chrono::Utc;
use notify::Watcher;            // Import the Watcher trait to call .watch()
use regex::Regex;
use sentry_core::{LogEntry, Severity};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;
use std::time::Duration;

use notify_debouncer_full::{DebounceEventResult, Debouncer, new_debouncer};

// ── FileTail ────────────────────────────────────────────────────
//
// Represents a single log file being tailed. Stateless except for
// the path — all position tracking is handled by sentry-store's
// checkpoint mechanism.
//
// Design note: we don't store the file handle or position in the
// struct because inotify tells us when a file changes, and we
// re-open + seek to the stored checkpoint. This is simpler than
// maintaining an open file descriptor per watched file.

pub struct FileTail {
    path: String,
}

impl FileTail {
    pub fn new(path: &str) -> Self {
        FileTail { path: path.to_string() }
    }

    // ── tail_existing ─────────────────────────────────────────
    //
    // Resumes reading from a known byte position. Handles log
    // rotation: if the current file is SMALLER than the checkpoint
    // position (rotation deleted the old file and created a new
    // empty one), we restart from the beginning.

    pub fn tail_existing(&self, position: u64) -> anyhow::Result<(Vec<LogEntry>, u64)> {
        let f = std::fs::File::open(&self.path)?;
        let metadata = f.metadata()?;
        let file_size = metadata.len();

        // inode is stored but not compared here — in practice,
        // rotation detection would compare the current inode
        // against the stored inode.
        let _inode = get_inode(&self.path).unwrap_or(0);

        // File was rotated (truncated or replaced) — start over
        if position > file_size {
            return self.tail_from_start();
        }

        let mut reader = BufReader::new(f);
        // Jump to where we left off
        reader.seek(SeekFrom::Start(position))?;

        let mut entries = Vec::new();
        let mut line = String::new();

        loop {
            line.clear();
            let bytes = reader.read_line(&mut line)?;
            if bytes == 0 {
                break;   // EOF
            }
            // parse_line returns Err for empty lines — skip those
            if let Ok(entry) = self.parse_line(&line) {
                entries.push(entry);
            }
        }

        // Get current position for checkpointing
        // seek(SeekFrom::Current(0)) returns the current offset
        // without moving. unwrap_or uses file_size as fallback.
        let new_pos = reader.seek(SeekFrom::Current(0)).unwrap_or(file_size);
        Ok((entries, new_pos))
    }

    // ── tail_from_start ────────────────────────────────────────
    //
    // Reads the entire file from byte 0. Used for initial read on
    // startup or after rotation detection.

    pub fn tail_from_start(&self) -> anyhow::Result<(Vec<LogEntry>, u64)> {
        let f = std::fs::File::open(&self.path)?;
        let metadata = f.metadata()?;
        let file_size = metadata.len();
        let reader = BufReader::new(f);

        let mut entries = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if let Ok(entry) = self.parse_line(&line) {
                entries.push(entry);
            }
        }

        Ok((entries, file_size))
    }

    // ── parse_line ────────────────────────────────────────────
    //
    // Parses a single log line into a LogEntry. The line is
    // classified by format, severity is assessed, and IP/user are
    // extracted via regex.

    pub fn parse_line(&self, line: &str) -> anyhow::Result<LogEntry> {
        let line = line.trim();
        if line.is_empty() {
            return Err(anyhow!("empty line"));
        }

        let format = detect_format(line);
        let severity = detect_severity(line);
        let (source_ip, user) = extract_fields(line, &format);

        Ok(LogEntry {
            timestamp: Utc::now(),          // We use ingestion time, not log line time
            host: hostname(),
            source: "file".to_string(),
            format,
            raw: line.to_string(),
            source_ip,
            user,
            event_type: None,               // Populated later by detection engine
            mitre_tactic: None,
            mitre_technique: None,
            severity,
            tags: vec![],
        })
    }
}

// ── detect_format ──────────────────────────────────────────────
//
// Classification by keyword matching. These functions are pure
// (no side effects, deterministic) and could be replaced with a
// more sophisticated ML-based classifier later.
//
// The order of checks matters: "sshd" is tested before generic
// "syslog" catch-all. More specific patterns come first.

pub fn detect_format(line: &str) -> String {
    if line.contains("sshd") || line.contains("ssh-pam") || line.contains("authentication failure") {
        "ssh".to_string()
    } else if line.contains("sudo") || line.contains("su:") || line.contains("pam_unix") {
        "auth".to_string()
    } else if line.contains("OUT=") || line.contains("IN=")
        || line.contains("DPT=") || line.contains("nf_conntrack")
        || line.contains("iptables") || line.contains("nftables")
    {
        "firewall".to_string()
    } else if line.contains("nginx") || line.contains("apache")
        || line.contains("GET ") || line.contains("POST ") || line.contains("HTTP/")
    {
        "web".to_string()
    } else if line.contains("audit") || line.contains("type=") {
        "auditd".to_string()
    } else if line.contains("FAILED LOGIN") || line.contains("Invalid user") {
        "ssh".to_string()
    } else {
        "syslog".to_string()    // Default / catch-all
    }
}

// ── detect_severity ────────────────────────────────────────────
//
// Keyword-based severity assessment. The order tests Critical
// first (rare, severe), then High, Medium, Low, defaulting to
// Info. This is a heuristic — in production, more nuance would
// be needed.

pub fn detect_severity(line: &str) -> Severity {
    let lower = line.to_lowercase();
    if lower.contains("critical") || lower.contains("emerg") {
        Severity::Critical
    } else if lower.contains("error") || lower.contains("err") || lower.contains("fail")
        || lower.contains("denied") || lower.contains("refused") || lower.contains("invalid")
    {
        Severity::High
    } else if lower.contains("warn") || lower.contains("authentication failure")
        || lower.contains("failed password")
    {
        Severity::Medium
    } else if lower.contains("notice") || lower.contains("info") {
        Severity::Low
    } else {
        Severity::Info
    }
}

// ── extract_fields ─────────────────────────────────────────────
//
// Uses regex to extract structured fields from the raw log line.
// Returns (Option<source_ip>, Option<user>).
//
// The IP regex matches IPv4 addresses (simplified — no validation,
// just pattern matching). The user regex varies by format:
//   ssh: "user root" or "for root"
//   auth: "sudo: alice" or "su: bob" or "user=charlie"

pub fn extract_fields(line: &str, format: &str) -> (Option<String>, Option<String>) {
    // \b is a word boundary. ?: is a non-capturing group.
    // The pattern matches four octets separated by dots.
    let ip_re = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap();
    let source_ip = ip_re.find(line).map(|m| m.as_str().to_string());

    let user = match format {
        "ssh" => {
            // Capture the first non-whitespace token after "user" or "for"
            let user_re = Regex::new(r"(?:user|for)\s+(\S+)").unwrap();
            user_re.captures(line)
                .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
        }
        "auth" => {
            // Capture token after "sudo:", "su:" or "user="
            let user_re = Regex::new(r"(?:sudo|su:|user=)\s*(\S+)").unwrap();
            user_re.captures(line)
                .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
        }
        _ => None,
    };

    (source_ip, user)
}

// ── hostname ───────────────────────────────────────────────────
//
// Same pattern as in sentry-agent — tries env var, then file,
// then fallback.

fn hostname() -> String {
    std::env::var("HOSTNAME").unwrap_or_else(|_| {
        std::fs::read_to_string("/etc/hostname")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    })
}

// ── get_inode ──────────────────────────────────────────────────
//
// Returns the inode number of a file on Unix. Used for rotation
// detection: if the inode changes, the file was replaced.
// #[cfg(unix)] makes this function compile only on Unix platforms,
// ensuring portability. The #[cfg(not(unix))] arm provides a
// fallback.

fn get_inode(path: &str) -> Option<u64> {
    std::fs::metadata(path).ok().and_then(|_m| {
        #[cfg(unix)]
        {
            // Import the Unix metadata extension trait, which adds
            // .ino() to std::fs::Metadata on Unix.
            use std::os::unix::fs::MetadataExt;
            Some(_m.ino())
        }
        #[cfg(not(unix))]
        { Some(0) }
    })
}

// ── watch_files ────────────────────────────────────────────────
//
// THE MAIN ASYNC ENTRY POINT for file ingestion.
//
//  1. Resolve glob patterns to actual file paths.
//  2. Read initial content of each file.
//  3. Set up inotify watchers on each file.
//  4. Loop: wait for inotify events, read new content, send
//     LogEntry values through the tokio channel.
//  5. On shutdown signal, exit cleanly.
//
// The Debouncer wraps the inotify watcher and coalesces rapid
// events (e.g., multiple writes in quick succession) into a
// single notification after a 1-second quiet period.

pub async fn watch_files(
    patterns: Vec<String>,
    tx: tokio::sync::mpsc::UnboundedSender<LogEntry>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    // ── Step 1: Expand globs to paths ──────────────────────────
    let mut paths: Vec<String> = Vec::new();
    for pattern in &patterns {
        // glob::glob returns an iterator of Result<PathBuf>
        if let Ok(matches) = glob::glob(pattern) {
            for entry in matches.flatten() {
                paths.push(entry.to_string_lossy().to_string());
            }
        }
    }

    if paths.is_empty() {
        tracing::warn!("no files matched patterns: {:?}", patterns);
        return Ok(());
    }

    // ── Step 2: Read initial content ──────────────────────────
    //
    // On first startup, we read the entire existing content. On
    // restart, we would use checkpoints to resume from where we
    // left off. For now, we always start from the beginning.
    for p in &paths {
        let tail = FileTail::new(p);
        if let Ok((entries, _pos)) = tail.tail_from_start() {
            for e in entries {
                let _ = tx.send(e);
            }
        }
    }

    // ── Step 3: Set up inotify debouncer ───────────────────────
    //
    // The Debouncer uses a channel internally. Our closure
    // receives DebounceEventResult and forwards file paths to
    // debounce_tx. We use a separate channel (debounce_tx/rx)
    // because the debouncer's closure is not async — it can't
    // call tx.send() directly.

    let (debounce_tx, mut debounce_rx) = tokio::sync::mpsc::unbounded_channel::<String>();

    let mut debouncer: Debouncer<_, _> = new_debouncer(
        Duration::from_secs(1),    // Debounce window: 1 second
        None,                       // No optional channel override
        move |result: DebounceEventResult| {
            if let Ok(events) = result {
                // Forward each modified file path to our channel
                for event in events {
                    // DebouncedEvent derefs to notify::Event, which
                    // has a .paths field (Vec<PathBuf>).
                    for path in &event.paths {
                        let _ = debounce_tx.send(path.to_string_lossy().to_string());
                    }
                }
            }
        },
    )?;

    // Register watches — .watcher() returns a &mut INotifyWatcher
    let watcher = debouncer.watcher();
    for p in &paths {
        watcher.watch(Path::new(p), notify::RecursiveMode::NonRecursive)?;
    }

    // ── Step 4: Event loop ─────────────────────────────────────
    loop {
        tokio::select! {
            // A file changed — re-read it from the start
            Some(file_path) = debounce_rx.recv() => {
                let tail = FileTail::new(&file_path);
                if let Ok((entries, _pos)) = tail.tail_from_start() {
                    for e in entries {
                        let _ = tx.send(e);
                    }
                }
            }
            // Shutdown signal received — exit loop
            _ = shutdown_rx.changed() => break,
        }
    }

    Ok(())
}

// Note on future improvements:
//   - The current implementation re-reads the entire file on each
//     notification. A production version would use checkpoints to
//     read only new content (tail -f style).
//   - Log rotation detection would compare inodes and handle the
//     case where a file is deleted/recreated.
//   - The debouncer closure captures debounce_tx by move. If
//     debounce_tx is dropped (channel closed), the closure will
//     silently drop events. This is acceptable on shutdown.
