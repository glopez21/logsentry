// ─────────────────────────────────────────────────────────────────
// sentry-store: SQLite-backed Local Event Queue
//
// This is the agent's "offline buffer" — when the hub is
// unreachable, events go into SQLite. When the connection comes
// back, they drain in FIFO order.
//
// Key architecture decisions:
//
//   1. Mutex<Connection> — rusqlite's Connection is Send but not
//      Sync (it uses RefCell internally for prepared statement
//      caching). std::sync::Mutex adds thread-safety so
//      Arc<LocalStore> can be shared across tokio spawns.
//      The lock is held briefly per operation (microseconds).
//
//   2. JSON serialization — we store full LogEntry JSON rather
//      than normalized columns. This keeps the schema simple and
//      avoids having to migrate the DB when LogEntry fields change.
//      The cost is that we can't query by field value in SQL, but
//      we never need to — we always pop the oldest unsent events.
//
//   3. FIFO with sentinel flag — the sent column (0 = pending,
//      1 = sent) lets us retry failed sends without deleting rows.
//      This is an "at-least-once" delivery guarantee.
//
//   4. max_pending watermark — when the queue exceeds this limit,
//      the OLDEST unsent events are dropped. This prevents disk
//      from filling up if the hub is down for days.
// ─────────────────────────────────────────────────────────────────

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection};
use sentry_core::{LogEntry, SentryError};

// ── LocalStore ──────────────────────────────────────────────────
//
// The Mutex wraps rusqlite's Connection. Every public method
// locks the mutex, performs the operation, and releases.
//
// retention_days is stored but not yet enforced by a background
// purge task — it's wired up in purge_sent() which can be called
// periodically.

pub struct LocalStore {
    conn: Mutex<Connection>,
    #[allow(dead_code)]        // retention_days is reserved for future use
    retention_days: u32,
    max_pending: u32,
}

impl LocalStore {
    // ── open ───────────────────────────────────────────────────
    //
    // Creates or opens the SQLite database at `path`. Creates
    // parent directories if they don't exist. Runs schema
    // migration (CREATE TABLE IF NOT EXISTS).
    //
    // Result<T, E> is Rust's standard fallible return type.
    // Ok(T) = success with value, Err(E) = failure with error.
    // The ? operator unwraps Ok or returns early with Err.

    pub fn open(path: &Path, max_pending: u32, retention_days: u32) -> Result<Self, SentryError> {
        // `if let` destructures an Option: if parent_dir exists,
        // create it recursively. This is a concise pattern for
        // "do something if Some, otherwise skip".
        if let Some(parent) = path.parent() {
            // .map_err() converts one error type to another.
            // Here, std::io::Error → SentryError::Io via the #[from]
            // derive. The closure form is needed because we want
            // to use the ? operator after the conversion.
            std::fs::create_dir_all(parent).map_err(SentryError::Io)?;
        }

        // Connection::open creates or opens the SQLite file.
        // The ? operator: if Err, return early with the error
        // (automatically converted to SentryError via map_err).
        let conn = Connection::open(path)
            .map_err(|e| SentryError::Db(e.to_string()))?;

        let store = LocalStore {
            conn: Mutex::new(conn),
            retention_days,
            max_pending,
        };

        // Run schema migration — we call this after construction
        // because migrate() needs the Mutex-locked connection.
        store.migrate()?;
        Ok(store)
    }

    // ── migrate ────────────────────────────────────────────────
    //
    // Creates tables and indexes. Idempotent (IF NOT EXISTS) so
    // safe to call every startup.

    fn migrate(&self) -> Result<(), SentryError> {
        // .lock() returns a MutexGuard (RAII guard). When `conn`
        // goes out of scope, the mutex is released automatically.
        // map_err handles the poisoning case (if another thread
        // panicked while holding the lock).
        let conn = self.conn.lock()
            .map_err(|e| SentryError::Db(e.to_string()))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS event_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL DEFAULT (datetime('now')),
                event_json TEXT NOT NULL,
                sent INTEGER NOT NULL DEFAULT 0,
                send_attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_event_queue_unsent
                ON event_queue(sent, created_at);
            CREATE TABLE IF NOT EXISTS checkpoint (
                file_path TEXT PRIMARY KEY,
                inode INTEGER NOT NULL DEFAULT 0,
                position INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            PRAGMA journal_mode=WAL;
            PRAGMA busy_timeout=5000;",
        )
        .map_err(|e| SentryError::Db(e.to_string()))
        // Note: execute_batch returns (), not rows, so no ? needed

        // WAL (Write-Ahead Log) journaling: much faster concurrent
        // reads while writing. Without it, SQLite uses a rollback
        // journal that blocks readers during writes.
        // busy_timeout=5000: wait up to 5 seconds if the DB is
        // locked instead of immediately returning an error.
    }

    // ── push_event ─────────────────────────────────────────────
    //
    // Serializes a LogEntry to JSON and inserts it. d(conn) before
    // enforce_max_pending avoids holding the lock while deleting.

    pub fn push_event(&self, entry: &LogEntry) -> Result<(), SentryError> {
        // serde_json::to_string serializes any Serialize type to JSON
        let json = serde_json::to_string(entry)
            .map_err(|e| SentryError::Db(e.to_string()))?;

        let conn = self.conn.lock()
            .map_err(|e| SentryError::Db(e.to_string()))?;
        conn.execute(
            "INSERT INTO event_queue (event_json) VALUES (?1)",
            // params![] is a rusqlite macro for binding parameters
            params![json],
        ).map_err(|e| SentryError::Db(e.to_string()))?;

        // drop(conn) explicitly releases the MutexGuard before
        // calling enforce_max_pending. Without this, the second
        // .lock() would deadlock (Mutex is not reentrant).
        drop(conn);
        self.enforce_max_pending()?;
        Ok(())
    }

    // ── pop_unsent ─────────────────────────────────────────────
    //
    // Returns up to `batch_size` unsent events in FIFO order.
    // Events with corrupt JSON are marked sent with an error
    // message and skipped (poisoned event handling).
    //
    // Note: we don't mark events as "in-flight" — the caller
    // (sentry-agent) pops events and sends them, then calls
    // mark_sent() on success. If the agent crashes between pop
    // and mark_sent, events will be re-delivered (at-least-once).

    pub fn pop_unsent(&self, batch_size: u32) -> Result<Vec<LogEntry>, SentryError> {
        let conn = self.conn.lock()
            .map_err(|e| SentryError::Db(e.to_string()))?;

        // Prepared statement — compiled once, executed many times.
        // This is more efficient than raw execute() for repeated use.
        let mut stmt = conn.prepare(
            "SELECT id, event_json FROM event_queue
             WHERE sent = 0 ORDER BY created_at ASC LIMIT ?1",
        ).map_err(|e| SentryError::Db(e.to_string()))?;

        // query_map iterates over result rows, calling the closure
        // for each. The closure returns rusqlite::Result<(i64, String)>.
        let rows = stmt.query_map(params![batch_size], |row| {
            let id: i64 = row.get(0)?;     // column 0: id
            let json: String = row.get(1)?; // column 1: event_json
            Ok((id, json))
        }).map_err(|e| SentryError::Db(e.to_string()))?;

        let mut entries = Vec::new();
        // rows is an iterator of Result<(i64, String), rusqlite::Error>
        for row in rows {
            let (id, json) = row.map_err(|e| SentryError::Db(e.to_string()))?;
            match serde_json::from_str::<LogEntry>(&json) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    // Corrupt event — log and mark as sent to avoid
                    // blocking the queue forever. This shouldn't
                    // happen in practice.
                    tracing::warn!("corrupt event in queue (id={}): {}", id, e);
                    let _ = conn.execute(
                        "UPDATE event_queue SET sent = 1, last_error = ?1 WHERE id = ?2",
                        params![format!("deserialize failed: {}", e), id],
                    );
                }
            }
        }
        Ok(entries)
    }

    // ── mark_sent ──────────────────────────────────────────────
    //
    // Marks the oldest N unsent events as sent. Called after
    // successful batch push to the hub.

    pub fn mark_sent(&self, count: u32) -> Result<(), SentryError> {
        let conn = self.conn.lock()
            .map_err(|e| SentryError::Db(e.to_string()))?;
        conn.execute(
            "UPDATE event_queue SET sent = 1 WHERE id IN (
                SELECT id FROM event_queue WHERE sent = 0 ORDER BY created_at ASC LIMIT ?1
            )",
            params![count],
        ).map_err(|e| SentryError::Db(e.to_string()))?;
        Ok(())
    }

    // ── count_pending ──────────────────────────────────────────
    //
    // Returns how many events are still unsent.

    pub fn count_pending(&self) -> Result<u64, SentryError> {
        let conn = self.conn.lock()
            .map_err(|e| SentryError::Db(e.to_string()))?;
        // query_row expects exactly one row. The closure maps
        // the row to the return value.
        conn.query_row(
            "SELECT COUNT(*) FROM event_queue WHERE sent = 0",
            [],
            |row| row.get(0),
        ).map_err(|e| SentryError::Db(e.to_string()))
    }

    // ── enforce_max_pending ────────────────────────────────────
    //
    // If the queue exceeds max_pending, drops the OLDEST events
    // beyond the limit. "LIMIT -1 OFFSET ?1" is SQLite syntax
    // for "delete everything except the last N rows".

    fn enforce_max_pending(&self) -> Result<(), SentryError> {
        let conn = self.conn.lock()
            .map_err(|e| SentryError::Db(e.to_string()))?;
        conn.execute(
            "DELETE FROM event_queue WHERE id IN (
                SELECT id FROM event_queue WHERE sent = 0
                ORDER BY created_at DESC LIMIT -1 OFFSET ?1
            )",
            params![self.max_pending],
        ).map_err(|e| SentryError::Db(e.to_string()))?;
        Ok(())
    }

    // ── purge_sent ─────────────────────────────────────────────
    //
    // Cleans up events sent more than 7 days ago. Intended to be
    // called periodically by a background task.

    #[allow(dead_code)]
    pub fn purge_sent(&self) -> Result<(), SentryError> {
        let conn = self.conn.lock()
            .map_err(|e| SentryError::Db(e.to_string()))?;
        conn.execute(
            "DELETE FROM event_queue WHERE sent = 1 AND created_at < datetime('now', '-7 days')",
            [],
        ).map_err(|e| SentryError::Db(e.to_string()))?;
        Ok(())
    }

    // ── Checkpoints (File Tail Resume) ────────────────────────
    //
    // The checkpoint table stores the byte offset + inode for each
    // watched file. On restart, sentry-ingest reads the checkpoint
    // and resumes from where it left off, avoiding re-processing
    // the entire file.
    //
    // get_checkpoint returns Option<(inode, position)> — None if
    // no checkpoint exists (file not seen before).

    pub fn get_checkpoint(&self, file_path: &str) -> Result<Option<(u64, u64)>, SentryError> {
        let conn = self.conn.lock()
            .map_err(|e| SentryError::Db(e.to_string()))?;
        let mut stmt = conn.prepare(
            "SELECT inode, position FROM checkpoint WHERE file_path = ?1",
        ).map_err(|e| SentryError::Db(e.to_string()))?;

        // query_row returns Result<T, Error> where Error is
        // rusqlite::Error. .ok() converts Err to None — we treat
        // "no such row" the same as "no checkpoint".
        let result = stmt.query_row(params![file_path], |row| {
            let inode: u64 = row.get(0)?;
            let pos: u64 = row.get(1)?;
            Ok((inode, pos))
        }).ok();
        Ok(result)
    }

    pub fn set_checkpoint(&self, file_path: &str, inode: u64, position: u64) -> Result<(), SentryError> {
        let conn = self.conn.lock()
            .map_err(|e| SentryError::Db(e.to_string()))?;
        // INSERT OR REPLACE = upsert: insert if not exists, update
        // if the primary key (file_path) already exists.
        conn.execute(
            "INSERT OR REPLACE INTO checkpoint (file_path, inode, position, updated_at)
             VALUES (?1, ?2, ?3, datetime('now'))",
            params![file_path, inode, position],
        ).map_err(|e| SentryError::Db(e.to_string()))?;
        Ok(())
    }
}
