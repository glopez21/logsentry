// ─────────────────────────────────────────────────────────────────
// sentry-exec: Remote Task Executor
//
// This crate handles the "respond" side of the agent protocol:
// the hub sends a RemoteTask enum, we execute it, and return a
// TaskResult.
//
// The main entry point is execute_task(), which matches on the
// RemoteTask enum variant and dispatches to the appropriate
// handler.
//
// Each handler follows the same pattern:
//   1. Perform the action (write script, spawn process, read file)
//   2. Apply timeout via tokio::time::timeout()
//   3. Return TaskResult with status, output, and artifacts
//
// Key Rust concepts:
//   - tokio::process::Command — async subprocess (non-blocking wait)
//   - tokio::fs — async file I/O
//   - tokio::time::timeout — race between completion and deadline
//   - match on enum variants with destructuring — extract fields
//     from each RemoteTask variant
//   - String::from_utf8_lossy — convert Vec<u8> to String,
//     replacing invalid UTF-8 with � instead of failing
// ─────────────────────────────────────────────────────────────────

use std::time::Duration;

use sentry_core::{RemoteTask, TaskResult, TaskStatus};
use tokio::process::Command;
use tokio::time;
use uuid::Uuid;

// ── execute_task ───────────────────────────────────────────────
//
// Top-level dispatcher. Each RemoteTask variant is destructured
// in the match arm, and the fields are passed to the handler.
//
// A new task_id (UUID v4) is generated for every execution,
// regardless of whether the hub assigned one. This ensures every
// result is uniquely identifiable.

pub async fn execute_task(task: RemoteTask) -> TaskResult {
    let task_id = Uuid::new_v4().to_string();

    match task {
        RemoteTask::RunScript {
            script,
            interpreter,
            timeout_secs,
        } => run_script(&task_id, &script, &interpreter, timeout_secs).await,

        RemoteTask::CollectFile {
            path,
            max_bytes,
        } => collect_file(&task_id, &path, max_bytes).await,

        RemoteTask::RunCommand {
            command,
            args,
            timeout_secs,
        } => run_command(&task_id, &command, &args, timeout_secs).await,

        RemoteTask::AcquireMemory {
            tool,
            output_path,
        } => acquire_memory(&task_id, &tool, &output_path).await,
    }
}

// ── run_script ─────────────────────────────────────────────────
//
// 1. Write the script content to a temp file in /tmp
// 2. Execute it with the specified interpreter (e.g., /bin/bash)
// 3. Delete the temp file
//
// The temp file is named sentry_task_<uuid> to prevent collisions.

async fn run_script(
    task_id: &str,
    script: &str,
    interpreter: &str,
    timeout_secs: u32,
) -> TaskResult {
    let tmp_path = format!("/tmp/sentry_task_{}", Uuid::new_v4());

    // Write script asynchronously
    if let Err(e) = tokio::fs::write(&tmp_path, script).await {
        return TaskResult {
            task_id: task_id.to_string(),
            status: TaskStatus::Failed,
            stdout: None,
            stderr: Some(format!("failed to write script file: {}", e)),
            exit_code: Some(-1),
            artifacts: vec![],
        };
    }

    // Execute using the interpreter
    let result = run_command(task_id, interpreter, &[tmp_path.clone()], timeout_secs).await;

    // Cleanup — ignore errors (temp file might not exist if /tmp was cleaned)
    let _ = tokio::fs::remove_file(&tmp_path).await;
    result
}

// ── run_command ────────────────────────────────────────────────
//
// Spawns a subprocess with tokio::process::Command and waits for
// it to complete (or timeout). The timeout is asymmetric:
//   - If timeout completes first → TaskStatus::Timeout
//   - If process completes first → TaskStatus::Completed or Failed
//
// tokio::time::timeout returns:
//   Ok(Result) — process finished within time
//   Err(Elapsed) — timeout expired, process is dropped (SIGKILL)

async fn run_command(
    task_id: &str,
    command: &str,
    args: &[String],
    timeout_secs: u32,
) -> TaskResult {
    // Build the command. .arg() accepts &str or &String (due to
    // the AsRef<OsStr> blanket impl).
    let mut cmd = Command::new(command);
    cmd.args(args);

    // Race the process against the timeout clock
    let result = time::timeout(
        Duration::from_secs(timeout_secs as u64),
        cmd.output(),
    )
    .await;

    match result {
        // ── Process completed within timeout ──────────────────
        Ok(Ok(output)) => TaskResult {
            task_id: task_id.to_string(),
            // .success() returns true if exit code == 0
            status: if output.status.success() {
                TaskStatus::Completed
            } else {
                TaskStatus::Failed
            },
            // from_utf8_lossy handles non-UTF-8 output gracefully
            stdout: Some(String::from_utf8_lossy(&output.stdout).to_string()),
            stderr: Some(String::from_utf8_lossy(&output.stderr).to_string()),
            exit_code: output.status.code(),
            artifacts: vec![],
        },

        // ── Failed to spawn or I/O error (not timeout) ───────
        Ok(Err(e)) => TaskResult {
            task_id: task_id.to_string(),
            status: TaskStatus::Failed,
            stdout: None,
            stderr: Some(format!("execution error: {}", e)),
            exit_code: Some(-1),
            artifacts: vec![],
        },

        // ── Timeout — process took too long ──────────────────
        Err(_) => TaskResult {
            task_id: task_id.to_string(),
            status: TaskStatus::Timeout,
            stdout: None,
            stderr: Some(format!("timed out after {}s", timeout_secs)),
            exit_code: None,    // Process was killed, no exit code
            artifacts: vec![],
        },
    }
}

// ── collect_file ───────────────────────────────────────────────
//
// Reads a file from disk and returns its contents as stdout.
// Truncates at max_bytes to prevent sending multi-GB files.
//
// The file path is also listed in artifacts for provenance.

async fn collect_file(task_id: &str, path: &str, max_bytes: u64) -> TaskResult {
    let data = tokio::fs::read(path).await;

    match data {
        Ok(bytes) => {
            let content = if bytes.len() > max_bytes as usize {
                // Prefix with truncation notice
                format!(
                    "[truncated {} bytes to {}]\n{}",
                    bytes.len(),
                    max_bytes,
                    String::from_utf8_lossy(&bytes[..max_bytes as usize])
                )
            } else {
                String::from_utf8_lossy(&bytes).to_string()
            };
            TaskResult {
                task_id: task_id.to_string(),
                status: TaskStatus::Completed,
                stdout: Some(content),
                stderr: None,
                exit_code: Some(0),
                artifacts: vec![path.to_string()],
            }
        }
        Err(e) => TaskResult {
            task_id: task_id.to_string(),
            status: TaskStatus::Failed,
            stdout: None,
            stderr: Some(format!("read error: {}", e)),
            exit_code: Some(-1),
            artifacts: vec![],
        },
    }
}

// ── acquire_memory ────────────────────────────────────────────
//
// Runs a memory acquisition tool to dump RAM. Supports:
//   - avml (Azure VM Memory Logger) — ARM64/AMD64 native
//   - lime (Linux Memory Extractor) — kernel module
//   - dumpmem — Python-based tool
//
// Falls through to raw tool name + output_path for custom tools.
// Timeout is hardcoded to 300 seconds (5 min) because memory
// dumps can be very large.

async fn acquire_memory(task_id: &str, tool: &str, output_path: &str) -> TaskResult {
    let (cmd, args) = match tool {
        "avml" => ("avml", vec![output_path.to_string()]),
        "lime" => ("lime", vec!["-o".to_string(), output_path.to_string()]),
        "dumpmem" => (
            "python3",
            vec![
                "-m".to_string(),
                "dumpmem".to_string(),
                output_path.to_string(),
            ],
        ),
        _ => (tool, vec![output_path.to_string()]),
    };

    let result = run_command(task_id, cmd, &args, 300).await;

    // Only report the output path as an artifact if acquisition
    // succeeded (Completed status).
    TaskResult {
        artifacts: if result.status == TaskStatus::Completed {
            vec![output_path.to_string()]
        } else {
            vec![]
        },
        ..result  // Spread the rest of the fields from result
    }
}
