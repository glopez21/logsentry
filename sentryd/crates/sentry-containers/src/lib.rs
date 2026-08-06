use std::collections::HashMap;
use std::time::Duration;

use sentry_core::ContainerInfo;
use tokio::process::Command;

/// Run a command and return stdout as a String, or None if the command
/// doesn't exist / fails to spawn.
async fn try_cmd(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .await
        .ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        None
    }
}

/// Probe Docker via `docker ps -a --format '{{json .}}'`.
async fn probe_docker() -> Vec<ContainerInfo> {
    let output = match try_cmd("docker", &["ps", "-a", "--format", "{{json .}}"]).await {
        Some(o) => o,
        None => return vec![],
    };

    output.lines().filter_map(|line| parse_docker_line(line)).collect()
}

fn parse_docker_line(line: &str) -> Option<ContainerInfo> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let raw_id = v.get("ID")?.as_str()?;
    let short_id = if raw_id.len() > 12 { &raw_id[..12] } else { raw_id };
    Some(ContainerInfo {
        container_id: short_id.to_string(),
        name: v.get("Names")?.as_str()?.trim_start_matches('/').to_string(),
        image: v.get("Image")?.as_str()?.to_string(),
        status: v.get("State")?.as_str()?.to_string(),
        ports: v.get("Ports")
            .and_then(|p| p.as_str())
            .map(|p| {
                if p.is_empty() {
                    vec![]
                } else {
                    p.split(", ").map(String::from).collect()
                }
            })
            .unwrap_or_default(),
        labels: HashMap::new(),
        created: v.get("CreatedAt")
            .and_then(|c| c.as_str())
            .unwrap_or("")
            .to_string(),
        runtime: "docker".to_string(),
        pid: None,
    })
}

/// Probe containerd via `nerdctl ps -a --format '{{json .}}'`.
async fn probe_nerdctl() -> Vec<ContainerInfo> {
    let output = match try_cmd("nerdctl", &["ps", "-a", "--format", "{{json .}}"]).await {
        Some(o) => o,
        None => return vec![],
    };

    output.lines().filter_map(|line| parse_nerdctl_line(line)).collect()
}

fn parse_nerdctl_line(line: &str) -> Option<ContainerInfo> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    Some(ContainerInfo {
        container_id: v.get("ID")?.as_str()?.to_string(),
        name: v.get("Names")?.as_str()?.trim_start_matches('/').to_string(),
        image: v.get("Image")?.as_str()?.to_string(),
        status: v.get("Status")?.as_str()?.to_string(),
        ports: v.get("Ports")
            .and_then(|p| p.as_str())
            .map(|p| {
                if p.is_empty() { vec![] } else { p.split(", ").map(String::from).collect() }
            })
            .unwrap_or_default(),
        labels: HashMap::new(),
        created: v.get("CreatedAt")
            .and_then(|c| c.as_str())
            .unwrap_or("")
            .to_string(),
        runtime: "containerd".to_string(),
        pid: None,
    })
}

/// Probe Podman via `podman ps -a --format '{{json .}}'`.
async fn probe_podman() -> Vec<ContainerInfo> {
    let output = match try_cmd("podman", &["ps", "-a", "--format", "{{json .}}"]).await {
        Some(o) => o,
        None => return vec![],
    };

    output.lines().filter_map(|line| parse_podman_line(line)).collect()
}

fn parse_podman_line(line: &str) -> Option<ContainerInfo> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    Some(ContainerInfo {
        container_id: v.get("ID")?.as_str()?.to_string(),
        name: v.get("Names")?.as_str()?.trim_start_matches('/').to_string(),
        image: v.get("Image")?.as_str()?.to_string(),
        status: v.get("State")?.as_str()?.to_string(),
        ports: {
            let raw = v.get("Ports").and_then(|p| p.as_str()).unwrap_or("");
            if raw.is_empty() {
                v.get("Ports").and_then(|p| p.as_array()).map(|arr| {
                    arr.iter().filter_map(|e| e.as_str().map(String::from)).collect()
                }).unwrap_or_default()
            } else {
                raw.split(", ").map(String::from).collect()
            }
        },
        labels: HashMap::new(),
        created: v.get("CreatedAt")
            .and_then(|c| c.as_str())
            .unwrap_or("")
            .to_string(),
        runtime: "podman".to_string(),
        pid: None,
    })
}

/// Discover containers from all configured runtimes.
pub async fn discover(runtimes: &[String]) -> Vec<ContainerInfo> {
    let mut all = Vec::new();

    if runtimes.iter().any(|r| r == "docker") {
        let containers = probe_docker().await;
        tracing::info!("docker: {} containers", containers.len());
        all.extend(containers);
    }

    if runtimes.iter().any(|r| r == "containerd") {
        let containers = probe_nerdctl().await;
        tracing::info!("containerd: {} containers", containers.len());
        all.extend(containers);
    }

    if runtimes.iter().any(|r| r == "podman") {
        let containers = probe_podman().await;
        tracing::info!("podman: {} containers", containers.len());
        all.extend(containers);
    }

    all
}

/// Periodic discovery loop. Runs `discover()` every `interval_secs`
/// and calls `callback` with all discovered containers.
pub async fn discovery_loop(
    runtimes: Vec<String>,
    interval_secs: u64,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    callback: impl Fn(Vec<ContainerInfo>) + Send + 'static,
) {
    // Do an initial scan immediately
    let containers = discover(&runtimes).await;
    callback(containers);

    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(interval_secs)) => {}
            _ = shutdown_rx.changed() => break,
        }

        if *shutdown_rx.borrow() {
            break;
        }

        let containers = discover(&runtimes).await;
        callback(containers);
    }
}
