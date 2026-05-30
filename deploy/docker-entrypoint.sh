#!/usr/bin/env bash
# LogSentry Docker entrypoint
set -euo pipefail

# If config not mounted, generate one with defaults
CONFIG=${LOGSENTRY_CONFIG:-/etc/logsentry/logsentry.yaml}
if [[ ! -f "$CONFIG" ]]; then
    cat > "$CONFIG" <<'YAML'
engine:
  mode: daemon
  log_level: info
  detection_interval: 30
  stats_interval: 60
storage:
  dsn: ${LOGSENTRY_DSN:-postgresql://logsentry:logsentry@postgres:5432/logsentry}
  pool_min: 2
  pool_max: 10
  retention_days: 90
  batch_size: 500
  flush_interval: 5
ingest:
  syslog:
    enabled: true
    bind: 0.0.0.0
    port: 514
    protocol: udp
  http:
    enabled: true
  file_watchers:
    enabled: false
    paths: []
detection:
  enabled: true
  alerts:
    stdout: true
server:
  host: 0.0.0.0
  port: 8080
YAML
fi

# Run command
exec python /app/main.py "$@"
