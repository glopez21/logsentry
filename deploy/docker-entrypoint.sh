#!/usr/bin/env bash
# LogSentry Docker entrypoint
set -euo pipefail

# If config not mounted, generate one with defaults
CONFIG=${LOGSENTRY_CONFIG:-/etc/logsentry/logsentry.yaml}
if [[ ! -f "$CONFIG" ]]; then
    mkdir -p "$(dirname "$CONFIG")"
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
  api_key: ${LOGSENTRY_API_KEY:-}
augur:
  enabled: ${AUGUR_URL:+true}
  hub_url: ${AUGUR_URL:-}
  agent_name: ${AUGUR_AGENT_NAME:-logsentry}
  agent_type: ${AUGUR_AGENT_TYPE:-logsentry}
  api_key: ${AUGUR_API_KEY:-}
  heartbeat_interval: ${AUGUR_HEARTBEAT_INTERVAL:-30}
threatpulse:
  enabled: ${THREATPULSE_URL:+true}
  api_url: ${THREATPULSE_URL:-}
  api_key: ${THREATPULSE_API_KEY:-}
  timeout: ${THREATPULSE_TIMEOUT:-5.0}
YAML
fi

# Run command (prefer project venv created by `uv sync`)
# Prefer project venv if present (created by `uv sync` at build time)
PY_BIN=/app/.venv/bin/python
if [ -x "$PY_BIN" ]; then
  exec "$PY_BIN" /app/main.py "$@"
fi

# Fallback to uv run if available (will resolve environment on the fly)
if command -v uv >/dev/null 2>&1; then
  exec uv run /app/main.py "$@"
fi

# Last resort: system python
exec python /app/main.py "$@"
