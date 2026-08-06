#!/usr/bin/env bash
# LogSentry Docker Installer — runs the engine in a container with ports and config
#
# Usage:
#   sudo bash install-docker.sh \
#     --image ghcr.io/glopez21/logsentry:latest \
#     --api-key <API_KEY> \
#     --db-dsn postgresql://logsentry:logsentry@localhost:5432/logsentry \
#     [--augur-url http://augur:8001 --augur-api-key ...] \
#     [--threatpulse-url http://threatpulse:8080 --threatpulse-api-key ...]

set -euo pipefail

IMAGE="ghcr.io/glopez21/logsentry:latest"
MODE="daemon" # or serve for no-DB API demo
API_KEY=""
DB_DSN="postgresql://logsentry:logsentry@localhost:5432/logsentry"
AUGUR_URL=""
AUGUR_API_KEY=""
THREATPULSE_URL=""
THREATPULSE_API_KEY=""
CONFIG_DIR="/etc/logsentry"
CONTAINER_NAME="logsentry"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --image) IMAGE="$2"; shift 2 ;;
    --api-key) API_KEY="$2"; shift 2 ;;
    --db-dsn) DB_DSN="$2"; shift 2 ;;
    --augur-url) AUGUR_URL="$2"; shift 2 ;;
    --augur-api-key) AUGUR_API_KEY="$2"; shift 2 ;;
    --threatpulse-url) THREATPULSE_URL="$2"; shift 2 ;;
    --threatpulse-api-key) THREATPULSE_API_KEY="$2"; shift 2 ;;
    --name) CONTAINER_NAME="$2"; shift 2 ;;
    --mode) MODE="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: $0 [--image IMG] [--api-key KEY] [--db-dsn DSN] [--augur-url URL --augur-api-key KEY] [--threatpulse-url URL --threatpulse-api-key KEY] [--name NAME] [--mode daemon|serve]"; exit 0 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

if ! command -v docker &>/dev/null; then
  echo "[!] Docker is required" >&2
  exit 1
fi

mkdir -p "$CONFIG_DIR"

CONFIG_FILE="$CONFIG_DIR/logsentry.yaml"
if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "[+] Writing default config to $CONFIG_FILE"
  cat > "$CONFIG_FILE" <<YAML
engine:
  mode: daemon
  log_level: info
  detection_interval: 30
  stats_interval: 60
storage:
  dsn: ${DB_DSN}
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
    stdout:
      enabled: true
      format: json
server:
  host: 0.0.0.0
  port: 8080
  api_key: ${API_KEY}
YAML
  chmod 640 "$CONFIG_FILE"
fi

echo "[*] Pulling image: $IMAGE"
docker pull "$IMAGE" >/dev/null || true

echo "[*] Starting container: $CONTAINER_NAME"
docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER_NAME" \
  --restart unless-stopped \
  -p 514:514/udp -p 514:514/tcp -p 8080:8080 \
  -v "$CONFIG_FILE":/etc/logsentry/logsentry.yaml:ro \
  -e LOGSENTRY_DSN="$DB_DSN" \
  -e LOGSENTRY_MODE=daemon \
  -e LOGSENTRY_API_KEY="$API_KEY" \
  -e AUGUR_URL="$AUGUR_URL" -e AUGUR_API_KEY="$AUGUR_API_KEY" \
  -e THREATPULSE_URL="$THREATPULSE_URL" -e THREATPULSE_API_KEY="$THREATPULSE_API_KEY" \
  "$IMAGE" $MODE

echo "[+] Logsentry container started. API: http://<host>:8080 (x-api-key if set)"
echo "    Syslog UDP/TCP: 514"
