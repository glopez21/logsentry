#!/usr/bin/env bash
# Install LogSentry Engine as a Docker container (pulls image)
#
# Configure before running:
#   ENGINE_DSN="postgresql://logsentry:logsentry@localhost:5432/logsentry"
#   LOGSENTRY_API_KEY=""     # Protect server endpoints
#   AUGUR_URL="" AUGUR_API_KEY=""
#   THREATPULSE_URL="" THREATPULSE_API_KEY=""
#
set -euo pipefail

IMAGE="ghcr.io/glopez21/logsentry:latest"

: "${ENGINE_DSN:=postgresql://logsentry:logsentry@localhost:5432/logsentry}"
: "${LOGSENTRY_API_KEY:=}"
: "${AUGUR_URL:=}"
: "${AUGUR_API_KEY:=}"
: "${THREATPULSE_URL:=}"
: "${THREATPULSE_API_KEY:=}"

echo "[+] Fetching docker installer..."
curl -sL https://raw.githubusercontent.com/glopez21/logsentry/main/deploy/install-docker.sh -o /tmp/logsentry-install-docker.sh
chmod +x /tmp/logsentry-install-docker.sh

echo "[+] Running docker installer..."
sudo /tmp/logsentry-install-docker.sh \
  --image "$IMAGE" \
  --api-key "$LOGSENTRY_API_KEY" \
  --db-dsn "$ENGINE_DSN" \
  ${AUGUR_URL:+--augur-url "$AUGUR_URL"} ${AUGUR_API_KEY:+--augur-api-key "$AUGUR_API_KEY"} \
  ${THREATPULSE_URL:+--threatpulse-url "$THREATPULSE_URL"} ${THREATPULSE_API_KEY:+--threatpulse-api-key "$THREATPULSE_API_KEY"}

echo "[+] Container started (ports: 514/udp, 514/tcp, 8080). Test: curl http://<host>:8080/health"
