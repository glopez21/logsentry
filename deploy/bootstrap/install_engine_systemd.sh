#!/usr/bin/env bash
# Install LogSentry Engine on a VM/VPS using systemd (pulls from repo)
#
# Configure before running:
#   ENGINE_DSN="postgresql://logsentry:logsentry@localhost:5432/logsentry"
#   AUGUR_URL=""            # e.g. http://augur:8001
#   AUGUR_API_KEY=""
#   THREATPULSE_URL=""      # e.g. http://threatpulse:8080
#   THREATPULSE_API_KEY=""
#   RSYSLOG_HOST=""         # e.g. engine public DNS (optional self-forward)
#   RSYSLOG_PROTOCOL="udp"  # udp|tcp
#
set -euo pipefail

REPO_URL="https://github.com/glopez21/logsentry"
BRANCH=""

: "${ENGINE_DSN:=postgresql://logsentry:logsentry@localhost:5432/logsentry}"
: "${AUGUR_URL:=}"
: "${AUGUR_API_KEY:=}"
: "${THREATPULSE_URL:=}"
: "${THREATPULSE_API_KEY:=}"
: "${RSYSLOG_HOST:=}"
: "${RSYSLOG_PROTOCOL:=udp}"

echo "[+] Fetching installer..."
curl -sL https://raw.githubusercontent.com/glopez21/logsentry/main/deploy/install.sh -o /tmp/logsentry-install.sh
chmod +x /tmp/logsentry-install.sh

echo "[+] Running installer..."
sudo /tmp/logsentry-install.sh \
  --repo "$REPO_URL" ${BRANCH:+--branch "$BRANCH"} \
  --db-dsn "$ENGINE_DSN" \
  ${AUGUR_URL:+--augur-url "$AUGUR_URL"} ${AUGUR_API_KEY:+--augur-api-key "$AUGUR_API_KEY"} \
  ${THREATPULSE_URL:+--threatpulse-url "$THREATPULSE_URL"} ${THREATPULSE_API_KEY:+--threatpulse-api-key "$THREATPULSE_API_KEY"} \
  ${RSYSLOG_HOST:+--rsyslog-host "$RSYSLOG_HOST"} --rsyslog-protocol "$RSYSLOG_PROTOCOL"

echo "[+] Start the service: sudo systemctl start logsentry && sudo systemctl status logsentry"
