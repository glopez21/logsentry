#!/usr/bin/env bash
# Configure rsyslog on this host to forward logs to a LogSentry Engine
#
# Configure before running:
#   LOGSENTRY_HOST="engine.example.com"  # Required
#   LOGSENTRY_PROTOCOL="udp"             # udp|tcp
#
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "[!] Run as root (sudo)." >&2
  exit 1
fi

: "${LOGSENTRY_HOST:=}"
: "${LOGSENTRY_PROTOCOL:=udp}"

if [[ -z "$LOGSENTRY_HOST" ]]; then
  echo "[!] Set LOGSENTRY_HOST to the engine host or IP" >&2
  exit 1
fi

if ! command -v rsyslogd &>/dev/null && [[ ! -d /etc/rsyslog.d ]]; then
  echo "[+] Installing rsyslog..."
  if command -v apt-get &>/dev/null; then apt-get update -qq && apt-get install -y -qq rsyslog; fi
  if command -v yum &>/dev/null; then yum install -y -q rsyslog; fi
  if command -v dnf &>/dev/null; then dnf install -y -q rsyslog; fi
  if command -v apk &>/dev/null; then apk add --quiet rsyslog; fi
fi

mkdir -p /etc/rsyslog.d
echo "[+] Writing /etc/rsyslog.d/90-logsentry.conf"
cat > /etc/rsyslog.d/90-logsentry.conf <<CONF
# LogSentry forwarder
module(load="imuxsock")
module(load="imklog")
module(load="omfwd")

$ActionQueueType LinkedList
$ActionQueueFileName logsentry
$ActionQueueSaveOnShutdown on
$ActionResumeRetryCount -1

*.* @${LOGSENTRY_HOST}:514;RSYSLOG_SyslogProtocol23Format

local0.* /var/log/logsentry-agent.log
CONF

if [[ "$LOGSENTRY_PROTOCOL" == "tcp" ]]; then
  sed -i 's/@'"$LOGSENTRY_HOST"':514/@@'"$LOGSENTRY_HOST"':514/g' /etc/rsyslog.d/90-logsentry.conf || true
fi

systemctl restart rsyslog 2>/dev/null || service rsyslog restart 2>/dev/null || true
echo "[+] rsyslog forwarding enabled to $LOGSENTRY_HOST:514/$LOGSENTRY_PROTOCOL"
