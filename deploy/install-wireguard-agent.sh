#!/usr/bin/env bash
# WireGuard Agent Installer — connects a sentryd host to the WireGuard hub
set -euo pipefail

WG_INTERFACE="wg-sentry"
CONFIG_DIR="/etc/wireguard"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${RED}[!]${NC} $1"; }
info() { echo -e "${CYAN}[*]${NC} $1"; }

if [[ $EUID -ne 0 ]]; then
    warn "Must be run as root"
    exit 1
fi

# ── Parse args ──────────────────────────────────────────────────
HUB_ENDPOINT=""
HUB_PUBKEY=""
AGENT_IP=""
OVERLAY_SUBNET="10.200.0.0/24"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --hub-endpoint) HUB_ENDPOINT="$2"; shift 2 ;;
        --hub-pubkey) HUB_PUBKEY="$2"; shift 2 ;;
        --agent-ip) AGENT_IP="$2"; shift 2 ;;
        --subnet) OVERLAY_SUBNET="$2"; shift 2 ;;
        *) warn "Unknown: $1"; exit 1 ;;
    esac
done

if [[ -z "$HUB_ENDPOINT" || -z "$HUB_PUBKEY" || -z "$AGENT_IP" ]]; then
    warn "Missing required args: --hub-endpoint, --hub-pubkey, --agent-ip"
    echo "Usage: $0 --hub-endpoint <ip:port> --hub-pubkey <key> --agent-ip <overlay_ip> [--subnet <subnet>]"
    exit 1
fi

info "WireGuard agent setup"
info "  Hub endpoint: $HUB_ENDPOINT"
info "  Agent IP:     $AGENT_IP"
info "  Overlay:      $OVERLAY_SUBNET"

# ── Install WireGuard ───────────────────────────────────────────
if ! command -v wg &>/dev/null; then
    log "Installing WireGuard..."
    apt-get update -qq
    apt-get install -y -qq wireguard resolvconf
fi

# ── Generate agent keypair ─────────────────────────────────────
mkdir -p "$CONFIG_DIR"
if [[ ! -f "$CONFIG_DIR/${WG_INTERFACE}.key" ]]; then
    log "Generating agent WireGuard keypair..."
    wg genkey | tee "$CONFIG_DIR/${WG_INTERFACE}.key" | wg pubkey > "$CONFIG_DIR/${WG_INTERFACE}.pub"
    chmod 600 "$CONFIG_DIR/${WG_INTERFACE}.key"
fi

AGENT_PRIVATE_KEY=$(cat "$CONFIG_DIR/${WG_INTERFACE}.key")
AGENT_PUBLIC_KEY=$(cat "$CONFIG_DIR/${WG_INTERFACE}.pub")
log "Agent public key: $AGENT_PUBLIC_KEY"

# ── Generate config ────────────────────────────────────────────
log "Generating agent WireGuard config..."
cat > "$CONFIG_DIR/${WG_INTERFACE}.conf" <<CONFIG
[Interface]
Address = ${AGENT_IP}/24
PrivateKey = ${AGENT_PRIVATE_KEY}
MTU = 1420

[Peer]
PublicKey = ${HUB_PUBKEY}
Endpoint = ${HUB_ENDPOINT}
AllowedIPs = ${OVERLAY_SUBNET}
PersistentKeepalive = 25
CONFIG

chmod 600 "$CONFIG_DIR/${WG_INTERFACE}.conf"

# ── Enable and start ────────────────────────────────────────────
log "Enabling and starting WireGuard..."
systemctl enable wg-quick@${WG_INTERFACE}
systemctl restart wg-quick@${WG_INTERFACE}

# ── Verify ─────────────────────────────────────────────────────
sleep 2
if wg show ${WG_INTERFACE} 2>/dev/null | grep -q "latest handshake"; then
    log "WireGuard handshake established!"
else
    warn "No handshake yet — check hub endpoint and firewall"
    info "Ensure UDP port is open and hub has your public key registered"
fi

# ── Output for hub registration ─────────────────────────────────
echo ""
echo "=== Give this to the hub admin ==="
echo "Agent name:   $(hostname)"
echo "Public key:   $AGENT_PUBLIC_KEY"
echo "Overlay IP:   $AGENT_IP"
echo "Run on hub:   sentry-wg-add-agent $(hostname) $AGENT_PUBLIC_KEY $AGENT_IP"
echo ""

# ── Update sentryd config for mesh overlay ────────────────────
SENTRYD_CONFIG="/etc/sentryd/sentryd.mesh.yaml"
if [[ -f "$SENTRYD_CONFIG" ]]; then
    log "Updating sentryd hub URL to use WireGuard overlay..."
    HUB_GATEWAY="${AGENT_IP%.*}.1"
    sed -i "s|url:.*|url: \"http://${HUB_GATEWAY}:8000\"|" "$SENTRYD_CONFIG"
    log "sentryd hub URL set to http://${HUB_GATEWAY}:8000"
fi

log "WireGuard agent setup complete!"
echo ""
echo "  Interface: ${WG_INTERFACE}"
echo "  Agent overlay IP: ${AGENT_IP}"
echo "  Hub overlay IP:   ${AGENT_IP%.*}.1"
echo "  Hub endpoint:     ${HUB_ENDPOINT}"
