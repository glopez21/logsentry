#!/usr/bin/env bash
# WireGuard Hub Installer — sets up the central WireGuard VPN hub
# for sentryd agents to connect through.
set -euo pipefail

HUB_DIR="/etc/wireguard"
WG_INTERFACE="wg-sentry"

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
WG_PORT="${WG_PORT:-51820}"
OVERLAY_SUBNET="${OVERLAY_SUBNET:-10.200.0.0/24}"
OVERLAY_GATEWAY="${OVERLAY_GATEWAY:-10.200.0.1}"
WAN_INTERFACE="${WAN_INTERFACE:-eth0}"
HOSTNAME="${HOSTNAME:-wg-hub}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --port) WG_PORT="$2"; shift 2 ;;
        --subnet) OVERLAY_SUBNET="$2"; shift 2 ;;
        --gateway) OVERLAY_GATEWAY="$2"; shift 2 ;;
        --wan) WAN_INTERFACE="$2"; shift 2 ;;
        *) warn "Unknown: $1"; exit 1 ;;
    esac
done

info "WireGuard hub setup"
info "  Port:     $WG_PORT"
info "  Subnet:   $OVERLAY_SUBNET"
info "  Gateway:  $OVERLAY_GATEWAY"
info "  WAN iface: $WAN_INTERFACE"

# ── Install WireGuard ───────────────────────────────────────────
if ! command -v wg &>/dev/null; then
    log "Installing WireGuard..."
    apt-get update -qq
    apt-get install -y -qq wireguard resolvconf
fi

# ── Generate hub keypair ──────────────────────────────────────
mkdir -p "$HUB_DIR"
if [[ ! -f "$HUB_DIR/${WG_INTERFACE}.key" ]]; then
    log "Generating hub WireGuard keypair..."
    wg genkey | tee "$HUB_DIR/${WG_INTERFACE}.key" | wg pubkey > "$HUB_DIR/${WG_INTERFACE}.pub"
    chmod 600 "$HUB_DIR/${WG_INTERFACE}.key"
fi

HUB_PRIVATE_KEY=$(cat "$HUB_DIR/${WG_INTERFACE}.key")
HUB_PUBLIC_KEY=$(cat "$HUB_DIR/${WG_INTERFACE}.pub")
log "Hub public key: $HUB_PUBLIC_KEY"

# ── Generate config ────────────────────────────────────────────
log "Generating hub config..."
cat > "$HUB_DIR/${WG_INTERFACE}.conf" <<CONFIG
[Interface]
Address = ${OVERLAY_GATEWAY}/24
ListenPort = ${WG_PORT}
PrivateKey = ${HUB_PRIVATE_KEY}

PostUp = sysctl -w net.ipv4.ip_forward=1
PostUp = iptables -A FORWARD -i ${WG_INTERFACE} -j ACCEPT
PostUp = iptables -A FORWARD -o ${WG_INTERFACE} -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${WAN_INTERFACE} -j MASQUERADE
PostDown = iptables -D FORWARD -i ${WG_INTERFACE} -j ACCEPT 2>/dev/null || true
PostDown = iptables -D FORWARD -o ${WG_INTERFACE} -j ACCEPT 2>/dev/null || true
PostDown = iptables -t nat -D POSTROUTING -o ${WAN_INTERFACE} -j MASQUERADE 2>/dev/null || true

# ── Agents ──────────────────────────────────────────────────
# Add each agent as a [Peer] section below:
# [Peer]
# PublicKey = <agent_public_key>
# AllowedIPs = 10.200.0.10/32
# PersistentKeepalive = 25
CONFIG

chmod 600 "$HUB_DIR/${WG_INTERFACE}.conf"

# ── Enable IP forwarding ────────────────────────────────────────
sysctl -w net.ipv4.ip_forward=1 > /dev/null
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-wireguard.conf

# ── Create add-agent script ────────────────────────────────────
cat > /usr/local/bin/sentry-wg-add-agent <<SCRIPT
#!/usr/bin/env bash
# Usage: sentry-wg-add-agent <agent_name> <agent_public_key> <overlay_ip>
set -euo pipefail
if [[ \$# -ne 3 ]]; then
    echo "Usage: \$0 <agent_name> <agent_public_key> <overlay_ip>"
    exit 1
fi
NAME="\$1"
PK="\$2"
IP="\$3"
CONF="${HUB_DIR}/${WG_INTERFACE}.conf"
cat >> "\$CONF" <<EOF

# \$NAME
[Peer]
PublicKey = \$PK
AllowedIPs = \$IP/32
PersistentKeepalive = 25
EOF
wg addconf ${WG_INTERFACE} <(wg-quick strip ${WG_INTERFACE}) 2>/dev/null || true
systemctl restart wg-quick@${WG_INTERFACE}
echo "Agent \$NAME (\$PK) added with IP \$IP"
SCRIPT
chmod +x /usr/local/bin/sentry-wg-add-agent

# ── Enable and start ────────────────────────────────────────────
log "Enabling and starting WireGuard..."
systemctl enable wg-quick@${WG_INTERFACE}
systemctl restart wg-quick@${WG_INTERFACE}

# ── Done ────────────────────────────────────────────────────────
log "WireGuard hub setup complete!"
echo ""
echo "  Interface: ${WG_INTERFACE}"
echo "  Hub overlay IP: ${OVERLAY_GATEWAY}"
echo "  Hub public key: ${HUB_PUBLIC_KEY}"
echo ""
echo "  To add an agent:"
echo "    sentry-wg-add-agent my-agent <agent_pubkey> 10.200.0.10"
echo ""
echo "  Agent will connect to this hub at:"
echo "    Endpoint = $(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}'):${WG_PORT}"
