#!/usr/bin/env bash
# sentryd Mesh Agent Installer — installs sentryd + w3bv01d sidecar
set -euo pipefail

INSTALL_DIR="/opt/sentryd"
CONFIG_DIR="/etc/sentryd"
SENTRYD_REPO="https://github.com/w01f/logsentry"
W3BV01D_REPO="https://github.com/w01f/w3bv01d"

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
COORDINATOR="ws://coordinator.mesh:8765"
HUB_PEER_ID="augur-hub"
HUB_PORT=8000
RELAY=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --coordinator) COORDINATOR="$2"; shift 2 ;;
        --hub-peer-id) HUB_PEER_ID="$2"; shift 2 ;;
        --hub-port) HUB_PORT="$2"; shift 2 ;;
        --relay) RELAY="$2"; shift 2 ;;
        *) warn "Unknown: $1"; exit 1 ;;
    esac
done

info "Coordinator: $COORDINATOR"
info "Hub peer ID: $HUB_PEER_ID"
info "Hub port:    $HUB_PORT"

# ── Dependencies ────────────────────────────────────────────────
log "Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq \
    python3 python3-pip python3-venv \
    cargo rustc pkg-config libsqlite3-dev \
    iproute2 iptables net-tools curl git

# ── Install Rust (if needed) ────────────────────────────────────
if ! command -v cargo &>/dev/null; then
    log "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

# ── Clone / update sentryd ─────────────────────────────────────
if [[ -d "$INSTALL_DIR/.git" ]]; then
    log "Updating sentryd..."
    cd "$INSTALL_DIR"
    git pull --ff-only
else
    log "Cloning sentryd..."
    rm -rf "$INSTALL_DIR"
    git clone "$SENTRYD_REPO" "$INSTALL_DIR"
fi

# ── Build sentryd (Rust) ───────────────────────────────────────
log "Building sentryd (Rust) — this may take a few minutes..."
cd "$INSTALL_DIR/sentryd"
cargo build --release --bin sentryd
cp target/release/sentryd /usr/local/bin/sentryd
log "sentryd binary installed to /usr/local/bin/sentryd"

# ── Python virtualenv for mesh-discover ─────────────────────────
log "Setting up Python virtualenv for mesh tooling..."
python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/.venv/bin/pip" install --quiet websockets pynacl pyyaml

# ── Config ──────────────────────────────────────────────────────
mkdir -p "$CONFIG_DIR"
if [[ ! -f "$CONFIG_DIR/sentryd.mesh.yaml" ]]; then
    log "Creating mesh config at $CONFIG_DIR/sentryd.mesh.yaml"
    cp "$INSTALL_DIR/sentryd/config/sentryd.mesh.yaml" "$CONFIG_DIR/sentryd.mesh.yaml"
    chmod 640 "$CONFIG_DIR/sentryd.mesh.yaml"
fi

# ── Systemd: w3bv01d service ────────────────────────────────────
log "Installing w3bv01d service..."

if [[ ! -d /opt/w3bv01d ]]; then
    git clone "$W3BV01D_REPO" /opt/w3bv01d
    python3 -m venv /opt/w3bv01d/.venv
    /opt/w3bv01d/.venv/bin/pip install --quiet websockets pynacl textual
fi

cat > /etc/systemd/system/w3bv01d.service <<UNIT
[Unit]
Description=w3bv01d mesh VPN peer
Documentation=https://github.com/w01f/w3bv01d
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/w3bv01d
ExecStart=/opt/w3bv01d/.venv/bin/python3 -m peer.node \\
    --coordinator ${COORDINATOR} \\
    --tun \\
    ${RELAY:+--relay ${RELAY}}
Restart=on-failure
RestartSec=5
CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN
AmbientCapabilities=CAP_NET_ADMIN CAP_SYS_ADMIN
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT

# ── Systemd: sentryd-mesh service ───────────────────────────────
log "Installing sentryd-mesh service..."

cat > /etc/systemd/system/sentryd-mesh.service <<UNIT
[Unit]
Description=sentryd mesh SOC agent
Documentation=https://github.com/w01f/logsentry
After=network-online.target w3bv01d.service
Wants=network-online.target w3bv01d.service

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/.venv/bin/python3 ${INSTALL_DIR}/scripts/mesh-discover.py \\
    --coordinator ${COORDINATOR} \\
    ${RELAY:+--relay ${RELAY}} \\
    --hub-peer-id ${HUB_PEER_ID} \\
    --hub-port ${HUB_PORT} \\
    /usr/local/bin/sentryd daemon
Environment=SENTRYD_CONFIG=${CONFIG_DIR}/sentryd.mesh.yaml
Environment=MESH_COORDINATOR=${COORDINATOR}
Environment=MESH_HUB_PEER_ID=${HUB_PEER_ID}
Restart=on-failure
RestartSec=5
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_SYS_ADMIN
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_SYS_ADMIN
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable w3bv01d.service
systemctl enable sentryd-mesh.service

# ── Done ─────────────────────────────────────────────────────────
log "Installation complete!"
echo ""
echo "  Next steps:"
echo "    1. Verify config at $CONFIG_DIR/sentryd.mesh.yaml"
echo "    2. Edit the hub peer ID if needed:"
echo "       sudo sed -i 's/HUB_PEER_ID=.*/HUB_PEER_ID=your-hub-id/' /etc/systemd/system/sentryd-mesh.service"
echo "    3. Start services:"
echo "       sudo systemctl start w3bv01d"
echo "       sudo systemctl start sentryd-mesh"
echo "    4. Check status:"
echo "       sudo systemctl status w3bv01d"
echo "       sudo systemctl status sentryd-mesh"
echo "       journalctl -u sentryd-mesh -f"
echo ""
echo "  Coordinator: ${COORDINATOR}"
echo "  Hub peer:    ${HUB_PEER_ID}:${HUB_PORT}"
