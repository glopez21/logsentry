#!/usr/bin/env bash
# LogSentry Installer — deploys engine + systemd unit
set -euo pipefail

INSTALL_DIR="/opt/logsentry"
CONFIG_DIR="/etc/logsentry"
SERVICE_NAME="logsentry"
REPO_URL="https://github.com/w01f/logsentry"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${RED}[!]${NC} $1"; }
info() { echo -e "${CYAN}[*]${NC} $1"; }

# -- Root check -------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    warn "This script must be run as root (or with sudo)"
    exit 1
fi

# -- Parse args -------------------------------------------------------
SKIP_DEPS=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-deps) SKIP_DEPS=true ;;
        *) warn "Unknown option: $1"; exit 1 ;;
    esac
    shift
done

# -- Dependencies -----------------------------------------------------
if ! $SKIP_DEPS; then
    info "Installing system dependencies..."
    apt-get update -qq
    apt-get install -y -qq \
        python3 python3-pip python3-venv \
        curl git 2>/dev/null || true
fi

# -- Create user ------------------------------------------------------
if ! id -u logsentry &>/dev/null; then
    log "Creating logsentry user..."
    useradd --system --no-create-home --shell /usr/sbin/nologin logsentry
else
    info "User logsentry already exists"
fi

# -- Clone / update ---------------------------------------------------
if [[ -d "$INSTALL_DIR/.git" ]]; then
    log "Updating LogSentry..."
    cd "$INSTALL_DIR"
    git pull --ff-only
else
    log "Cloning LogSentry..."
    rm -rf "$INSTALL_DIR"
    git clone "$REPO_URL" "$INSTALL_DIR"
fi
cd "$INSTALL_DIR"

# -- Virtualenv -------------------------------------------------------
log "Setting up Python virtualenv..."
python3 -m venv .venv
.venv/bin/pip install --quiet --upgrade pip uv
.venv/bin/uv sync --frozen --no-dev --extra server 2>&1 | tail -1

# -- Config -----------------------------------------------------------
mkdir -p "$CONFIG_DIR"
if [[ ! -f "$CONFIG_DIR/logsentry.yaml" ]]; then
    log "Creating default config at $CONFIG_DIR/logsentry.yaml"
    cp logsentry.yaml "$CONFIG_DIR/logsentry.yaml"
    chmod 640 "$CONFIG_DIR/logsentry.yaml"
    chown logsentry:logsentry "$CONFIG_DIR/logsentry.yaml"
else
    info "Config already exists at $CONFIG_DIR/logsentry.yaml (skipping)"
fi

# -- Systemd unit -----------------------------------------------------
log "Installing systemd unit..."
cp deploy/logsentry.service /etc/systemd/system/$SERVICE_NAME.service
chmod 644 /etc/systemd/system/$SERVICE_NAME.service
systemctl daemon-reload
systemctl enable $SERVICE_NAME

# -- Permissions ------------------------------------------------------
chown -R logsentry:logsentry "$INSTALL_DIR"

# -- Done -------------------------------------------------------------
log "Installation complete!"
echo ""
echo "  Next steps:"
echo "    1. Edit $CONFIG_DIR/logsentry.yaml with your Postgres DSN"
echo "    2. Initialize the database:"
echo "       $INSTALL_DIR/.venv/bin/python main.py daemon --init-db"
echo "    3. Start the service:"
echo "       sudo systemctl start logsentry"
echo "       sudo systemctl status logsentry"
echo ""
echo "  See logs: journalctl -u logsentry -f"
