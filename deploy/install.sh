#!/usr/bin/env bash
# LogSentry Installer — deploys engine + systemd unit
# Works with any git host: GitHub, Forgejo, GitLab, Gitea, self-hosted, etc.
#
# Usage:
#   sudo bash install.sh
#   sudo bash install.sh --repo https://forgejo.example.com/w01f/logsentry.git
#   sudo bash install.sh --repo https://forgejo.example.com/w01f/logsentry.git --branch dev
#   sudo bash install.sh --augur-url http://10.0.0.5:5173 --threatpulse-url http://10.0.0.6:8080
#
# One-liner (pipe to bash from any host):
#   curl -sL https://raw.githubusercontent.com/w01f/logsentry/main/deploy/install.sh | sudo bash -s -- --repo https://YOUR_HOST/w01f/logsentry.git
set -euo pipefail

INSTALL_DIR="/opt/logsentry"
CONFIG_DIR="/etc/logsentry"
SERVICE_NAME="logsentry"
REPO_URL="https://github.com/glopez21/logsentry"
BRANCH=""

# -- Colors -------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${RED}[!]${NC} $1"; }
info() { echo -e "${CYAN}[*]${NC} $1"; }

# -- Parse args (before root check so --help works without sudo) ------
SKIP_DEPS=false
AUGUR_URL=""
THREATPULSE_URL=""
AUGUR_API_KEY=""
THREATPULSE_API_KEY=""
DB_DSN=""

RSYSLOG_HOST=""
RSYSLOG_PROTOCOL="udp"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-deps)        SKIP_DEPS=true; shift ;;
        --repo)             REPO_URL="$2"; shift 2 ;;
        --branch)           BRANCH="$2"; shift 2 ;;
        --augur-url)        AUGUR_URL="$2"; shift 2 ;;
        --threatpulse-url)  THREATPULSE_URL="$2"; shift 2 ;;
        --augur-api-key)    AUGUR_API_KEY="$2"; shift 2 ;;
        --threatpulse-api-key) THREATPULSE_API_KEY="$2"; shift 2 ;;
        --db-dsn)           DB_DSN="$2"; shift 2 ;;
        --rsyslog-host)     RSYSLOG_HOST="$2"; shift 2 ;;
        --rsyslog-protocol) RSYSLOG_PROTOCOL="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: sudo bash install.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --repo URL              Git repository URL (default: GitHub)"
            echo "  --branch NAME           Git branch to checkout (default: main)"
            echo "  --augur-url URL         Augur hub URL (e.g. http://10.0.0.5:5173)"
            echo "  --threatpulse-url URL   ThreatPulse URL (e.g. http://10.0.0.6:8080)"
            echo "  --augur-api-key KEY     Augur API key (if required)"
            echo "  --threatpulse-api-key KEY  ThreatPulse API key (if required)"
            echo "  --db-dsn DSN            PostgreSQL connection string"
            echo "  --rsyslog-host HOST     Configure rsyslog forwarder to HOST (engine host)"
            echo "  --rsyslog-protocol udp|tcp  Forward via UDP or TCP (default: udp)"
            echo "  --skip-deps             Skip system dependency installation"
            echo "  -h, --help              Show this help"
            exit 0
            ;;
        *) warn "Unknown option: $1 (use --help for usage)"; exit 1 ;;
    esac
done

# -- Root check ---------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    warn "This script must be run as root (or with sudo)"
    exit 1
fi

info "Repository: $REPO_URL"
[[ -n "$BRANCH" ]] && info "Branch: $BRANCH"
[[ -n "$AUGUR_URL" ]] && info "Augur: $AUGUR_URL"
[[ -n "$THREATPULSE_URL" ]] && info "ThreatPulse: $THREATPULSE_URL"

# -- Detect package manager ---------------------------------------------
install_pkg() {
    if command -v apt-get &>/dev/null; then
        apt-get update -qq
        apt-get install -y -qq "$@" 2>/dev/null || true
    elif command -v dnf &>/dev/null; then
        dnf install -y -q "$@" 2>/dev/null || true
    elif command -v yum &>/dev/null; then
        yum install -y -q "$@" 2>/dev/null || true
    elif command -v pacman &>/dev/null; then
        pacman -S --noconfirm --needed "$@" 2>/dev/null || true
    elif command -v apk &>/dev/null; then
        apk add --quiet "$@" 2>/dev/null || true
    else
        warn "No supported package manager found — install deps manually"
    fi
}

# -- Dependencies -------------------------------------------------------
if ! $SKIP_DEPS; then
    info "Installing system dependencies..."
    install_pkg python3 python3-pip python3-venv curl git
fi

# -- Create user --------------------------------------------------------
if ! id -u logsentry &>/dev/null; then
    log "Creating logsentry user..."
    useradd --system --no-create-home --shell /usr/sbin/nologin logsentry
else
    info "User logsentry already exists"
fi

# -- Clone / update -----------------------------------------------------
CLONE_ARGS=()
if [[ -n "$BRANCH" ]]; then
    CLONE_ARGS+=(-b "$BRANCH")
fi

if [[ -d "$INSTALL_DIR/.git" ]]; then
    log "Updating LogSentry..."
    cd "$INSTALL_DIR"
    if [[ -n "$BRANCH" ]]; then
        git fetch origin
        git checkout "$BRANCH"
        git pull --ff-only
    else
        git pull --ff-only
    fi
else
    log "Cloning LogSentry from $REPO_URL ..."
    rm -rf "$INSTALL_DIR"
    git clone "${CLONE_ARGS[@]}" "$REPO_URL" "$INSTALL_DIR"
fi
cd "$INSTALL_DIR"

# -- Virtualenv ---------------------------------------------------------
log "Setting up Python virtualenv..."
python3 -m venv .venv
.venv/bin/pip install --quiet --upgrade pip uv
# Pin the venv to the distro interpreter so the service user (logsentry) can
# always exec it — without this, uv may swap in a managed interpreter under
# /root (unreachable for the hardened service unit).
.venv/bin/uv sync --frozen --no-dev --extra server --extra augur --python python3 2>&1 | tail -1
chown -R logsentry:logsentry .venv

# -- Config -------------------------------------------------------------
mkdir -p "$CONFIG_DIR"
if [[ ! -f "$CONFIG_DIR/logsentry.yaml" ]]; then
    log "Creating default config at $CONFIG_DIR/logsentry.yaml"
    cp logsentry.yaml "$CONFIG_DIR/logsentry.yaml"
    chmod 640 "$CONFIG_DIR/logsentry.yaml"
    chown logsentry:logsentry "$CONFIG_DIR/logsentry.yaml"
else
    info "Config already exists at $CONFIG_DIR/logsentry.yaml (skipping)"
fi

# -- Optional: configure rsyslog forwarder -------------------------------
if [[ -n "$RSYSLOG_HOST" ]]; then
    info "Configuring rsyslog to forward to $RSYSLOG_HOST via $RSYSLOG_PROTOCOL..."
    if command -v rsyslogd &>/dev/null || [[ -d /etc/rsyslog.d ]]; then
        mkdir -p /etc/rsyslog.d
        TEMPLATE_FILE="deploy/rsyslog-forward-udp.conf"
        if [[ -f "$TEMPLATE_FILE" ]]; then
            sed "s/LOGSENTRY_HOST/$RSYSLOG_HOST/g" "$TEMPLATE_FILE" > /etc/rsyslog.d/90-logsentry.conf
            if [[ "$RSYSLOG_PROTOCOL" == "tcp" ]]; then
                sed -i 's/*\.\* @.*/&\n# TCP mode enabled by installer/' /etc/rsyslog.d/90-logsentry.conf || true
                sed -i 's/@'"$RSYSLOG_HOST"':514/@@'"$RSYSLOG_HOST"':514/g' /etc/rsyslog.d/90-logsentry.conf || true
            fi
            systemctl restart rsyslog 2>/dev/null || service rsyslog restart 2>/dev/null || true
            log "rsyslog forwarder installed: /etc/rsyslog.d/90-logsentry.conf"
        else
            warn "Template $TEMPLATE_FILE not found (skipping rsyslog config)"
        fi
    else
        warn "rsyslog not present on this system (skipping forwarder setup)"
    fi
fi

# -- Endpoints ----------------------------------------------------------
if [[ ! -f "$CONFIG_DIR/endpoints.env" ]]; then
    log "Creating endpoint config at $CONFIG_DIR/endpoints.env"
    cat > "$CONFIG_DIR/endpoints.env" <<ENV
# Augur SOC Hub (telemetry + alert ingestion)
AUGUR_URL=${AUGUR_URL:-http://augur:5173}
AUGUR_API_KEY=${AUGUR_API_KEY:-}

# ThreatPulse platform (detection events + metrics)
THREATPULSE_URL=${THREATPULSE_URL:-http://threatpulse:8080}
THREATPULSE_API_KEY=${THREATPULSE_API_KEY:-}

# Postgres (shared by all hosts)
LOGSENTRY_DSN=${DB_DSN:-postgresql://logsentry:logsentry@localhost:5432/logsentry}
ENV
    chmod 640 "$CONFIG_DIR/endpoints.env"
    chown logsentry:logsentry "$CONFIG_DIR/endpoints.env"
else
    info "Endpoint config already exists at $CONFIG_DIR/endpoints.env (skipping)"
fi

# -- Systemd unit -------------------------------------------------------
log "Installing systemd unit..."
cp deploy/logsentry.service /etc/systemd/system/$SERVICE_NAME.service
chmod 644 /etc/systemd/system/$SERVICE_NAME.service
systemctl daemon-reload
systemctl enable $SERVICE_NAME

# -- Permissions --------------------------------------------------------
chown -R logsentry:logsentry "$INSTALL_DIR"

# -- Done ---------------------------------------------------------------
log "Installation complete!"
echo ""
echo "  Repository:  $REPO_URL"
echo "  Install dir: $INSTALL_DIR"
echo "  Config dir:  $CONFIG_DIR"
echo ""
echo "  Next steps:"
echo "    1. Edit $CONFIG_DIR/endpoints.env (Augur/ThreatPulse URLs for this host)"
if [[ -n "$AUGUR_URL" && -n "$THREATPULSE_URL" ]]; then
    echo "       (Already set via --augur-url and --threatpulse-url)"
fi
echo "    2. Initialize the database (once):"
echo "       sudo $INSTALL_DIR/.venv/bin/python main.py daemon --init-db"
echo "    3. Start the service:"
echo "       sudo systemctl start logsentry"
echo "       sudo systemctl status logsentry"
echo ""
echo "  See logs: journalctl -u logsentry -f"
