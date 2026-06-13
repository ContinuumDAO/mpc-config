#!/usr/bin/env bash
# One-shot MPC node install for Ubuntu/Debian VPS (run as root on the target server).
#
# Typical use (paste on VPS after ssh root@VPS_IP):
#   curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/install-node-debian-ubuntu.sh" \
#     | bash -s -- --node-mgt-key "0xYour40Hex..." --ip "203.0.113.50"
#
# Or pipe from your PC over SSH:
#   curl -fsSL "…/install-node-debian-ubuntu.sh" \
#     | ssh root@203.0.113.50 bash -s -- --node-mgt-key "0x..." --ip "203.0.113.50"
#
# Tracks main on GitHub. After install, update mpc-config from the MPA Maintenance tab (git pull + updateMpcAuth).
#
set -euo pipefail

INSTALL_SCRIPT_VERSION="1.0.0"

MPC_CONFIG_REPO="${MPC_CONFIG_REPO:-https://github.com/ContinuumDAO/mpc-config.git}"
MPC_CONFIG_REF="${MPC_CONFIG_REF:-main}"
MPC_USER="${MPC_USER:-mpcnode}"
REPO_DIR="${MPC_REPO_DIR:-/home/${MPC_USER}/mpc-config}"

INSTALL_SYSTEMD=true
SKIP_PACKAGES=false
SKIP_USER=false
SKIP_CLONE=false
DRY_RUN=false
NO_START=false
PROVISION_NODE_IP=""

# Collected provision-node.sh arguments (built while parsing).
PROVISION_ARGS=()

usage() {
    cat <<'EOF'
Usage:
  curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/REF/scripts/install-node-debian-ubuntu.sh" \
    | bash -s -- [install options] [provision options]

Run as root on an Ubuntu/Debian VPS. Installs packages, creates mpcnode, clones mpc-config,
runs scripts/provision-node.sh, then docker compose up -d.

Provision options (at least one management key required):
  -k, --node-mgt-key ADDR     Ethereum NodeMgtKey (0x + 40 hex)
      --public-mgt-key KEY    Ed25519 PublicMgtKey (64 hex or ssh-ed25519 line)
  -i, --ip ADDRESS            This node's public IPv4 (strongly recommended on VPS)
  -p, --http-port PORT        nodeAddresses HTTP port (default 8081)
      --relay-host HOST       Relay placeholder (default 0.0.0.0)
      --force-browser-certs   Pass --force-browser-https-certs to process_config.sh
      --no-loopback             Disable browser loopback HTTP
      --no-firewall             Skip UFW setup in process_config.sh
      --no-agent-llm-config-path

Install options:
      --no-systemd              Do not pass --install-systemd to provision-node.sh
      --mpc-user USER           OS user (default: mpcnode)
      --repo-dir PATH           Clone path (default: /home/mpcnode/mpc-config)
      --ref REF                 Git branch (default: main; same branch Maintenance git pull uses)
      --repo-url URL            Git remote (default: ContinuumDAO/mpc-config)
      --skip-clone              Use existing repo at --repo-dir
      --skip-packages           Skip apt install (repo already has deps)
      --skip-user               Skip mpcnode user creation
      --no-start                Provision only; skip docker compose up -d
      --dry-run                 Print actions without executing
  -h, --help                    Show this help

Environment:
  MPC_CONFIG_REF, MPC_CONFIG_REPO, MPC_USER, MPC_REPO_DIR, RELAYER_API_URL

Examples:
  bash -s -- --node-mgt-key "0xabc..." --ip "203.0.113.50"
  bash -s -- --public-mgt-key "64hex..." --ip "203.0.113.50"
EOF
}

log() {
    printf '==> %s\n' "$*"
}

warn() {
    printf 'warning: %s\n' "$*" >&2
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

require_root() {
    if [ "${EUID:-0}" -ne 0 ]; then
        die "run as root on the target VPS (e.g. ssh root@VPS_IP, then paste this script)"
    fi
}

require_debian_ubuntu() {
    if ! command -v apt-get >/dev/null 2>&1; then
        die "this installer only supports Debian/Ubuntu (apt-based systems)"
    fi
    if [ ! -r /etc/os-release ]; then
        die "cannot read /etc/os-release"
    fi
    # shellcheck source=/dev/null
    . /etc/os-release
    local id="${ID:-}" id_like="${ID_LIKE:-}"
    case "$id" in
        debian | ubuntu | linuxmint) return 0 ;;
    esac
    if [[ "$id_like" == *"ubuntu"* || "$id_like" == *"debian"* ]]; then
        return 0
    fi
    die "unsupported OS: ${PRETTY_NAME:-unknown} (need Ubuntu or Debian)"
}

run_or_dry() {
    if [ "$DRY_RUN" = true ]; then
        printf '[dry-run] %s\n' "$*"
    else
        "$@"
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -k|--node-mgt-key|--public-mgt-key|-i|--ip|-p|--http-port|--relay-host)
            if [[ $# -lt 2 ]]; then
                die "option $1 requires a value"
            fi
            if [ "$1" = "-i" ] || [ "$1" = "--ip" ]; then
                PROVISION_NODE_IP="$2"
            fi
            PROVISION_ARGS+=("$1" "$2")
            shift 2
            ;;
        --force-browser-certs|--no-loopback|--no-firewall|--no-agent-llm-config-path)
            PROVISION_ARGS+=("$1")
            shift
            ;;
        --no-systemd)
            INSTALL_SYSTEMD=false
            shift
            ;;
        --mpc-user)
            MPC_USER="${2:?}"
            REPO_DIR="${MPC_REPO_DIR:-/home/${MPC_USER}/mpc-config}"
            shift 2
            ;;
        --repo-dir)
            REPO_DIR="${2:?}"
            shift 2
            ;;
        --ref)
            MPC_CONFIG_REF="${2:?}"
            shift 2
            ;;
        --repo-url)
            MPC_CONFIG_REPO="${2:?}"
            shift 2
            ;;
        --skip-clone)
            SKIP_CLONE=true
            shift
            ;;
        --skip-packages)
            SKIP_PACKAGES=true
            shift
            ;;
        --skip-user)
            SKIP_USER=true
            shift
            ;;
        --no-start)
            NO_START=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            die "unknown option: $1 (try --help)"
            ;;
        *)
            die "unexpected argument: $1 (try --help)"
            ;;
    esac
done

if [ "$INSTALL_SYSTEMD" = true ]; then
    PROVISION_ARGS+=(--install-systemd)
fi

require_root
require_debian_ubuntu

log "ContinuumDAO MPC node one-shot install (installer v${INSTALL_SCRIPT_VERSION})"
log "Target repo: ${REPO_DIR} (ref: ${MPC_CONFIG_REF})"

if [ "$SKIP_PACKAGES" = false ]; then
    log "Installing system packages"
    run_or_dry apt-get update -qq
    run_or_dry apt-get install -y \
        ca-certificates \
        curl \
        wget \
        git \
        openssl \
        gnupg \
        iptables \
        docker.io \
        docker-compose \
        python3 \
        python3-pip \
        python3-ruamel.yaml \
        python3-cryptography \
        mongodb-database-tools \
        jq
    if [ "$DRY_RUN" = false ]; then
        systemctl enable --now docker 2>/dev/null || true
    else
        printf '[dry-run] systemctl enable --now docker\n'
    fi
fi

if [ "$SKIP_USER" = false ]; then
    log "Ensuring OS user ${MPC_USER} with password-protected sudo"
    if [ "$DRY_RUN" = false ]; then
        if ! id "$MPC_USER" >/dev/null 2>&1; then
            adduser --disabled-password --gecos "ContinuumDAO MPC node" "$MPC_USER"
        fi
        usermod -aG sudo "$MPC_USER" 2>/dev/null || true
        if getent group docker >/dev/null 2>&1; then
            usermod -aG docker "$MPC_USER" 2>/dev/null || true
        fi
        install -d -m 0750 /etc/sudoers.d
        printf '%s ALL=(ALL:ALL) ALL\n' "$MPC_USER" >"/etc/sudoers.d/${MPC_USER}"
        chmod 0440 "/etc/sudoers.d/${MPC_USER}"
        visudo -cf "/etc/sudoers.d/${MPC_USER}" >/dev/null
    else
        printf '[dry-run] create user %s, sudoers.d, docker group\n' "$MPC_USER"
    fi
fi

if [ "$SKIP_CLONE" = false ]; then
    log "Cloning mpc-config to ${REPO_DIR}"
    if [ "$DRY_RUN" = false ]; then
        if [ -d "$REPO_DIR" ]; then
            if [ -f "${REPO_DIR}/configs.yaml" ]; then
                die "refusing to proceed: ${REPO_DIR}/configs.yaml already exists (remove or use --skip-clone on an empty tree)"
            fi
            if [ -d "${REPO_DIR}/.git" ]; then
                warn "${REPO_DIR} exists without configs.yaml — using existing clone"
            else
                die "${REPO_DIR} exists and is not a git repo — remove it or choose --repo-dir"
            fi
        else
            install -d -o "$MPC_USER" -g "$MPC_USER" "$(dirname "$REPO_DIR")"
            sudo -u "$MPC_USER" git clone --depth 1 --branch "$MPC_CONFIG_REF" "$MPC_CONFIG_REPO" "$REPO_DIR"
        fi
    else
        printf '[dry-run] git clone --branch %s %s %s\n' "$MPC_CONFIG_REF" "$MPC_CONFIG_REPO" "$REPO_DIR"
    fi
else
    log "Skipping clone (--skip-clone); using ${REPO_DIR}"
    [ -d "$REPO_DIR" ] || die "repo directory not found: $REPO_DIR"
fi

PROVISION_SH="${REPO_DIR}/scripts/provision-node.sh"
DOCKER_V2_SH="${REPO_DIR}/scripts/docker-V2_debian_ubuntu.sh"

if [ "$DRY_RUN" = false ]; then
    [ -f "$PROVISION_SH" ] || die "missing ${PROVISION_SH} — check clone/ref"
    [ -f "$DOCKER_V2_SH" ] || die "missing ${DOCKER_V2_SH}"
fi

log "Installing Docker Compose v2 plugin"
if [ "$DRY_RUN" = true ]; then
    printf '[dry-run] bash %s\n' "$DOCKER_V2_SH"
else
    bash "$DOCKER_V2_SH" || die "docker-V2_debian_ubuntu.sh failed"
fi

log "Provisioning node (scripts/provision-node.sh)"
if [ "$DRY_RUN" = true ]; then
    printf '[dry-run] bash %s %s\n' "$PROVISION_SH" "${PROVISION_ARGS[*]:-}"
else
    cd "$REPO_DIR"
    # Preserve RELAYER_API_URL and other env through root run.
    bash "$PROVISION_SH" "${PROVISION_ARGS[@]}"
fi

if [ "$DRY_RUN" = false ]; then
    log "Setting ownership to ${MPC_USER}"
    chown -R "${MPC_USER}:${MPC_USER}" "$REPO_DIR"
fi

if [ "$NO_START" = false ]; then
    log "Starting Docker stack (docker compose up -d)"
    if [ "$DRY_RUN" = true ]; then
        printf '[dry-run] cd %s && docker compose up -d\n' "$REPO_DIR"
    else
        cd "$REPO_DIR"
        if ! docker compose version >/dev/null 2>&1; then
            die "'docker compose' (v2) is required — see scripts/docker-V2_debian_ubuntu.sh"
        fi
        docker compose up -d
        log "Running containers:"
        docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null || docker ps
    fi
else
    log "Skipping docker compose (--no-start)"
fi

if [ -n "$PROVISION_NODE_IP" ]; then
    MPC_PASSWD_SSH="ssh root@${PROVISION_NODE_IP} 'passwd ${MPC_USER}'"
else
    MPC_PASSWD_SSH="ssh root@YOUR_VPS_IP 'passwd ${MPC_USER}'"
fi

cat <<EOF

==> Node provision complete
    Repo:     ${REPO_DIR}
    Ref:      ${MPC_CONFIG_REF}
    OS user:  ${MPC_USER} (password-protected sudo; no login password set yet)

Next steps:
  1. Set ${MPC_USER} login password over SSH (do not set passwords inside curl|bash — use SSH):
       ${MPC_PASSWD_SSH}
  2. Attach your node at https://mpa.continuumdao.org
  3. Back up ${REPO_DIR}/bootstrap_key/ if PublicMgtKey was auto-generated
  4. Configure peer IPs and MQTT certs in the MPA Nodes page

EOF
