#!/usr/bin/env bash
# One-shot MPC node install for Ubuntu/Debian VPS (run as root on the target server).
#
# Typical use (paste on VPS after ssh root@VPS_IP):
#   curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/install-node-debian-ubuntu.sh" \
#     | bash -s -- --node-mgt-key "0xYour40Hex..." --ip "203.0.113.50"
#
# Or from your PC (curl runs ON the VPS — do not use curl | ssh bash -s):
#   ssh root@203.0.113.50 'curl -fsSL "…/install-node-debian-ubuntu.sh" | bash -s -- --node-mgt-key "0x..." --ip "203.0.113.50"'
#
# Tracks main on GitHub. After install, update mpc-config from the MPA Maintenance tab (git pull + updateMpcAuth).
#
set -euo pipefail

CONTINUUM_INSTALL_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
# shellcheck source=lib/load-install-progress.sh
if [ -n "$CONTINUUM_INSTALL_SCRIPT_DIR" ] && [ -f "${CONTINUUM_INSTALL_SCRIPT_DIR}/lib/load-install-progress.sh" ]; then
    # shellcheck source=lib/load-install-progress.sh
    . "${CONTINUUM_INSTALL_SCRIPT_DIR}/lib/load-install-progress.sh"
    # shellcheck source=lib/install-progress-docker.sh
    . "${CONTINUUM_INSTALL_SCRIPT_DIR}/lib/install-progress-docker.sh"
else
    _bootstrap_tmp="$(mktemp -d 2>/dev/null || echo "/tmp/continuum-bootstrap-$$")"
    _raw_base="https://raw.githubusercontent.com/ContinuumDAO/mpc-config/${MPC_CONFIG_REF:-main}"
    mkdir -p "${_bootstrap_tmp}/lib"
    if curl -fsSL "${_raw_base}/scripts/lib/load-install-progress.sh" -o "${_bootstrap_tmp}/lib/load-install-progress.sh" 2>/dev/null; then
        CONTINUUM_INSTALL_SCRIPT_DIR="${_bootstrap_tmp}"
        # shellcheck source=/dev/null
        . "${_bootstrap_tmp}/lib/load-install-progress.sh"
        if curl -fsSL "${_raw_base}/scripts/lib/install-progress-docker.sh" -o "${_bootstrap_tmp}/lib/install-progress-docker.sh" 2>/dev/null; then
            # shellcheck source=/dev/null
            . "${_bootstrap_tmp}/lib/install-progress-docker.sh"
        fi
    else
        CONTINUUM_INSTALL_PROGRESS=off
        export CONTINUUM_INSTALL_PROGRESS
    fi
fi

INSTALL_SCRIPT_VERSION="1.0.8"
INSTALL_LOG="${INSTALL_LOG:-/var/log/continuumdao-mpc-install.log}"

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
FORCE_FRESH_INSTALL=false
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
      --install-systemd           Enable systemd units (default; accepted for compatibility with generated commands)
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
      --force-fresh-install     Continue if MPC Docker containers are running (configs.yaml must still be absent)
  -h, --help                    Show this help

Environment:
  MPC_CONFIG_REF, MPC_CONFIG_REPO, MPC_USER, MPC_REPO_DIR, RELAYER_API_URL
  APT_LOCK_WAIT_SECS          Seconds to wait for apt/dpkg lock (default 300)
  APT_LOCK_NO_FORCE_CLEAR=1   Do not kill stuck apt or remove locks after timeout; exit instead

Examples:
  bash -s -- --node-mgt-key "0xabc..." --ip "203.0.113.50"
  bash -s -- --public-mgt-key "64hex..." --ip "203.0.113.50"
EOF
}

log() {
    printf '==> %s\n' "$*" >&2
    if [ "$DRY_RUN" = false ]; then
        printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >>"$INSTALL_LOG" 2>/dev/null || true
    fi
}

warn() {
    printf 'warning: %s\n' "$*" >&2
    if [ "$DRY_RUN" = false ]; then
        printf '[%s] warning: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >>"$INSTALL_LOG" 2>/dev/null || true
    fi
}

die() {
    printf 'error: %s\n' "$*" >&2
    if [ "$DRY_RUN" = false ]; then
        printf '[%s] error: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >>"$INSTALL_LOG" 2>/dev/null || true
    fi
    exit 1
}

on_err() {
    local ec=$?
    install_progress_finish false 2>/dev/null || true
    printf 'error: install failed at line %s (exit %s). See %s on the server.\n' "${BASH_LINENO[0]:-?}" "$ec" "$INSTALL_LOG" >&2
    exit "$ec"
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

# Wait until apt/dpkg locks are free; after timeout, recover stale locks (see recover_stuck_apt_lock).
wait_for_apt_lock() {
    if [ "$DRY_RUN" = true ]; then
        printf '[dry-run] wait for apt/dpkg lock\n'
        return 0
    fi

    local max_wait="${APT_LOCK_WAIT_SECS:-300}"
    local interval=5
    local waited=0
    local lock_paths=(
        /var/lib/dpkg/lock-frontend
        /var/lib/dpkg/lock
        /var/lib/apt/lists/lock
        /var/cache/apt/archives/lock
    )

    _apt_lock_held() {
        local p
        for p in "${lock_paths[@]}"; do
            [ -e "$p" ] || continue
            if command -v fuser >/dev/null 2>&1; then
                fuser "$p" >/dev/null 2>&1 && return 0
            else
                # Without fuser, treat existing lock files as held.
                return 0
            fi
        done
        return 1
    }

    if ! _apt_lock_held; then
        return 0
    fi

    log "Waiting for apt/dpkg lock (another package manager may be running, e.g. unattended-upgrades)…"
    while _apt_lock_held; do
        if [ "$waited" -ge "$max_wait" ]; then
            if [ "${APT_LOCK_NO_FORCE_CLEAR:-0}" = "1" ]; then
                printf 'error: apt/dpkg lock still held after %ss (APT_LOCK_NO_FORCE_CLEAR=1).\n' "$max_wait" >&2
                printf 'Check: fuser -v /var/lib/dpkg/lock-frontend\n' >&2
                exit 1
            fi
            recover_stuck_apt_lock "$max_wait"
            if _apt_lock_held; then
                die "apt/dpkg lock still held after lock recovery — fix manually: fuser -v /var/lib/dpkg/lock-frontend"
            fi
            return 0
        fi
        sleep "$interval"
        waited=$((waited + interval))
        if [ $((waited % 30)) -eq 0 ]; then
            log "Still waiting for apt lock (${waited}s / ${max_wait}s)…"
        fi
    done
    log "apt/dpkg lock released — continuing"
}

# After APT_LOCK_WAIT_SECS, stop stuck apt/daily services, clear lock files, reconfigure dpkg.
recover_stuck_apt_lock() {
    local max_wait="${1:-300}"
    warn "apt/dpkg lock still held after ${max_wait}s — clearing stale locks"

    if command -v fuser >/dev/null 2>&1; then
        fuser -v /var/lib/dpkg/lock-frontend 2>&1 | sed 's/^/  /' >&2 || true
    fi

    local svc
    for svc in apt-daily.service apt-daily-upgrade.service unattended-upgrades.service; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            warn "Stopping ${svc}…"
            systemctl stop "$svc" 2>/dev/null || true
        fi
    done

    local pid comm
    for pid in $(pgrep -x apt-get 2>/dev/null || true) $(pgrep -x apt 2>/dev/null || true) $(pgrep -x dpkg 2>/dev/null || true); do
        [ -n "$pid" ] || continue
        comm="$(ps -p "$pid" -o comm= 2>/dev/null || echo '?')"
        warn "Stopping stuck package manager pid ${pid} (${comm})"
        kill -TERM "$pid" 2>/dev/null || true
    done
    sleep 2
    for pid in $(pgrep -x apt-get 2>/dev/null || true) $(pgrep -x apt 2>/dev/null || true) $(pgrep -x dpkg 2>/dev/null || true); do
        [ -n "$pid" ] || continue
        kill -KILL "$pid" 2>/dev/null || true
    done

    rm -f /var/lib/apt/lists/lock
    rm -f /var/cache/apt/archives/lock
    rm -f /var/lib/dpkg/lock-frontend
    rm -f /var/lib/dpkg/lock

    log "Running dpkg --configure -a after lock recovery"
    if ! dpkg --configure -a; then
        die "dpkg --configure -a failed after lock recovery — repair dpkg on the host and re-run"
    fi
    log "Stale apt/dpkg locks cleared"
}

# Skip apt when a prior run already installed dependencies but exited before mpcnode/clone.
packages_already_installed() {
    command -v docker >/dev/null 2>&1 \
        && command -v git >/dev/null 2>&1 \
        && command -v python3 >/dev/null 2>&1 \
        && python3 -c "import ruamel.yaml, cryptography" 2>/dev/null \
        && command -v wg-quick >/dev/null 2>&1 \
        && command -v socat >/dev/null 2>&1
}

maybe_auto_skip_packages() {
    if [ "$SKIP_PACKAGES" = true ]; then
        return 0
    fi
    if packages_already_installed; then
        warn "Required packages already installed — skipping apt (resume after interrupted install)"
        SKIP_PACKAGES=true
    fi
}

# Refuse to clobber an existing node (run before apt/packages).
preflight_check_fresh_install() {
    local cfg="${REPO_DIR}/configs.yaml"

    if [ -f "$cfg" ]; then
        printf 'error: %s already exists — this installer is for a new node only.\n' "$cfg" >&2
        printf 'Remove or back up that file (and stop containers) before reprovisioning, or use MPA Maintenance to update.\n' >&2
        exit 1
    fi

    local docker_block=0
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        local project line name image
        project="$(basename "$REPO_DIR")"
        if docker ps --filter "label=com.docker.compose.project=${project}" -q 2>/dev/null | grep -q .; then
            docker_block=1
            printf 'error: Docker Compose project %q has running containers:\n' "$project" >&2
            docker ps --filter "label=com.docker.compose.project=${project}" \
                --format '  {{.Names}}  ({{.Image}})  {{.Status}}' >&2 || true
        else
            while IFS= read -r line; do
                [ -z "$line" ] && continue
                name="${line%%$'\t'*}"
                image="${line#*$'\t'}"
                case "$image" in
                    continuumdao/mpc-auth*|mongo:6*|continuumdao/continuumdao-node-app*|continuumdao/continuum-mcp-server*|eclipse-mosquitto:2*)
                        if [ "$docker_block" -eq 0 ]; then
                            printf 'error: MPC node Docker containers are already running:\n' >&2
                        fi
                        docker_block=1
                        printf '  %s  (%s)\n' "$name" "$image" >&2
                        ;;
                esac
            done < <(docker ps --format '{{.Names}}	{{.Image}}' 2>/dev/null || true)
        fi
    fi

    if [ "$docker_block" -ne 0 ]; then
        printf '\n' >&2
        printf 'Stop the existing stack first (e.g. cd %s && docker compose down).\n' "$REPO_DIR" >&2
        printf 'To update a running node use https://mpa.continuumdao.org (Maintenance).\n' >&2
        printf 'Override (containers only): --force-fresh-install\n' >&2
        if [ "$FORCE_FRESH_INSTALL" = true ]; then
            warn "--force-fresh-install set — continuing despite running containers"
            log "Preflight OK: configs.yaml absent; running containers ignored by --force-fresh-install"
            return 0
        fi
        exit 1
    fi

    log "Preflight OK: no existing configs.yaml or MPC Docker stack detected at ${REPO_DIR}"
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
        --install-systemd)
            INSTALL_SYSTEMD=true
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
        --force-fresh-install)
            FORCE_FRESH_INSTALL=true
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
trap on_err ERR

if [ "$DRY_RUN" = false ]; then
    install -d -m 0755 "$(dirname "$INSTALL_LOG")" 2>/dev/null || true
    printf '[%s] install start v%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$INSTALL_SCRIPT_VERSION" >>"$INSTALL_LOG" 2>/dev/null || true
fi

log "ContinuumDAO MPC node one-shot install (installer v${INSTALL_SCRIPT_VERSION})"
log "Install log: ${INSTALL_LOG}"
log "Target repo: ${REPO_DIR} (ref: ${MPC_CONFIG_REF})"

export CONTINUUM_INSTALL_DRY_RUN="$DRY_RUN"
install_progress_init vps

install_progress_topic_begin preflight
preflight_check_fresh_install
install_progress_topic_done preflight

maybe_auto_skip_packages
if [ "$SKIP_PACKAGES" = true ]; then
    install_progress_mark_done_if packages true
fi

if [ "$SKIP_PACKAGES" = false ]; then
    log "Installing system packages"
    install_progress_topic_begin packages
    install_progress_spinner_start
    wait_for_apt_lock
    install_progress_topic_set packages 15
    run_or_dry apt-get -o "DPkg::Lock::Timeout=${APT_LOCK_WAIT_SECS:-300}" update -qq
    wait_for_apt_lock
    install_progress_topic_set packages 40
    run_or_dry apt-get -o "DPkg::Lock::Timeout=${APT_LOCK_WAIT_SECS:-300}" install -y \
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
        wireguard \
        socat \
        jq
    install_progress_topic_set packages 85
    if [ "$DRY_RUN" = false ]; then
        systemctl enable --now docker 2>/dev/null || true
    else
        printf '[dry-run] systemctl enable --now docker\n'
    fi
    install_progress_spinner_stop
    install_progress_topic_done packages
    log "Packages phase complete"
fi

# shellcheck source=lib/ensure-vpn-host-packages.sh
if [ -z "${CONTINUUM_INSTALL_SCRIPT_DIR:-}" ]; then
    CONTINUUM_INSTALL_SCRIPT_DIR="$(mktemp -d 2>/dev/null || echo "/tmp/continuum-bootstrap-$$")"
fi
_ensure_vpn_lib="${CONTINUUM_INSTALL_SCRIPT_DIR}/lib/ensure-vpn-host-packages.sh"
if [ ! -f "$_ensure_vpn_lib" ]; then
    _raw_base="https://raw.githubusercontent.com/ContinuumDAO/mpc-config/${MPC_CONFIG_REF:-main}"
    mkdir -p "${CONTINUUM_INSTALL_SCRIPT_DIR}/lib"
    curl -fsSL "${_raw_base}/scripts/lib/ensure-vpn-host-packages.sh" -o "$_ensure_vpn_lib"
fi
. "$_ensure_vpn_lib"
export CONTINUUM_INSTALL_DRY_RUN="$DRY_RUN"
ensure_vpn_host_packages || warn "wireguard/socat missing — VPN enable will fail until: sudo apt install -y wireguard socat"
log "WireGuard host packages ready. If admin VPN handshakes fail later, allow inbound UDP 51820 in the VPS provider firewall (UFW rules are applied automatically on enable)."

_ensure_ss_lib="${CONTINUUM_INSTALL_SCRIPT_DIR}/lib/ensure-shadowsocks-host-packages.sh"
if [ ! -f "$_ensure_ss_lib" ]; then
    _raw_base="${_raw_base:-https://raw.githubusercontent.com/ContinuumDAO/mpc-config/${MPC_CONFIG_REF:-main}}"
    mkdir -p "${CONTINUUM_INSTALL_SCRIPT_DIR}/lib"
    curl -fsSL "${_raw_base}/scripts/lib/ensure-shadowsocks-host-packages.sh" -o "$_ensure_ss_lib" 2>/dev/null || true
fi
if [ -f "$_ensure_ss_lib" ]; then
    # shellcheck source=lib/ensure-shadowsocks-host-packages.sh
    . "$_ensure_ss_lib"
    ensure_shadowsocks_host_packages || warn "shadowsocks-rust missing — VPN obfuscation unavailable until installed"
fi

if [ "$SKIP_USER" = false ]; then
    log "Ensuring OS user ${MPC_USER} with password-protected sudo"
    install_progress_topic_begin os-user
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
    install_progress_topic_done os-user
else
    install_progress_mark_done_if os-user true
fi

if [ "$SKIP_CLONE" = false ]; then
    log "Cloning mpc-config to ${REPO_DIR}"
    install_progress_topic_begin clone
    install_progress_spinner_start
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
    install_progress_spinner_stop
    install_progress_topic_done clone
else
    log "Skipping clone (--skip-clone); using ${REPO_DIR}"
    [ -d "$REPO_DIR" ] || die "repo directory not found: $REPO_DIR"
    install_progress_mark_done_if clone true
fi

PROVISION_SH="${REPO_DIR}/scripts/provision-node.sh"
DOCKER_V2_SH="${REPO_DIR}/scripts/docker-V2_debian_ubuntu.sh"

if [ "$DRY_RUN" = false ]; then
    [ -f "$PROVISION_SH" ] || die "missing ${PROVISION_SH} — check clone/ref"
    [ -f "$DOCKER_V2_SH" ] || die "missing ${DOCKER_V2_SH}"
fi

log "Installing Docker Compose v2 plugin"
install_progress_topic_begin docker-v2
install_progress_spinner_start
if [ "$DRY_RUN" = true ]; then
    printf '[dry-run] bash %s\n' "$DOCKER_V2_SH"
else
    bash "$DOCKER_V2_SH" || die "docker-V2_debian_ubuntu.sh failed"
fi
install_progress_spinner_stop
install_progress_topic_done docker-v2

log "Provisioning node (scripts/provision-node.sh)"
export CONTINUUM_INSTALL_SCRIPT_DIR="${REPO_DIR}/scripts"
install_progress_register_pc_topics 0 0
if [ "$DRY_RUN" = true ]; then
    printf '[dry-run] bash %s %s\n' "$PROVISION_SH" "${PROVISION_ARGS[*]:-}"
    install_progress_topic_done provision-setup 2>/dev/null || true
    install_progress_topic_done configure-node 2>/dev/null || true
else
    cd "$REPO_DIR"
    # Preserve RELAYER_API_URL and other env through root run.
    CONTINUUM_INSTALL_PROGRESS_SUPPRESS_SYNC=1 bash "$PROVISION_SH" "${PROVISION_ARGS[@]}"
    install_progress_topic_done provision-setup
    install_progress_topic_done configure-node
fi

if [ "$DRY_RUN" = false ]; then
    log "Setting ownership to ${MPC_USER}"
    chown -R "${MPC_USER}:${MPC_USER}" "$REPO_DIR"
fi

if [ "$NO_START" = false ]; then
    log "Pulling images and starting Docker stack"
    if [ "$DRY_RUN" = true ]; then
        printf '[dry-run] install_progress_docker_pull_and_up %q\n' "$REPO_DIR"
        install_progress_register_compose_pull_topics "$REPO_DIR" 2>/dev/null || true
        install_progress_topic_done start-stack 2>/dev/null || true
    else
        cd "$REPO_DIR"
        if ! docker compose version >/dev/null 2>&1; then
            die "'docker compose' (v2) is required — see scripts/docker-V2_debian_ubuntu.sh"
        fi
        _docker_progress_lib="${REPO_DIR}/scripts/lib/install-progress-docker.sh"
        if [ ! -f "$_docker_progress_lib" ]; then
            _docker_progress_lib="${CONTINUUM_INSTALL_SCRIPT_DIR}/lib/install-progress-docker.sh"
        fi
        if [ ! -f "$_docker_progress_lib" ]; then
            _raw_base="https://raw.githubusercontent.com/ContinuumDAO/mpc-config/${MPC_CONFIG_REF:-main}"
            mkdir -p "${CONTINUUM_INSTALL_SCRIPT_DIR}/lib"
            _docker_progress_lib="${CONTINUUM_INSTALL_SCRIPT_DIR}/lib/install-progress-docker.sh"
            curl -fsSL "${_raw_base}/scripts/lib/install-progress-docker.sh" -o "$_docker_progress_lib"
        fi
        # shellcheck source=/dev/null
        . "$_docker_progress_lib"
        install_progress_docker_pull_and_up "$REPO_DIR"
        log "Running containers:"
        docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null || docker ps
    fi
else
    log "Skipping docker compose (--no-start)"
    install_progress_mark_done_if start-stack true
fi

install_progress_finish true

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
  5. Admin VPN (optional): enable from the MPA VPN Panel; allow inbound UDP 51820 in your VPS provider firewall if the client shows 0 B received

EOF
