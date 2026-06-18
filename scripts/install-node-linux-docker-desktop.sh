#!/usr/bin/env bash
# Local MPC node install for Docker Desktop on native Linux (Debian/Ubuntu).
# Installs system packages (except Docker), enables UFW + systemd, provisions, compose up.
# Docker Engine + compose v2 come from Docker Desktop — not apt.
#
# Run via the Continuum extension (host CLI → desktop-local-orchestrate.sh --profile linux)
# or manually after clone to ~/mpc-config:
#
#   sudo ./scripts/install-node-linux-docker-desktop.sh \
#     --repo-dir ~/mpc-config --skip-clone \
#     --node-mgt-key "0xYour40Hex..." --ip "203.0.113.50"
#
set -euo pipefail

CONTINUUM_INSTALL_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
# shellcheck source=lib/load-install-progress.sh
if [ -n "$CONTINUUM_INSTALL_SCRIPT_DIR" ] && [ -f "${CONTINUUM_INSTALL_SCRIPT_DIR}/lib/load-install-progress.sh" ]; then
    # shellcheck source=lib/load-install-progress.sh
    . "${CONTINUUM_INSTALL_SCRIPT_DIR}/lib/load-install-progress.sh"
    # shellcheck source=lib/install-progress-docker.sh
    . "${CONTINUUM_INSTALL_SCRIPT_DIR}/lib/install-progress-docker.sh"
    # shellcheck source=lib/configure-desktop-compose-discovery.sh
    . "${CONTINUUM_INSTALL_SCRIPT_DIR}/lib/configure-desktop-compose-discovery.sh"
else
    CONTINUUM_INSTALL_PROGRESS=off
    export CONTINUUM_INSTALL_PROGRESS
fi

INSTALL_SCRIPT_VERSION="0.1.0"
INSTALL_LOG="${INSTALL_LOG:-/var/log/continuumdao-mpc-linux-desktop-install.log}"

MPC_CONFIG_REPO="${MPC_CONFIG_REPO:-https://github.com/ContinuumDAO/mpc-config.git}"
MPC_CONFIG_REF="${MPC_CONFIG_REF:-main}"
REPO_DIR="${MPC_REPO_DIR:-${HOME}/mpc-config}"

SKIP_PACKAGES=false
SKIP_CLONE=false
DRY_RUN=false
NO_START=false
FORCE_FRESH_INSTALL=false
FORCE_BROWSER=false
ENABLE_LOOPBACK=true
PROVISION_ARGS=()

usage() {
    cat <<'EOF'
Usage:
  sudo ./scripts/install-node-linux-docker-desktop.sh [options]

Linux Docker Desktop profile (Debian/Ubuntu). Requires docker + docker compose v2 from Docker Desktop.
Installs apt packages except docker.io; enables UFW and systemd via provision-node.sh.

Provision options (at least one management key required):
  -k, --node-mgt-key ADDR     Ethereum NodeMgtKey (0x + 40 hex)
      --public-mgt-key KEY    Ed25519 PublicMgtKey (64 hex or ssh-ed25519 line)
  -i, --ip ADDRESS            This node's public IPv4
  -p, --http-port PORT        nodeAddresses HTTP port (default 8081)
      --relay-host HOST       Relay placeholder (default 0.0.0.0)
      --force-browser-certs   Pass --force-browser-https-certs to process_config.sh
      --no-loopback           Disable browser loopback HTTP

Install options:
      --repo-dir PATH         mpc-config root (default: ~/mpc-config)
      --ref REF                 Git branch (default: main)
      --repo-url URL            Git remote
      --skip-clone              Use existing repo at --repo-dir
      --skip-packages           Skip apt install
      --no-start                Provision only; skip docker compose up -d
      --dry-run                 Print actions without executing
      --force-fresh-install     Continue if MPC Docker containers are running
  -h, --help                  Show this help

Environment:
  MPC_REPO_DIR, MPC_CONFIG_REPO, MPC_CONFIG_REF, APT_LOCK_WAIT_SECS
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
    install_progress_finish false 2>/dev/null || true
    printf 'error: %s\n' "$*" >&2
    if [ "$DRY_RUN" = false ]; then
        printf '[%s] error: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >>"$INSTALL_LOG" 2>/dev/null || true
    fi
    exit 1
}

on_err() {
    local ec=$?
    install_progress_finish false 2>/dev/null || true
    printf 'error: install failed at line %s (exit %s). See %s.\n' "${BASH_LINENO[0]:-?}" "$ec" "$INSTALL_LOG" >&2
    exit "$ec"
}

require_root() {
    if [ "${EUID:-0}" -ne 0 ]; then
        die "run with sudo on Linux Docker Desktop (e.g. sudo ./scripts/install-node-linux-docker-desktop.sh …)"
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
                return 0
            fi
        done
        return 1
    }

    if ! _apt_lock_held; then
        return 0
    fi

    log "Waiting for apt/dpkg lock…"
    while _apt_lock_held; do
        if [ "$waited" -ge "$max_wait" ]; then
            die "apt/dpkg lock still held after ${max_wait}s"
        fi
        sleep "$interval"
        waited=$((waited + interval))
    done
}

packages_already_installed() {
    command -v git >/dev/null 2>&1 \
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
        warn "Required packages already installed — skipping apt"
        SKIP_PACKAGES=true
    fi
}

ensure_vpn_host_packages() {
    if command -v wg-quick >/dev/null 2>&1 && command -v socat >/dev/null 2>&1; then
        return 0
    fi
    if [ "$DRY_RUN" = true ]; then
        printf '[dry-run] apt-get install -y wireguard socat\n'
        return 0
    fi
    log "Installing wireguard and socat (VPN host automation)"
    wait_for_apt_lock
    apt-get -o "DPkg::Lock::Timeout=${APT_LOCK_WAIT_SECS:-300}" install -y wireguard socat \
        || warn "wireguard/socat install failed — VPN enable from the node app will fail until packages are installed"
}

preflight_docker() {
    if ! command -v docker >/dev/null 2>&1; then
        die "docker not found — start Docker Desktop"
    fi
    if ! docker info >/dev/null 2>&1; then
        die "docker info failed — is Docker Desktop running?"
    fi
    if ! docker compose version >/dev/null 2>&1; then
        die "docker compose v2 required — update Docker Desktop"
    fi
}

preflight_check_fresh_install() {
    local cfg="${REPO_DIR}/configs.yaml"

    if [ -f "$cfg" ]; then
        printf 'error: %s already exists — fresh install only (use MPA Maintenance to update).\n' "$cfg" >&2
        exit 1
    fi

    local docker_block=0
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        local project line name image
        project="$(basename "$REPO_DIR")"
        if docker ps --filter "label=com.docker.compose.project=${project}" -q 2>/dev/null | grep -q .; then
            docker_block=1
        else
            while IFS= read -r line; do
                [ -z "$line" ] && continue
                name="${line%%$'\t'*}"
                image="${line#*$'\t'}"
                case "$image" in
                    continuumdao/mpc-auth*|mongo:6*|continuumdao/continuumdao-node-app*|continuumdao/continuum-mcp-server*|eclipse-mosquitto:2*)
                        docker_block=1
                        ;;
                esac
            done < <(docker ps --format '{{.Names}}	{{.Image}}' 2>/dev/null || true)
        fi
    fi

    if [ "$docker_block" -ne 0 ] && [ "$FORCE_FRESH_INSTALL" != true ]; then
        printf 'error: MPC Docker containers already running — stop them or use --force-fresh-install\n' >&2
        exit 1
    fi

    log "Preflight OK: no existing configs.yaml at ${REPO_DIR}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -k|--node-mgt-key|--public-mgt-key|-i|--ip|-p|--http-port|--relay-host)
            [[ $# -ge 2 ]] || die "option $1 requires a value"
            PROVISION_ARGS+=("$1" "$2")
            shift 2
            ;;
        --force-browser-certs)
            FORCE_BROWSER=true
            shift
            ;;
        --no-loopback)
            ENABLE_LOOPBACK=false
            shift
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

if [ "${#PROVISION_ARGS[@]}" -eq 0 ]; then
    die "provide --node-mgt-key and/or --public-mgt-key (try --help)"
fi

PROVISION_ARGS+=(--install-systemd)
if [ "$ENABLE_LOOPBACK" = false ]; then
    PROVISION_ARGS+=(--no-loopback)
fi
if [ "$FORCE_BROWSER" = true ]; then
    PROVISION_ARGS+=(--force-browser-certs)
fi

require_root
require_debian_ubuntu
trap on_err ERR

if [ "$DRY_RUN" = false ]; then
    install -d -m 0755 "$(dirname "$INSTALL_LOG")" 2>/dev/null || true
fi

log "ContinuumDAO MPC node Linux Docker Desktop install (v${INSTALL_SCRIPT_VERSION})"
log "Install log: ${INSTALL_LOG}"
log "Target repo: ${REPO_DIR} (ref: ${MPC_CONFIG_REF})"

export CONTINUUM_INSTALL_DRY_RUN="$DRY_RUN"
install_progress_init linux-desktop

install_progress_topic_begin preflight
if [ "$DRY_RUN" = false ]; then
    preflight_docker
fi
preflight_check_fresh_install
install_progress_topic_done preflight

maybe_auto_skip_packages
if [ "$SKIP_PACKAGES" = true ]; then
    install_progress_mark_done_if packages true
fi

if [ "$SKIP_PACKAGES" = false ]; then
    log "Installing system packages (Docker Desktop provides docker — skipping docker.io)"
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
        python3 \
        python3-pip \
        python3-ruamel.yaml \
        python3-cryptography \
        mongodb-database-tools \
        wireguard \
        socat \
        jq
    install_progress_spinner_stop
    install_progress_topic_done packages
fi

ensure_vpn_host_packages

if [ "$SKIP_CLONE" = false ]; then
    log "Cloning mpc-config to ${REPO_DIR}"
    install_progress_topic_begin clone
    install_progress_spinner_start
    if [ "$DRY_RUN" = false ]; then
        if [ -d "$REPO_DIR" ]; then
            if [ -f "${REPO_DIR}/configs.yaml" ]; then
                die "refusing to proceed: ${REPO_DIR}/configs.yaml already exists"
            fi
            if [ ! -d "${REPO_DIR}/.git" ]; then
                die "${REPO_DIR} exists and is not a git repo — remove it or choose --repo-dir"
            fi
            warn "${REPO_DIR} exists without configs.yaml — using existing clone"
        else
            clone_user="${SUDO_USER:-${USER:-root}}"
            install -d -o "$clone_user" -g "$clone_user" "$(dirname "$REPO_DIR")"
            sudo -u "$clone_user" git clone --depth 1 --branch "$MPC_CONFIG_REF" "$MPC_CONFIG_REPO" "$REPO_DIR"
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
if [ "$DRY_RUN" = false ]; then
    [ -f "$PROVISION_SH" ] || die "missing ${PROVISION_SH} — check clone/ref"
fi

log "Provisioning node (scripts/provision-node.sh with systemd + UFW)"
export CONTINUUM_INSTALL_SCRIPT_DIR="${REPO_DIR}/scripts"
install_progress_register_pc_topics 0 0
if [ "$DRY_RUN" = true ]; then
    printf '[dry-run] bash %s %s\n' "$PROVISION_SH" "${PROVISION_ARGS[*]:-}"
    install_progress_topic_done provision-setup 2>/dev/null || true
    install_progress_topic_done configure-node 2>/dev/null || true
else
    cd "$REPO_DIR"
    CONTINUUM_INSTALL_PROGRESS_SUPPRESS_SYNC=1 bash "$PROVISION_SH" "${PROVISION_ARGS[@]}"
    install_progress_topic_done provision-setup
    install_progress_topic_done configure-node
fi

configure_desktop_compose_discovery "$REPO_DIR" "$DRY_RUN"

if [ "$DRY_RUN" = false ] && [ -n "${SUDO_USER:-}" ]; then
    log "Setting ownership to ${SUDO_USER}"
    chown -R "${SUDO_USER}:${SUDO_USER}" "$REPO_DIR"
fi

if [ "$NO_START" = false ]; then
    log "Pulling images and starting Docker stack"
    if [ "$DRY_RUN" = true ]; then
        printf '[dry-run] install_progress_docker_pull_and_up %q\n' "$REPO_DIR"
        install_progress_register_compose_pull_topics "$REPO_DIR" 2>/dev/null || true
        install_progress_topic_done start-stack 2>/dev/null || true
    else
        cd "$REPO_DIR"
        install_progress_docker_pull_and_up "$REPO_DIR"
        log "Running containers:"
        docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null || docker ps
    fi
else
    log "Skipping docker compose (--no-start)"
    install_progress_mark_done_if start-stack true
fi

install_progress_finish true

cat <<EOF

Node provision complete (Linux Docker Desktop).
Repo: ${REPO_DIR}

Docker Desktop: mpc-auth, mongo, continuum-mcp, and node-app containers are listed under Containers.
Config and keys on disk: ${REPO_DIR}/configs.yaml, bootstrap_key/, added_keys/

Next steps:
  1. Attach your node at https://mpa.continuumdao.org
  2. Back up ${REPO_DIR}/bootstrap_key/ if PublicMgtKey was auto-generated
  3. Use MPA Maintenance for guided updates when available
  4. VPN: enable from the node app VPN panel; host applies via pending-vpn.json + mpc-auth-vpn-pending.path (same as VPS; open UDP 51820 if remote clients connect)

EOF
