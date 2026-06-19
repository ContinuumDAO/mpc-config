#!/usr/bin/env bash
# Local MPC node install for Docker Desktop on Windows (WSL2).
# Uses existing provision + process_config; skips apt docker, UFW, and systemd.
#
# Run inside WSL with Docker Desktop WSL integration, or via the Continuum extension
# (host CLI → wsl.exe → desktop-local-orchestrate.sh → this script → ~/mpc-config).
#
#   ./scripts/install-node-docker-desktop.sh \
#     --node-mgt-key "0xYour40Hex..." \
#     --ip "203.0.113.50"
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

INSTALL_SCRIPT_VERSION="0.2.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${MPC_REPO_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
PROVISION_VENV="${MPC_PROVISION_VENV:-${REPO_DIR}/.venv-provision}"
PROVISION_PY_DIR="${MPC_PROVISION_PY_DIR:-${REPO_DIR}/.provision-py}"
GET_PIP_URL="${GET_PIP_URL:-https://bootstrap.pypa.io/get-pip.py}"
MPC_AUTH_COMPOSE_SERVICE="${MPC_AUTH_COMPOSE_SERVICE:-app}"

DRY_RUN=false
NO_START=false
FORCE_BROWSER=false
ENABLE_LOOPBACK=true
PROVISION_ARGS=()

usage() {
    cat <<'EOF'
Usage:
  ./scripts/install-node-docker-desktop.sh [options]

Windows Docker Desktop + WSL2 profile (not for VPS or native Linux). Requires docker + docker compose v2.
Installs Python deps into .venv-provision or .provision-py (PEP 668–safe; no sudo apt when pip --target works).
Skips UFW (--no-firewall) and systemd.

Provision options (at least one management key required):
  -k, --node-mgt-key ADDR     Ethereum NodeMgtKey (0x + 40 hex)
      --public-mgt-key KEY    Ed25519 PublicMgtKey (64 hex or ssh-ed25519 line)
  -i, --ip ADDRESS            This node's public IPv4 (for --ip and cert SANs)
  -p, --http-port PORT        nodeAddresses HTTP port (default 8081)
      --relay-host HOST       Relay placeholder (default 0.0.0.0)
      --force-browser-certs   Pass --force-browser-https-certs to process_config.sh
      --no-loopback           Disable browser loopback HTTP

Install options:
      --repo-dir PATH         mpc-config root (default: parent of scripts/)
      --no-start              Provision only; skip docker compose up -d
      --dry-run               Print actions without executing
  -h, --help                  Show this help

Environment:
  MPC_REPO_DIR                Same as --repo-dir

Notes:
  - Maintenance auto-restart via systemd paths is not available on desktop.
  - After updates, restart manually: cd mpc-config && docker compose restart
  - Dashboard discovery is configured post-provision so the dashboard container reaches mpc-auth via the compose service "app".
EOF
}

preflight_wsl() {
    if [ -n "${WSL_DISTRO_NAME:-}" ]; then
        return 0
    fi
    if [ -r /proc/version ] && grep -qi microsoft /proc/version 2>/dev/null; then
        return 0
    fi
    die "this installer requires WSL2 on Windows Docker Desktop (run inside your WSL distro, not PowerShell)"
}

passwordless_sudo_instruction_message() {
    local wsl_user="${1:-$(whoami)}"
    local wsl_distro="${2:-${WSL_DISTRO_NAME:-<your-wsl-distro>}}"
    cat <<EOF
passwordless sudo required for Docker Desktop install on Windows.

WSL user: ${wsl_user}
WSL distro: ${wsl_distro}

The Docker extension runs the installer as your default WSL user and cannot type your sudo password.
Host automation (/var/lib/mpc-auth-docker), apt packages, and maintenance restart/update all need sudo -n.

Configure passwordless sudo from Windows PowerShell:

  wsl -d ${wsl_distro} -u root

Then in the root WSL shell:

  visudo

Add this line (replace ${wsl_user} if your username differs):

  ${wsl_user} ALL=(ALL) NOPASSWD: ALL

Verify as your normal WSL user (exit the root shell first):

  wsl -d ${wsl_distro}
  sudo -n true && echo OK

Then click Install again in the Docker extension.
EOF
}

preflight_passwordless_sudo() {
    local wsl_user wsl_distro reason=""
    wsl_user="$(whoami)"
    wsl_distro="${WSL_DISTRO_NAME:-<your-wsl-distro>}"

    if [ "$(id -u)" -eq 0 ]; then
        warn "running install as root — prefer default WSL user with passwordless sudo"
        return 0
    fi

    if ! command -v sudo >/dev/null 2>&1; then
        reason="sudo is not installed in WSL"
        die "$(passwordless_sudo_instruction_message "$wsl_user" "$wsl_distro")"$'\n'"(${reason})"
    fi

    if sudo -n true 2>/dev/null; then
        log "Passwordless sudo OK for WSL user ${wsl_user}"
        return 0
    fi

    if groups "$wsl_user" 2>/dev/null | grep -qE '(^|[[:space:]])sudo([[:space:]]|$)|(^|[[:space:]])wheel([[:space:]]|$)'; then
        reason="user ${wsl_user} is in sudo/wheel but sudo -n failed (password still required)"
    else
        reason="user ${wsl_user} is not in the sudo group or has no NOPASSWD rule"
    fi

    die "$(passwordless_sudo_instruction_message "$wsl_user" "$wsl_distro")"$'\n'"(${reason})"
}

log() { printf '==> %s\n' "$*" >&2; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() {
    install_progress_finish false 2>/dev/null || true
    printf 'error: %s\n' "$*" >&2
    exit 1
}

run_or_dry() {
    if [ "$DRY_RUN" = true ]; then
        printf '[dry-run] %s\n' "$*"
    else
        "$@"
    fi
}

preflight_docker() {
    if ! command -v docker >/dev/null 2>&1; then
        die "docker not found — start Docker Desktop and enable WSL integration for your Ubuntu distro"
    fi
    if ! docker info >/dev/null 2>&1; then
        die "docker info failed — is Docker Desktop running?"
    fi
    if ! docker compose version >/dev/null 2>&1; then
        die "docker compose v2 required — update Docker Desktop"
    fi
}

preflight_repo() {
    [ -d "$REPO_DIR" ] || die "repo directory not found: $REPO_DIR"
    [ -f "$REPO_DIR/configs-original.yaml" ] || die "missing configs-original.yaml under $REPO_DIR"
    [ -f "$REPO_DIR/process_config.sh" ] || die "missing process_config.sh under $REPO_DIR"
    [ -f "$REPO_DIR/scripts/provision-node.sh" ] || die "missing scripts/provision-node.sh under $REPO_DIR"
}

preflight_fresh() {
    if [ -f "$REPO_DIR/configs.yaml" ]; then
        die "$REPO_DIR/configs.yaml already exists — desktop install is for a new node only (use MPA Maintenance to update)"
    fi
}

python3_minor_version() {
    python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")'
}

python_provision_import_check() {
    local py="$1"
    local path_prefix="${2:-}"
    if [ -n "$path_prefix" ]; then
        PYTHONPATH="${path_prefix}${PYTHONPATH:+:${PYTHONPATH}}" "$py" -c "import ruamel.yaml, cryptography" 2>/dev/null
    else
        "$py" -c "import ruamel.yaml, cryptography" 2>/dev/null
    fi
}

python_provision_deps_ok() {
    if [ -x "${PROVISION_VENV}/bin/python3" ]; then
        python_provision_import_check "${PROVISION_VENV}/bin/python3" && return 0
    fi
    if [ -d "${PROVISION_PY_DIR}" ]; then
        python_provision_import_check python3 "${PROVISION_PY_DIR}" && return 0
    fi
    return 1
}

install_provision_pip_packages() {
    local pip="$1"
    "$pip" install --upgrade pip wheel >/dev/null 2>&1 || true
    "$pip" install ruamel.yaml cryptography
}

try_pip_target_provision_deps() {
    command -v python3 >/dev/null 2>&1 || return 1
    python3 -m pip --version >/dev/null 2>&1 || return 1

    log "Installing ruamel.yaml + cryptography via pip --target ${PROVISION_PY_DIR} (no python3-venv required)"
    rm -rf "${PROVISION_PY_DIR}"
    mkdir -p "${PROVISION_PY_DIR}"
    if ! python3 -m pip install --target "${PROVISION_PY_DIR}" ruamel.yaml cryptography; then
        rm -rf "${PROVISION_PY_DIR}"
        return 1
    fi
    python_provision_deps_ok
}

try_venv_provision_deps() {
    local mode="$1"
    rm -rf "${PROVISION_VENV}"

    if [ "$mode" = "without-pip" ]; then
        log "Trying python3 -m venv --without-pip ${PROVISION_VENV}"
        python3 -m venv --without-pip "${PROVISION_VENV}" 2>/dev/null || return 1
        local get_pip="${PROVISION_VENV}/get-pip.py"
        curl -fsSL "${GET_PIP_URL}" -o "${get_pip}" || return 1
        "${PROVISION_VENV}/bin/python3" "${get_pip}" || return 1
        rm -f "${get_pip}"
    else
        log "Trying python3 -m venv ${PROVISION_VENV}"
        python3 -m venv "${PROVISION_VENV}" 2>/dev/null || return 1
    fi

    install_provision_pip_packages "${PROVISION_VENV}/bin/pip"
    python_provision_deps_ok
}

try_apt_python_venv_packages() {
    command -v apt-get >/dev/null 2>&1 || return 1
    command -v sudo >/dev/null 2>&1 || return 1
    sudo -n true 2>/dev/null || return 1

    local py_minor
    py_minor="$(python3_minor_version 2>/dev/null || true)"
    log "Trying passwordless apt install of python venv packages (python${py_minor}-venv / python3-venv)"
    sudo -n apt-get update -qq || return 1
    if [ -n "$py_minor" ]; then
        sudo -n apt-get install -y "python${py_minor}-venv" python3-venv python3-full 2>/dev/null \
            || sudo -n apt-get install -y python3-venv python3-full 2>/dev/null \
            || return 1
    else
        sudo -n apt-get install -y python3-venv python3-full || return 1
    fi
}

try_apt_vpn_packages() {
    command -v wg-quick >/dev/null 2>&1 && command -v socat >/dev/null 2>&1 && return 0
    command -v apt-get >/dev/null 2>&1 || return 1
    command -v sudo >/dev/null 2>&1 || return 1
    sudo -n true 2>/dev/null || return 1
    log "Trying passwordless apt install of wireguard-tools and socat (VPN host automation)"
    sudo -n apt-get update -qq || return 1
    sudo -n apt-get install -y wireguard-tools socat || return 1
}

ensure_vpn_host_tools() {
    if command -v wg-quick >/dev/null 2>&1 && command -v socat >/dev/null 2>&1; then
        return 0
    fi
    if [ "$DRY_RUN" = true ]; then
        printf '[dry-run] sudo apt install -y wireguard-tools socat\n'
        return 0
    fi
    if try_apt_vpn_packages; then
        log "WireGuard host tools ready (wg-quick, socat)"
        return 0
    fi
    warn "wireguard-tools and/or socat missing — VPN enable from the node app will fail until you run: sudo apt install -y wireguard-tools socat"
}

manual_provision_python_instructions() {
    local py_minor
    py_minor="$(python3_minor_version 2>/dev/null || echo "3.x")"
    cat <<EOF
Could not install Python deps (ruamel.yaml, cryptography) without interactive sudo.
The Docker extension cannot enter your WSL sudo password.

Option A — pip --target (often works on Ubuntu ${py_minor} without python3-venv):
  cd ${REPO_DIR}
  python3 -m pip install --target .provision-py ruamel.yaml cryptography
  PYTHONPATH=${REPO_DIR}/.provision-py ./scripts/install-node-docker-desktop.sh ...

Option B — venv (requires python3-venv once):
  sudo apt update
  sudo apt install -y python${py_minor}-venv openssl curl git
  python3 -m venv ${PROVISION_VENV}
  ${PROVISION_VENV}/bin/pip install ruamel.yaml cryptography
  ./scripts/install-node-docker-desktop.sh ...

Then re-run Install in the Docker extension.
EOF
}

ensure_provision_python_deps() {
    if python_provision_deps_ok; then
        if [ -x "${PROVISION_VENV}/bin/python3" ]; then
            log "Using provision venv at ${PROVISION_VENV}"
        else
            log "Using provision Python path ${PROVISION_PY_DIR}"
        fi
        return 0
    fi

    command -v python3 >/dev/null 2>&1 || die "python3 not found in WSL — sudo apt install -y python3"
    command -v curl >/dev/null 2>&1 || die "curl not found — sudo apt install -y curl"

    if [ "$DRY_RUN" = true ]; then
        printf '[dry-run] pip --target %q OR python3 -m venv %q\n' "$PROVISION_PY_DIR" "$PROVISION_VENV"
        return 0
    fi

    log "Ensuring Python deps for provision-node.sh / process_config.sh"

    if try_pip_target_provision_deps; then
        log "Provision Python deps ready (.provision-py)"
        return 0
    fi

    if try_venv_provision_deps standard; then
        log "Provision Python deps ready (venv)"
        return 0
    fi

    if try_venv_provision_deps without-pip; then
        log "Provision Python deps ready (venv --without-pip + get-pip)"
        return 0
    fi

    if try_apt_python_venv_packages; then
        if try_venv_provision_deps standard || try_venv_provision_deps without-pip; then
            log "Provision Python deps ready (venv after apt)"
            return 0
        fi
    fi

    die "$(manual_provision_python_instructions)"
}

activate_provision_python() {
    if [ -x "${PROVISION_VENV}/bin/python3" ] && python_provision_import_check "${PROVISION_VENV}/bin/python3"; then
        export VIRTUAL_ENV="$PROVISION_VENV"
        export PATH="${PROVISION_VENV}/bin:${PATH}"
        return 0
    fi
    if [ -d "${PROVISION_PY_DIR}" ]; then
        export PYTHONPATH="${PROVISION_PY_DIR}${PYTHONPATH:+:${PYTHONPATH}}"
        return 0
    fi
    die "provision Python environment not activated"
}

preflight_desktop_tools() {
    command -v openssl >/dev/null 2>&1 || warn "openssl not found — process_config may fail (sudo apt install openssl)"
    command -v curl >/dev/null 2>&1 || warn "curl not found — sudo apt install curl"
    command -v git >/dev/null 2>&1 || warn "git not found — sudo apt install git"
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

if [ "${#PROVISION_ARGS[@]}" -eq 0 ]; then
    die "provide --node-mgt-key and/or --public-mgt-key (try --help)"
fi

log "ContinuumDAO MPC node Windows Docker Desktop install (v${INSTALL_SCRIPT_VERSION})"
log "Repo: $REPO_DIR"

export CONTINUUM_INSTALL_DRY_RUN="$DRY_RUN"
install_progress_init desktop
if [ -d "$REPO_DIR/.git" ]; then
    install_progress_mark_done_if clone true
fi

if [ "$DRY_RUN" = false ]; then
    preflight_wsl
    install_progress_topic_begin passwordless-sudo "Passwordless sudo"
    preflight_passwordless_sudo
    install_progress_topic_done passwordless-sudo
    preflight_docker
    preflight_fresh
    install_progress_topic_begin python-deps
    install_progress_spinner_start
    ensure_provision_python_deps
    install_progress_spinner_stop
    install_progress_topic_done python-deps
    activate_provision_python
    preflight_desktop_tools
else
    install_progress_topic_begin python-deps
    install_progress_topic_done python-deps
fi
preflight_repo

PROVISION_SH=(bash "$REPO_DIR/scripts/provision-node.sh")
PROVISION_SH+=("${PROVISION_ARGS[@]}")
PROVISION_SH+=(--no-firewall)
if [ "$ENABLE_LOOPBACK" = false ]; then
    PROVISION_SH+=(--no-loopback)
fi
if [ "$FORCE_BROWSER" = true ]; then
    PROVISION_SH+=(--force-browser-certs)
fi

log "Provisioning node (scripts/provision-node.sh --no-firewall, no systemd)"
export CONTINUUM_INSTALL_SCRIPT_DIR="${REPO_DIR}/scripts"
install_progress_register_pc_topics 1 1
if [ "$DRY_RUN" = true ]; then
    printf '[dry-run] %q ' "${PROVISION_SH[@]}"
    printf '\n'
    install_progress_topic_done provision-setup 2>/dev/null || true
    install_progress_topic_done configure-node 2>/dev/null || true
else
    cd "$REPO_DIR"
    export PROCESS_CONFIG_SKIP_SYSTEMD=1
    CONTINUUM_INSTALL_PROGRESS_SUPPRESS_SYNC=1 "${PROVISION_SH[@]}"
    install_progress_topic_done provision-setup
    install_progress_topic_done configure-node
fi

configure_desktop_compose_discovery "$REPO_DIR" "$DRY_RUN"

ensure_vpn_host_tools

if [ "$DRY_RUN" = true ]; then
    printf '[dry-run] bash %s/wsl-desktop/install-wsl-desktop-host-automation.sh --repo-dir %q\n' "$REPO_DIR" "$REPO_DIR"
else
    log "Installing WSL pending-update host automation (wsl-desktop watcher)"
    bash "$REPO_DIR/wsl-desktop/install-wsl-desktop-host-automation.sh" --repo-dir "$REPO_DIR"
fi

if [ "$NO_START" = false ]; then
    log "Pulling images and starting Docker stack"
    if [ "$DRY_RUN" = true ]; then
        printf '[dry-run] install_progress_docker_pull_and_up %q\n' "$REPO_DIR"
        install_progress_register_compose_pull_topics "$REPO_DIR" 2>/dev/null || true
        install_progress_topic_done start-stack 2>/dev/null || true
    else
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

Node provision complete (Windows Docker Desktop / WSL2).
Repo: ${REPO_DIR}

Docker Desktop: mpc-auth, mongo, continuum-mcp, and node-app containers are listed under Containers.
Config and keys on disk: ${REPO_DIR}/configs.yaml, bootstrap_key/, added_keys/

Next steps:
  1. Attach your node at https://mpa.continuumdao.org
  2. Back up ${REPO_DIR}/bootstrap_key/ if PublicMgtKey was auto-generated
  3. Host restart automation: WSL pending-update watcher (see ~/mpc-config/wsl-desktop/status-watcher.sh). A Windows logon task is registered by the Docker extension after install.
  4. VPN: enable from the node app VPN panel; host applies via pending-vpn.json + the same WSL watcher (UDP 51820 must reach WSL for remote clients).

EOF
