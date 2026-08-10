#!/usr/bin/env bash
# Local MPC node install for Docker Desktop on macOS.
# Uses existing provision + process_config; skips UFW and systemd.
#
# Run via the Continuum extension (host CLI → desktop-local-orchestrate.sh --profile macos)
# or manually after clone to ~/mpc-config:
#
#   ./scripts/install-node-macos-docker-desktop.sh \
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

INSTALL_SCRIPT_VERSION="0.1.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${MPC_REPO_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
PROVISION_VENV="${MPC_PROVISION_VENV:-${REPO_DIR}/.venv-provision}"
PROVISION_PY_DIR="${MPC_PROVISION_PY_DIR:-${REPO_DIR}/.provision-py}"
GET_PIP_URL="${GET_PIP_URL:-https://bootstrap.pypa.io/get-pip.py}"

DRY_RUN=false
NO_START=false
FORCE_BROWSER=false
ENABLE_LOOPBACK=true
PROVISION_ARGS=()

usage() {
    cat <<'EOF'
Usage:
  ./scripts/install-node-macos-docker-desktop.sh [options]

macOS Docker Desktop profile. Requires docker + docker compose v2 from Docker Desktop.
Installs Homebrew packages (wireguard-tools, socat, yq) when brew is available.
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
  - Host restart/update automation: macos-desktop pending watcher + launchd LaunchAgent.
  - Passwordless sudo recommended for extension-driven install (/var/lib/mpc-auth-docker).
EOF
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

preflight_darwin() {
    if [ "$(uname -s 2>/dev/null || true)" != "Darwin" ]; then
        die "this installer requires macOS (Darwin)"
    fi
}

passwordless_sudo_instruction_message() {
    local mac_user="${1:-$(whoami)}"
    cat <<EOF
passwordless sudo required for Docker Desktop install on macOS.

macOS user: ${mac_user}

The Docker extension runs the installer as your user and cannot type your sudo password.
Host automation (/var/lib/mpc-auth-docker) and VPN (wg-quick) need sudo -n.

Configure passwordless sudo (macOS default %admin rule requires a password — put NOPASSWD in /etc/sudoers.d/ or after %admin):

  sudo visudo -f /etc/sudoers.d/${mac_user}

Add this line (replace ${mac_user} if your username differs):

  ${mac_user} ALL=(ALL) NOPASSWD: ALL

Verify (clears any cached sudo ticket first):

  sudo -k
  sudo -n true && echo OK

The visudo line must match the macOS user shown when the extension runs whoami.

Then click Install again in the Docker extension.
EOF
}

preflight_passwordless_sudo() {
    local mac_user
    mac_user="$(whoami)"

    if [ "$(id -u)" -eq 0 ]; then
        warn "running install as root — prefer your macOS user with passwordless sudo"
        return 0
    fi

    if ! command -v sudo >/dev/null 2>&1; then
        die "sudo not found on macOS"
    fi

    if /usr/bin/sudo -n /usr/bin/true 2>/dev/null; then
        log "Passwordless sudo OK for macOS user ${mac_user}"
        return 0
    fi

    local sudo_err=""
    sudo_err="$(/usr/bin/sudo -n /usr/bin/true 2>&1 >/dev/null || true)"
    if [ -n "$sudo_err" ]; then
        warn "sudo -n failed: ${sudo_err}"
    fi

    die "$(passwordless_sudo_instruction_message "$mac_user")"
}

preflight_docker() {
    if ! command -v docker >/dev/null 2>&1; then
        die "docker not found — install and start Docker Desktop for Mac"
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

    log "Installing ruamel.yaml + cryptography via pip --target ${PROVISION_PY_DIR}"
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

try_brew_python() {
    command -v brew >/dev/null 2>&1 || return 1
    if ! python3 -c 'import venv' 2>/dev/null; then
        log "Trying brew install python@3 (venv support)"
        brew install python@3 2>/dev/null || brew install python3 2>/dev/null || return 1
    fi
}

manual_provision_python_instructions() {
    cat <<EOF
Could not install Python deps (ruamel.yaml, cryptography).

Option A — pip --target:
  cd ${REPO_DIR}
  python3 -m pip install --target .provision-py ruamel.yaml cryptography
  PYTHONPATH=${REPO_DIR}/.provision-py ./scripts/install-node-macos-docker-desktop.sh ...

Option B — Homebrew + venv:
  brew install python@3
  python3 -m venv ${PROVISION_VENV}
  ${PROVISION_VENV}/bin/pip install ruamel.yaml cryptography
  ./scripts/install-node-macos-docker-desktop.sh ...
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

    command -v python3 >/dev/null 2>&1 || die "python3 not found — brew install python@3"
    command -v curl >/dev/null 2>&1 || die "curl not found"

    if [ "$DRY_RUN" = true ]; then
        printf '[dry-run] pip --target %q OR python3 -m venv %q\n' "$PROVISION_PY_DIR" "$PROVISION_VENV"
        return 0
    fi

    log "Ensuring Python deps for provision-node.sh / process_config.sh"

    if try_pip_target_provision_deps; then
        log "Provision Python deps ready (.provision-py)"
        return 0
    fi

    try_brew_python

    if try_venv_provision_deps standard; then
        log "Provision Python deps ready (venv)"
        return 0
    fi

    if try_venv_provision_deps without-pip; then
        log "Provision Python deps ready (venv --without-pip + get-pip)"
        return 0
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

try_brew_vpn_packages() {
    command -v brew >/dev/null 2>&1 || return 1
    local missing=()
    command -v wg-quick >/dev/null 2>&1 || missing+=(wireguard-tools)
    command -v socat >/dev/null 2>&1 || missing+=(socat)
    command -v yq >/dev/null 2>&1 || missing+=(yq)
    if [ "${#missing[@]}" -eq 0 ]; then
        return 0
    fi
    log "Installing brew packages: ${missing[*]}"
    brew install "${missing[@]}"
}

ensure_vpn_host_tools() {
    if command -v wg-quick >/dev/null 2>&1 && command -v socat >/dev/null 2>&1; then
        return 0
    fi
    if [ "$DRY_RUN" = true ]; then
        printf '[dry-run] brew install wireguard-tools socat\n'
        return 0
    fi
    if try_brew_vpn_packages; then
        log "WireGuard host tools ready (wg-quick, socat)"
        return 0
    fi
    warn "wireguard-tools and/or socat missing — VPN enable from the node app will fail until you run: brew install wireguard-tools socat"
}

ensure_shadowsocks_host_tools() {
    if command -v ssserver >/dev/null 2>&1 && command -v sslocal >/dev/null 2>&1; then
        return 0
    fi
    if [ "$DRY_RUN" = true ]; then
        printf '[dry-run] brew install shadowsocks-rust (optional)\n'
        return 0
    fi
    local ss_lib="${REPO_DIR}/scripts/lib/ensure-shadowsocks-host-packages.sh"
    if [ -f "$ss_lib" ]; then
        # shellcheck source=lib/ensure-shadowsocks-host-packages.sh
        . "$ss_lib"
        ensure_shadowsocks_host_packages || warn "shadowsocks-rust missing — VPN obfuscation unavailable"
        return 0
    fi
    warn "shadowsocks-rust not installed — VPN obfuscation unavailable"
}

preflight_desktop_tools() {
    command -v openssl >/dev/null 2>&1 || warn "openssl not found — brew install openssl"
    command -v curl >/dev/null 2>&1 || warn "curl not found"
    command -v git >/dev/null 2>&1 || warn "git not found — brew install git"
    if ! command -v yq >/dev/null 2>&1; then
        if [ "$DRY_RUN" = true ]; then
            printf '[dry-run] brew install yq\n'
        else
            try_brew_vpn_packages || warn "yq not found — brew install yq (process_config may need it)"
        fi
    fi
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

log "ContinuumDAO MPC node macOS Docker Desktop install (v${INSTALL_SCRIPT_VERSION})"
log "Repo: $REPO_DIR"

export CONTINUUM_INSTALL_DRY_RUN="$DRY_RUN"
install_progress_init desktop
if [ -d "$REPO_DIR/.git" ]; then
    install_progress_mark_done_if clone true
fi

if [ "$DRY_RUN" = false ]; then
    preflight_darwin
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
ensure_shadowsocks_host_tools

if [ "$DRY_RUN" = true ]; then
    printf '[dry-run] bash %s/macos-desktop/install-macos-desktop-host-automation.sh --repo-dir %q\n' "$REPO_DIR" "$REPO_DIR"
else
    log "Installing macOS pending-update host automation (macos-desktop watcher + launchd)"
    bash "$REPO_DIR/macos-desktop/install-macos-desktop-host-automation.sh" --repo-dir "$REPO_DIR"
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

Node provision complete (macOS Docker Desktop).
Repo: ${REPO_DIR}

Docker Desktop: mpc-auth, mongo, continuum-mcp, and node-app containers are listed under Containers.
Config and keys on disk: ${REPO_DIR}/configs.yaml, bootstrap_key/, added_keys/

Next steps:
  1. Attach your node at https://mpa.continuumdao.org
  2. Back up ${REPO_DIR}/bootstrap_key/ if PublicMgtKey was auto-generated
  3. Host restart automation: macos-desktop pending watcher (see ~/mpc-config/macos-desktop/status-watcher.sh). LaunchAgent: com.continuumdao.mpc-auth-watcher.
  4. VPN: enable from the node app VPN panel; host applies via pending-vpn.json + the same watcher (allow UDP 51820 in macOS firewall).
  5. Telegram ngrok: enable from the node app AI Agent webhooks panel; host starts sidecar mpc-auth-telegram-ngrok via pending-telegram-ngrok.json + the same watcher.

EOF
