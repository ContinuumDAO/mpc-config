#!/usr/bin/env bash
# Local MPC node install for Docker Desktop (Windows WSL / macOS Desktop).
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
else
    CONTINUUM_INSTALL_PROGRESS=off
    export CONTINUUM_INSTALL_PROGRESS
fi

INSTALL_SCRIPT_VERSION="0.1.9"
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

Docker Desktop local profile (not for VPS). Requires docker + docker compose v2.
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
  - Dashboard discovery is patched post-provision so Next.js in Docker reaches mpc-auth via the compose service "app".
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

# Desktop-only: process_config leaves dashboard discovery aliases pointing at host.docker.internal.
# On Docker Desktop (WSL), continuumdao-node-app runs in the dashboard container; mpc-auth is the
# compose service "app" on local-network (same as continuum-mcp MPC_AUTH_URL). Patch env + extra_hosts
# so Maintenance /api/node-read/* can reach PublicDiscoveryPort without NAT hairpin to the WAN IP.
provision_arg_value() {
    local flag="$1"
    local i=0
    while [ "$i" -lt "${#PROVISION_ARGS[@]}" ]; do
        if [ "${PROVISION_ARGS[$i]}" = "$flag" ] && [ $((i + 1)) -lt "${#PROVISION_ARGS[@]}" ]; then
            printf '%s' "${PROVISION_ARGS[$((i + 1))]}"
            return 0
        fi
        i=$((i + 1))
    done
    return 1
}

patch_desktop_dashboard_compose_discovery() {
    local compose_file="$REPO_DIR/docker-compose.yml"
    local config_file="$REPO_DIR/configs.yaml"
    [ -f "$compose_file" ] || die "missing $compose_file after provision"
    [ -f "$config_file" ] || die "missing $config_file after provision"

    local desktop_ip=""
    desktop_ip="$(provision_arg_value -i 2>/dev/null || true)"
    [ -n "$desktop_ip" ] || desktop_ip="$(provision_arg_value --ip 2>/dev/null || true)"

    if [ "$DRY_RUN" = true ]; then
        printf '[dry-run] patch dashboard discovery in %q (WAN IP %q → compose service %q)\n' \
            "$compose_file" "${desktop_ip:-<from configs.yaml>}" "$MPC_AUTH_COMPOSE_SERVICE"
        return 0
    fi

    log "Patching dashboard container discovery env for Docker Desktop (mpc-auth via compose service ${MPC_AUTH_COMPOSE_SERVICE})"

    DESKTOP_COMPOSE_FILE="$compose_file" \
    DESKTOP_CONFIG_FILE="$config_file" \
    DESKTOP_NODE_PUBLIC_IP="$desktop_ip" \
    DESKTOP_MPC_AUTH_SERVICE="$MPC_AUTH_COMPOSE_SERVICE" \
    python3 <<'PYDESKTOP'
import os
import re
import sys
from urllib.parse import urlparse

try:
    from ruamel.yaml import YAML
except ImportError:
    print("error: ruamel.yaml required to patch docker-compose.yml", file=sys.stderr)
    sys.exit(1)

compose_path = os.environ.get("DESKTOP_COMPOSE_FILE", "")
config_path = os.environ.get("DESKTOP_CONFIG_FILE", "")
cli_ip = (os.environ.get("DESKTOP_NODE_PUBLIC_IP") or "").strip()
mpc_auth = (os.environ.get("DESKTOP_MPC_AUTH_SERVICE") or "app").strip() or "app"

if not compose_path or not config_path:
    sys.exit(1)

y = YAML()
y.preserve_quotes = True
y.width = 4096

with open(config_path, encoding="utf-8") as f:
    cfg = y.load(f) or {}

if not isinstance(cfg, dict):
    cfg = {}


def host_from_node_address(url):
    s = str(url or "").strip()
    if not s:
        return None
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", s):
        s = "http://" + s
    try:
        h = urlparse(s).hostname
    except ValueError:
        return None
    return h.strip().lower() if h else None


def collect_node_hosts(cfg_dict):
    hosts = set()
    if cli_ip:
        h = host_from_node_address(cli_ip) or cli_ip.strip().lower()
        if h:
            hosts.add(h)
    groups = cfg_dict.get("MPCGroups")
    if not isinstance(groups, list) or not groups:
        return hosts
    g0 = groups[0]
    if not isinstance(g0, dict):
        return hosts
    na = g0.get("nodeAddresses")
    if not isinstance(na, dict):
        return hosts
    for v in na.values():
        h = host_from_node_address(v)
        if h:
            hosts.add(h)
    return hosts


def merge_aliases(hosts, target):
    parts = [
        f"127.0.0.1={target}",
        f"localhost={target}",
        f"::1={target}",
    ]
    seen = {"127.0.0.1", "localhost", "::1"}
    for h in sorted(hosts):
        if h in seen:
            continue
        parts.append(f"{h}={target}")
        seen.add(h)
    return ",".join(parts)


def normalize_env(env):
    if env is None:
        return {}
    if isinstance(env, dict):
        return dict(env)
    if isinstance(env, list):
        out = {}
        for item in env:
            if isinstance(item, str) and "=" in item:
                k, v = item.split("=", 1)
                out[k] = v
        return out
    return {}


def normalize_extra_hosts(extra):
    if extra is None:
        return []
    if isinstance(extra, list):
        return [str(x) for x in extra]
    return [str(extra)]


hosts = collect_node_hosts(cfg)
aliases = merge_aliases(hosts, mpc_auth)
ipv4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

with open(compose_path, encoding="utf-8") as f:
    compose = y.load(f)

if not isinstance(compose, dict):
    print("error: invalid docker-compose.yml", file=sys.stderr)
    sys.exit(1)

services = compose.get("services")
if not isinstance(services, dict) or "dashboard" not in services:
    print("error: docker-compose.yml has no dashboard service", file=sys.stderr)
    sys.exit(1)

dash = services["dashboard"]
if not isinstance(dash, dict):
    print("error: dashboard service is not a mapping", file=sys.stderr)
    sys.exit(1)

env = normalize_env(dash.get("environment"))
env["NODE_READ_DISCOVERY_LOCAL_BIND_ALIASES"] = aliases
env["NODE_READ_DISCOVERY_HAIRPIN_FALLBACK"] = "1"
env.setdefault("NODE_READ_DISCOVERY_ALLOW_PRIVATE", "1")
env.setdefault("ENABLE_PLAIN_HTTP_ATTACH", "1")
dash["environment"] = env

extra = normalize_extra_hosts(dash.get("extra_hosts"))
have = set()
for entry in extra:
    host = entry.split(":", 1)[0].strip().lower()
    have.add(host)
if "host.docker.internal" not in have:
    extra.append("host.docker.internal:host-gateway")
    have.add("host.docker.internal")
for h in sorted(hosts):
    if ipv4.match(h) and h not in have:
        extra.append(f"{h}:host-gateway")
        have.add(h)
dash["extra_hosts"] = extra

with open(compose_path, "w", encoding="utf-8") as f:
    y.dump(compose, f)

print(f"ok aliases={aliases}", flush=True)
PYDESKTOP
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

log "ContinuumDAO MPC node Docker Desktop install (v${INSTALL_SCRIPT_VERSION})"
log "Repo: $REPO_DIR"

export CONTINUUM_INSTALL_DRY_RUN="$DRY_RUN"
install_progress_init desktop
if [ -d "$REPO_DIR/.git" ]; then
    install_progress_mark_done_if clone true
fi

if [ "$DRY_RUN" = false ]; then
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
else
    cd "$REPO_DIR"
    export PROCESS_CONFIG_SKIP_SYSTEMD=1
    "${PROVISION_SH[@]}"
fi

install_progress_topic_begin desktop-patch
patch_desktop_dashboard_compose_discovery
install_progress_topic_done desktop-patch

PULL_HELPER="${REPO_DIR}/scripts/lib/docker-compose-pull-with-progress.sh"
if [ "$NO_START" = false ]; then
    log "Pulling images and starting Docker stack"
    if [ "$DRY_RUN" = true ]; then
        printf '[dry-run] bash %q %q\n' "$PULL_HELPER" "$REPO_DIR"
        install_progress_topic_begin start-stack
        install_progress_topic_done start-stack
    else
        cd "$REPO_DIR"
        bash "$PULL_HELPER" "$REPO_DIR"
        log "Running containers:"
        docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null || docker ps
    fi
else
    log "Skipping docker compose (--no-start)"
    install_progress_mark_done_if start-stack true
fi

install_progress_finish true

cat <<EOF

Node provision complete (Docker Desktop profile).
Repo: ${REPO_DIR}

Docker Desktop: mpc-auth, mongo, continuum-mcp, and node-app containers are listed under Containers.
Config and keys on disk: ${REPO_DIR}/configs.yaml, bootstrap_key/, added_keys/

Next steps:
  1. Attach your node at https://mpa.continuumdao.org
  2. Back up ${REPO_DIR}/bootstrap_key/ if PublicMgtKey was auto-generated
  3. systemd Maintenance auto-restart is not used on desktop — restart containers manually after config updates

EOF
