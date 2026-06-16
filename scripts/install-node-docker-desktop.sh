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

INSTALL_SCRIPT_VERSION="0.1.1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="${MPC_REPO_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"

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
Skips apt docker.io, UFW (--no-firewall), and systemd (--no-systemd).

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
EOF
}

log() { printf '==> %s\n' "$*" >&2; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

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

if [ "$DRY_RUN" = false ]; then
    preflight_docker
    preflight_fresh
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
if [ "$DRY_RUN" = true ]; then
    printf '[dry-run] %q ' "${PROVISION_SH[@]}"
    printf '\n'
else
    cd "$REPO_DIR"
    export PROCESS_CONFIG_SKIP_SYSTEMD=1
    "${PROVISION_SH[@]}"
fi

if [ "$NO_START" = false ]; then
    log "Starting Docker stack (docker compose up -d)"
    if [ "$DRY_RUN" = true ]; then
        printf '[dry-run] cd %q && docker compose up -d\n' "$REPO_DIR"
    else
        cd "$REPO_DIR"
        docker compose up -d
        log "Running containers:"
        docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null || docker ps
    fi
else
    log "Skipping docker compose (--no-start)"
fi

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
