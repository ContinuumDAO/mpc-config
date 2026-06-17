#!/usr/bin/env bash
# Desktop local orchestrator: clone mpc-config to ~/mpc-config (or MPC_REPO_DIR), then run
# the OS-specific Docker Desktop install script (Windows WSL or native Linux).
#
# Run inside WSL (Windows) or native Linux shell (extension invokes via host CLI):
#
#   curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/desktop-local-orchestrate.sh" \
#     -o /tmp/continuum-desktop-orchestrate.sh
#   bash /tmp/continuum-desktop-orchestrate.sh --profile windows --node-mgt-key "0x…" --ip "203.0.113.50"
#
set -euo pipefail

ORCHESTRATE_VERSION="0.1.9"
MPC_CONFIG_REPO="${MPC_CONFIG_REPO:-https://github.com/ContinuumDAO/mpc-config.git}"
MPC_CONFIG_REF="${MPC_CONFIG_REF:-main}"
REPO_DIR="${MPC_REPO_DIR:-${HOME}/mpc-config}"
PROFILE=""

INSTALL_ARGS=()

usage() {
    cat <<'EOF'
Usage:
  desktop-local-orchestrate.sh [options]

Clones ContinuumDAO/mpc-config to ~/mpc-config (default) if missing, then runs the
Docker Desktop install script for the selected profile.

Profiles:
  windows   install-node-docker-desktop.sh (WSL2 on Windows Docker Desktop)
  linux     install-node-linux-docker-desktop.sh (native Linux Docker Desktop)

Options passed through to the install script:
  -k, --node-mgt-key ADDR
      --public-mgt-key KEY
  -i, --ip ADDRESS
  -p, --http-port PORT
      --relay-host HOST
      --force-browser-certs
      --no-loopback
      --no-start
      --dry-run

Orchestrator options:
      --profile windows|linux   Install profile (auto-detected when omitted)
      --repo-dir PATH           Clone target (default: ~/mpc-config)
      --repo-url URL            Git remote (default: ContinuumDAO/mpc-config)
      --ref REF                 Git branch/tag (default: main)
  -h, --help

Environment:
  MPC_REPO_DIR, MPC_CONFIG_REPO, MPC_CONFIG_REF
  CONTINUUM_INSTALL_PROGRESS=json   Structured progress for Docker extension
EOF
}

log() { printf '==> %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

require_git() {
    command -v git >/dev/null 2>&1 || die "git not found — install git"
}

detect_profile() {
    if [ -n "$PROFILE" ]; then
        printf '%s' "$PROFILE"
        return 0
    fi
    if [ -n "${WSL_DISTRO_NAME:-}" ] || { [ -r /proc/version ] && grep -qi microsoft /proc/version 2>/dev/null; }; then
        printf 'windows'
        return 0
    fi
    if [ "$(uname -s 2>/dev/null || true)" = "Linux" ]; then
        printf 'linux'
        return 0
    fi
    printf 'windows'
}

clone_repo() {
    if [ -d "$REPO_DIR/.git" ]; then
        log "Using existing mpc-config at $REPO_DIR"
        return 0
    fi
    if [ -e "$REPO_DIR" ]; then
        die "$REPO_DIR exists but is not a git checkout — remove it or pass --repo-dir"
    fi
    log "Cloning mpc-config ($MPC_CONFIG_REF) to $REPO_DIR"
    git clone --branch "$MPC_CONFIG_REF" --depth 1 "$MPC_CONFIG_REPO" "$REPO_DIR"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile)
            PROFILE="${2:?}"
            case "$PROFILE" in
                windows|linux) ;;
                *) die "--profile must be windows or linux (got: $PROFILE)" ;;
            esac
            shift 2
            ;;
        --repo-dir)
            REPO_DIR="${2:?}"
            shift 2
            ;;
        --repo-url)
            MPC_CONFIG_REPO="${2:?}"
            shift 2
            ;;
        --ref)
            MPC_CONFIG_REF="${2:?}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            INSTALL_ARGS+=("$1")
            case "$1" in
                -k|--node-mgt-key|--public-mgt-key|-i|--ip|-p|--http-port|--relay-host)
                    [[ $# -ge 2 ]] || die "option $1 requires a value"
                    INSTALL_ARGS+=("$2")
                    shift 2
                    ;;
                *)
                    shift
                    ;;
            esac
            ;;
    esac
done

PROFILE="$(detect_profile)"
log "Continuum desktop local orchestrator (v${ORCHESTRATE_VERSION})"
log "Profile: $PROFILE"
log "Target repo: $REPO_DIR"

require_git
clone_repo

case "$PROFILE" in
    windows)
        INSTALL_SH="$REPO_DIR/scripts/install-node-docker-desktop.sh"
        [ -x "$INSTALL_SH" ] || [ -f "$INSTALL_SH" ] || die "missing $INSTALL_SH after clone"
        log "Running install-node-docker-desktop.sh as $(whoami) (Windows WSL profile)"
        exec bash "$INSTALL_SH" --repo-dir "$REPO_DIR" "${INSTALL_ARGS[@]}"
        ;;
    linux)
        INSTALL_SH="$REPO_DIR/scripts/install-node-linux-docker-desktop.sh"
        [ -x "$INSTALL_SH" ] || [ -f "$INSTALL_SH" ] || die "missing $INSTALL_SH after clone"
        log "Running install-node-linux-docker-desktop.sh via sudo (Linux Docker Desktop profile)"
        exec sudo -E env CONTINUUM_INSTALL_PROGRESS="${CONTINUUM_INSTALL_PROGRESS:-}" \
            bash "$INSTALL_SH" --repo-dir "$REPO_DIR" --skip-clone "${INSTALL_ARGS[@]}"
        ;;
    *)
        die "unsupported profile: $PROFILE"
        ;;
esac
