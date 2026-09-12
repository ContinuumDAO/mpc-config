#!/usr/bin/env bash
# Verify a ContinuumDAO MPC / MPA macOS Docker Desktop install layout.
# Does not modify the system. Safe to run anytime on the Mac.
#
#   curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/verify-node-install-macos-desktop.sh" | bash -s
#   ./scripts/verify-node-install-macos-desktop.sh [--repo-dir PATH]
#
set -euo pipefail

REPO_DIR="${MPC_REPO_DIR:-${HOME}/mpc-config}"
LAUNCH_AGENT_LABEL="com.continuumdao.mpc-auth-watcher"
PLIST_PATH="${HOME}/Library/LaunchAgents/${LAUNCH_AGENT_LABEL}.plist"

usage() {
    cat <<'EOF'
Usage: verify-node-install-macos-desktop.sh [--repo-dir PATH]

Checks that a macOS Docker Desktop node matches the expected layout:
  - repo at ~/mpc-config (or --repo-dir)
  - configs.yaml present
  - Docker Compose stack for mpc-config running
  - LaunchAgent com.continuumdao.mpc-auth-watcher (warn if missing)

Exit 0 if required checks pass; exit 1 otherwise.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --repo-dir)
            REPO_DIR="${2:?}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "error: unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

pass=0
fail=0
warn=0

ok() {
    printf 'OK   %s\n' "$*"
    pass=$((pass + 1))
}

bad() {
    printf 'FAIL %s\n' "$*"
    fail=$((fail + 1))
}

note() {
    printf 'WARN %s\n' "$*"
    warn=$((warn + 1))
}

case "$(uname -s)" in
    Darwin) ok "Running on macOS" ;;
    *)
        note "Not macOS ($(uname -s)) — this script targets Docker Desktop on Mac"
        ;;
esac

CANONICAL="${HOME}/mpc-config"
if [ -d "$REPO_DIR" ]; then
    ok "Repo directory ${REPO_DIR} exists"
else
    bad "Repo directory ${REPO_DIR} missing (expected ~/mpc-config on Mac)"
fi

if [ "$REPO_DIR" != "$CANONICAL" ]; then
    note "Non-canonical repo path (expected ${CANONICAL})"
fi

if [ -f "${REPO_DIR}/configs.yaml" ]; then
    ok "configs.yaml present"
else
    bad "configs.yaml missing under ${REPO_DIR}"
fi

if [ -d "${REPO_DIR}/.git" ]; then
    ok "Git clone at repo path"
else
    note "No .git at ${REPO_DIR} (extension or copied tree)"
fi

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    project="$(basename "$REPO_DIR")"
    if docker ps --filter "label=com.docker.compose.project=${project}" -q 2>/dev/null | grep -q .; then
        ok "Docker Compose project ${project} has running containers"
    else
        bad "No running containers for compose project ${project} (is Docker Desktop running?)"
    fi
else
    bad "Docker not available or Docker Desktop daemon not running"
fi

if launchctl list 2>/dev/null | grep -q "${LAUNCH_AGENT_LABEL}"; then
    ok "LaunchAgent ${LAUNCH_AGENT_LABEL} loaded"
elif [ -f "$PLIST_PATH" ]; then
    note "LaunchAgent plist exists but label not loaded — try: launchctl bootstrap gui/$(id -u) ${PLIST_PATH}"
else
    note "LaunchAgent ${LAUNCH_AGENT_LABEL} not found (common after shell-only install; extension path registers it)"
fi

if [ -d "${REPO_DIR}/macos-desktop" ]; then
    ok "macos-desktop host automation directory present"
else
    note "macos-desktop/ missing (may be incomplete install)"
fi

printf '\nSummary: %s passed, %s failed, %s warnings\n' "$pass" "$fail" "$warn"

if [ "$fail" -gt 0 ]; then
    printf '\nThis Mac node does not match the expected Docker Desktop layout.\n'
    printf 'Agents: do not declare install complete until fixed.\n'
    printf 'See: https://docs.continuumdao.org/ContinuumDAO/MPAWallet/AgentInstallAntiPatterns\n'
    exit 1
fi

printf '\nmacOS Docker Desktop layout verified.\n'
exit 0
