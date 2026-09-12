#!/usr/bin/env bash
# Verify a ContinuumDAO MPC / MPA VPS install matches the one-shot layout.
# Does not modify the system. Safe to run anytime.
#
#   curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/verify-node-install.sh" | bash -s
#   ./scripts/verify-node-install.sh [--repo-dir PATH] [--user NAME]
#
set -euo pipefail

MPC_USER="${MPC_USER:-mpcnode}"
REPO_DIR="${MPC_REPO_DIR:-/home/${MPC_USER}/mpc-config}"
INSTALL_LOG="${INSTALL_LOG:-/var/log/continuumdao-mpc-install.log}"

usage() {
    cat <<'EOF'
Usage: verify-node-install.sh [--repo-dir PATH] [--user NAME]

Checks that a Linux VPS node matches the canonical one-shot layout:
  - OS user mpcnode (or --user)
  - repo at /home/mpcnode/mpc-config (or --repo-dir)
  - configs.yaml present
  - Docker Compose stack for mpc-config running

Exit 0 if all required checks pass; exit 1 otherwise.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --repo-dir)
            REPO_DIR="${2:?}"
            shift 2
            ;;
        --user)
            MPC_USER="${2:?}"
            REPO_DIR="${MPC_REPO_DIR:-/home/${MPC_USER}/mpc-config}"
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

if id "$MPC_USER" >/dev/null 2>&1; then
    ok "OS user ${MPC_USER} exists"
else
    bad "OS user ${MPC_USER} missing (one-shot creates this user)"
fi

if [ -d "$REPO_DIR" ]; then
    ok "Repo directory ${REPO_DIR} exists"
else
    bad "Repo directory ${REPO_DIR} missing (expected /home/${MPC_USER}/mpc-config on VPS)"
fi

if [ -f "${REPO_DIR}/configs.yaml" ]; then
    ok "configs.yaml present"
else
    bad "configs.yaml missing under ${REPO_DIR}"
fi

if [ -d "${REPO_DIR}/.git" ]; then
    ok "Git clone at repo path"
else
    note "No .git at ${REPO_DIR} (non-standard or copied tree)"
fi

if [ -f "$INSTALL_LOG" ]; then
    ok "One-shot install log ${INSTALL_LOG} present"
else
    note "Install log ${INSTALL_LOG} not found (may be manual install or different log path)"
fi

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    project="$(basename "$REPO_DIR")"
    if docker ps --filter "label=com.docker.compose.project=${project}" -q 2>/dev/null | grep -q .; then
        ok "Docker Compose project ${project} has running containers"
    else
        bad "No running containers for compose project ${project}"
    fi
else
    bad "Docker not available or daemon not running"
fi

# Common anti-pattern hints
if [ "$REPO_DIR" != "/home/${MPC_USER}/mpc-config" ]; then
    note "Non-canonical repo path (custom layout — see AgentInstallAntiPatterns.md)"
fi

if [ -d "/root/mpc-config" ] && [ "$REPO_DIR" != "/root/mpc-config" ]; then
    note "Found /root/mpc-config — possible root-only duplicate install"
fi

printf '\nSummary: %s passed, %s failed, %s warnings\n' "$pass" "$fail" "$warn"

if [ "$fail" -gt 0 ]; then
    printf '\nThis node does not match the canonical one-shot VPS layout.\n'
    printf 'Agents: do not continue mesh setup until fixed.\n'
    printf 'See: https://docs.continuumdao.org/ContinuumDAO/MPAWallet/AgentInstallAntiPatterns\n'
    exit 1
fi

printf '\nCanonical VPS layout verified.\n'
exit 0
