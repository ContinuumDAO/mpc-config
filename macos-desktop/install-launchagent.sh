#!/usr/bin/env bash
# Load launchd LaunchAgent for the macOS pending-update watcher (login persistence).
#
# Usage:
#   bash macos-desktop/install-launchagent.sh --repo-dir ~/mpc-config
#
set -euo pipefail

REPO_DIR=""

usage() {
	cat <<'EOF'
Usage:
  bash macos-desktop/install-launchagent.sh --repo-dir PATH
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--repo-dir)
		REPO_DIR="${2:?}"
		shift 2
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "error: unknown option: $1" >&2
		usage
		exit 1
		;;
	esac
done

if [[ -z "$REPO_DIR" ]]; then
	echo "error: --repo-dir required" >&2
	exit 1
fi

REPO_DIR="$(cd "$REPO_DIR" && pwd)"
MACOS_ROOT="${REPO_DIR}/macos-desktop"
TEMPLATE="${MACOS_ROOT}/com.continuumdao.mpc-auth-watcher.plist"
AGENTS_DIR="${HOME}/Library/LaunchAgents"
PLIST_DST="${AGENTS_DIR}/com.continuumdao.mpc-auth-watcher.plist"
LABEL="com.continuumdao.mpc-auth-watcher"

if [[ ! -f "$TEMPLATE" ]]; then
	echo "error: missing ${TEMPLATE}" >&2
	exit 1
fi

mkdir -p "$AGENTS_DIR"
sed "s|__MACOS_DESKTOP_ROOT__|${MACOS_ROOT}|g" "$TEMPLATE" >"$PLIST_DST"

launchctl bootout "gui/$(id -u)/${LABEL}" 2>/dev/null || launchctl unload "$PLIST_DST" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST_DST" 2>/dev/null || launchctl load "$PLIST_DST"

echo "Loaded LaunchAgent ${LABEL}"
echo "  plist: ${PLIST_DST}"
echo "  log:   ${MACOS_ROOT}/launchagent.log"
