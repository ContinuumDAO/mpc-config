#!/usr/bin/env bash
# Register launchd LaunchAgent for macOS pending-update watcher.
# Shipped with the Continuum Docker extension (host.binaries).
#
# Usage: continuum-register-launchagent.sh
set -euo pipefail

REPO="${HOME}/mpc-config"
INSTALL="${REPO}/macos-desktop/install-launchagent.sh"

if [[ ! -x "$INSTALL" ]]; then
	echo "error: missing ${INSTALL} — complete node install first" >&2
	exit 1
fi

exec bash "$INSTALL" --repo-dir "$REPO"
