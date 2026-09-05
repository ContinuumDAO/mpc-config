#!/usr/bin/env bash
# Uninstall a Continuum MPC node installed with Docker Desktop on macOS.
#
# AGENT / AUTOMATION:
#   Agent guide: docs/UNINSTALL_NODE.md  ·  Skill: docs/skills/uninstall-node-macos/SKILL.md
#   Keywords: uninstall node, remove node, macOS, Docker Desktop, launchd
#
# Run as root (sudo). Does not delete the macOS login user.
#
#   curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/uninstall-node-macos-docker-desktop.sh" \
#     | sudo bash -s -- --yes
#
set -euo pipefail

UNINSTALL_SCRIPT_VERSION="1.0.0"
MPC_CONFIG_REF="${MPC_CONFIG_REF:-main}"

UNINSTALL_YES=false
UNINSTALL_DRY_RUN=false
UNINSTALL_KEEP_IMAGES=false
UNINSTALL_KEEP_REPO=false
REPO_DIR="${MPC_REPO_DIR:-}"

CONTINUUM_UNINSTALL_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"

_load_uninstall_common() {
	local lib=""
	if [ -n "$CONTINUUM_UNINSTALL_SCRIPT_DIR" ] && [ -f "${CONTINUUM_UNINSTALL_SCRIPT_DIR}/lib/uninstall-node-common.sh" ]; then
		lib="${CONTINUUM_UNINSTALL_SCRIPT_DIR}/lib/uninstall-node-common.sh"
	fi
	if [ -z "$lib" ]; then
		local tmp
		tmp="$(mktemp -d 2>/dev/null || echo "/tmp/continuum-uninstall-$$")"
		mkdir -p "${tmp}/lib"
		if curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/${MPC_CONFIG_REF}/scripts/lib/uninstall-node-common.sh" \
			-o "${tmp}/lib/uninstall-node-common.sh"; then
			lib="${tmp}/lib/uninstall-node-common.sh"
			CONTINUUM_UNINSTALL_SCRIPT_DIR="$tmp"
		fi
	fi
	if [ -z "$lib" ] || [ ! -f "$lib" ]; then
		echo "error: could not load scripts/lib/uninstall-node-common.sh" >&2
		exit 1
	fi
	# shellcheck source=lib/uninstall-node-common.sh
	. "$lib"
}

_load_uninstall_common

usage() {
	cat <<'EOF'
Usage:
  sudo ./scripts/uninstall-node-macos-docker-desktop.sh [options]

macOS Docker Desktop uninstall. Run as root.
Refuses Linux and WSL — those use uninstall-node-debian-ubuntu.sh /
uninstall-node-docker-desktop.sh.
Stops compose, removes Continuum images, LaunchAgent, watcher,
/var/lib/mpc-auth-docker, and ~/mpc-config.

Does not uninstall Docker Desktop, Homebrew packages, or the login user.

Options:
      --yes                 Skip interactive prompts (AI agents)
      --dry-run             Print actions without changing the system
      --repo-dir PATH       mpc-config path (default: ~login/mpc-config)
      --keep-images         Leave Docker images on the host
      --keep-repo           Leave the mpc-config directory
  -h, --help                Show this help

Environment:
  MPC_CONFIG_REF, MPC_REPO_DIR
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--yes | -y) UNINSTALL_YES=true ;;
	--dry-run) UNINSTALL_DRY_RUN=true ;;
	--keep-images) UNINSTALL_KEEP_IMAGES=true ;;
	--keep-repo) UNINSTALL_KEEP_REPO=true ;;
	--repo-dir)
		REPO_DIR="${2:?missing value for --repo-dir}"
		shift
		;;
	--repo-dir=*) REPO_DIR="${1#*=}" ;;
	-h | --help)
		usage
		exit 0
		;;
	-*)
		echo "error: unknown option: $1 (try --help)" >&2
		exit 1
		;;
	*)
		echo "error: unexpected argument: $1 (try --help)" >&2
		exit 1
		;;
	esac
	shift
done

export UNINSTALL_YES UNINSTALL_DRY_RUN UNINSTALL_KEEP_IMAGES UNINSTALL_KEEP_REPO

if [[ -z "$REPO_DIR" ]]; then
	REPO_DIR="$(uninstall_login_home)/mpc-config"
fi

LOGIN_USER="$(uninstall_login_user)"
LOGIN_HOME="$(uninstall_login_home)"
LABEL="com.continuumdao.mpc-auth-watcher"
PLIST_DST="${LOGIN_HOME}/Library/LaunchAgents/${LABEL}.plist"

stop_macos_watcher() {
	local stop="${REPO_DIR}/macos-desktop/stop-watcher.sh"
	if [[ -f "$stop" ]]; then
		echo "Stopping macOS pending watcher..." >&2
		if [[ "$UNINSTALL_DRY_RUN" == true ]]; then
			echo "[dry-run] bash ${stop}" >&2
		else
			# Watcher runs as the login user, not root.
			if [[ "$LOGIN_USER" != "root" ]] && command -v sudo >/dev/null 2>&1; then
				sudo -u "$LOGIN_USER" bash "$stop" || true
			else
				bash "$stop" || true
			fi
		fi
	fi
}

remove_launchagent() {
	local uid
	uid="$(id -u "$LOGIN_USER" 2>/dev/null || true)"
	echo "Removing LaunchAgent ${LABEL}..." >&2
	if [[ "$UNINSTALL_DRY_RUN" == true ]]; then
		echo "[dry-run] launchctl bootout gui/${uid:-501}/${LABEL}" >&2
		echo "[dry-run] rm -f ${PLIST_DST}" >&2
		return 0
	fi
	if [[ -n "$uid" ]] && command -v launchctl >/dev/null 2>&1; then
		launchctl bootout "gui/${uid}/${LABEL}" 2>/dev/null || true
		if [[ "$LOGIN_USER" != "root" ]]; then
			sudo -u "$LOGIN_USER" launchctl bootout "gui/${uid}/${LABEL}" 2>/dev/null || true
			sudo -u "$LOGIN_USER" launchctl unload "$PLIST_DST" 2>/dev/null || true
		fi
	fi
	uninstall_run rm -f "$PLIST_DST"
}

uninstall_require_host macos || exit 1
uninstall_require_root || exit 1

echo "ContinuumDAO MPC node uninstall (macOS) v${UNINSTALL_SCRIPT_VERSION} (dry-run=${UNINSTALL_DRY_RUN})" >&2
echo "Repo: ${REPO_DIR} (login user: ${LOGIN_USER})" >&2

uninstall_print_warnings
uninstall_confirm || exit 1

stop_macos_watcher
remove_launchagent
uninstall_compose_down "$REPO_DIR"
uninstall_remove_sidecar
uninstall_remove_images
uninstall_remove_var_lib
uninstall_remove_repo "$REPO_DIR"

echo "Done. Docker Desktop, Homebrew, and the macOS login user were left installed." >&2
echo "Verify: docker ps (no mpc-config containers); test ! -d ${REPO_DIR}; LaunchAgent ${LABEL} gone." >&2
echo "Optional: docker extension rm continuumdao/continuum-node-installer" >&2
