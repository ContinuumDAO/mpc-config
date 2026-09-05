#!/usr/bin/env bash
# Uninstall a Continuum MPC node installed with Docker Desktop on Windows (WSL2).
#
# AGENT / AUTOMATION:
#   Agent guide: docs/UNINSTALL_NODE.md  ·  Skill: docs/skills/uninstall-node-windows/SKILL.md
#   Keywords: uninstall node, remove node, Windows, WSL, Docker Desktop
#
# Run as root inside WSL (sudo). Does not delete a dedicated mpcnode OS user
# (desktop installs use the WSL login user).
#
#   curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/uninstall-node-docker-desktop.sh" \
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
  sudo ./scripts/uninstall-node-docker-desktop.sh [options]

Windows Docker Desktop + WSL2 uninstall. Run as root inside WSL.
Refuses native Linux and macOS — those use uninstall-node-debian-ubuntu.sh /
uninstall-node-macos-docker-desktop.sh.
Stops compose, removes Continuum images, watcher, Scheduled Tasks, WSL boot
command, /var/lib/mpc-auth-docker, and ~/mpc-config.

Does not uninstall Docker Desktop, WSL, or the login user.

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

stop_wsl_watcher() {
	local stop="${REPO_DIR}/wsl-desktop/stop-watcher.sh"
	if [[ -x "$stop" || -f "$stop" ]]; then
		echo "Stopping WSL pending watcher..." >&2
		if [[ "$UNINSTALL_DRY_RUN" == true ]]; then
			echo "[dry-run] bash ${stop}" >&2
		else
			bash "$stop" || true
		fi
	fi
}

unregister_scheduled_tasks() {
	local helper="${REPO_DIR}/wsl-desktop/unregister-windows-scheduled-task.sh"
	if [[ -f "$helper" ]]; then
		echo "Removing Windows Scheduled Tasks..." >&2
		if [[ "$UNINSTALL_DRY_RUN" == true ]]; then
			echo "[dry-run] bash ${helper}" >&2
			return 0
		fi
		bash "$helper" || true
		return 0
	fi
	if ! command -v powershell.exe >/dev/null 2>&1; then
		echo "warning: powershell.exe not found — delete Scheduled Tasks from Windows if present:" >&2
		echo "  schtasks /Delete /TN ContinuumNodeMpcAuthWatcher /F" >&2
		echo "  schtasks /Delete /TN ContinuumNodeMpcAuthWatcherPoll /F" >&2
		return 0
	fi
	echo "Removing Windows Scheduled Tasks..." >&2
	if [[ "$UNINSTALL_DRY_RUN" == true ]]; then
		echo "[dry-run] powershell.exe schtasks delete ContinuumNodeMpcAuthWatcher{,Poll}" >&2
		return 0
	fi
	powershell.exe -NoProfile -Command \
		'foreach ($t in @("ContinuumNodeMpcAuthWatcher","ContinuumNodeMpcAuthWatcherPoll")) { schtasks /Query /TN $t 2>$null | Out-Null; if ($LASTEXITCODE -eq 0) { schtasks /Delete /TN $t /F } }' \
		|| true
}

remove_wsl_boot_command() {
	local helper="${REPO_DIR}/wsl-desktop/uninstall-wsl-boot-command.sh"
	if [[ -f "$helper" ]]; then
		echo "Clearing WSL [boot] command..." >&2
		if [[ "$UNINSTALL_DRY_RUN" == true ]]; then
			echo "[dry-run] bash ${helper}" >&2
			return 0
		fi
		bash "$helper" || true
		return 0
	fi
	if [[ ! -f /etc/wsl.conf ]]; then
		return 0
	fi
	echo "Clearing WSL [boot] command..." >&2
	if [[ "$UNINSTALL_DRY_RUN" == true ]]; then
		echo "[dry-run] edit /etc/wsl.conf [boot] command" >&2
		return 0
	fi
	python3 - /etc/wsl.conf <<'PY' || true
import configparser, sys
path = sys.argv[1]
parser = configparser.ConfigParser(interpolation=None)
parser.optionxform = str
try:
    parser.read(path)
except configparser.Error:
    sys.exit(0)
if not parser.has_section("boot") or not parser.has_option("boot", "command"):
    sys.exit(0)
command = parser.get("boot", "command")
if "mpc-config" not in command and "wsl-desktop" not in command and "start-watcher" not in command:
    sys.exit(0)
parser.remove_option("boot", "command")
if not parser.options("boot"):
    parser.remove_section("boot")
with open(path, "w", encoding="utf-8") as f:
    parser.write(f, space_around_delimiters=True)
print("Removed Continuum [boot] command from wsl.conf")
PY
}

uninstall_require_host wsl || exit 1
uninstall_require_root || exit 1

echo "ContinuumDAO MPC node uninstall (Windows/WSL) v${UNINSTALL_SCRIPT_VERSION} (dry-run=${UNINSTALL_DRY_RUN})" >&2
echo "Repo: ${REPO_DIR}" >&2

uninstall_print_warnings
uninstall_confirm || exit 1

stop_wsl_watcher
uninstall_compose_down "$REPO_DIR"
uninstall_remove_sidecar
uninstall_remove_images
unregister_scheduled_tasks
remove_wsl_boot_command
uninstall_remove_var_lib
uninstall_remove_repo "$REPO_DIR"

echo "Done. Docker Desktop and the WSL login user were left installed." >&2
echo "Verify: docker ps (no mpc-config containers); test ! -d ${REPO_DIR}." >&2
echo "Optional: docker extension rm continuumdao/continuum-node-installer" >&2
