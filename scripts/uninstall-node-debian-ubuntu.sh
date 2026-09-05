#!/usr/bin/env bash
# One-shot MPC / MPA wallet node uninstall for Ubuntu/Debian (run as root on the target).
#
# AGENT / AUTOMATION:
#   Canonical script to REMOVE a ContinuumDAO mpc-auth node on a VPS (or Linux Docker Desktop).
#   Agent guide: docs/UNINSTALL_NODE.md  ·  Skill: docs/skills/uninstall-node-linux/SKILL.md
#   Keywords: uninstall node, remove node, decommission, wipe mpcnode, MPA wallet
#
# Typical use (paste on VPS after ssh root@VPS_IP):
#   curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/main/scripts/uninstall-node-debian-ubuntu.sh" \
#     | bash -s -- --yes
#
# Or from your PC (curl runs ON the VPS):
#   ssh root@203.0.113.50 'curl -fsSL "…/uninstall-node-debian-ubuntu.sh" | bash -s -- --yes'
#
# Interactive by default (TTY). Agents skip prompts with --yes after warning the operator.
#
set -euo pipefail

UNINSTALL_SCRIPT_VERSION="1.0.0"
MPC_CONFIG_REF="${MPC_CONFIG_REF:-main}"

UNINSTALL_YES=false
UNINSTALL_DRY_RUN=false
UNINSTALL_KEEP_IMAGES=false
UNINSTALL_KEEP_REPO=false
UNINSTALL_KEEP_USER=false
PROFILE=""
MPC_USER="${MPC_USER:-mpcnode}"
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
  curl -fsSL "https://raw.githubusercontent.com/ContinuumDAO/mpc-config/REF/scripts/uninstall-node-debian-ubuntu.sh" \
    | bash -s -- [options]

Run as root on an Ubuntu/Debian VPS (or a Linux Docker Desktop host).
Refuses Windows/WSL and macOS — those use uninstall-node-docker-desktop.sh /
uninstall-node-macos-docker-desktop.sh.
Stops the compose stack, removes Continuum Docker images, systemd helpers,
/var/lib/mpc-auth-docker, the mpc-config folder, and (VPS profile) the mpcnode user.

Does not uninstall Docker Engine, UFW, WireGuard, or apt packages.

Options:
      --yes                 Skip interactive prompts (AI agents). Still prints warnings.
      --dry-run             Print actions without changing the system
      --profile vps|linux-desktop
                            vps: /home/mpcnode/mpc-config + remove mpcnode (default)
                            linux-desktop: ~/mpc-config, keep the login user
      --mpc-user USER       OS user to remove on VPS (default: mpcnode)
      --repo-dir PATH       mpc-config path (default depends on profile)
      --keep-user           Do not delete the mpcnode user / sudoers drop-in
      --keep-images         Leave Docker images on the host
      --keep-repo           Leave the mpc-config directory
  -h, --help                Show this help

Environment:
  MPC_CONFIG_REF, MPC_USER, MPC_REPO_DIR

Examples:
  bash -s -- --yes
  bash -s -- --dry-run
  bash -s -- --profile linux-desktop --yes
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--yes | -y) UNINSTALL_YES=true ;;
	--dry-run) UNINSTALL_DRY_RUN=true ;;
	--keep-images) UNINSTALL_KEEP_IMAGES=true ;;
	--keep-repo) UNINSTALL_KEEP_REPO=true ;;
	--keep-user) UNINSTALL_KEEP_USER=true ;;
	--profile)
		PROFILE="${2:?missing value for --profile}"
		shift
		;;
	--profile=*) PROFILE="${1#*=}" ;;
	--mpc-user)
		MPC_USER="${2:?missing value for --mpc-user}"
		shift
		;;
	--mpc-user=*) MPC_USER="${1#*=}" ;;
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

resolve_profile() {
	if [[ -n "$PROFILE" ]]; then
		case "$PROFILE" in
		vps | linux-desktop) return 0 ;;
		*)
			echo "error: --profile must be vps or linux-desktop" >&2
			exit 1
			;;
		esac
	fi
	if [[ -f /home/mpcnode/mpc-config/configs.yaml ]] || id mpcnode >/dev/null 2>&1; then
		PROFILE="vps"
	else
		PROFILE="linux-desktop"
	fi
}

resolve_repo_dir() {
	if [[ -n "$REPO_DIR" ]]; then
		return 0
	fi
	if [[ "$PROFILE" == "vps" ]]; then
		REPO_DIR="/home/${MPC_USER}/mpc-config"
	else
		REPO_DIR="$(uninstall_login_home)/mpc-config"
	fi
}

run_systemd_uninstall() {
	local helper="" tmp
	if [[ -n "$CONTINUUM_UNINSTALL_SCRIPT_DIR" && -f "${CONTINUUM_UNINSTALL_SCRIPT_DIR}/uninstall-mpc-auth-docker-systemd.sh" ]]; then
		helper="${CONTINUUM_UNINSTALL_SCRIPT_DIR}/uninstall-mpc-auth-docker-systemd.sh"
	elif [[ -f "${REPO_DIR}/scripts/uninstall-mpc-auth-docker-systemd.sh" ]]; then
		helper="${REPO_DIR}/scripts/uninstall-mpc-auth-docker-systemd.sh"
	fi
	if [[ -z "$helper" ]]; then
		tmp="$(mktemp)"
		if uninstall_fetch_raw "scripts/uninstall-mpc-auth-docker-systemd.sh" "$tmp"; then
			chmod +x "$tmp"
			helper="$tmp"
		fi
	fi
	if [[ -z "$helper" || ! -f "$helper" ]]; then
		echo "warning: systemd uninstall helper not found — skipping unit teardown." >&2
		return 0
	fi
	if ! command -v systemctl >/dev/null 2>&1; then
		echo "systemctl not found — skipping systemd teardown." >&2
		return 0
	fi
	local args=(--purge-var-lib --purge-env-backups)
	if [[ "$UNINSTALL_DRY_RUN" == true ]]; then
		args+=(--dry-run)
	fi
	echo "Removing mpc-auth systemd units and libexec..." >&2
	bash "$helper" "${args[@]}" || true
}

remove_mpcnode_user() {
	if [[ "$PROFILE" != "vps" || "$UNINSTALL_KEEP_USER" == true || "$UNINSTALL_KEEP_REPO" == true ]]; then
		if [[ "$UNINSTALL_KEEP_USER" == true || "$UNINSTALL_KEEP_REPO" == true ]]; then
			echo "Keeping OS user ${MPC_USER}." >&2
		fi
		return 0
	fi
	if [[ "$(id -un)" == "$MPC_USER" ]]; then
		echo "error: refusing to delete the user you are running as (${MPC_USER})" >&2
		return 1
	fi
	if ! id "$MPC_USER" >/dev/null 2>&1; then
		echo "No OS user ${MPC_USER}." >&2
		return 0
	fi
	if pgrep -u "$MPC_USER" >/dev/null 2>&1; then
		echo "error: processes still running as ${MPC_USER}. Stop them, then re-run." >&2
		pgrep -u "$MPC_USER" -a >&2 || true
		return 1
	fi
	if [[ -f "/etc/sudoers.d/${MPC_USER}" ]]; then
		echo "Removing /etc/sudoers.d/${MPC_USER}..." >&2
		uninstall_run rm -f "/etc/sudoers.d/${MPC_USER}"
	fi
	echo "Removing OS user ${MPC_USER}..." >&2
	uninstall_run userdel -r "$MPC_USER" || uninstall_run userdel "$MPC_USER" || true
}

uninstall_require_host linux || exit 1
uninstall_require_root || exit 1
resolve_profile
resolve_repo_dir

echo "ContinuumDAO MPC node uninstall v${UNINSTALL_SCRIPT_VERSION} (profile=${PROFILE}, dry-run=${UNINSTALL_DRY_RUN})" >&2
echo "Repo: ${REPO_DIR}" >&2

uninstall_print_warnings
uninstall_confirm || exit 1

uninstall_compose_down "$REPO_DIR"
uninstall_remove_sidecar
uninstall_remove_images
run_systemd_uninstall
uninstall_remove_var_lib
uninstall_remove_install_logs
uninstall_remove_repo "$REPO_DIR"
remove_mpcnode_user

echo "Done. Docker Engine and OS packages were left installed." >&2
echo "Verify: docker ps (no mpc-config containers); test ! -d ${REPO_DIR}; id ${MPC_USER} should fail on VPS." >&2
