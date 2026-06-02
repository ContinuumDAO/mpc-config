#!/usr/bin/env bash
# Fix root-owned files under agent_llm_config/ and user_folder/ (mpc-auth bind mounts).
# Docker runs the app as root by default; new installs use MPC_AUTH_RUN_AS_UID/GID in .env (see process_config.sh).
#
# Usage (on the node, before git pull if ownership blocks checkout):
#   ./scripts/fix-bind-mount-ownership.sh
#   sudo ./scripts/fix-bind-mount-ownership.sh   # when files are root-owned
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -r /etc/default/mpc-auth-docker ]]; then
	# shellcheck source=/dev/null
	. /etc/default/mpc-auth-docker
fi
WORKDIR="${MPC_AUTH_COMPOSE_WORKDIR:-$ROOT}"

if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != root ]]; then
	TARGET_USER="$SUDO_USER"
	TARGET_UID="$(id -u "$SUDO_USER")"
	TARGET_GID="$(id -g "$SUDO_USER")"
else
	TARGET_USER="$(id -un)"
	TARGET_UID="$(id -u)"
	TARGET_GID="$(id -g)"
fi

fix_tree() {
	local dir="$1"
	[[ -e "$dir" ]] || return 0
	if [[ "${EUID:-0}" -eq 0 ]]; then
		chown -R "${TARGET_UID}:${TARGET_GID}" "$dir"
	else
		sudo chown -R "${TARGET_UID}:${TARGET_GID}" "$dir"
	fi
	echo "chown ${TARGET_USER}:${TARGET_GID} → ${dir}"
}

fix_tree "${WORKDIR}/agent_llm_config"
fix_tree "${WORKDIR}/user_folder"

echo "Done. Re-create the app container after setting MPC_AUTH_RUN_AS_UID/GID: docker compose up -d --no-deps --force-recreate app"
