#!/usr/bin/env bash
# Align docker-compose.yml (relay vs client) with configs.yaml before mpc-auth Docker restart/update.
# Invoked from mpc-auth-docker-update.sh (restart-only and full image update paths).
#
# Prints a machine-readable line: compose_role_sync: role=relay|client changed=0|1 needs_full_stack=0|1

set -euo pipefail

LIBEXEC="${LIBEXEC:-/usr/local/libexec/mpc-auth}"
ENV_FILE="${ENV_FILE:-/etc/default/mpc-auth-docker}"
if [[ -f "$ENV_FILE" ]]; then
	# shellcheck disable=SC1090
	source "$ENV_FILE"
fi

mpc_auth_trim() {
	local s="${1:-}"
	s="${s#"${s%%[![:space:]]*}"}"
	s="${s%"${s##*[![:space:]]}"}"
	printf '%s' "$s"
}

workdir="$(mpc_auth_trim "${MPC_AUTH_COMPOSE_WORKDIR:-${MPC_AUTH_COMPOSE_DIR:-}}")"
if [[ -z "$workdir" || ! -d "$workdir" ]]; then
	echo "mpc-auth-sync-compose-role: MPC_AUTH_COMPOSE_WORKDIR unset or missing — skipping compose role sync." >&2
	echo "compose_role_sync: role=unknown changed=0 needs_full_stack=0"
	exit 0
fi

process_config="${MPC_AUTH_PROCESS_CONFIG_SH:-${workdir}/process_config.sh}"
if [[ ! -f "$process_config" ]]; then
	here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
	alt="$(cd "$here/.." && pwd)/process_config.sh"
	if [[ -f "$alt" ]]; then
		process_config="$alt"
	fi
fi
if [[ ! -f "$process_config" ]]; then
	echo "mpc-auth-sync-compose-role: process_config.sh not found (tried ${workdir}/process_config.sh)." >&2
	echo "compose_role_sync: role=unknown changed=0 needs_full_stack=0"
	exit 0
fi

echo "mpc-auth-sync-compose-role: running process_config.sh --sync-compose-role-only in $(printf %q "$workdir")"

_sync_out=""
_sync_rc=0
_sync_out="$(
	cd "$workdir"
	PROCESS_CONFIG_NONINTERACTIVE=1 SKIP_NODE_ADDRESS_MENU=1 \
		bash "$process_config" --sync-compose-role-only --no-firewall --no-systemd 2>&1
)" || _sync_rc=$?

printf '%s\n' "$_sync_out" >&2

_sync_line="$(printf '%s\n' "$_sync_out" | grep -E '^compose_role_sync:' | tail -n 1 || true)"
if [[ -n "$_sync_line" ]]; then
	printf '%s\n' "$_sync_line"
else
	echo "compose_role_sync: role=unknown changed=0 needs_full_stack=0"
fi

if [[ "$_sync_rc" -ne 0 ]]; then
	echo "mpc-auth-sync-compose-role: process_config.sh exited ${_sync_rc} (compose role may be unchanged)." >&2
	exit 0
fi

exit 0
