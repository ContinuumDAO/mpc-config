#!/usr/bin/env bash
# Start udp2raw server for WireGuard transport (fake TCP). Reads server.env from mpc-auth.
set -euo pipefail
ENV_FILE="${MPC_AUTH_UDP2RAW_SERVER_ENV:-/var/lib/mpc-auth-docker/udp2raw/server.env}"
if [[ ! -f "$ENV_FILE" ]]; then
	echo "mpc-auth-udp2raw-run: missing ${ENV_FILE}" >&2
	exit 1
fi
set -a
# shellcheck source=/dev/null
source "$ENV_FILE"
set +a
: "${LISTEN_PORT:?}"
: "${WG_PORT:?}"
: "${KEY:?}"
exec udp2raw -s -l "0.0.0.0:${LISTEN_PORT}" -r "127.0.0.1:${WG_PORT}" -k "${KEY}" --raw-mode faketcp -a
