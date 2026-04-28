#!/usr/bin/env bash
# Restart only the mpc-auth container (matches MPC_AUTH_CONTAINER_NAME).
# Typical install: chmod +x; copy to /usr/local/libexec/mpc-auth/;
# systemd: mpc-auth-docker-restart.service references this script.

set -euo pipefail

if [[ -r /etc/default/mpc-auth-docker ]]; then
	# shellcheck source=/dev/null
	. /etc/default/mpc-auth-docker
fi

CONTAINER="${MPC_AUTH_CONTAINER_NAME:-mpc-auth}"

exec docker restart "$CONTAINER"
