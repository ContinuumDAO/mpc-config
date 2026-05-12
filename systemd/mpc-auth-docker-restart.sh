#!/usr/bin/env bash
# Restart the mpc-auth Docker container named MPC_AUTH_CONTAINER_NAME (defaults in mpc-auth-docker.env).
# If that name does not exist and MPC_AUTH_RESTART_STRICT is unset, detects a lone container whose image
# contains "mpc-auth" (typical continuumdao image across different compose project prefixes).
#
# Typical install: chmod +x; copy to /usr/local/libexec/mpc-auth/;
# systemd: mpc-auth-docker-restart.service references this script.

set -euo pipefail

if [[ -r /etc/default/mpc-auth-docker ]]; then
	# shellcheck source=/dev/null
	. /etc/default/mpc-auth-docker
fi

CONTAINER="${MPC_AUTH_CONTAINER_NAME:-mpc-config-app-1}"

if ! docker ps >/dev/null 2>&1; then
	echo "mpc-auth-docker-restart: cannot talk to Docker (is the daemon running?)" >&2
	exit 1
fi

case "${MPC_AUTH_RESTART_STRICT:-}" in
	1 | true | TRUE | yes | YES)
		exec docker restart "$CONTAINER"
		;;
esac

if docker inspect "$CONTAINER" >/dev/null 2>&1; then
	exec docker restart "$CONTAINER"
fi

# Configured name missing — optionally restart the single container using an mpc-auth image (Compose project varies by host/dir).
hits=()
while IFS=$'\t' read -r cname img; do
	case "$img" in
		*mpc-auth*) hits+=("$cname") ;;
	esac
done < <(docker ps -a --format '{{.Names}}\t{{.Image}}')

if [[ "${#hits[@]}" -eq 1 ]]; then
	echo "mpc-auth-docker-restart: no container named ${CONTAINER}; restarting sole app image container: ${hits[0]}" >&2
	exec docker restart "${hits[0]}"
fi

if [[ "${#hits[@]}" -eq 0 ]]; then
	echo "mpc-auth-docker-restart: No container named ${CONTAINER} and no image matching *mpc-auth* (docker ps -a). Set MPC_AUTH_CONTAINER_NAME to your NAMES column in /etc/default/mpc-auth-docker." >&2
	exit 1
fi

echo "mpc-auth-docker-restart: Multiple app image containers (*mpc-auth*): ${hits[*]}. Set MPC_AUTH_CONTAINER_NAME in /etc/default/mpc-auth-docker." >&2
exit 1
