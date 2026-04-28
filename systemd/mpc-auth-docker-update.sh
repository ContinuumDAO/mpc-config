#!/usr/bin/env bash
# Stop mpc-auth container, force-remove its image reference, pull MPC_AUTH_IMAGE:TAG, verify digest, then compose.
#
# TAG: first CLI arg (Docker tag / systemd template instance); default latest.
# Expected digest: second CLI arg OR env MPC_AUTH_EXPECTED_DIGEST (sha256:... from POST /updateMpcAuth).
#   When set, pulled image must appear in docker image RepoDigests matching that digest or the script exits 1 before compose.
#
# Post-pull: if MPC_AUTH_POST_UPDATE_CMD is set (non-blank), it runs as-is. Otherwise the default is built from
#   docker compose OR docker-compose (whichever exists), plus MPC_AUTH_COMPOSE_WORKDIR and MPC_AUTH_COMPOSE_SERVICE.
#
# Order: capture running image → stop → rm container → rmi force that image → docker pull → digest verify → compose.

set -euo pipefail

if [[ -r /etc/default/mpc-auth-docker ]]; then
	# shellcheck source=/dev/null
	. /etc/default/mpc-auth-docker
fi

CONTAINER="${MPC_AUTH_CONTAINER_NAME:-mpc-config_app_1}"
REPO="${MPC_AUTH_IMAGE:-continuumdao/mpc-auth}"
TAG="${1:-latest}"
EXPECTED_DIGEST="${2:-}"
if [[ -z "$EXPECTED_DIGEST" ]]; then
	EXPECTED_DIGEST="${MPC_AUTH_EXPECTED_DIGEST:-}"
fi

mpc_auth_trim() {
	local s="${1:-}"
	s="${s#"${s%%[![:space:]]*}"}"
	s="${s%"${s##*[![:space:]]}"}"
	printf '%s' "$s"
}

OLD_IMAGE=""
if docker container inspect "$CONTAINER" &>/dev/null; then
	OLD_IMAGE="$(docker inspect -f '{{.Config.Image}}' "$CONTAINER")"
	echo "Stopping container $CONTAINER"
	docker stop "$CONTAINER"
	echo "Removing container $CONTAINER"
	docker rm "$CONTAINER"
fi

if [[ -n "$OLD_IMAGE" ]]; then
	echo "Removing image (force): $OLD_IMAGE"
	docker rmi --force "$OLD_IMAGE" || true
fi

NEW_REF="${REPO}:${TAG}"
echo "Pulling $NEW_REF"
docker pull "$NEW_REF"

if [[ -n "${EXPECTED_DIGEST:-}" ]]; then
	exp="${EXPECTED_DIGEST#sha256:}"
	echo "Verifying pulled image digest (expected sha256:${exp}…)"
	FOUND=0
	tmp_rd="$(mktemp)"
	docker image inspect "$NEW_REF" --format '{{range .RepoDigests}}{{.}}{{"\n"}}{{end}}' >"$tmp_rd" || true
	while IFS= read -r line || [[ -n "${line:-}" ]]; do
		line="${line//$'\r'/}"
		[[ -z "$line" ]] && continue
		if [[ "$line" == *"@sha256:${exp}" ]]; then
			FOUND=1
			echo "RepoDigest match: $line"
			break
		fi
	done <"$tmp_rd"
	rm -f "$tmp_rd"
	if [[ "$FOUND" -ne 1 ]]; then
		echo "error: pulled image $NEW_REF does not match expected digest (sha256:${exp}). Refusing post-update compose." >&2
		docker image inspect "$NEW_REF" --format '{{json .RepoDigests}}' >&2 || true
		exit 1
	fi
else
	echo "WARNING: no EXPECTED_DIGEST/MPC_AUTH_EXPECTED_DIGEST — skipping digest check (set from POST /updateMpcAuth registryDigest before production use)."
fi

mpc_auth_run_default_compose_up() {
	local workdir svc
	workdir="$(mpc_auth_trim "${MPC_AUTH_COMPOSE_WORKDIR:-${MPC_AUTH_COMPOSE_DIR:-}}")"
	svc="$(mpc_auth_trim "${MPC_AUTH_COMPOSE_SERVICE:-app}")"
	[[ -z "$svc" ]] && svc="app"
	if docker compose version &>/dev/null 2>&1; then
		if [[ -n "$workdir" ]]; then
			echo "Running: cd $(printf %q "$workdir") && docker compose up -d $(printf %q "$svc")"
			(cd "$workdir" && docker compose up -d "$svc")
		else
			echo "WARNING: MPC_AUTH_COMPOSE_WORKDIR unset — running docker compose from cwd ($(pwd))." >&2
			echo "Running: docker compose up -d $(printf %q "$svc")"
			docker compose up -d "$svc"
		fi
		return 0
	fi
	if command -v docker-compose &>/dev/null 2>&1; then
		if [[ -n "$workdir" ]]; then
			echo "Running: cd $(printf %q "$workdir") && docker-compose up -d $(printf %q "$svc")"
			(cd "$workdir" && docker-compose up -d "$svc")
		else
			echo "WARNING: MPC_AUTH_COMPOSE_WORKDIR unset — running docker-compose from cwd ($(pwd))." >&2
			echo "Running: docker-compose up -d $(printf %q "$svc")"
			docker-compose up -d "$svc"
		fi
		return 0
	fi
	return 1
}

explicit="$(mpc_auth_trim "${MPC_AUTH_POST_UPDATE_CMD:-}")"
if [[ -n "$explicit" ]]; then
	echo "Running MPC_AUTH_POST_UPDATE_CMD: $explicit"
	env TAG="$TAG" MPC_AUTH_CONTAINER_NAME="$CONTAINER" MPC_AUTH_IMAGE="$REPO" MPC_AUTH_EXPECTED_DIGEST="${EXPECTED_DIGEST:-}" bash -lc "$explicit"
elif mpc_auth_run_default_compose_up; then
	:
else
	echo "Note: skipping post-pull compose — MPC_AUTH_POST_UPDATE_CMD unset and neither 'docker compose' nor docker-compose is available." >&2
fi

echo "Update complete for $NEW_REF."
