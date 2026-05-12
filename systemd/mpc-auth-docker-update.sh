#!/usr/bin/env bash
# (A) Full update: stop mpc-auth container, rmi old ref, pull, digest verify, compose up -d --no-deps --force-recreate (app only).
# (B) Restart-only: no pull — docker compose restart, or compose up -d --no-deps --force-recreate when
#     MPC_AUTH_PENDING_FORCE_RECREATE=1 (set from pending-update.json by mpc-auth-apply-pending-update.sh).
#
# TAG: first CLI arg (Docker tag / systemd template instance); default latest.
# Expected digest: second CLI arg OR env MPC_AUTH_EXPECTED_DIGEST — only used on full update (not restart-only).
#
# Post-pull / post-restart: if MPC_AUTH_POST_UPDATE_CMD is set (non-blank), it runs instead of default compose helpers.

set -euo pipefail

if [[ -r /etc/default/mpc-auth-docker ]]; then
	# shellcheck source=/dev/null
	. /etc/default/mpc-auth-docker
fi

CONTAINER="${MPC_AUTH_CONTAINER_NAME:-mpc-config-app-1}"
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

RESTART_ONLY="$(mpc_auth_trim "${MPC_AUTH_PENDING_RESTART_ONLY:-0}")"
FORCE_RECREATE="$(mpc_auth_trim "${MPC_AUTH_PENDING_FORCE_RECREATE:-0}")"

# systemd oneshots often have WorkingDirectory=/; never run "docker compose" from cwd without an explicit project dir.
mpc_auth_compose_workdir_resolve() {
	printf '%s' "$(mpc_auth_trim "${MPC_AUTH_COMPOSE_WORKDIR:-${MPC_AUTH_COMPOSE_DIR:-}}")"
}

mpc_auth_require_compose_workdir() {
	local w
	w="$(mpc_auth_compose_workdir_resolve)"
	if [[ -z "$w" ]]; then
		echo "error: set MPC_AUTH_COMPOSE_WORKDIR (or MPC_AUTH_COMPOSE_DIR) in /etc/default/mpc-auth-docker to the directory containing docker-compose.yml." >&2
		echo "  systemd runs this script with a non-project cwd; compose must not run without an absolute workdir." >&2
		echo "  Or set MPC_AUTH_POST_UPDATE_CMD to a full command (e.g. cd /path/to/mpc-config && docker compose up -d app)." >&2
		exit 1
	fi
	if [[ ! -d "$w" ]]; then
		echo "error: MPC_AUTH_COMPOSE_WORKDIR is not a directory: $w" >&2
		exit 1
	fi
}

mpc_auth_run_restart_or_recreate() {
	local workdir svc explicit
	svc="$(mpc_auth_trim "${MPC_AUTH_COMPOSE_SERVICE:-app}")"
	[[ -z "$svc" ]] && svc="app"
	explicit="$(mpc_auth_trim "${MPC_AUTH_POST_UPDATE_CMD:-}")"
	if [[ -n "$explicit" ]]; then
		echo "Running MPC_AUTH_POST_UPDATE_CMD (restart-only context): $explicit"
		if ! env TAG="$TAG" MPC_AUTH_CONTAINER_NAME="$CONTAINER" MPC_AUTH_IMAGE="$REPO" MPC_AUTH_EXPECTED_DIGEST="${EXPECTED_DIGEST:-}" \
			MPC_AUTH_PENDING_RESTART_ONLY="${RESTART_ONLY}" MPC_AUTH_PENDING_FORCE_RECREATE="${FORCE_RECREATE}" bash -lc "$explicit"; then
			echo "error: MPC_AUTH_POST_UPDATE_CMD exited with an error." >&2
			return 1
		fi
		return 0
	fi
	# --no-deps: only recreate/restart the app service — never touch mongodb/mosquitto (avoids v1 compose
	# trying to recreate dependencies and corrupting volume state).
	if docker compose version &>/dev/null 2>&1; then
		mpc_auth_require_compose_workdir
		workdir="$(mpc_auth_compose_workdir_resolve)"
		if [[ "$FORCE_RECREATE" == "1" ]]; then
			echo "Running: cd $(printf %q "$workdir") && docker compose up -d --no-deps --force-recreate $(printf %q "$svc")"
			if ! (cd "$workdir" && docker compose up -d --no-deps --force-recreate "$svc"); then
				echo "error: docker compose up failed." >&2
				return 1
			fi
		else
			echo "Running: cd $(printf %q "$workdir") && docker compose restart $(printf %q "$svc")"
			if ! (cd "$workdir" && docker compose restart "$svc"); then
				echo "error: docker compose restart failed." >&2
				return 1
			fi
		fi
		return 0
	fi
	if command -v docker-compose &>/dev/null 2>&1; then
		echo "WARNING: using legacy docker-compose (v1). Prefer Docker Compose v2: \`docker compose\` plugin — v1 often breaks on modern Docker (e.g. KeyError 'ContainerConfig') and may recreate dependency services without --no-deps." >&2
		mpc_auth_require_compose_workdir
		workdir="$(mpc_auth_compose_workdir_resolve)"
		if [[ "$FORCE_RECREATE" == "1" ]]; then
			echo "Running: cd $(printf %q "$workdir") && docker-compose up -d --no-deps --force-recreate $(printf %q "$svc")"
			if ! (cd "$workdir" && docker-compose up -d --no-deps --force-recreate "$svc"); then
				echo "error: docker-compose up failed." >&2
				return 1
			fi
		else
			echo "Running: cd $(printf %q "$workdir") && docker-compose restart $(printf %q "$svc")"
			if ! (cd "$workdir" && docker-compose restart "$svc"); then
				echo "error: docker-compose restart failed." >&2
				return 1
			fi
		fi
		return 0
	fi
	if docker container inspect "$CONTAINER" &>/dev/null; then
		echo "No docker compose — falling back to: docker restart $(printf %q "$CONTAINER")"
		if ! docker restart "$CONTAINER"; then
			echo "error: docker restart failed." >&2
			return 1
		fi
		return 0
	fi
	echo "error: restart-only mode but no compose and container $(printf %q "$CONTAINER") not found." >&2
	return 1
}

if [[ "$RESTART_ONLY" == "1" ]]; then
	echo "MPC_AUTH_PENDING_RESTART_ONLY=1 — restarting/recreating without pull/rmi (tag=$TAG)."
	mpc_auth_run_restart_or_recreate
	echo "Restart-only complete (tag $TAG)."
	exit 0
fi

OLD_IMAGE=""
if docker container inspect "$CONTAINER" &>/dev/null; then
	OLD_IMAGE="$(docker inspect -f '{{.Config.Image}}' "$CONTAINER")"
	echo "Stopping container $CONTAINER"
	docker stop "$CONTAINER"
	echo "Removing container $CONTAINER"
	docker rm "$CONTAINER"
else
	echo "WARNING: container $(printf %q "$CONTAINER") not found — stop/rm skipped. If this name does not match your Compose service," >&2
	echo "  set MPC_AUTH_CONTAINER_NAME in /etc/default/mpc-auth-docker. Post-pull compose still runs up -d --no-deps --force-recreate for the app service only." >&2
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

# mpc-config compose defaults to image: ${REPO}:latest. We pull and verify ${REPO}:${TAG} (e.g. v1.1.1);
# `docker compose up` does not switch the service to that tag unless we align local tags.
retag_target="$(mpc_auth_trim "${MPC_AUTH_COMPOSE_IMAGE_REF:-${REPO}:latest}")"
if [[ -n "$retag_target" && "$NEW_REF" != "$retag_target" ]] && docker image inspect "$NEW_REF" &>/dev/null; then
	if [[ "$(mpc_auth_trim "${MPC_AUTH_SKIP_RETAG_LATEST:-0}")" != "1" ]]; then
		echo "Pointing $(printf %q "$retag_target") at verified pull $(printf %q "$NEW_REF") (so compose recreates with this image)."
		docker tag "$NEW_REF" "$retag_target"
	fi
fi

# After a pull, always recreate the service container. Without this, if stop/rm missed the live
# container (wrong MPC_AUTH_CONTAINER_NAME), plain `up -d` can no-op and mpc-auth never restarts
# (draining stays true in the old process).
mpc_auth_run_default_compose_up() {
	local workdir svc
	mpc_auth_require_compose_workdir
	workdir="$(mpc_auth_compose_workdir_resolve)"
	svc="$(mpc_auth_trim "${MPC_AUTH_COMPOSE_SERVICE:-app}")"
	[[ -z "$svc" ]] && svc="app"
	if docker compose version &>/dev/null 2>&1; then
		echo "Running: cd $(printf %q "$workdir") && docker compose up -d --no-deps --force-recreate $(printf %q "$svc")"
		if ! (cd "$workdir" && docker compose up -d --no-deps --force-recreate "$svc"); then
			echo "error: docker compose up failed." >&2
			return 1
		fi
		return 0
	fi
	if command -v docker-compose &>/dev/null 2>&1; then
		echo "WARNING: using legacy docker-compose (v1). Install the \`docker compose\` v2 plugin; v1 often fails on modern Docker with KeyError 'ContainerConfig'." >&2
		echo "Running: cd $(printf %q "$workdir") && docker-compose up -d --no-deps --force-recreate $(printf %q "$svc")"
		if ! (cd "$workdir" && docker-compose up -d --no-deps --force-recreate "$svc"); then
			echo "error: docker-compose up failed." >&2
			return 1
		fi
		return 0
	fi
	return 1
}

explicit="$(mpc_auth_trim "${MPC_AUTH_POST_UPDATE_CMD:-}")"
if [[ -n "$explicit" ]]; then
	echo "Running MPC_AUTH_POST_UPDATE_CMD: $explicit"
	if ! env TAG="$TAG" MPC_AUTH_CONTAINER_NAME="$CONTAINER" MPC_AUTH_IMAGE="$REPO" MPC_AUTH_EXPECTED_DIGEST="${EXPECTED_DIGEST:-}" bash -lc "$explicit"; then
		echo "error: MPC_AUTH_POST_UPDATE_CMD exited with an error." >&2
		exit 1
	fi
elif mpc_auth_run_default_compose_up; then
	:
else
	echo "error: MPC_AUTH_POST_UPDATE_CMD unset and neither 'docker compose' nor docker-compose is available; cannot bring stack up." >&2
	exit 1
fi

echo "Update complete for $NEW_REF."
