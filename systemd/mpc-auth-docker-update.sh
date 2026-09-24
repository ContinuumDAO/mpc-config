#!/usr/bin/env bash
# (A) Full update: stop mpc-auth container, rmi old ref, pull, digest verify, compose up -d --no-deps --force-recreate (app only).
# (B) Restart-only: git pull in MPC_AUTH_COMPOSE_WORKDIR (mpc-config) when configured, then restart/recreate
#     without Docker image pull/rmi — docker compose restart, or compose up -d --no-deps --force-recreate when
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

mpc_auth_image_id() {
	local ref="$1"
	docker image inspect "$ref" --format '{{.Id}}' 2>/dev/null || true
}

mpc_auth_keep_ids_contains() {
	local needle="$1"
	shift || true
	local k
	for k in "$@"; do
		[[ -n "$k" && "$k" == "$needle" ]] && return 0
	done
	return 1
}

mpc_auth_image_in_use() {
	local img_id="$1"
	local used
	used="$(docker ps -a --filter "ancestor=${img_id}" -q 2>/dev/null | head -n 1 || true)"
	[[ -n "$used" ]]
}

# After a successful pull/recreate: remove old tagged/dangling images for REPO, keeping refs passed as args
# (e.g. continuumdao/mpc-auth:v1.2.7 and :latest). Skips images still referenced by any container.
# Disable with MPC_AUTH_PRUNE_OLD_IMAGES=0 in /etc/default/mpc-auth-docker.
mpc_auth_prune_unused_repo_images() {
	case "${MPC_AUTH_PRUNE_OLD_IMAGES:-1}" in
	0 | false | FALSE | no | NO) return 0 ;;
	esac

	local repo="$1"
	shift || true
	local -a keep_refs=("$@")
	local -a keep_ids=()
	local ref id rep tag display

	repo="$(mpc_auth_trim "$repo")"
	[[ -z "$repo" ]] && return 0

	for ref in "${keep_refs[@]}"; do
		ref="$(mpc_auth_trim "$ref")"
		[[ -z "$ref" ]] && continue
		id="$(mpc_auth_image_id "$ref")"
		[[ -z "$id" ]] && continue
		if ! mpc_auth_keep_ids_contains "$id" "${keep_ids[@]}"; then
			keep_ids+=("$id")
		fi
	done

	if [[ "${#keep_ids[@]}" -eq 0 ]]; then
		echo "warning: prune skipped for ${repo} — no keep refs resolved." >&2
		return 0
	fi

	while IFS=$'\t' read -r id rep tag; do
		[[ -z "$id" || "$rep" != "$repo" ]] && continue
		if mpc_auth_keep_ids_contains "$id" "${keep_ids[@]}"; then
			continue
		fi
		if mpc_auth_image_in_use "$id"; then
			display="${rep}:${tag}"
			[[ "$tag" == "<none>" ]] && display="${rep} (${id#sha256:})"
			echo "Skipping prune (in use by a container): ${display}"
			continue
		fi
		display="${rep}:${tag}"
		[[ "$tag" == "<none>" ]] && display="${rep} (${id#sha256:})"
		echo "Pruning unused ${repo} image: ${display}"
		docker rmi --force "$id" || true
	done < <(docker images --no-trunc --format '{{.ID}}\t{{.Repository}}\t{{.Tag}}' "$repo" 2>/dev/null || true)

	return 0
}

# systemd oneshots often have WorkingDirectory=/; never run "docker compose" from cwd without an explicit project dir.
mpc_auth_compose_workdir_resolve() {
	printf '%s' "$(mpc_auth_trim "${MPC_AUTH_COMPOSE_WORKDIR:-${MPC_AUTH_COMPOSE_DIR:-}}")"
}

# Before restart/recreate: switch docker-compose.yml relay/client from configs.yaml (e.g. after app sets this node relay).
mpc_auth_sync_compose_role_if_needed() {
	local sync_script="${MPC_AUTH_SYNC_COMPOSE_ROLE_SCRIPT:-/usr/local/libexec/mpc-auth/mpc-auth-sync-compose-role.sh}"
	local sync_line role changed needs_full
	case "${MPC_AUTH_SKIP_COMPOSE_ROLE_SYNC:-0}" in
	1 | true | TRUE | yes | YES) return 0 ;;
	esac
	if [[ ! -x "$sync_script" ]]; then
		echo "mpc-auth-docker-update: compose role sync script missing ($(printf %q "$sync_script")) — skipping." >&2
		return 0
	fi
	sync_line="$("$sync_script" 2>&1 | grep -E '^compose_role_sync:' | tail -n 1 || true)"
	if [[ -z "$sync_line" ]]; then
		return 0
	fi
	echo "mpc-auth-docker-update: ${sync_line}"
	role="$(printf '%s' "$sync_line" | sed -n 's/.*role=\([^[:space:]]*\).*/\1/p')"
	changed="$(printf '%s' "$sync_line" | sed -n 's/.*changed=\([01]\).*/\1/p')"
	needs_full="$(printf '%s' "$sync_line" | sed -n 's/.*needs_full_stack=\([01]\).*/\1/p')"
	export MPC_AUTH_COMPOSE_ROLE="${role:-unknown}"
	export MPC_AUTH_COMPOSE_ROLE_CHANGED="${changed:-0}"
	export MPC_AUTH_COMPOSE_NEEDS_FULL_STACK="${needs_full:-0}"
}

mpc_auth_run_full_compose_up() {
	local workdir force orphan_args=()
	mpc_auth_require_compose_workdir
	workdir="$(mpc_auth_compose_workdir_resolve)"
	force="$(mpc_auth_trim "${MPC_AUTH_PENDING_FORCE_RECREATE:-0}")"
	# Relay→client demotion drops mosquitto from compose; remove the old broker container (and any other orphans).
	if [[ "${MPC_AUTH_COMPOSE_ROLE_CHANGED:-0}" == "1" ]]; then
		orphan_args+=(--remove-orphans)
	fi
	if docker compose version &>/dev/null 2>&1; then
		if [[ "$force" == "1" ]]; then
			echo "Running: cd $(printf %q "$workdir") && docker compose up -d --force-recreate ${orphan_args[*]:-}"
			(cd "$workdir" && docker compose up -d --force-recreate "${orphan_args[@]}")
		else
			echo "Running: cd $(printf %q "$workdir") && docker compose up -d ${orphan_args[*]:-}"
			(cd "$workdir" && docker compose up -d "${orphan_args[@]}")
		fi
		return 0
	fi
	if command -v docker-compose &>/dev/null 2>&1; then
		echo "WARNING: using legacy docker-compose (v1) for full stack up." >&2
		if [[ "$force" == "1" ]]; then
			echo "Running: cd $(printf %q "$workdir") && docker-compose up -d --force-recreate ${orphan_args[*]:-}"
			(cd "$workdir" && docker-compose up -d --force-recreate "${orphan_args[@]}")
		else
			echo "Running: cd $(printf %q "$workdir") && docker-compose up -d ${orphan_args[*]:-}"
			(cd "$workdir" && docker-compose up -d "${orphan_args[@]}")
		fi
		return 0
	fi
	echo "error: full stack compose up requires docker compose or docker-compose." >&2
	return 1
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

# Full image updates: pull mpc-config as the checkout owner (systemd runs this script as root; git must use the home user's credentials).
mpc_auth_git_pull_compose_repo() {
	case "${MPC_AUTH_SKIP_GIT_PULL:-0}" in
	1 | true | TRUE | yes | YES) return 0 ;;
	esac

	local workdir owner parent home
	workdir="$(mpc_auth_compose_workdir_resolve)"
	if [[ -z "$workdir" ]]; then
		echo "warning: MPC_AUTH_COMPOSE_WORKDIR unset — skipping mpc-config git pull." >&2
		return 0
	fi
	if [[ ! -d "$workdir/.git" ]]; then
		echo "warning: $(printf %q "$workdir") has no .git — skipping git pull." >&2
		return 0
	fi

	owner="$(stat -c '%U' "$workdir" 2>/dev/null || true)"
	if [[ -z "$owner" || "$owner" == "UNKNOWN" || "$owner" == "root" ]]; then
		parent="$(dirname "$workdir")"
		owner="$(stat -c '%U' "$parent" 2>/dev/null || true)"
	fi
	if [[ -z "$owner" || "$owner" == "UNKNOWN" || "$owner" == "root" ]]; then
		echo "warning: cannot determine non-root owner for $(printf %q "$workdir") — skipping git pull." >&2
		return 0
	fi

	echo "mpc-config: git pull in $(printf %q "$workdir") as user $(printf %q "$owner") (before Docker image pull)"

	if [[ "$(id -u)" -eq 0 ]]; then
		home="$(getent passwd "$owner" 2>/dev/null | awk -F: '{print $6}' || true)"
		[[ -z "$home" ]] && home="/home/$owner"
		if command -v runuser &>/dev/null; then
			if ! runuser -u "$owner" -w "$home" -- git -C "$workdir" pull; then
				echo "error: git pull failed in $(printf %q "$workdir") as $(printf %q "$owner")." >&2
				exit 1
			fi
			return 0
		fi
		if ! su - "$owner" -c "cd $(printf '%q' "$workdir") && git pull"; then
			echo "error: git pull failed in $(printf %q "$workdir") as $(printf %q "$owner")." >&2
			exit 1
		fi
		return 0
	fi

	if ! git -C "$workdir" pull; then
		echo "error: git pull failed in $(printf %q "$workdir")." >&2
		exit 1
	fi
}

# systemd units run /usr/local/libexec/mpc-auth/*.sh — not the repo checkout. After git pull,
# re-install with --no-env so libexec + unit files match while preserving /etc/default/mpc-auth-docker.
mpc_auth_sync_libexec_from_compose_repo() {
	case "${MPC_AUTH_SKIP_SYSTEMD_SYNC:-${PROCESS_CONFIG_SKIP_SYSTEMD:-0}}" in
	1 | true | TRUE | yes | YES) return 0 ;;
	esac

	if [[ ! -d /etc/systemd/system ]]; then
		return 0
	fi
	if [[ ! -f /etc/systemd/system/mpc-auth-docker-restart.service ]] \
		&& [[ ! -f /etc/systemd/system/mpc-auth-docker-pending-update.service ]] \
		&& [[ ! -f /etc/systemd/system/mpc-auth-docker-pending-reboot.service ]] \
		&& [[ ! -f /etc/systemd/system/mpc-auth-vpn-pending.path ]]; then
		return 0
	fi

	local workdir ins_script
	workdir="$(mpc_auth_compose_workdir_resolve)"
	if [[ -z "$workdir" ]]; then
		return 0
	fi
	ins_script="${workdir}/systemd/install-mpc-auth-docker-systemd.sh"
	if [[ ! -f "$ins_script" ]]; then
		echo "warning: mpc-auth systemd sync skipped — missing $(printf %q "$ins_script") (not an mpc-config checkout?)." >&2
		return 0
	fi

	echo "mpc-config: refreshing /usr/local/libexec/mpc-auth/ from $(printf %q "$ins_script") (--no-env preserves /etc/default/mpc-auth-docker)"
	if bash "$ins_script" --no-env; then
		echo "mpc-config: host libexec scripts and systemd units updated from repo."
	else
		echo "warning: install-mpc-auth-docker-systemd.sh --no-env failed. Run manually: sudo bash $(printf %q "$ins_script") --no-env" >&2
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

# Host result the running mpc-auth reads (GET /maintenance/dockerUpdateStatus). Same directory as pending-update.json.
UPDATE_STATUS_STARTED=""
COMPANION_PROBLEMS=""

mpc_auth_update_status_path() {
	local pending
	pending="$(mpc_auth_trim "${MPC_AUTH_DOCKER_PENDING_FILE:-/var/lib/mpc-auth-docker/pending-update.json}")"
	printf '%s/update-status.json' "$(dirname "$pending")"
}

mpc_auth_write_update_status() {
	local phase="$1" ok_flag="$2" msg="$3" path started
	path="$(mpc_auth_update_status_path)"
	if ! command -v python3 &>/dev/null; then
		echo "warning: python3 missing — not writing ${path}" >&2
		return 0
	fi
	mkdir -p "$(dirname "$path")" || return 0
	started="${UPDATE_STATUS_STARTED:-}"
	UPDATE_STATUS_STARTED="$(
		python3 - "$path" "$phase" "$ok_flag" "$TAG" "$msg" "$started" "${MPC_AUTH_UPDATE_ATTEMPT:-}" <<'PY'
import datetime, json, os, sys
path, phase, ok_flag, tag, msg, started, attempt = sys.argv[1:8]
now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
if not started:
    started = now
doc = {
    "phase": phase,
    "ok": ok_flag == "1",
    "tag": tag,
    "startedAt": started,
    "message": msg,
}
if attempt:
    doc["attemptId"] = attempt
if phase == "finished":
    doc["finishedAt"] = now
tmp = path + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    json.dump(doc, f)
os.chmod(tmp, 0o640)
os.replace(tmp, path)
print(started)
PY
	)" || true
}

mpc_auth_note_companion_problem() {
	local sentence="$1"
	echo "error: ${sentence}" >&2
	if [[ -n "$COMPANION_PROBLEMS" ]]; then
		COMPANION_PROBLEMS="${COMPANION_PROBLEMS} ${sentence}"
	else
		COMPANION_PROBLEMS="$sentence"
	fi
}

# Pull failed or the digest did not match. Do not remove the running container or its image.
# Recreate with --pull never so maintenance draining clears and the previous image keeps running.
mpc_auth_keep_previous_image() {
	local msg="$1" svc workdir
	mpc_auth_write_update_status finished 0 "$msg"
	echo "error: ${msg}" >&2
	svc="$(mpc_auth_trim "${MPC_AUTH_COMPOSE_SERVICE:-app}")"
	[[ -z "$svc" ]] && svc="app"
	workdir="$(mpc_auth_compose_workdir_resolve)"
	if [[ -n "$workdir" && -d "$workdir" ]] && docker compose version &>/dev/null 2>&1; then
		echo "Recreating $(printf %q "$svc") without pulling, so the previous image keeps running."
		(cd "$workdir" && docker compose up -d --no-deps --force-recreate --pull never "$svc") || \
			(cd "$workdir" && docker compose up -d --no-deps --force-recreate "$svc") || true
	elif docker container inspect "$CONTAINER" &>/dev/null; then
		docker start "$CONTAINER" || true
	fi
	exit 1
}

if [[ "$RESTART_ONLY" == "1" ]]; then
	echo "MPC_AUTH_PENDING_RESTART_ONLY=1 — mpc-config git pull (if configured), then restart/recreate without Docker image pull/rmi (tag=$TAG)."
	mpc_auth_git_pull_compose_repo
	mpc_auth_sync_libexec_from_compose_repo
	mpc_auth_sync_compose_role_if_needed || true
	if [[ "${MPC_AUTH_COMPOSE_NEEDS_FULL_STACK:-0}" == "1" ]]; then
		echo "mpc-auth-docker-update: relay/client compose role requires full stack (mosquitto + app)."
		mpc_auth_run_full_compose_up
	else
		mpc_auth_run_restart_or_recreate
	fi
	echo "Restart-only complete (tag $TAG)."
	exit 0
fi

# Fail before stop/rm/pull so a misconfigured host does not leave mpc-auth down (MPC_AUTH_COMPOSE_WORKDIR empty).
if [[ -z "$(mpc_auth_trim "${MPC_AUTH_POST_UPDATE_CMD:-}")" ]]; then
	mpc_auth_require_compose_workdir
fi

mpc_auth_git_pull_compose_repo
mpc_auth_sync_libexec_from_compose_repo
mpc_auth_sync_compose_role_if_needed || true

mpc_auth_write_update_status running 0 "Downloading the new image. This node is still running the previous image until that download succeeds."

NEW_REF="${REPO}:${TAG}"
OLD_RUNNING_ID=""
if docker container inspect "$CONTAINER" &>/dev/null; then
	OLD_RUNNING_ID="$(docker inspect -f '{{.Image}}' "$CONTAINER")"
fi

echo "Pulling $NEW_REF (running container is left in place until this succeeds)"
if ! docker pull "$NEW_REF"; then
	mpc_auth_keep_previous_image "The mpc-auth image did not update. Docker could not download ${NEW_REF}. This node is still running the previous image."
fi

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
		docker image inspect "$NEW_REF" --format '{{json .RepoDigests}}' >&2 || true
		if [[ -n "$OLD_RUNNING_ID" ]]; then
			echo "Restoring ${NEW_REF} to the image the container is already running."
			docker tag "$OLD_RUNNING_ID" "$NEW_REF" || true
		fi
		mpc_auth_keep_previous_image "The mpc-auth image did not update. The downloaded image ${NEW_REF} did not match the expected checksum, so it was not installed. This node is still running the previous image."
	fi
else
	echo "WARNING: no EXPECTED_DIGEST/MPC_AUTH_EXPECTED_DIGEST — skipping digest check (set from POST /updateMpcAuth registryDigest before production use)."
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

# Hub newest vMAJOR.MINOR.PATCH for a docker.io repo (continuumdao/continuum-mcp-server).
# Compose defaults to :latest; pulling only that alias can no-op on a stale local latest while Hub already moved.
mpc_auth_dockerhub_latest_semver_tag() {
	local repo="$1" attempt tag
	repo="$(mpc_auth_trim "$repo")"
	[[ -z "$repo" ]] && return 0
	if ! command -v python3 &>/dev/null; then
		echo "warning: python3 missing — cannot resolve Hub semver for ${repo}." >&2
		return 0
	fi
	for attempt in 1 2 3; do
		if tag="$(python3 - "$repo" <<'PY'
import json, re, sys, urllib.request

repo = sys.argv[1].strip().lstrip("/")
pat = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
best = None
url = f"https://hub.docker.com/v2/repositories/{repo}/tags?page_size=100&ordering=last_updated"
try:
    for _ in range(10):
        req = urllib.request.Request(
            url,
            headers={"Accept": "application/json", "User-Agent": "mpc-auth-docker-update"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.load(resp)
        for row in data.get("results") or []:
            name = str(row.get("name") or "")
            m = pat.match(name)
            if not m:
                continue
            key = tuple(int(x) for x in m.groups())
            updated = str(row.get("last_updated") or "")
            if best is None or key > best[0] or (key == best[0] and updated > best[1]):
                best = (key, updated, name)
        url = data.get("next")
        if not url:
            break
except Exception as exc:
    print(f"hub tag lookup {repo}: {exc}", file=sys.stderr)
    sys.exit(1)
if not best:
    print(f"hub tag lookup {repo}: no vX.Y.Z tags", file=sys.stderr)
    sys.exit(1)
print(best[2])
PY
		)"; then
			tag="$(mpc_auth_trim "$tag")"
			if [[ -n "$tag" ]]; then
				printf '%s' "$tag"
				return 0
			fi
		fi
		echo "warning: Docker Hub semver lookup failed for ${repo} (attempt ${attempt}/3)." >&2
		sleep $((attempt * 2))
	done
	return 0
}

# Image name compose will start for this service (docker-compose.yml), empty if unreadable.
mpc_auth_compose_service_image() {
	local workdir="$1" svc="$2" img
	[[ -z "$workdir" || -z "$svc" ]] && return 0
	img="$(
		cd "$workdir" && docker compose config --format json 2>/dev/null | python3 -c '
import json, sys
svc = sys.argv[1]
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
item = (data.get("services") or {}).get(svc) or {}
image = item.get("image")
if isinstance(image, str):
    sys.stdout.write(image.strip())
' "$svc"
	)" || true
	printf '%s' "$(mpc_auth_trim "$img")"
}

# Pull Docker Hub's newest vX.Y.Z. NODE_APP_TAG / MCP_SERVER_TAG (from configs) are not the
# update target — a stale pin such as v1.3.14 must not be pulled. The configured tag is only
# used when Hub cannot be reached. Callers capture stdout as the image ref; status goes to stderr.
mpc_auth_companion_pull_ref() {
	local img="$1"
	local tag="$2"
	local hub
	img="$(mpc_auth_trim "$img")"
	tag="$(mpc_auth_trim "$tag")"
	[[ -z "$tag" ]] && tag="latest"
	hub="$(mpc_auth_trim "$(mpc_auth_dockerhub_latest_semver_tag "$img")")"
	if [[ -n "$hub" ]]; then
		if [[ "$tag" != "latest" && "$tag" != "$hub" ]]; then
			echo "Companion ${img}: configured tag ${tag} is stale; pulling Docker Hub ${hub}." >&2
		else
			echo "Companion ${img}: pulling Docker Hub ${hub}." >&2
		fi
		printf '%s' "${img}:${hub}"
		return 0
	fi
	echo "warning: Docker Hub semver lookup failed for ${img}; falling back to configured tag ${tag}." >&2
	printf '%s' "${img}:${tag}"
}

mpc_auth_companion_retag_compose() {
	local pulled="$1"
	local compose_ref="$2"
	pulled="$(mpc_auth_trim "$pulled")"
	compose_ref="$(mpc_auth_image_ref_bare "$compose_ref")"
	[[ -z "$pulled" || -z "$compose_ref" ]] && return 0
	if [[ "$pulled" == "$compose_ref" ]]; then
		return 0
	fi
	if [[ "$(mpc_auth_trim "${MPC_AUTH_SKIP_RETAG_LATEST:-0}")" == "1" ]]; then
		return 0
	fi
	if docker image inspect "$pulled" &>/dev/null; then
		echo "Pointing $(printf %q "$compose_ref") at companion pull $(printf %q "$pulled") (so compose recreates with this image)."
		docker tag "$pulled" "$compose_ref"
	fi
}

# docker compose config can append @sha256:<digest of the image already running>.
# docker tag refuses that form, so the compose-file name stays on the previous image.
mpc_auth_image_ref_bare() {
	local ref
	ref="$(mpc_auth_trim "${1:-}")"
	ref="${ref%@sha256:*}"
	printf '%s' "$ref"
}

mpc_auth_image_ref_ok() {
	local ref="$1"
	[[ "$ref" =~ ^[A-Za-z0-9_./:-]+$ ]]
}

# True when both refs are the same local image (id or shared repo digest).
mpc_auth_same_image() {
	local left="$1" right="$2" id_left id_right digests_left digests_right line
	[[ -z "$left" || -z "$right" ]] && return 1
	id_left="$(docker image inspect -f '{{.Id}}' "$left" 2>/dev/null || true)"
	id_right="$(docker image inspect -f '{{.Id}}' "$right" 2>/dev/null || true)"
	if [[ -n "$id_left" && "$id_left" == "$id_right" ]]; then
		return 0
	fi
	digests_left="$(docker image inspect -f '{{range .RepoDigests}}{{println .}}{{end}}' "$left" 2>/dev/null || true)"
	digests_right="$(docker image inspect -f '{{range .RepoDigests}}{{println .}}{{end}}' "$right" 2>/dev/null || true)"
	[[ -z "$digests_left" || -z "$digests_right" ]] && return 1
	while IFS= read -r line; do
		[[ -z "$line" ]] && continue
		if grep -Fxq -- "$line" <<<"$digests_right"; then
			return 0
		fi
	done <<<"$digests_left"
	return 1
}

mpc_auth_companion_service_container() {
	local workdir="$1" svc="$2" configured="$3" id
	configured="$(mpc_auth_trim "$configured")"
	if [[ -n "$configured" ]] && docker container inspect "$configured" &>/dev/null; then
		printf '%s' "$configured"
		return 0
	fi
	id="$(
		cd "$workdir" && docker compose ps -aq "$svc" 2>/dev/null | head -n 1 || true
	)"
	printf '%s' "$(mpc_auth_trim "$id")"
}

mpc_auth_container_has_image() {
	local container="$1" ref="$2" image_id
	[[ -z "$container" || -z "$ref" ]] && return 1
	docker container inspect "$container" &>/dev/null || return 1
	image_id="$(docker inspect -f '{{.Image}}' "$container" 2>/dev/null || true)"
	mpc_auth_same_image "$image_id" "$ref"
}

# Compose --pull never recreates a container from the image id it already has when the
# compose-file tag string does not change. Pin the pulled tag in a one-shot override so
# the new container is that image, without pulling :latest again.
mpc_auth_compose_up_service() {
	local workdir="$1" override="$2"
	shift 2
	(
		cd "$workdir" || exit 1
		local -a files=()
		local file
		if [[ -n "${COMPOSE_FILE:-}" ]]; then
			local part
			IFS=':' read -ra part <<<"$COMPOSE_FILE"
			files+=("${part[@]}")
		elif [[ -f compose.yaml ]]; then
			files+=(compose.yaml)
			[[ -f compose.override.yaml ]] && files+=(compose.override.yaml)
		elif [[ -f compose.yml ]]; then
			files+=(compose.yml)
			[[ -f compose.override.yml ]] && files+=(compose.override.yml)
		elif [[ -f docker-compose.yml ]]; then
			files+=(docker-compose.yml)
			[[ -f docker-compose.override.yml ]] && files+=(docker-compose.override.yml)
		fi
		if [[ -n "$override" && -f "$override" ]]; then
			files+=("$override")
		fi
		if [[ ${#files[@]} -gt 0 ]]; then
			local -a args=()
			for file in "${files[@]}"; do
				[[ -n "$file" ]] || continue
				args+=(-f "$file")
			done
			docker compose "${args[@]}" "$@"
		else
			docker compose "$@"
		fi
	)
}

# Recreate one companion service from the image already pulled. Do not pull again: compose pull
# and --pull always re-fetch the compose-file tag and can put a stale local :latest back.
mpc_auth_companion_compose_recreate() {
	local workdir="$1"
	local svc="$2"
	local pulled="${3:-}"
	local compose_image bare override rc
	compose_image="$(mpc_auth_compose_service_image "$workdir" "$svc")"
	bare="$(mpc_auth_image_ref_bare "$compose_image")"
	if [[ -n "$pulled" && -n "$bare" && "$pulled" != "$bare" ]]; then
		echo "Companion ${svc}: compose file image is ${bare}; tagging pulled ${pulled} onto it."
		docker tag "$pulled" "$bare" || echo "warning: docker tag ${pulled} ${bare} failed." >&2
	fi
	override=""
	if [[ -n "$pulled" ]] && mpc_auth_image_ref_ok "$pulled" && mpc_auth_image_ref_ok "$svc"; then
		override="$(mktemp)"
		cat >"$override" <<EOF
services:
  ${svc}:
    image: ${pulled}
EOF
	fi
	rc=1
	if docker compose version &>/dev/null 2>&1; then
		echo "Running companion recreate for $(printf %q "$svc") from $(printf %q "${pulled:-the compose file image}")"
		if mpc_auth_compose_up_service "$workdir" "$override" up -d --no-deps --force-recreate --pull never "$svc"; then
			rc=0
		else
			echo "warning: docker compose up --pull never failed for ${svc}; retrying with the pulled tag still pinned." >&2
			if mpc_auth_compose_up_service "$workdir" "$override" up -d --no-deps --force-recreate --pull missing "$svc"; then
				rc=0
			fi
		fi
	elif command -v docker-compose &>/dev/null 2>&1; then
		echo "WARNING: using legacy docker-compose (v1) for companion recreate." >&2
		echo "Running: cd $(printf %q "$workdir") && docker-compose up -d --no-deps --force-recreate $(printf %q "$svc")"
		if (cd "$workdir" && docker-compose up -d --no-deps --force-recreate "$svc"); then
			rc=0
		fi
	fi
	[[ -n "$override" ]] && rm -f "$override"
	return "$rc"
}

# Start the pulled image. If that container does not come up on it, put the previous image back.
# Returns 0 when the service is running the pulled image (including when it already was).
mpc_auth_companion_install_image() {
	local workdir="$1" svc="$2" container="$3" pulled="$4" compose_ref="$5"
	local old_id current bare
	container="$(mpc_auth_companion_service_container "$workdir" "$svc" "$container")"
	old_id=""
	if [[ -n "$container" ]]; then
		old_id="$(docker inspect -f '{{.Image}}' "$container" 2>/dev/null || true)"
	fi
	if [[ -n "$old_id" ]] && mpc_auth_same_image "$old_id" "$pulled"; then
		echo "Companion ${svc}: already running ${pulled} (${old_id})."
		return 0
	fi
	echo "Companion ${svc}: container ${container:-unknown} image ${old_id:-none}; want ${pulled}."
	if ! mpc_auth_companion_compose_recreate "$workdir" "$svc" "$pulled"; then
		echo "warning: compose recreate failed for ${svc}." >&2
	fi
	container="$(mpc_auth_companion_service_container "$workdir" "$svc" "$container")"
	if mpc_auth_container_has_image "$container" "$pulled"; then
		mpc_auth_companion_drop_old_image "$old_id" "$pulled" "$svc"
		return 0
	fi
	# The running container still pins the previous image. Remove it and create from the pulled tag.
	if [[ -n "$container" ]]; then
		echo "Companion ${svc}: removing ${container} so it can start ${pulled}."
		docker rm -f "$container" || true
	fi
	if mpc_auth_companion_compose_recreate "$workdir" "$svc" "$pulled"; then
		container="$(mpc_auth_companion_service_container "$workdir" "$svc" "$container")"
		if mpc_auth_container_has_image "$container" "$pulled"; then
			mpc_auth_companion_drop_old_image "$old_id" "$pulled" "$svc"
			return 0
		fi
	fi
	current=""
	if [[ -n "$container" ]] && docker container inspect "$container" &>/dev/null; then
		current="$(docker inspect -f '{{.Image}}' "$container" 2>/dev/null || true)"
	fi
	echo "error: ${svc} is on ${current:-no container}, not ${pulled}. Restoring the previous image." >&2
	bare="$(mpc_auth_image_ref_bare "$(mpc_auth_compose_service_image "$workdir" "$svc")")"
	if [[ -n "$old_id" && -n "$bare" ]]; then
		docker tag "$old_id" "$bare" || true
	fi
	compose_ref="$(mpc_auth_image_ref_bare "$compose_ref")"
	if [[ -n "$old_id" && -n "$compose_ref" && "$compose_ref" != "$bare" ]]; then
		docker tag "$old_id" "$compose_ref" || true
	fi
	if docker compose version &>/dev/null 2>&1; then
		(cd "$workdir" && docker compose up -d --no-deps --force-recreate --pull never "$svc") || \
			(cd "$workdir" && docker compose up -d --no-deps --force-recreate "$svc") || true
	elif command -v docker-compose &>/dev/null 2>&1; then
		(cd "$workdir" && docker-compose up -d --no-deps --force-recreate "$svc") || true
	fi
	return 1
}

mpc_auth_companion_drop_old_image() {
	local old_id="$1" pulled="$2" svc="$3"
	[[ -z "$old_id" ]] && return 0
	if mpc_auth_same_image "$old_id" "$pulled"; then
		return 0
	fi
	echo "Removing previous companion ${svc} image (force): ${old_id}"
	docker rmi --force "$old_id" || true
}

# After mpc-auth pulls and compose recreates app: pull continuumdao-node-app (configs ContinuumdaoNodeApp) if MPC_AUTH_UPDATE_NODE_APP=1.
mpc_auth_companion_dashboard_pull_and_recreate() {
	case "${MPC_AUTH_UPDATE_NODE_APP:-1}" in
	0 | false | FALSE | no | NO) return 0 ;;
	esac
	local img svc tag ref compose_ref workdir dash_container
	img="$(mpc_auth_trim "${NODE_APP_IMAGE:-}")"
	svc="$(mpc_auth_trim "${MPC_AUTH_NODE_APP_COMPOSE_SERVICE:-dashboard}")"
	[[ -z "$img" ]] && return 0
	tag="$(mpc_auth_trim "${NODE_APP_TAG:-latest}")"
	[[ -z "$tag" ]] && tag="latest"
	ref="$(mpc_auth_companion_pull_ref "$img" "$tag")"
	compose_ref="$(mpc_auth_trim "${NODE_APP_COMPOSE_IMAGE_REF:-${img}:latest}")"
	dash_container="$(mpc_auth_trim "${NODE_APP_CONTAINER_NAME:-}")"

	echo "Companion (continuumdao-node-app): pulling ${ref}"
	docker pull "$ref" || {
		mpc_auth_note_companion_problem "The node app image did not update. Docker could not download ${ref}. The node app is still running the previous image."
		return 0
	}
	echo "Companion (continuumdao-node-app): pulled ${ref} id=$(docker image inspect -f '{{.Id}}' "$ref" 2>/dev/null || echo unknown)"
	mpc_auth_companion_retag_compose "$ref" "$compose_ref"
	COMPANION_NODE_APP_PULLED_REF="$ref"
	COMPANION_NODE_APP_COMPOSE_REF="$compose_ref"
	workdir="$(mpc_auth_compose_workdir_resolve)"
	if [[ -z "$workdir" ]] || [[ ! -d "$workdir" ]]; then
		echo "warning: MPC_AUTH_COMPOSE_WORKDIR (or MPC_AUTH_COMPOSE_DIR) unset or missing — skipping continuumdao-node-app recreate." >&2
		return 0
	fi
	if ! mpc_auth_companion_install_image "$workdir" "$svc" "$dash_container" "$ref" "$compose_ref"; then
		mpc_auth_note_companion_problem "The node app image did not update to ${ref}. The container is still running the previous image."
	fi
	return 0
}

# After mpc-auth pulls and compose recreates app: pull continuum-mcp-server (configs ContinuumMcpServer) if MPC_AUTH_UPDATE_MCP_SERVER=1.
mpc_auth_companion_mcp_server_pull_and_recreate() {
	case "${MPC_AUTH_UPDATE_MCP_SERVER:-1}" in
	0 | false | FALSE | no | NO) return 0 ;;
	esac
	local img svc tag ref compose_ref workdir mcp_container
	img="$(mpc_auth_trim "${MCP_SERVER_IMAGE:-}")"
	svc="$(mpc_auth_trim "${MPC_AUTH_MCP_SERVER_COMPOSE_SERVICE:-continuum-mcp}")"
	[[ -z "$img" ]] && return 0
	tag="$(mpc_auth_trim "${MCP_SERVER_TAG:-latest}")"
	[[ -z "$tag" ]] && tag="latest"
	ref="$(mpc_auth_companion_pull_ref "$img" "$tag")"
	compose_ref="$(mpc_auth_trim "${MCP_SERVER_COMPOSE_IMAGE_REF:-${img}:latest}")"
	mcp_container="$(mpc_auth_trim "${MCP_SERVER_CONTAINER_NAME:-}")"

	echo "Companion (continuum-mcp-server): pulling ${ref}"
	docker pull "$ref" || {
		mpc_auth_note_companion_problem "The MCP server image did not update. Docker could not download ${ref}. The MCP server is still running the previous image."
		return 0
	}
	echo "Companion (continuum-mcp-server): pulled ${ref} id=$(docker image inspect -f '{{.Id}}' "$ref" 2>/dev/null || echo unknown)"
	mpc_auth_companion_retag_compose "$ref" "$compose_ref"
	COMPANION_MCP_PULLED_REF="$ref"
	COMPANION_MCP_COMPOSE_REF="$compose_ref"
	workdir="$(mpc_auth_compose_workdir_resolve)"
	if [[ -z "$workdir" ]] || [[ ! -d "$workdir" ]]; then
		echo "warning: MPC_AUTH_COMPOSE_WORKDIR (or MPC_AUTH_COMPOSE_DIR) unset or missing — skipping MCP server recreate." >&2
		return 0
	fi
	if ! mpc_auth_companion_install_image "$workdir" "$svc" "$mcp_container" "$ref" "$compose_ref"; then
		mpc_auth_note_companion_problem "The MCP server image did not update to ${ref}. The container is still running the previous image."
	fi
	return 0
}

mpc_auth_restore_previous_image_tags() {
	[[ -z "${OLD_RUNNING_ID:-}" ]] && return 0
	docker tag "$OLD_RUNNING_ID" "$NEW_REF" || true
	if [[ -n "${retag_target:-}" ]]; then
		docker tag "$OLD_RUNNING_ID" "$retag_target" || true
	fi
}

explicit="$(mpc_auth_trim "${MPC_AUTH_POST_UPDATE_CMD:-}")"
if [[ -n "$explicit" ]]; then
	echo "Running MPC_AUTH_POST_UPDATE_CMD: $explicit"
	if ! env TAG="$TAG" MPC_AUTH_CONTAINER_NAME="$CONTAINER" MPC_AUTH_IMAGE="$REPO" MPC_AUTH_EXPECTED_DIGEST="${EXPECTED_DIGEST:-}" bash -lc "$explicit"; then
		mpc_auth_restore_previous_image_tags
		mpc_auth_keep_previous_image "The mpc-auth image did not update. The host update command failed, so this node is still running the previous image."
	fi
elif [[ "${MPC_AUTH_COMPOSE_NEEDS_FULL_STACK:-0}" == "1" ]] && mpc_auth_run_full_compose_up; then
	:
elif mpc_auth_run_default_compose_up; then
	:
else
	mpc_auth_restore_previous_image_tags
	mpc_auth_keep_previous_image "The mpc-auth image did not update. The new container could not be started, so this node is still running the previous image."
fi

mpc_auth_companion_dashboard_pull_and_recreate || true
mpc_auth_companion_mcp_server_pull_and_recreate || true

mpc_auth_prune_unused_repo_images "$REPO" "$NEW_REF" "$retag_target" || true

_node_app_image="$(mpc_auth_trim "${NODE_APP_IMAGE:-}")"
if [[ -n "$_node_app_image" ]]; then
	_node_app_tag="$(mpc_auth_trim "${NODE_APP_TAG:-latest}")"
	[[ -z "$_node_app_tag" ]] && _node_app_tag="latest"
	mpc_auth_prune_unused_repo_images "$_node_app_image" \
		"${_node_app_image}:${_node_app_tag}" \
		"${COMPANION_NODE_APP_PULLED_REF:-}" \
		"${COMPANION_NODE_APP_COMPOSE_REF:-${_node_app_image}:latest}" || true
fi

_mcp_server_image="$(mpc_auth_trim "${MCP_SERVER_IMAGE:-}")"
if [[ -n "$_mcp_server_image" ]]; then
	_mcp_server_tag="$(mpc_auth_trim "${MCP_SERVER_TAG:-latest}")"
	[[ -z "$_mcp_server_tag" ]] && _mcp_server_tag="latest"
	mpc_auth_prune_unused_repo_images "$_mcp_server_image" \
		"${_mcp_server_image}:${_mcp_server_tag}" \
		"${COMPANION_MCP_PULLED_REF:-}" \
		"${COMPANION_MCP_COMPOSE_REF:-${_mcp_server_image}:latest}" || true
fi

if [[ -n "$COMPANION_PROBLEMS" ]]; then
	mpc_auth_write_update_status finished 0 "mpc-auth updated to ${TAG}. ${COMPANION_PROBLEMS}"
	echo "Update finished with image problems for $NEW_REF."
	exit 1
fi
mpc_auth_write_update_status finished 1 "mpc-auth updated to ${TAG}."
echo "Update complete for $NEW_REF."
