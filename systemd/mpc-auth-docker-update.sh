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

# After mpc-auth pulls and compose recreates app: pull continuumdao-node-app (configs ContinuumdaoNodeApp) if MPC_AUTH_UPDATE_NODE_APP=1.
mpc_auth_companion_dashboard_pull_and_recreate() {
	case "${MPC_AUTH_UPDATE_NODE_APP:-1}" in
	0 | false | FALSE | no | NO) return 0 ;;
	esac
	local img svc tag ref workdir dash_container old_img_id new_img_id compose_ok
	img="$(mpc_auth_trim "${NODE_APP_IMAGE:-}")"
	svc="$(mpc_auth_trim "${MPC_AUTH_NODE_APP_COMPOSE_SERVICE:-dashboard}")"
	[[ -z "$img" ]] && return 0
	tag="$(mpc_auth_trim "${NODE_APP_TAG:-latest}")"
	[[ -z "$tag" ]] && tag="latest"
	ref="${img}:${tag}"
	dash_container="$(mpc_auth_trim "${NODE_APP_CONTAINER_NAME:-}")"

	old_img_id=""
	if [[ -n "$dash_container" ]] && docker container inspect "$dash_container" &>/dev/null; then
		old_img_id="$(docker inspect -f '{{.Image}}' "$dash_container")"
	fi

	echo "Companion (continuumdao-node-app): pulling ${ref}"
	docker pull "$ref" || {
		echo "warning: companion continuumdao-node-app docker pull failed: ${ref}" >&2
		return 0
	}
	workdir="$(mpc_auth_compose_workdir_resolve)"
	if [[ -z "$workdir" ]] || [[ ! -d "$workdir" ]]; then
		echo "warning: MPC_AUTH_COMPOSE_WORKDIR (or MPC_AUTH_COMPOSE_DIR) unset or missing — skipping continuumdao-node-app recreate." >&2
		return 0
	fi
	compose_ok=1
	if docker compose version &>/dev/null 2>&1; then
		echo "Running: cd $(printf %q "$workdir") && docker compose up -d --no-deps --force-recreate $(printf %q "$svc")"
		if (cd "$workdir" && docker compose up -d --no-deps --force-recreate "$svc"); then
			compose_ok=0
		else
			echo "warning: continuumdao-node-app compose recreate failed (ContinuumdaoNodeApp disabled or compose has no '${svc}' service?)." >&2
		fi
	elif command -v docker-compose &>/dev/null 2>&1; then
		echo "WARNING: using legacy docker-compose (v1) for continuumdao-node-app recreate." >&2
		echo "Running: cd $(printf %q "$workdir") && docker-compose up -d --no-deps --force-recreate $(printf %q "$svc")"
		if (cd "$workdir" && docker-compose up -d --no-deps --force-recreate "$svc"); then
			compose_ok=0
		else
			echo "warning: continuumdao-node-app docker-compose recreate failed." >&2
		fi
	fi

	if [[ "$compose_ok" -eq 0 && -n "$old_img_id" ]]; then
		new_img_id=""
		if [[ -n "$dash_container" ]] && docker container inspect "$dash_container" &>/dev/null; then
			new_img_id="$(docker inspect -f '{{.Image}}' "$dash_container")"
		fi
		if [[ -n "$new_img_id" && "$new_img_id" != "$old_img_id" ]]; then
			echo "Removing previous companion continuumdao-node-app image (force): ${old_img_id}"
			docker rmi --force "$old_img_id" || true
		fi
	fi
	return 0
}

# After mpc-auth pulls and compose recreates app: pull continuum-mcp-server (configs ContinuumMcpServer) if MPC_AUTH_UPDATE_MCP_SERVER=1.
mpc_auth_companion_mcp_server_pull_and_recreate() {
	case "${MPC_AUTH_UPDATE_MCP_SERVER:-1}" in
	0 | false | FALSE | no | NO) return 0 ;;
	esac
	local img svc tag ref workdir mcp_container old_img_id new_img_id compose_ok
	img="$(mpc_auth_trim "${MCP_SERVER_IMAGE:-}")"
	svc="$(mpc_auth_trim "${MPC_AUTH_MCP_SERVER_COMPOSE_SERVICE:-continuum-mcp}")"
	[[ -z "$img" ]] && return 0
	tag="$(mpc_auth_trim "${MCP_SERVER_TAG:-latest}")"
	[[ -z "$tag" ]] && tag="latest"
	ref="${img}:${tag}"
	mcp_container="$(mpc_auth_trim "${MCP_SERVER_CONTAINER_NAME:-}")"

	old_img_id=""
	if [[ -n "$mcp_container" ]] && docker container inspect "$mcp_container" &>/dev/null; then
		old_img_id="$(docker inspect -f '{{.Image}}' "$mcp_container")"
	fi

	echo "Companion (continuum-mcp-server): pulling ${ref}"
	docker pull "$ref" || {
		echo "warning: companion MCP server docker pull failed: ${ref}" >&2
		return 0
	}
	workdir="$(mpc_auth_compose_workdir_resolve)"
	if [[ -z "$workdir" ]] || [[ ! -d "$workdir" ]]; then
		echo "warning: MPC_AUTH_COMPOSE_WORKDIR (or MPC_AUTH_COMPOSE_DIR) unset or missing — skipping MCP server recreate." >&2
		return 0
	fi
	compose_ok=1
	if docker compose version &>/dev/null 2>&1; then
		echo "Running: cd $(printf %q "$workdir") && docker compose up -d --no-deps --force-recreate $(printf %q "$svc")"
		if (cd "$workdir" && docker compose up -d --no-deps --force-recreate "$svc"); then
			compose_ok=0
		else
			echo "warning: MCP server compose recreate failed (ContinuumMcpServer disabled or compose has no '${svc}' service?)." >&2
		fi
	elif command -v docker-compose &>/dev/null 2>&1; then
		echo "WARNING: using legacy docker-compose (v1) for MCP server recreate." >&2
		echo "Running: cd $(printf %q "$workdir") && docker-compose up -d --no-deps --force-recreate $(printf %q "$svc")"
		if (cd "$workdir" && docker-compose up -d --no-deps --force-recreate "$svc"); then
			compose_ok=0
		else
			echo "warning: MCP server docker-compose recreate failed." >&2
		fi
	fi

	if [[ "$compose_ok" -eq 0 && -n "$old_img_id" ]]; then
		new_img_id=""
		if [[ -n "$mcp_container" ]] && docker container inspect "$mcp_container" &>/dev/null; then
			new_img_id="$(docker inspect -f '{{.Image}}' "$mcp_container")"
		fi
		if [[ -n "$new_img_id" && "$new_img_id" != "$old_img_id" ]]; then
			echo "Removing previous companion MCP server image (force): ${old_img_id}"
			docker rmi --force "$old_img_id" || true
		fi
	fi
	return 0
}

explicit="$(mpc_auth_trim "${MPC_AUTH_POST_UPDATE_CMD:-}")"
if [[ -n "$explicit" ]]; then
	echo "Running MPC_AUTH_POST_UPDATE_CMD: $explicit"
	if ! env TAG="$TAG" MPC_AUTH_CONTAINER_NAME="$CONTAINER" MPC_AUTH_IMAGE="$REPO" MPC_AUTH_EXPECTED_DIGEST="${EXPECTED_DIGEST:-}" bash -lc "$explicit"; then
		echo "error: MPC_AUTH_POST_UPDATE_CMD exited with an error." >&2
		exit 1
	fi
elif [[ "${MPC_AUTH_COMPOSE_NEEDS_FULL_STACK:-0}" == "1" ]] && mpc_auth_run_full_compose_up; then
	:
elif mpc_auth_run_default_compose_up; then
	:
else
	echo "error: MPC_AUTH_POST_UPDATE_CMD unset and neither 'docker compose' nor docker-compose is available; cannot bring stack up." >&2
	exit 1
fi

mpc_auth_companion_dashboard_pull_and_recreate || true
mpc_auth_companion_mcp_server_pull_and_recreate || true

mpc_auth_prune_unused_repo_images "$REPO" "$NEW_REF" "$retag_target" || true

_node_app_image="$(mpc_auth_trim "${NODE_APP_IMAGE:-}")"
if [[ -n "$_node_app_image" ]]; then
	_node_app_tag="$(mpc_auth_trim "${NODE_APP_TAG:-latest}")"
	[[ -z "$_node_app_tag" ]] && _node_app_tag="latest"
	mpc_auth_prune_unused_repo_images "$_node_app_image" "${_node_app_image}:${_node_app_tag}" || true
fi

_mcp_server_image="$(mpc_auth_trim "${MCP_SERVER_IMAGE:-}")"
if [[ -n "$_mcp_server_image" ]]; then
	_mcp_server_tag="$(mpc_auth_trim "${MCP_SERVER_TAG:-latest}")"
	[[ -z "$_mcp_server_tag" ]] && _mcp_server_tag="latest"
	mpc_auth_prune_unused_repo_images "$_mcp_server_image" "${_mcp_server_image}:${_mcp_server_tag}" || true
fi

echo "Update complete for $NEW_REF."
