#!/usr/bin/env bash
# Optional host hook when agent-llm-config.json changes (management POST from node app).
# mpc-auth re-reads the file on each /agent/chat turn; restart is only needed for env-level changes.
#
# Usage: invoked by mpc-auth-agent-llm-config.path (stamp file) or manually after config POST.
#
set -euo pipefail

LIBEXEC="${LIBEXEC:-/usr/local/libexec/mpc-auth}"
ENV_FILE="${ENV_FILE:-/etc/default/mpc-auth-docker}"
if [[ -f "$ENV_FILE" ]]; then
	# shellcheck disable=SC1090
	source "$ENV_FILE"
fi

STAMP_DIR="${MPC_AUTH_AGENT_LLM_STAMP_DIR:-/var/lib/mpc-auth-docker}"
mkdir -p "$STAMP_DIR"
date -u +"%Y-%m-%dT%H:%M:%SZ" >"${STAMP_DIR}/agent-llm-config.stamp"

if [[ "${MPC_AUTH_RESTART_ON_AGENT_LLM_CONFIG:-0}" == "1" ]]; then
	COMPOSE_WORKDIR="${MPC_AUTH_COMPOSE_WORKDIR:-}"
	SERVICE="${MPC_AUTH_COMPOSE_SERVICE:-app}"
	if [[ -n "$COMPOSE_WORKDIR" && -d "$COMPOSE_WORKDIR" ]]; then
		cd "$COMPOSE_WORKDIR"
		if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
			docker compose up -d --no-deps --force-recreate "$SERVICE"
		elif command -v docker-compose >/dev/null 2>&1; then
			docker-compose up -d --no-deps --force-recreate "$SERVICE"
		fi
	fi
fi

echo "agent LLM config stamp updated ($(cat "${STAMP_DIR}/agent-llm-config.stamp"))"
