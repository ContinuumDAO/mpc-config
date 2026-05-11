#!/usr/bin/env bash
# Install (first run) or update the local dashboard container: ensure .env exists, pull image, recreate service.
#
# Usage:
#   ./install-or-update-node-app.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ ! -f .env ]]; then
	if [[ ! -f .env.example ]]; then
		echo "error: missing .env.example in ${SCRIPT_DIR}" >&2
		exit 1
	fi
	if command -v install &>/dev/null; then
		install -m 0600 .env.example .env
	else
		cp .env.example .env
		chmod 0600 .env
	fi
	echo "Created .env from .env.example."
	echo "Edit REOWN_PROJECT_ID (and other values if needed), then run this script again."
	exit 1
fi

if [[ -f .env ]]; then
	set -a
	# shellcheck disable=SC1091
	source .env
	set +a
fi

IMAGE="${NODE_APP_IMAGE:-continuumdao/continuumdao-node-app}"
TAG="${NODE_APP_TAG:-latest}"

echo "Pulling ${IMAGE}:${TAG} ..."
docker pull "${IMAGE}:${TAG}"

echo "Starting (or recreating) stack ..."
docker compose up -d --force-recreate

echo "Dashboard should be available at http://127.0.0.1:${NODE_APP_PORT:-3333}/ (see README)"
docker compose ps
