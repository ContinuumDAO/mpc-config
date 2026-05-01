#!/usr/bin/env bash
# Pull the ContinuumDAO dashboard image from the registry (default: continuumdao/continuumdao-node-app:latest).
# Uses NODE_APP_IMAGE and NODE_APP_TAG from ./.env when that file exists.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ -f .env ]]; then
	set -a
	# shellcheck disable=SC1091
	source .env
	set +a
fi

IMAGE="${NODE_APP_IMAGE:-continuumdao/continuumdao-node-app}"
TAG="${NODE_APP_TAG:-latest}"
REF="${IMAGE}:${TAG}"

echo "Pulling ${REF} ..."
docker pull "${REF}"
echo "Done: ${REF}"
