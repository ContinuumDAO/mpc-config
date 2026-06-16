#!/usr/bin/env bash
# Pull docker compose images with per-image install progress topics, then compose up -d.
#
# Usage:
#   docker-compose-pull-with-progress.sh [repo_dir]
#
# Prefer sourcing install-progress-docker.sh from the parent install script when possible
# so progress state stays in one process (required for accurate extension UI completion).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=install-progress.sh
. "${SCRIPT_DIR}/install-progress.sh"
# shellcheck source=install-progress-docker.sh
. "${SCRIPT_DIR}/install-progress-docker.sh"

REPO_DIR="${1:-${MPC_REPO_DIR:-$(cd "$SCRIPT_DIR/../.." && pwd)}}"
install_progress_docker_pull_and_up "$REPO_DIR"
