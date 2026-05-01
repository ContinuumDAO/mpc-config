#!/usr/bin/env bash
# Run the dashboard in the foreground (docker compose up) so logs appear in this terminal.
# For normal use, prefer ./install-or-update-node-app.sh (detached + recreate).
#
# Usage:
#   ./run-node-app.sh              # attached, Ctrl+C stops containers
#   ./run-node-app.sh --detach   # same as: docker compose up -d

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ ! -f .env ]]; then
	echo "error: missing .env — copy .env.example to .env and set REOWN_PROJECT_ID, then run ./install-or-update-node-app.sh once." >&2
	exit 1
fi

if [[ "${1:-}" == "--detach" ]] || [[ "${1:-}" == "-d" ]]; then
	docker compose up -d
	echo "Running detached. Port: see NODE_APP_PORT in .env (default 3333)."
	docker compose ps
else
	exec docker compose up
fi
