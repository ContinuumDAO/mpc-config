#!/usr/bin/env bash
# Copy mpc-auth-generated OpenAPI specs into this repo's docs/{,references}/.
# Regenerate canonical files first: (cd ../mpc-auth && python3 scripts/generate_management_swagger.py)
# Override mpc-auth repo: MPC_AUTH_PATH=/path/to/mpc-auth ./scripts/sync_swagger_from_mpc_auth.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AUTH_DOCS="${MPC_AUTH_PATH:-"$ROOT/../mpc-auth"}/docs"

for name in swagger.json swagger.yaml; do
  if [[ ! -f "$AUTH_DOCS/$name" ]]; then
    echo "error: missing $AUTH_DOCS/$name (run generate_management_swagger.py in mpc-auth or set MPC_AUTH_PATH)" >&2
    exit 1
  fi
done

for dest in "$ROOT/docs" "$ROOT/docs/references"; do
  cp "$AUTH_DOCS/swagger.json" "$AUTH_DOCS/swagger.yaml" "$dest/"
  echo "Updated $dest"
done
