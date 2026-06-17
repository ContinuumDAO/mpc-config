#!/usr/bin/env bash
# Shipped host wrapper — Docker extension host.cli.exec resolves this by name.
# Delegates to the real host PATH (curl, bash, env, sudo, etc.).
#
# Docker Desktop's host exec sandbox often cannot write to /tmp (curl exit 23).
# When continuum-orchestrate.sh is bundled alongside this wrapper, skip the curl
# download and run the bundled script instead of /tmp/continuum-desktop-orchestrate.sh.
set -euo pipefail

HOST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORCHESTRATE="${HOST_DIR}/continuum-orchestrate.sh"

if [[ "${1:-}" == "curl" && -f "$ORCHESTRATE" ]]; then
  # UI: curl -fsSL <url> -o /tmp/continuum-desktop-orchestrate.sh — satisfy without writing /tmp.
  exit 0
fi

args=("$@")
if [[ -f "$ORCHESTRATE" ]]; then
  for i in "${!args[@]}"; do
    if [[ "${args[i]}" == "/tmp/continuum-desktop-orchestrate.sh" ]]; then
      args[i]="$ORCHESTRATE"
    fi
  done
fi

exec "${args[@]}"
