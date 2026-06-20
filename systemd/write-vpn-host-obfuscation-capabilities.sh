#!/usr/bin/env bash
# Write /var/lib/mpc-auth-docker/vpn-host-obfuscation.json (mpc-auth GET /vpn/status).
# Run after installing optional obfuscation binaries (LWO, udp2raw, etc.).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/.." && pwd)"

# shellcheck source=../scripts/lib/write-vpn-host-obfuscation-capabilities.sh
. "${REPO_ROOT}/scripts/lib/write-vpn-host-obfuscation-capabilities.sh"

write_vpn_host_obfuscation_capabilities "${1:-/var/lib/mpc-auth-docker}"
