#!/usr/bin/env bash
# Register the elevated Windows Firewall task and apply the shared connection plan.
# The firewall logic stays in this repo's desktop host automation. Docker Desktop
# only needs to call this after the node is cloned.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PS1="${HERE}/mpc-auth-firewall.ps1"

if [[ ! -f "$PS1" ]]; then
	echo "error: missing ${PS1}" >&2
	exit 1
fi

if ! command -v powershell.exe >/dev/null 2>&1; then
	echo "warning: powershell.exe not on PATH — Windows Firewall rules were not installed" >&2
	exit 0
fi

DISTRO="${WSL_DISTRO_NAME:-}"
if [[ -z "$DISTRO" ]]; then
	echo "warning: WSL_DISTRO_NAME unset — Windows Firewall rules were not installed" >&2
	exit 0
fi

if [[ -f "${HERE}/repo-dir.txt" ]]; then
	REPO="$(cat "${HERE}/repo-dir.txt")"
else
	REPO="$(cd "${HERE}/.." && pwd)"
fi

WIN_PS1="$PS1"
if command -v wslpath >/dev/null 2>&1; then
	WIN_PS1="$(wslpath -w "$PS1")"
fi

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$WIN_PS1" -Action install -Distro "$DISTRO" -Repo "$REPO"
