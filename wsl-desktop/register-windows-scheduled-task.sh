#!/usr/bin/env bash
# Register Windows Scheduled Tasks (logon + 5-minute interval) that start the WSL watcher.
# Called from WSL via powershell.exe. The Docker extension also registers via
# host/windows/continuum-register-watcher.cmd.
#
# Usage:
#   bash wsl-desktop/register-windows-scheduled-task.sh
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PS1="${HERE}/register-windows-scheduled-task.ps1"

if ! command -v powershell.exe >/dev/null 2>&1; then
	echo "warning: powershell.exe not on PATH — skip Windows Scheduled Task (use the Docker extension or continuum-register-watcher.cmd)" >&2
	exit 0
fi

DISTRO="${WSL_DISTRO_NAME:-}"
if [[ -z "$DISTRO" ]]; then
	echo "warning: WSL_DISTRO_NAME unset — skip Scheduled Task registration" >&2
	exit 0
fi

if [[ ! -f "$PS1" ]]; then
	echo "error: missing ${PS1}" >&2
	exit 1
fi

WIN_PS1="$PS1"
if command -v wslpath >/dev/null 2>&1; then
	WIN_PS1="$(wslpath -w "$PS1")"
fi

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$WIN_PS1" -Distro "$DISTRO"
