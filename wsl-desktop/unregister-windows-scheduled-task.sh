#!/usr/bin/env bash
# Delete ContinuumNodeMpcAuthWatcher / ContinuumNodeMpcAuthWatcherPoll via Windows schtasks.
# Must run inside WSL with powershell.exe on PATH.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PS1="${HERE}/unregister-windows-scheduled-task.ps1"

if [[ ! -f "$PS1" ]]; then
	echo "error: missing ${PS1}" >&2
	exit 1
fi

if ! command -v powershell.exe >/dev/null 2>&1; then
	echo "warning: powershell.exe not found — delete Scheduled Tasks from Windows:" >&2
	echo "  schtasks /Delete /TN ContinuumNodeMpcAuthWatcher /F" >&2
	echo "  schtasks /Delete /TN ContinuumNodeMpcAuthWatcherPoll /F" >&2
	exit 0
fi

win_ps1="$(wslpath -w "$PS1" 2>/dev/null || true)"
if [[ -z "$win_ps1" ]]; then
	echo "warning: wslpath failed — skipping Scheduled Task delete." >&2
	exit 0
fi

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$win_ps1"
