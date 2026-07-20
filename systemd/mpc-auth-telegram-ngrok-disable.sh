#!/usr/bin/env bash
# Stop ngrok sidecar after mpc-auth POST /telegramNgrok/setEnabled (disable).

set -euo pipefail

DEFAULT_ENV="/etc/default/mpc-auth-docker"
[[ -r "$DEFAULT_ENV" ]] && . "$DEFAULT_ENV"

STATE_FILE="${MPC_AUTH_TELEGRAM_NGROK_STATE_FILE:-/var/lib/mpc-auth-docker/telegram-ngrok-state.json}"
SIDECAR="${MPC_AUTH_TELEGRAM_NGROK_CONTAINER_NAME:-mpc-auth-telegram-ngrok}"

if command -v docker >/dev/null 2>&1; then
	docker rm -f "$SIDECAR" 2>/dev/null || true
fi

if command -v python3 >/dev/null 2>&1; then
	python3 - "$STATE_FILE" "$SIDECAR" <<'PY'
import json, os, sys, datetime
path, sidecar = sys.argv[1], sys.argv[2]
webhook_id = ""
hook_port = 18090
if os.path.isfile(path):
    try:
        with open(path, encoding="utf-8") as f:
            prev = json.load(f)
        webhook_id = (prev.get("webhookId") or "").strip()
        hook_port = int(prev.get("hookPort") or hook_port)
    except (OSError, json.JSONDecodeError, ValueError, TypeError):
        pass
state = {
    "active": False,
    "webhookId": webhook_id,
    "publicUrl": "",
    "inboundUrl": "",
    "hookPort": hook_port,
    "sidecarContainerName": sidecar,
    "updatedAt": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
}
with open(path + ".tmp", "w", encoding="utf-8") as f:
    json.dump(state, f)
os.replace(path + ".tmp", path)
PY
fi

echo "mpc-auth-telegram-ngrok-disable: stopped ${SIDECAR}" >&2
