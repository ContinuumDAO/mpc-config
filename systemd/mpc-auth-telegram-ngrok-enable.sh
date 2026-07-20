#!/usr/bin/env bash
# Start ngrok sidecar sharing the mpc-auth app container network namespace.
# Invoked by mpc-auth-apply-pending-telegram-ngrok.sh after POST /telegramNgrok/setEnabled.

set -euo pipefail

DEFAULT_ENV="/etc/default/mpc-auth-docker"
[[ -r "$DEFAULT_ENV" ]] && . "$DEFAULT_ENV"

STATE_FILE="${MPC_AUTH_TELEGRAM_NGROK_STATE_FILE:-/var/lib/mpc-auth-docker/telegram-ngrok-state.json}"
APP_CONTAINER="${MPC_AUTH_CONTAINER_NAME:-mpc-config-app-1}"
SIDECAR="${MPC_AUTH_TELEGRAM_NGROK_CONTAINER_NAME:-mpc-auth-telegram-ngrok}"
NGROK_IMAGE="${MPC_AUTH_TELEGRAM_NGROK_IMAGE:-ngrok/ngrok:latest}"
PENDING_JSON="${MPC_APPLY_PENDING_TELEGRAM_NGROK_JSON:-}"

if [[ -z "$PENDING_JSON" || ! -f "$PENDING_JSON" ]]; then
	echo "mpc-auth-telegram-ngrok-enable: missing pending JSON" >&2
	exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
	echo "mpc-auth-telegram-ngrok-enable: docker not found" >&2
	exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
	echo "mpc-auth-telegram-ngrok-enable: python3 required" >&2
	exit 1
fi

eval "$(python3 - "$PENDING_JSON" <<'PY'
import json, os, shlex, sys
path = sys.argv[1]
with open(path, encoding="utf-8") as f:
    d = json.load(f)
webhook_id = (d.get("webhookId") or "").strip()
token = (d.get("ngrokAuthtoken") or "").strip()
hook_port = int(d.get("hookPort") or 18090)
sidecar = (d.get("sidecarContainerName") or os.environ.get("MPC_AUTH_TELEGRAM_NGROK_CONTAINER_NAME") or "mpc-auth-telegram-ngrok").strip()
if not webhook_id:
    sys.stderr.write("mpc-auth-telegram-ngrok-enable: webhookId required\n")
    sys.exit(2)
if not token:
    sys.stderr.write("mpc-auth-telegram-ngrok-enable: ngrokAuthtoken required\n")
    sys.exit(2)
if hook_port <= 0 or hook_port > 65535:
    sys.stderr.write(f"mpc-auth-telegram-ngrok-enable: invalid hookPort {hook_port}\n")
    sys.exit(2)
print(f"export WEBHOOK_ID={shlex.quote(webhook_id)}")
print(f"export NGROK_AUTHTOKEN={shlex.quote(token)}")
print(f"export HOOK_PORT={shlex.quote(str(hook_port))}")
print(f"export SIDECAR={shlex.quote(sidecar)}")
PY
)"

APP_CID="$(docker ps -qf "name=^${APP_CONTAINER}$" | head -n1 || true)"
if [[ -z "$APP_CID" ]]; then
	echo "mpc-auth-telegram-ngrok-enable: app container ${APP_CONTAINER} not running" >&2
	python3 - "$STATE_FILE" "$WEBHOOK_ID" "$HOOK_PORT" "$SIDECAR" "app container not running" <<'PY'
import json, sys, datetime
path, webhook_id, hook_port, sidecar, err = sys.argv[1:6]
state = {
    "active": False,
    "webhookId": webhook_id,
    "hookPort": int(hook_port),
    "sidecarContainerName": sidecar,
    "updatedAt": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    "lastError": err,
}
with open(path + ".tmp", "w", encoding="utf-8") as f:
    json.dump(state, f)
import os
os.replace(path + ".tmp", path)
PY
	exit 1
fi

docker rm -f "$SIDECAR" 2>/dev/null || true

if ! docker run -d \
	--name "$SIDECAR" \
	--restart unless-stopped \
	--network "container:${APP_CID}" \
	-e "NGROK_AUTHTOKEN=${NGROK_AUTHTOKEN}" \
	"$NGROK_IMAGE" \
	http "${HOOK_PORT}" >/dev/null; then
	echo "mpc-auth-telegram-ngrok-enable: docker run failed" >&2
	exit 1
fi

PUBLIC_URL=""
for _ in $(seq 1 45); do
	RAW="$(docker exec "$SIDECAR" wget -qO- http://127.0.0.1:4040/api/tunnels 2>/dev/null || true)"
	if [[ -n "$RAW" ]]; then
		PUBLIC_URL="$(python3 - <<'PY'
import json, sys
raw = sys.stdin.read()
try:
    data = json.loads(raw)
except json.JSONDecodeError:
    raise SystemExit(1)
tunnels = data.get("tunnels") or []
for t in tunnels:
    if (t.get("proto") or "").lower() == "https" and t.get("public_url"):
        print(t["public_url"].rstrip("/"))
        raise SystemExit(0)
for t in tunnels:
    if t.get("public_url"):
        print(str(t["public_url"]).rstrip("/"))
        raise SystemExit(0)
raise SystemExit(1)
PY
<<<"$RAW")" || PUBLIC_URL=""
		[[ -n "$PUBLIC_URL" ]] && break
	fi
	sleep 1
done

if [[ -z "$PUBLIC_URL" ]]; then
	docker rm -f "$SIDECAR" 2>/dev/null || true
	python3 - "$STATE_FILE" "$WEBHOOK_ID" "$HOOK_PORT" "$SIDECAR" "timed out waiting for ngrok public URL" <<'PY'
import json, sys, datetime
path, webhook_id, hook_port, sidecar, err = sys.argv[1:6]
state = {
    "active": False,
    "webhookId": webhook_id,
    "hookPort": int(hook_port),
    "sidecarContainerName": sidecar,
    "updatedAt": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
    "lastError": err,
}
with open(path + ".tmp", "w", encoding="utf-8") as f:
    json.dump(state, f)
import os
os.replace(path + ".tmp", path)
PY
	echo "mpc-auth-telegram-ngrok-enable: timed out waiting for ngrok public URL" >&2
	exit 1
fi

python3 - "$STATE_FILE" "$WEBHOOK_ID" "$PUBLIC_URL" "$HOOK_PORT" "$SIDECAR" <<'PY'
import json, sys, datetime
path, webhook_id, public_url, hook_port, sidecar = sys.argv[1:6]
public_url = public_url.rstrip("/")
inbound = f"{public_url}/hooks/inbound/{webhook_id}"
state = {
    "active": True,
    "webhookId": webhook_id,
    "publicUrl": public_url,
    "inboundUrl": inbound,
    "hookPort": int(hook_port),
    "sidecarContainerName": sidecar,
    "updatedAt": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
}
with open(path + ".tmp", "w", encoding="utf-8") as f:
    json.dump(state, f)
import os
os.replace(path + ".tmp", path)
print(inbound)
PY

echo "mpc-auth-telegram-ngrok-enable: tunnel ready for webhook ${WEBHOOK_ID}" >&2
