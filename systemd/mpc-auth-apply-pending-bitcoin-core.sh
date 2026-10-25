#!/usr/bin/env bash
# Consume pending-bitcoin-core.json written by mpc-auth POST /startBitcoinCore and POST /stopBitcoinCore.
# Starts or stops the bitcoin-core Compose service. Does not publish an RPC port.

set -euo pipefail

if [[ -n "${MPC_AUTH_WSL_ENV_FILE:-}" && -r "${MPC_AUTH_WSL_ENV_FILE}" ]]; then
	# shellcheck source=/dev/null
	. "${MPC_AUTH_WSL_ENV_FILE}"
elif [[ -n "${MPC_AUTH_MACOS_ENV_FILE:-}" && -r "${MPC_AUTH_MACOS_ENV_FILE}" ]]; then
	# shellcheck source=/dev/null
	. "${MPC_AUTH_MACOS_ENV_FILE}"
elif [[ -r /etc/default/mpc-auth-docker ]]; then
	# shellcheck source=/dev/null
	. /etc/default/mpc-auth-docker
fi

PENDING_FILE="${MPC_AUTH_BITCOIN_CORE_PENDING_FILE:-/var/lib/mpc-auth-docker/pending-bitcoin-core.json}"
STATE_FILE="${MPC_AUTH_BITCOIN_CORE_STATE_FILE:-/var/lib/mpc-auth-docker/bitcoin-core-state.json}"
RPC_FILE="${MPC_AUTH_BITCOIN_CORE_RPC_FILE:-/var/lib/mpc-auth-docker/bitcoin-core-rpc.json}"
DATA_DIR="${MPC_AUTH_BITCOIN_CORE_DATA_DIR:-/var/lib/mpc-auth-docker/bitcoin-core-data}"
DISK_DIR="${MPC_AUTH_BITCOIN_CORE_DISK_DIR:-/var/lib/mpc-auth-docker}"
IMAGE="${MPC_AUTH_BITCOIN_CORE_IMAGE:-continuumdao/bitcoin-core:v28.4}"
FALLBACK_IMAGE="${MPC_AUTH_BITCOIN_CORE_FALLBACK_IMAGE:-bitcoin/bitcoin:28.4}"
REQUIRED_KB=$((100 * 1024 * 1024))
DONE_DIR="$(dirname "$PENDING_FILE")/applied"
PROCESSING="${PENDING_FILE}.processing"

mkdir -p "$DONE_DIR" "$DISK_DIR"

write_state() {
	local action="$1" network="$2" ok="$3" err="$4"
	python3 - "$STATE_FILE" "$action" "$network" "$ok" "$err" <<'PY'
import json, sys
path, action, network, ok, err = sys.argv[1:]
body = {
    "action": action,
    "network": network,
    "ok": ok == "true",
    "error": err,
    "updatedAt": __import__("datetime").datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
}
tmp = path + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    json.dump(body, f)
os_replace = __import__("os").replace
os_replace(tmp, path)
PY
}

if [[ ! -f "$PENDING_FILE" ]]; then
	exit 0
fi
if ! mv "$PENDING_FILE" "$PROCESSING"; then
	echo "mpc-auth-apply-pending-bitcoin-core: failed to claim ${PENDING_FILE}" >&2
	exit 1
fi

_stamp() { date +%Y%m%d%H%M%S; }

fail() {
	local action="$1" network="$2" msg="$3"
	echo "mpc-auth-apply-pending-bitcoin-core: ${msg}" >&2
	write_state "$action" "$network" false "$msg" || true
	mv -f "$PROCESSING" "${DONE_DIR}/failed-$(_stamp).json" || true
	exit 1
}

export MPC_APPLY_PENDING_BITCOIN_CORE_JSON="$PROCESSING"
eval "$(python3 <<'PY'
import json, os, shlex, sys
path = os.environ["MPC_APPLY_PENDING_BITCOIN_CORE_JSON"]
with open(path) as f:
    d = json.load(f)
action = (d.get("action") or "").strip().lower()
network = (d.get("network") or "mainnet").strip().lower()
if action not in ("start", "stop"):
    sys.stderr.write(f"unexpected action {action!r}\n")
    sys.exit(2)
if network not in ("mainnet", "testnet", "signet"):
    sys.stderr.write(f"unexpected network {network!r}\n")
    sys.exit(2)
print(f"export MPC_AUTH_BITCOIN_CORE_ACTION={shlex.quote(action)}")
print(f"export MPC_AUTH_BITCOIN_CORE_NETWORK={shlex.quote(network)}")
PY
)" || fail "start" "mainnet" "invalid pending JSON"

ACTION="$MPC_AUTH_BITCOIN_CORE_ACTION"
NETWORK="$MPC_AUTH_BITCOIN_CORE_NETWORK"
WORKDIR="${MPC_AUTH_COMPOSE_WORKDIR:-${MPC_AUTH_COMPOSE_DIR:-}}"
if [[ -z "$WORKDIR" || ! -f "${WORKDIR}/docker-compose.yml" ]]; then
	fail "$ACTION" "$NETWORK" "MPC_AUTH_COMPOSE_WORKDIR is not set to a directory containing docker-compose.yml"
fi

free_kb() {
	df -Pk "$DISK_DIR" | awk 'NR==2 {print $4}'
}

if [[ "$ACTION" == "start" ]]; then
	avail="$(free_kb || true)"
	if [[ -z "$avail" || "$avail" -lt "$REQUIRED_KB" ]]; then
		fail "$ACTION" "$NETWORK" "This disk has less than 100 GB free. Bitcoin Core was not installed."
	fi
	if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
		if ! docker pull "$IMAGE"; then
			docker pull "$FALLBACK_IMAGE"
			docker tag "$FALLBACK_IMAGE" "$IMAGE"
		fi
	fi
	mkdir -p "$DATA_DIR"
	rpc_pass="$(openssl rand -hex 24)"
	chain_line=""
	case "$NETWORK" in
	testnet) chain_line="chain=test" ;;
	signet) chain_line="signet=1" ;;
	esac
	cat >"${DATA_DIR}/bitcoin.conf" <<EOF
server=1
disablewallet=1
prune=2000
txindex=0
rpcuser=continuum
rpcpassword=${rpc_pass}
rpcport=8332
rpcbind=0.0.0.0
rpcallowip=10.0.0.0/8
rpcallowip=172.16.0.0/12
rpcallowip=192.168.0.0/16
${chain_line}
EOF
	chmod 0644 "${DATA_DIR}/bitcoin.conf"
	python3 - "$RPC_FILE" "$rpc_pass" "$NETWORK" <<'PY'
import json, os, sys
path, password, network = sys.argv[1:]
body = {
    "url": "http://bitcoin-core:8332",
    "user": "continuum",
    "password": password,
    "network": network,
}
tmp = path + ".tmp"
with open(tmp, "w", encoding="utf-8") as f:
    json.dump(body, f)
os.replace(tmp, path)
os.chmod(path, 0o640)
PY
	if ! (cd "$WORKDIR" && docker compose --profile bitcoin-core up -d --no-deps --force-recreate bitcoin-core); then
		rm -f "$RPC_FILE"
		fail "$ACTION" "$NETWORK" "docker compose could not start bitcoin-core"
	fi
	write_state "$ACTION" "$NETWORK" true ""
else
	(cd "$WORKDIR" && docker compose --profile bitcoin-core stop bitcoin-core) || true
	rm -f "$RPC_FILE"
	write_state "$ACTION" "$NETWORK" true ""
fi

mv -f "$PROCESSING" "${DONE_DIR}/ok-$(_stamp).json" || rm -f "$PROCESSING"
exit 0
