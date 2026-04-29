#!/usr/bin/env bash
# Consume mpc-auth-docker pending-update JSON written by mpc-auth POST /updateMpcAuth (host path bind-mounted).
# Runs mpc-auth-docker-update.sh TAG DIGEST on the Docker host via systemd.path → this oneshot.
#
# pending-update.json may include restartOnly and forceRecreate; they are exported for mpc-auth-docker-update.sh.

set -euo pipefail

PENDING_FILE="${MPC_AUTH_DOCKER_PENDING_FILE:-/var/lib/mpc-auth-docker/pending-update.json}"
LIBEXEC="/usr/local/libexec/mpc-auth"
UPDATE_SCRIPT="${LIBEXEC}/mpc-auth-docker-update.sh"
DONE_DIR="$(dirname "$PENDING_FILE")/applied"
PROCESSING="${PENDING_FILE}.processing"

mkdir -p "$DONE_DIR"

if [[ ! -f "$PENDING_FILE" ]]; then
	exit 0
fi

if ! mv "$PENDING_FILE" "$PROCESSING"; then
	echo "mpc-auth-apply-pending-update: failed to claim ${PENDING_FILE}" >&2
	exit 1
fi

_stamp() {
	date +%Y%m%d%H%M%S
}

abort_bad_json() {
	echo "mpc-auth-apply-pending-update: invalid JSON — need non-empty tag; registryDigest required unless restartOnly" >&2
	mv -f "$PROCESSING" "${DONE_DIR}/failed-$(_stamp).bad.json" || true
	exit 1
}

run_update() {
	if [[ ! -x "$UPDATE_SCRIPT" ]]; then
		echo "mpc-auth-apply-pending-update: missing ${UPDATE_SCRIPT}" >&2
		mv -f "$PROCESSING" "${DONE_DIR}/failed-$(_stamp).noscript.json" || true
		exit 1
	fi
	echo "mpc-auth-apply-pending-update: applying tag=${_TAG:?} digest=${_DIG:-"(empty)"} restartOnly=${_RESTART_ONLY} forceRecreate=${_FORCE_RECREATE}"
	export MPC_AUTH_PENDING_RESTART_ONLY="${_RESTART_ONLY}"
	export MPC_AUTH_PENDING_FORCE_RECREATE="${_FORCE_RECREATE}"
	if "$UPDATE_SCRIPT" "$_TAG" "$_DIG"; then
		mv -f "$PROCESSING" "${DONE_DIR}/ok-$(_stamp).json" || rm -f "$PROCESSING"
		exit 0
	fi
	mv -f "$PROCESSING" "${DONE_DIR}/failed-$(_stamp).update.json" || true
	exit 1
}

if ! command -v python3 >/dev/null 2>&1; then
	echo "mpc-auth-apply-pending-update: python3 required to parse pending JSON" >&2
	mv -f "$PROCESSING" "${DONE_DIR}/failed-$(_stamp).nopython.json" || true
	exit 1
fi

_py_parse() {
	export MPC_APPLY_PENDING_JSON="$PROCESSING"
	python3 <<'PY'
import json, os, sys
path = os.environ["MPC_APPLY_PENDING_JSON"]
with open(path) as f:
    d = json.load(f)
tag = (d.get("tag") or d.get("newVersionRequested") or "").strip()
dig = (d.get("registryDigest") or d.get("registry_digest") or d.get("expectedDigest") or "").strip()
if dig and not dig.startswith("sha256:"):
    xs = "".join(c for c in dig.lower() if c in "0123456789abcdef")
    if len(xs) == 64:
        dig = "sha256:" + xs
restart_only = bool(d.get("restartOnly") or d.get("restart_only"))
force_recreate = bool(d.get("forceRecreate") or d.get("force_recreate"))
ro = "1" if restart_only else "0"
fr = "1" if force_recreate else "0"
sys.stdout.write(tag + "\n" + dig + "\n" + ro + "\n" + fr + "\n")
PY
}

_lines=()
if ! mapfile -t _lines < <(_py_parse); then
	abort_bad_json
fi

if [[ "${#_lines[@]}" -lt 4 ]]; then
	abort_bad_json
fi

_TAG="${_lines[0]}"
_DIG="${_lines[1]}"
_RESTART_ONLY="${_lines[2]}"
_FORCE_RECREATE="${_lines[3]}"

if [[ -z "${_TAG:-}" ]]; then
	abort_bad_json
fi
if [[ "${_RESTART_ONLY}" != "1" && -z "${_DIG:-}" ]]; then
	abort_bad_json
fi

run_update
