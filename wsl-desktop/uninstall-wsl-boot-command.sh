#!/usr/bin/env bash
# Remove the Continuum watcher [boot] command from /etc/wsl.conf. Other sections stay.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
if [[ -f "${HERE}/_lib.sh" ]]; then
	. "${HERE}/_lib.sh"
fi

CONF=/etc/wsl.conf
if [[ ! -f "$CONF" ]]; then
	echo "No ${CONF}."
	exit 0
fi

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

python3 - "$CONF" "$TMP" <<'PY'
import configparser
import os
import sys

conf_path, tmp_path = sys.argv[1], sys.argv[2]
parser = configparser.ConfigParser(interpolation=None)
parser.optionxform = str
try:
    parser.read(conf_path)
except configparser.Error:
    print(f"warning: could not parse {conf_path} — leaving as-is")
    sys.exit(0)

if not parser.has_section("boot") or not parser.has_option("boot", "command"):
    print("No [boot] command in wsl.conf.")
    sys.exit(0)

command = parser.get("boot", "command")
if "mpc-config" not in command and "wsl-desktop" not in command and "start-watcher" not in command:
    print(f"Leaving unrelated [boot] command: {command}")
    sys.exit(0)

parser.remove_option("boot", "command")
if not parser.options("boot"):
    parser.remove_section("boot")
with open(tmp_path, "w", encoding="utf-8") as f:
    parser.write(f, space_around_delimiters=True)
    if f.tell() == 0:
        f.write("# Continuum [boot] command removed\n")
print("Removed Continuum [boot] command from wsl.conf")
PY

if [[ ! -s "$TMP" ]]; then
	exit 0
fi

if declare -F wsl_desktop_sudo >/dev/null 2>&1; then
	wsl_desktop_sudo install -m 0644 "$TMP" "$CONF"
elif [[ "${EUID:-}" -eq 0 ]]; then
	install -m 0644 "$TMP" "$CONF"
else
	sudo install -m 0644 "$TMP" "$CONF"
fi
