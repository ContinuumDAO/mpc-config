#!/usr/bin/env bash
# Write Continuum [boot] command into /etc/wsl.conf (fresh-install overwrite of boot.command only).
# Other wsl.conf sections (e.g. [boot] systemd) are preserved.
#
# Usage:
#   bash wsl-desktop/install-wsl-boot-command.sh
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
. "${HERE}/_lib.sh"

WATCHER="${HERE}/start-watcher.sh"
if [[ ! -f "$WATCHER" ]]; then
	echo "error: missing ${WATCHER}" >&2
	exit 1
fi

COMMAND="/bin/bash ${WATCHER}"
CONF=/etc/wsl.conf
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

python3 - "$CONF" "$COMMAND" "$TMP" <<'PY'
import configparser
import os
import sys

conf_path, command, tmp_path = sys.argv[1], sys.argv[2], sys.argv[3]
parser = configparser.ConfigParser(interpolation=None)
parser.optionxform = str
if os.path.isfile(conf_path):
    try:
        parser.read(conf_path)
    except configparser.Error:
        pass
if not parser.has_section("boot"):
    parser.add_section("boot")
parser.set("boot", "command", command)
with open(tmp_path, "w", encoding="utf-8") as f:
    parser.write(f, space_around_delimiters=True)
print(f"wsl.conf [boot] command={command}")
PY

wsl_desktop_sudo install -m 0644 "$TMP" "$CONF"
