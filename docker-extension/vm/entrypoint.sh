#!/usr/bin/env bash
# Extension backend keeper — install orchestration runs on the host (WSL on Windows,
# native shell on Linux) via host.cli.exec, not inside this container.
set -euo pipefail
exec tail -f /dev/null
