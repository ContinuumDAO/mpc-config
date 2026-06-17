#!/usr/bin/env bash
# Configure dashboard container discovery for Docker Desktop local installs.
# Source from install scripts; do not execute directly.
#
# After provision-node.sh, process_config writes discovery aliases pointing at
# host.docker.internal. On Docker Desktop the dashboard and mpc-auth both run in
# compose — point loopback aliases at the mpc-auth compose service so containers
# communicate over the Docker network.

: "${CONFIGURE_DESKTOP_COMPOSE_DISCOVERY_LOADED:=}"
if [ -n "$CONFIGURE_DESKTOP_COMPOSE_DISCOVERY_LOADED" ]; then
    return 0 2>/dev/null || exit 0
fi
CONFIGURE_DESKTOP_COMPOSE_DISCOVERY_LOADED=1

configure_desktop_compose_discovery() {
    local repo_dir="${1:?repo_dir required}"
    local dry_run="${2:-false}"
    local mpc_auth_service="${MPC_AUTH_COMPOSE_SERVICE:-app}"

    local compose_file="${repo_dir}/docker-compose.yml"
    local config_file="${repo_dir}/configs.yaml"

    if [ "$dry_run" = true ]; then
        printf '[dry-run] configure dashboard discovery in %q (loopback → compose service %q)\n' \
            "$compose_file" "$mpc_auth_service"
        return 0
    fi

    [ -f "$compose_file" ] || {
        printf 'error: missing %s after provision\n' "$compose_file" >&2
        return 1
    }
    [ -f "$config_file" ] || {
        printf 'error: missing %s after provision\n' "$config_file" >&2
        return 1
    }

    printf '==> Configuring dashboard container discovery (mpc-auth via compose service %s)\n' "$mpc_auth_service" >&2

    DESKTOP_COMPOSE_FILE="$compose_file" \
    DESKTOP_MPC_AUTH_SERVICE="$mpc_auth_service" \
    python3 <<'PYDESKTOP'
import os
import sys

try:
    from ruamel.yaml import YAML
except ImportError:
    print("error: ruamel.yaml required to configure docker-compose.yml", file=sys.stderr)
    sys.exit(1)

compose_path = os.environ.get("DESKTOP_COMPOSE_FILE", "")
mpc_auth = (os.environ.get("DESKTOP_MPC_AUTH_SERVICE") or "app").strip() or "app"

if not compose_path:
    sys.exit(1)

aliases = f"127.0.0.1={mpc_auth},localhost={mpc_auth},::1={mpc_auth}"

y = YAML()
y.preserve_quotes = True
y.width = 4096

with open(compose_path, encoding="utf-8") as f:
    compose = y.load(f)

if not isinstance(compose, dict):
    print("error: invalid docker-compose.yml", file=sys.stderr)
    sys.exit(1)

services = compose.get("services")
if not isinstance(services, dict) or "dashboard" not in services:
    print("error: docker-compose.yml has no dashboard service", file=sys.stderr)
    sys.exit(1)

dash = services["dashboard"]
if not isinstance(dash, dict):
    print("error: dashboard service is not a mapping", file=sys.stderr)
    sys.exit(1)


def normalize_env(env):
    if env is None:
        return {}
    if isinstance(env, dict):
        return dict(env)
    if isinstance(env, list):
        out = {}
        for item in env:
            if isinstance(item, str) and "=" in item:
                k, v = item.split("=", 1)
                out[k] = v
        return out
    return {}


env = normalize_env(dash.get("environment"))
env["NODE_READ_DISCOVERY_LOCAL_BIND_ALIASES"] = aliases
env.pop("NODE_READ_DISCOVERY_HAIRPIN_FALLBACK", None)
env.setdefault("NODE_READ_DISCOVERY_ALLOW_PRIVATE", "1")
env.setdefault("ENABLE_PLAIN_HTTP_ATTACH", "1")
dash["environment"] = env

with open(compose_path, "w", encoding="utf-8") as f:
    y.dump(compose, f)

print(f"ok aliases={aliases}", flush=True)
PYDESKTOP
}
