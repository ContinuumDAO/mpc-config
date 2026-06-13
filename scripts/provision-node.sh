#!/usr/bin/env bash
# Automated single-node provisioning:
#   1. Requires a fresh configs.yaml — copies configs-original.yaml, then sets NodeMgtKey and/or PublicMgtKey (at least one).
#   2. Sets MPCGroups[0].nodeAddresses (relay placeholder + this host) and runs process_config.sh.
#
# Run as root, e.g.:
#   sudo -E ./scripts/provision-node.sh --node-mgt-key 0x...
#   sudo -E ./scripts/provision-node.sh --public-mgt-key '<64-hex or ssh-ed25519 line>'
#   sudo -E ./scripts/provision-node.sh -k 0x... --public-mgt-key '...'
# Legacy: one positional argument is treated as Ethereum NodeMgtKey.
# Use sudo -E if you rely on RELAYER_API_URL or other env vars after sudo.
#
# Prerequisites:
#   - Repo must contain configs-original.yaml (same directory layout as mpc-config).
#   - python3 + ruamel.yaml + cryptography (process_config runs tools/bootstrap_key_provision.py).
#
set -euo pipefail

# Same placeholder as process_config.sh — not a valid deployment key.
NODE_MGT_ETH_PLACEHOLDER_BODY="1234567890abcdef1234567890abcdef12345678"

RELAY_PLACEHOLDER_HOST="${PROVISION_RELAY_PLACEHOLDER_HOST:-0.0.0.0}"
# Port in nodeAddresses peer URLs (matches process_config.sh MPC_NODE_HTTP_PORT; not ManagementAPIsPort).
: "${PROVISION_HTTP_PORT:=8081}"

usage() {
    cat <<'EOF'
Usage:
  sudo [env vars...] ./scripts/provision-node.sh [options] [--node-mgt-key ADDR] [--public-mgt-key KEY]

  For a full VPS one-shot (packages, mpcnode user, clone, provision, docker compose up -d), see:
    ./scripts/install-node-debian-ubuntu.sh --help
    tools/provision-command.js (MPA frontend command builder)

  Provide at least one of:
    --node-mgt-key, -k ADDR   Ethereum management address (0x + 40 hex or 40 hex). Not the template placeholder.
    --public-mgt-key KEY      Ed25519 public: 64 hex (optional 0x), or full ssh-ed25519 line (quote if it contains spaces).

  If you pass only --node-mgt-key, process_config.sh generates PublicMgtKey + bootstrap_key + DeterministicNodeKey.
  With --public-mgt-key and no bootstrap seed file yet, configs set DeterministicNodeKey so mpc-auth stays bootstrap-pending
  (no random nodeKey) until you POST /postBootstrapKey or place bootstrap_key/ed25519_private.hex — e.g. frontend restore flow.
  Reinstall with seed on disk: copy bootstrap_key/ed25519_private.hex beside configs.yaml before this script; mpc-auth then
  derives the same deterministic nodeKey on fresh Mongo when the file matches PublicMgtKey.

  Legacy: a single positional argument is treated as NODE_MGT_ETH (same as -k).

Options:
  -c, --config PATH     Destination configs.yaml (default: <repo>/configs.yaml)
  -i, --ip ADDRESS      This node's peer address (default: auto-detect IPv4)
  -p, --http-port PORT  Port for http:// URLs in nodeAddresses (default: 8081, per process_config.sh MPC_NODE_HTTP_PORT)
      --relay-host HOST Relay placeholder host (default: 0.0.0.0)
      --install-systemd Pass --install-mpc-auth-systemd to process_config.sh
      --force-browser-certs  Pass --force-browser-https-certs
      --no-loopback       Do not enable BrowserLoopbackReadHTTP / omit --enable-loopback-http
      --no-firewall       Pass --no-firewall to process_config.sh
      --no-agent-llm-config-path  Pass --no-agent-llm-config-path to process_config.sh
  -h, --help            Show this help

If the destination configs.yaml already exists, the script exits with an error (nothing is overwritten).

Environment (optional):
  PROVISION_NODE_IP              Same as --ip
  PROVISION_HTTP_PORT            Peer URL port when --http-port omitted (default 8081)
  PROVISION_RELAY_PLACEHOLDER_HOST  Override relay placeholder (default 0.0.0.0)
  RELAYER_API_URL                Used by process_config.sh when RelayerAPIURL is empty
  PROCESS_CONFIG_NONINTERACTIVE  Defaults to 1 for this script (set 0 before sudo -E to allow process_config prompts)
  PROVISION_DEFER_NODE_KEY_UNTIL_BOOTSTRAP  Defaults to 1 when --public-mgt-key is set (bootstrap-pending, no random nodeKey).
                                             Set to 0 before sudo -E to restore the old behavior (omit DeterministicNodeKey when seed absent).
  See process_config.sh --help for additional variables.

Node layout written (MPCGroups[0] only):
  node1_key -> http://<relay-placeholder>:<port>
  node2_key -> http://<this-host>:<port>
EOF
}

require_root() {
    if [ "${EUID:-0}" -ne 0 ]; then
        echo "error: run as root (e.g. sudo $0)" >&2
        exit 1
    fi
}

# Print normalized 0x + 40 lowercase hex on stdout; exit 1 if invalid or placeholder.
validate_and_normalize_node_mgt_eth() {
    local raw="$1"
    raw="${raw#"${raw%%[![:space:]]*}"}"
    raw="${raw%"${raw##*[![:space:]]}"}"
    local body="$raw"
    if [[ "$body" =~ ^0[xX] ]]; then
        body="${body:2}"
    fi
    if [[ ! "$body" =~ ^[0-9a-fA-F]{40}$ ]]; then
        echo "error: NodeMgtKey must be an Ethereum address (40 hex digits, optional 0x prefix)" >&2
        return 1
    fi
    local low
    low=$(printf '%s' "$body" | tr '[:upper:]' '[:lower:]')
    if [ "$low" = "$NODE_MGT_ETH_PLACEHOLDER_BODY" ]; then
        echo "error: that address is the documentation placeholder — use your own keys" >&2
        return 1
    fi
    printf '0x%s' "$low"
}

# Print validated PublicMgtKey value on stdout: 64 lowercase hex, or ssh-ed25519 line (first line). Exit 1 on error.
validate_and_normalize_public_mgt_key() {
    local raw="$1"
    raw="${raw#"${raw%%[![:space:]]*}"}"
    raw="${raw%"${raw##*[![:space:]]}"}"
    if [ -z "$raw" ]; then
        echo "error: PublicMgtKey value is empty" >&2
        return 1
    fi
    local line
    line=$(printf '%s' "$raw" | head -1)
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    if [[ "$line" =~ ^ssh-ed25519[[:space:]] ]]; then
        printf '%s' "$line"
        return 0
    fi
    local s="$line"
    if [[ "$s" =~ ^0[xX] ]]; then
        s="${s:2}"
    fi
    s="${s//[[:space:]]/}"
    if [[ "$s" =~ ^[0-9a-fA-F]{128}$ ]]; then
        echo "error: PublicMgtKey looks like 128-hex secret material; use the 64-hex public key or an ssh-ed25519 line" >&2
        return 1
    fi
    if [[ ! "$s" =~ ^[0-9a-fA-F]{64}$ ]]; then
        echo "error: PublicMgtKey must be 64 hex (Ed25519 public) or an ssh-ed25519 \"...\" line" >&2
        return 1
    fi
    printf '%s' "$(printf '%s' "$s" | tr '[:upper:]' '[:lower:]')"
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PROCESS_CONFIG_SH="$REPO_ROOT/process_config.sh"
CONFIGS_ORIGINAL="$REPO_ROOT/configs-original.yaml"

CONFIG_FILE=""
NODE_IP=""
HTTP_PORT=""
INSTALL_SYSTEMD=false
FORCE_BROWSER=false
ENABLE_LOOPBACK=true
FIREWALL=true
SKIP_AGENT_LLM_CONFIG_PATH=false
NODE_MGT_KEY_CLI=""
PUBLIC_MGT_KEY_CLI=""
LEGACY_ETH_ARG=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        -k|--node-mgt-key)
            NODE_MGT_KEY_CLI="${2:?}"
            shift 2
            ;;
        --public-mgt-key)
            PUBLIC_MGT_KEY_CLI="${2:?}"
            shift 2
            ;;
        -c|--config)
            CONFIG_FILE="${2:?}"
            shift 2
            ;;
        -i|--ip)
            NODE_IP="${2:?}"
            shift 2
            ;;
        -p|--http-port)
            HTTP_PORT="${2:?}"
            shift 2
            ;;
        --relay-host)
            RELAY_PLACEHOLDER_HOST="${2:?}"
            shift 2
            ;;
        --install-systemd)
            INSTALL_SYSTEMD=true
            shift
            ;;
        --force-browser-certs)
            FORCE_BROWSER=true
            shift
            ;;
        --no-loopback)
            ENABLE_LOOPBACK=false
            shift
            ;;
        --no-firewall)
            FIREWALL=false
            shift
            ;;
        --no-agent-llm-config-path)
            SKIP_AGENT_LLM_CONFIG_PATH=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            echo "error: unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
        *)
            LEGACY_ETH_ARG+=("$1")
            shift
            ;;
    esac
done

require_root

if [ "${#LEGACY_ETH_ARG[@]}" -gt 0 ]; then
    if [ -n "$NODE_MGT_KEY_CLI" ] || [ -n "$PUBLIC_MGT_KEY_CLI" ]; then
        echo "error: do not mix bare arguments with --node-mgt-key or --public-mgt-key" >&2
        usage >&2
        exit 1
    fi
    if [ "${#LEGACY_ETH_ARG[@]}" -ne 1 ]; then
        echo "error: expected at most one legacy Ethereum positional argument, or use --node-mgt-key / --public-mgt-key" >&2
        usage >&2
        exit 1
    fi
    NODE_MGT_KEY_CLI="${LEGACY_ETH_ARG[0]}"
fi

if [ -z "$NODE_MGT_KEY_CLI" ] && [ -z "$PUBLIC_MGT_KEY_CLI" ]; then
    echo "error: provide --node-mgt-key (-k) and/or --public-mgt-key (at least one required)" >&2
    usage >&2
    exit 1
fi

NODE_MGT_FINAL=""
PUBLIC_MGT_FINAL=""
if [ -n "$NODE_MGT_KEY_CLI" ]; then
    NODE_MGT_FINAL="$(validate_and_normalize_node_mgt_eth "$NODE_MGT_KEY_CLI")" || exit 1
fi
if [ -n "$PUBLIC_MGT_KEY_CLI" ]; then
    PUBLIC_MGT_FINAL="$(validate_and_normalize_public_mgt_key "$PUBLIC_MGT_KEY_CLI")" || exit 1
fi

if [ -z "$CONFIG_FILE" ]; then
    CONFIG_FILE="$REPO_ROOT/configs.yaml"
fi

if [ -e "$CONFIG_FILE" ]; then
    echo "error: refusing to overwrite existing file: $CONFIG_FILE" >&2
    echo "       Remove or move it if you want a fresh provision from configs-original.yaml." >&2
    exit 1
fi

if [ ! -f "$CONFIGS_ORIGINAL" ]; then
    echo "error: template not found: $CONFIGS_ORIGINAL" >&2
    exit 1
fi

if [ ! -f "$PROCESS_CONFIG_SH" ]; then
    echo "error: process_config.sh not found at $PROCESS_CONFIG_SH" >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 is required" >&2
    exit 1
fi

if ! python3 -c "import ruamel.yaml" 2>/dev/null; then
    echo "error: python3 ruamel.yaml is required (e.g. sudo apt install python3-ruamel.yaml)" >&2
    exit 1
fi

if ! python3 -c "import cryptography" 2>/dev/null; then
    echo "error: python3 'cryptography' is required (process_config runs tools/bootstrap_key_provision.py to provision or sync DeterministicNodeKey)." >&2
    echo "       e.g. sudo apt install python3-cryptography  or  sudo pip install cryptography" >&2
    exit 1
fi

echo "==> Creating $CONFIG_FILE from configs-original.yaml"
cp -- "$CONFIGS_ORIGINAL" "$CONFIG_FILE"

set_management_keys() {
    local cfg="$1"
    local node_eth="$2"
    local pub_ed="$3"
    export MGT_CFG="$cfg" MGT_NODE="$node_eth" MGT_PUB="$pub_ed"
    python3 <<'PYMGT'
import os
import sys

try:
    from ruamel.yaml import YAML
except ImportError:
    sys.exit(1)

path = os.environ.get("MGT_CFG", "")
if not path:
    sys.exit(1)
node = os.environ.get("MGT_NODE", "")
pub = os.environ.get("MGT_PUB", "")

yaml = YAML()
yaml.preserve_quotes = True
yaml.width = 4096
yaml.indent(mapping=2, sequence=4, offset=2)

with open(path, "r") as f:
    data = yaml.load(f)
if not isinstance(data, dict):
    sys.exit(1)
# Empty string clears template placeholder / leaves field blank for process_config key checks.
data["NodeMgtKey"] = node if node.strip() else ""
data["PublicMgtKey"] = pub if pub.strip() else ""
with open(path, "w") as f:
    yaml.dump(data, f)
PYMGT
}

if [ -n "$NODE_MGT_FINAL" ]; then
    echo "    NodeMgtKey: $NODE_MGT_FINAL"
else
    echo "    NodeMgtKey: <empty>"
fi
if [ -n "$PUBLIC_MGT_FINAL" ]; then
    echo "    PublicMgtKey: set (${#PUBLIC_MGT_FINAL} characters)"
else
    echo "    PublicMgtKey: <empty>"
fi
set_management_keys "$CONFIG_FILE" "$NODE_MGT_FINAL" "$PUBLIC_MGT_FINAL"

detect_node_ip() {
    if [ -n "${PROVISION_NODE_IP:-}" ]; then
        printf '%s' "$PROVISION_NODE_IP"
        return 0
    fi
    if [ -n "$NODE_IP" ]; then
        printf '%s' "$NODE_IP"
        return 0
    fi
    local ip=""
    if command -v ip >/dev/null 2>&1; then
        ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{ for (i = 1; i < NF; i++) if ($i == "src") { print $(i + 1); exit } }' || true)
    fi
    if [ -z "$ip" ] && command -v hostname >/dev/null 2>&1; then
        ip=$(hostname -I 2>/dev/null | awk '{ print $1 }' || true)
    fi
    if [ -z "$ip" ]; then
        echo "error: could not detect this host's IPv4; pass --ip or set PROVISION_NODE_IP" >&2
        return 1
    fi
    printf '%s' "$ip"
}

if [ -z "$HTTP_PORT" ]; then
    HTTP_PORT="$PROVISION_HTTP_PORT"
fi

PEER_IP="$(detect_node_ip)"

merge_two_node_addresses() {
    local cfg="$1"
    local relay_h="$2"
    local peer="$3"
    local port="$4"
    export MERGE_CFG="$cfg" MERGE_RELAY="$relay_h" MERGE_PEER="$peer" MERGE_PORT="$port"
    python3 <<'PYMERGE'
import os
import sys

try:
    from ruamel.yaml import YAML
    from ruamel.yaml.comments import CommentedMap
except ImportError:
    sys.stderr.write("ruamel.yaml required\n")
    sys.exit(1)

path = os.environ.get("MERGE_CFG", "")
relay = os.environ.get("MERGE_RELAY", "").strip()
peer = os.environ.get("MERGE_PEER", "").strip()
port_s = os.environ.get("MERGE_PORT", "").strip()
if not path or not relay or not peer or not port_s:
    sys.stderr.write("internal: missing merge env\n")
    sys.exit(1)
try:
    port = int(port_s)
except ValueError:
    sys.stderr.write("invalid port\n")
    sys.exit(1)
if port <= 0 or port > 65535:
    sys.stderr.write("port out of range\n")
    sys.exit(1)

yaml = YAML()
yaml.preserve_quotes = True
yaml.width = 4096
yaml.indent(mapping=2, sequence=4, offset=2)

with open(path, "r") as f:
    data = yaml.load(f)
if not isinstance(data, dict):
    sys.stderr.write("configs.yaml: invalid root\n")
    sys.exit(1)
groups = data.get("MPCGroups")
if not groups or not isinstance(groups, list) or len(groups) < 1:
    sys.stderr.write("configs.yaml: need at least one MPCGroups entry\n")
    sys.exit(1)
grp = groups[0]
if not isinstance(grp, dict):
    sys.stderr.write("configs.yaml: MPCGroups[0] must be a mapping\n")
    sys.exit(1)

new_na = CommentedMap()
new_na["node1_key"] = f"http://{relay}:{port}"
new_na["node2_key"] = f"http://{peer}:{port}"
grp["nodeAddresses"] = new_na

with open(path, "w") as f:
    yaml.dump(data, f)
PYMERGE
}

echo "==> Provisioning nodeAddresses (relay placeholder + this host)"
echo "    Relay placeholder: http://${RELAY_PLACEHOLDER_HOST}:${HTTP_PORT}"
echo "    This host (peer): http://${PEER_IP}:${HTTP_PORT}"
merge_two_node_addresses "$CONFIG_FILE" "$RELAY_PLACEHOLDER_HOST" "$PEER_IP" "$HTTP_PORT"
echo "    Wrote MPCGroups[0].nodeAddresses (2 entries)."

export SKIP_NODE_ADDRESS_MENU="${SKIP_NODE_ADDRESS_MENU:-1}"

if [ "$ENABLE_LOOPBACK" = true ]; then
    export ENABLE_BROWSER_LOOPBACK_READ_HTTP="${ENABLE_BROWSER_LOOPBACK_READ_HTTP:-1}"
else
    export ENABLE_BROWSER_LOOPBACK_READ_HTTP="${ENABLE_BROWSER_LOOPBACK_READ_HTTP:-0}"
fi

PC_ARGS=()
if [ "$ENABLE_LOOPBACK" = true ]; then
    PC_ARGS+=(--enable-loopback-http)
fi
if [ "$INSTALL_SYSTEMD" = true ]; then
    PC_ARGS+=(--install-mpc-auth-systemd)
fi
if [ "$FORCE_BROWSER" = true ]; then
    PC_ARGS+=(--force-browser-https-certs)
fi
if [ "$FIREWALL" = false ]; then
    PC_ARGS+=(--no-firewall)
fi
if [ "$SKIP_AGENT_LLM_CONFIG_PATH" = true ]; then
    PC_ARGS+=(--no-agent-llm-config-path)
fi

echo ""
echo "==> Running process_config.sh (${PC_ARGS[*]:-})"
export PROCESS_CONFIG_NONINTERACTIVE="${PROCESS_CONFIG_NONINTERACTIVE:-1}"
# Preset Ed25519 bootstrap public key without a local seed: avoid mpc-auth generating a random nodeKey on empty Mongo.
if [ -n "$PUBLIC_MGT_KEY_CLI" ]; then
    export PROVISION_DEFER_NODE_KEY_UNTIL_BOOTSTRAP="${PROVISION_DEFER_NODE_KEY_UNTIL_BOOTSTRAP:-1}"
fi
cd "$REPO_ROOT"
bash "$PROCESS_CONFIG_SH" "${PC_ARGS[@]}"
