#!/bin/bash

# MQTT Broker Configuration Validator and Certificate Generator
# This script validates the MPC group configuration and generates CA and server certificates
# for Mosquitto MQTT broker. No domain registration required - works with IP addresses or hostnames

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
# Repo root: mpc-config keeps process_config.sh at repo root; mpc-auth keeps it under console/.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -d "$SCRIPT_DIR/mosquitto/config" ]; then
    REPO_ROOT="$SCRIPT_DIR"
else
    REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
fi

CONTINUUM_INSTALL_SCRIPT_DIR="${REPO_ROOT}/scripts"
if [ -f "${CONTINUUM_INSTALL_SCRIPT_DIR}/lib/load-install-progress.sh" ]; then
    # shellcheck source=scripts/lib/load-install-progress.sh
    . "${CONTINUUM_INSTALL_SCRIPT_DIR}/lib/load-install-progress.sh"
fi

# Prefer the invoking user's ids when running via sudo so repo-local paths are not left root-owned.
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ] && id -u "$SUDO_USER" &>/dev/null; then
    PROCESS_CONFIG_REPO_UID=$(id -u "$SUDO_USER")
    PROCESS_CONFIG_REPO_GID=$(id -g "$SUDO_USER")
    PROCESS_CONFIG_REPO_OWNER="$SUDO_USER"
    PROCESS_CONFIG_REPO_GROUP="$(id -gn "$SUDO_USER")"
elif [ "${EUID:-0}" -ne 0 ]; then
    PROCESS_CONFIG_REPO_UID=$(id -u)
    PROCESS_CONFIG_REPO_GID=$(id -g)
    PROCESS_CONFIG_REPO_OWNER="$(id -un)"
    PROCESS_CONFIG_REPO_GROUP="$(id -gn)"
else
    PROCESS_CONFIG_REPO_UID=$(id -u)
    PROCESS_CONFIG_REPO_GID=$(id -g)
    PROCESS_CONFIG_REPO_OWNER="$(id -un)"
    PROCESS_CONFIG_REPO_GROUP="$(id -gn)"
fi

CERT_DIR="${REPO_ROOT}/mosquitto/config/certs"
CA_KEY="${CERT_DIR}/ca.key"
CA_CRT="${CERT_DIR}/ca.crt"
SERVER_KEY="${CERT_DIR}/server.key"
SERVER_CSR="${CERT_DIR}/server.csr"
SERVER_CRT="${CERT_DIR}/server.crt"
CERT_VALIDITY_DAYS=365

# Browser HTTPS (TLS for DAO app): certs on host, mounted at /webTLS/config/certs in Docker
WEB_TLS_HOST_DIR="${REPO_ROOT}/webTLS/config/certs"
BROWSER_HTTPS_CRT="${WEB_TLS_HOST_DIR}/browser.crt"
BROWSER_HTTPS_KEY="${WEB_TLS_HOST_DIR}/browser.key"
BROWSER_HTTPS_CONTAINER_CERT="/webTLS/config/certs/browser.crt"
BROWSER_HTTPS_CONTAINER_KEY="/webTLS/config/certs/browser.key"
DEFAULT_BROWSER_HTTPS_ORIGIN="https://mpa.continuumdao.org"
# Pattern B (DAO app mints JWTs): public JWKS + issuer. Pattern A (standalone Railway issuer) — override in configs.yaml before merge.
DEFAULT_BROWSER_HTTPS_JWKS_URL="https://mpa.continuumdao.org/api/node-read/jwks"
DEFAULT_BROWSER_HTTPS_EXPECTED_ISSUER="https://mpa.continuumdao.org"

# HTTP port written into nodeAddresses URLs (management API); default Docker mapping is often 8080—set to match your deployment.
MPC_NODE_HTTP_PORT=8081

# If MPCGroups[0].nodeAddresses first URL host is this address, treat relay as unset: automation / frontend sets the real relay IP later.
# This host must still appear in nodeAddresses as some peer (not necessarily first); script uses client/MQTT path until first is a real relay IP.
NODE_ADDRESSES_RELAY_PLACEHOLDER_IPV4="0.0.0.0"

# BrowserLoopbackReadHTTP listener port (mpc-auth); must match docker-compose 127.0.0.1:<host>:<container> mapping.
DEFAULT_BROWSER_LOOPBACK_READ_HTTP_PORT="${DEFAULT_BROWSER_LOOPBACK_READ_HTTP_PORT:-8445}"

# Certificate regeneration: set to 1 or use --force-mqtt-certs / --force-browser-https-certs to overwrite existing files.
# Default is to leave existing mosquitto/config/certs/* and webTLS/config/certs/* in place (avoids permission errors).
FORCE_REGENERATE_MQTT_CERTS="${FORCE_REGENERATE_MQTT_CERTS:-0}"
FORCE_REGENERATE_BROWSER_HTTPS_CERTS="${FORCE_REGENERATE_BROWSER_HTTPS_CERTS:-0}"

# UFW: set to 1 to add "ufw allow" for ManagementAPIsPort (default 8080). Default is 0 — the management
# port is NOT opened in UFW; use cloud SG / VPN, or bind Docker to 127.0.0.1:8080:8080 for stricter lockdown.
UFW_OPEN_MANAGEMENT_PORT="${UFW_OPEN_MANAGEMENT_PORT:-0}"

# Default example NodeMgtKey in configs.yaml — treated like unset (must be replaced for a real deployment).
NODE_MGT_ETH_PLACEHOLDER="0x1234567890abcdef1234567890abcdef12345678"

# Default relayer HTTP base (pre-signing verification). Used when PreSigningVerification is set but RelayerAPIURL is empty.
DEFAULT_RELAYER_API_URL="http://82.208.20.136:8080"

# UFW + configs.yaml: used when ScannerAPIURLs is [] / missing (same host as default relayer unless you override).
# Full URLs are fine; :port is ignored for firewall (only host/IP/CIDR matter—same as RelayerAPIURL).
DEFAULT_SCANNER_API_URLS=(
    "http://82.208.20.136:8080"
)

# Agent LLM settings directory beside configs.yaml (bind-mounted ./agent_llm_config; see API_IMPLEMENTATION.md).
# Bundled templates (tracked in git) seed into agent_llm_config/ once per file if missing.
DEFAULT_AGENT_LLM_CONFIG_DIR="agent_llm_config"
DEFAULT_AGENT_LLM_CONFIG_BUNDLE_DIR="agent_llm_config.defaults"
DEFAULT_AGENT_LLM_CONFIG_DEFAULTS_CONTAINER_DIR="/app/agent_llm_config.defaults"
DEFAULT_AGENT_LLM_CONFIG_CONTAINER_FILE="/app/agent_llm_config/agent-llm-config.json"
DEFAULT_USER_FOLDER_DIR="user_folder"
DEFAULT_USER_FOLDER_CONTAINER_PATH="/app/user_folder"
DEFAULT_AGENT_MCP_DEFAULT_SERVERS_BASENAME="MCP_default_servers.json"
DEFAULT_AGENT_CRON_JOBS_REL="cron/jobs.json"
DEFAULT_AGENT_HOOKS_REL="hooks"

DEFAULT_AGENT_LLM_RUNTIME_README_BASENAME="runtime-README.md"

# Copy runtime-README.md → agent_llm_config/README.md on the node (once if missing).
_seed_agent_llm_runtime_readme() {
    local cfg_parent="$1"
    local src="${REPO_ROOT}/${DEFAULT_AGENT_LLM_CONFIG_BUNDLE_DIR}/${DEFAULT_AGENT_LLM_RUNTIME_README_BASENAME}"
    local dest="${cfg_parent}/${DEFAULT_AGENT_LLM_CONFIG_DIR}/README.md"
    if [ ! -f "$src" ]; then
        return 0
    fi
    if [ -f "$dest" ]; then
        return 0
    fi
    if cp "$src" "$dest" 2>/dev/null; then
        print_success "agent_llm_config: installed README.md"
    fi
}

# Copy MCP_default_servers.json into agent_llm_config/ (once) for continuum bootstrap on first DB migration only.
#
# OPTIONAL MCP CATALOG: edit agent_llm_config.defaults/MCP_servers.json in this repo only (never copy to
# agent_llm_config/, never duplicate in continuum-node-sdk). Nodes read it from the bind mount;
# GET /listMcpServers → availableCatalog; POST /addMcpServerFromCatalog activates a row. See
# agent_llm_config.defaults/CATALOG.md.
_seed_agent_mcp_json_file() {
    local cfg_parent="$1"
    local basename="$2"
    local src="${REPO_ROOT}/${DEFAULT_AGENT_LLM_CONFIG_BUNDLE_DIR}/${basename}"
    local dest="${cfg_parent}/${DEFAULT_AGENT_LLM_CONFIG_DIR}/${basename}"
    if [ ! -f "$src" ]; then
        return 0
    fi
    if [ -f "$dest" ]; then
        return 0
    fi
    if cp "$src" "$dest" 2>/dev/null; then
        print_success "agent_llm_config: installed ${basename}"
    fi
}

_seed_agent_mcp_default_servers_file() {
    _seed_agent_mcp_json_file "$1" "${DEFAULT_AGENT_MCP_DEFAULT_SERVERS_BASENAME}"
}

# Copy bundled agent skills (Skills/skills.json + .md/.txt) from agent_llm_config.defaults/ into agent_llm_config/ (once per file).
_seed_agent_skills_catalog() {
    local cfg_parent="$1"
    local src_dir="${REPO_ROOT}/${DEFAULT_AGENT_LLM_CONFIG_BUNDLE_DIR}/Skills"
    local dest_dir="${cfg_parent}/${DEFAULT_AGENT_LLM_CONFIG_DIR}/Skills"
    if [ ! -d "$src_dir" ]; then
        return 0
    fi
    mkdir -p "$dest_dir" 2>/dev/null || true
    if [ -f "${src_dir}/skills.json" ] && [ ! -f "${dest_dir}/skills.json" ]; then
        if cp "${src_dir}/skills.json" "${dest_dir}/skills.json" 2>/dev/null; then
            print_success "agent_llm_config: installed Skills/skills.json"
        fi
    fi
    local skill_file base
    for skill_file in "${src_dir}"/*.md "${src_dir}"/*.txt; do
        [ -f "$skill_file" ] || continue
        base="$(basename "$skill_file")"
        if [ -f "${dest_dir}/${base}" ]; then
            continue
        fi
        if cp "$skill_file" "${dest_dir}/${base}" 2>/dev/null; then
            print_success "agent_llm_config: installed Skills/${base}"
        fi
    done
}

# Seed agent cron manifest (cron/jobs.json) and runs/ directory beside configs.yaml (once if missing).
# When EnableAgentCron is true (default), copies bundled default jobs from mpc-config; otherwise seeds empty jobs.
_agent_cron_enabled_for_config() {
    local config_file="$1"
    case "${MPC_AUTH_ENABLE_AGENT_CRON:-}" in
        0|false|FALSE|no|NO|off|OFF) return 1 ;;
    esac
    if [ -z "$config_file" ] || [ ! -f "$config_file" ]; then
        return 0
    fi
    if command -v yq &>/dev/null; then
        local enabled
        enabled=$(yq eval '.EnableAgentCron // true' "$config_file" 2>/dev/null || echo true)
        case "$(printf '%s' "$enabled" | tr '[:upper:]' '[:lower:]')" in
            false|0|no|off) return 1 ;;
        esac
        return 0
    fi
    if grep -E '^[[:space:]]*EnableAgentCron:[[:space:]]*false([[:space:]]|$|#)' "$config_file" >/dev/null 2>&1; then
        return 1
    fi
    return 0
}

# Copy agent hooks (message_hook.json, message_hook_*.md) from agent_llm_config.defaults/ once per file.
#
# WEBHOOK CATALOG: edit agent_llm_config.defaults/hooks/webhooks.json in this repo only (skipped below).
# GET /listWebhooks → availableCatalog; POST /addWebhookFromCatalog activates. See agent_llm_config.defaults/CATALOG.md.
_seed_agent_hooks_catalog() {
    local cfg_parent="$1"
    local src_dir="${REPO_ROOT}/${DEFAULT_AGENT_LLM_CONFIG_BUNDLE_DIR}/${DEFAULT_AGENT_HOOKS_REL}"
    local dest_dir="${cfg_parent}/${DEFAULT_AGENT_LLM_CONFIG_DIR}/${DEFAULT_AGENT_HOOKS_REL}"
    if [ ! -d "$src_dir" ]; then
        return 0
    fi
    mkdir -p "${dest_dir}/runs" 2>/dev/null || true
    local hook_file base
    for hook_file in "${src_dir}"/*.json "${src_dir}"/*.md; do
        [ -f "$hook_file" ] || continue
        base="$(basename "$hook_file")"
        if [ "$base" = "webhooks.json" ]; then
            continue
        fi
        if [ -f "${dest_dir}/${base}" ]; then
            continue
        fi
        if cp "$hook_file" "${dest_dir}/${base}" 2>/dev/null; then
            print_success "agent_llm_config: installed ${DEFAULT_AGENT_HOOKS_REL}/${base}"
        fi
    done
}

_seed_agent_cron_catalog() {
    local cfg_parent="$1"
    local config_file="${2:-}"
    local dest_dir="${cfg_parent}/${DEFAULT_AGENT_LLM_CONFIG_DIR}/cron"
    local dest="${dest_dir}/jobs.json"
    local src="${REPO_ROOT}/${DEFAULT_AGENT_LLM_CONFIG_BUNDLE_DIR}/${DEFAULT_AGENT_CRON_JOBS_REL}"
    mkdir -p "${dest_dir}/runs" 2>/dev/null || true
    if [ -f "$dest" ]; then
        return 0
    fi
    if _agent_cron_enabled_for_config "$config_file" && [ -f "$src" ]; then
        if cp "$src" "$dest" 2>/dev/null; then
            print_success "agent_llm_config: installed ${DEFAULT_AGENT_CRON_JOBS_REL} (default cron jobs)"
            return 0
        fi
    fi
    if printf '%s\n' '{"jobs":[]}' >"$dest" 2>/dev/null; then
        print_success "agent_llm_config: created empty ${DEFAULT_AGENT_CRON_JOBS_REL}"
    fi
}

# Functions
print_error() {
    echo -e "${RED}ERROR: $1${NC}" >&2
}

print_success() {
    if install_progress_ui_active 2>/dev/null; then
        echo -e "${GREEN}✓ $1${NC}" >&2
    else
        echo -e "${GREEN}✓ $1${NC}"
    fi
}

print_warning() {
    if install_progress_ui_active 2>/dev/null; then
        echo -e "${YELLOW}⚠ $1${NC}" >&2
    else
        echo -e "${YELLOW}⚠ $1${NC}"
    fi
}

print_info() {
    if install_progress_ui_active 2>/dev/null; then
        echo -e "${BLUE}ℹ $1${NC}" >&2
    else
        echo -e "${BLUE}ℹ $1${NC}"
    fi
}

print_step() {
    if install_progress_ui_active 2>/dev/null; then
        echo -e "\n${BLUE}==> $1${NC}" >&2
    else
        echo -e "\n${BLUE}==> $1${NC}"
    fi
}

# Hand root-owned repo paths to the invoking user (sudo ./process_config.sh, or sudo mkdir as a normal user).
process_config_transfer_repo_path_to_invoking_user() {
    local target path_uid
    target="$1"
    [ -n "$target" ] || return 0
    [ -e "$target" ] || return 0
    path_uid=$(stat -c '%u' "$target" 2>/dev/null) || return 0
    [ "${path_uid:-1}" -eq 0 ] || return 0

    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
        if [ "${EUID:-0}" -eq 0 ]; then
            chown -R "${PROCESS_CONFIG_REPO_UID}:${PROCESS_CONFIG_REPO_GID}" "$target" 2>/dev/null || true
        else
            sudo chown -R "${PROCESS_CONFIG_REPO_UID}:${PROCESS_CONFIG_REPO_GID}" "$target" 2>/dev/null || true
        fi
        return 0
    fi
    if [ "${EUID:-0}" -ne 0 ]; then
        sudo chown -R "${PROCESS_CONFIG_REPO_UID}:${PROCESS_CONFIG_REPO_GID}" "$target" 2>/dev/null || true
    fi
}

# Same rules as configure_docker_compose(): where docker-compose.yml is written (repo root vs console/ vs parent).
_process_config_resolve_compose_project_dir() {
    local script_dir
    script_dir="$(cd "$(dirname "$0")" && pwd)"
    if [ -d "$script_dir/mosquitto/config" ]; then
        printf '%s\n' "$script_dir"
    elif [ -f "$script_dir/../docker-compose.yml" ]; then
        (cd "$script_dir/.." && pwd)
    else
        printf '%s\n' "$script_dir"
    fi
}

# When running via sudo, hand this path to SUDO_USER even if ownership is already non-root (e.g. rewritten in place).
process_config_repo_take_if_sudo_invoker() {
    local target="$1"
    [ -n "$target" ] || return 0
    [ -e "$target" ] || return 0
    [ "${EUID:-0}" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ] || return 0
    chown "${PROCESS_CONFIG_REPO_UID}:${PROCESS_CONFIG_REPO_GID}" "$target" 2>/dev/null || true
}

# Create a directory as the invoking user (uid + primary group), not root, when run via sudo.
_process_config_mkdir_owned_by_invoking_user() {
    local dir="$1"
    [ -n "$dir" ] || return 0
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ] && [ "${EUID:-0}" -eq 0 ]; then
        install -d -o "${PROCESS_CONFIG_REPO_UID}" -g "${PROCESS_CONFIG_REPO_GID}" -m 0750 "$dir" 2>/dev/null \
            || mkdir -p "$dir" 2>/dev/null \
            || true
        chown -R "${PROCESS_CONFIG_REPO_UID}:${PROCESS_CONFIG_REPO_GID}" "$dir" 2>/dev/null || true
    else
        mkdir -p "$dir" 2>/dev/null || true
    fi
}

# agent_llm_config/ and user_folder/ beside configs.yaml: user + primary group (git pull, editor).
# Also fixes root-owned bind-mount files written by mpc-auth before user: was set in compose.
_process_config_ensure_path_owned_by_invoking_user() {
    local target="$1"
    [ -n "$target" ] || return 0
    [ -e "$target" ] || return 0
    process_config_transfer_repo_path_to_invoking_user "$target"
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
        if [ "${EUID:-0}" -eq 0 ]; then
            chown -R "${PROCESS_CONFIG_REPO_UID}:${PROCESS_CONFIG_REPO_GID}" "$target" 2>/dev/null || true
        else
            sudo chown -R "${PROCESS_CONFIG_REPO_UID}:${PROCESS_CONFIG_REPO_GID}" "$target" 2>/dev/null || true
        fi
        return 0
    fi
    _process_config_chown_repo_tree_if_sudo_root "$target"
}

# openssl leaves root-owned keys/certs under the repo when the script runs via sudo — normalize regardless of parent dir ownership.
_process_config_chown_repo_tree_if_sudo_root() {
    local dir="$1"
    [ -n "$dir" ] || return 0
    [ "${EUID:-0}" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ] || return 0
    [ -e "$dir" ] || return 0
    chown -R "${PROCESS_CONFIG_REPO_UID}:${PROCESS_CONFIG_REPO_GID}" "$dir" 2>/dev/null || true
}

# Normal completion: fix typical sudo-created artifacts under the checkout (does not touch non-root-owned trees).
_process_config_finalize_repo_ownership_after_sudo() {
    [ -n "${CONFIG_FILE:-}" ] || return 0
    local compose_root compose_project_dir compose_file cf_alt
    compose_root=$(cd "$(dirname "$CONFIG_FILE")" && pwd)
    compose_project_dir="$(_process_config_resolve_compose_project_dir)"
    compose_file="${compose_project_dir}/docker-compose.yml"
    process_config_transfer_repo_path_to_invoking_user "$CONFIG_FILE"
    process_config_transfer_repo_path_to_invoking_user "${compose_root}/.env"
    process_config_transfer_repo_path_to_invoking_user "${REPO_ROOT}/.env"
    process_config_transfer_repo_path_to_invoking_user "${REPO_ROOT}/bootstrap_key"
    process_config_transfer_repo_path_to_invoking_user "${REPO_ROOT}/added_keys"
    process_config_repo_take_if_sudo_invoker "$compose_file"
    process_config_transfer_repo_path_to_invoking_user "$compose_file"
    cf_alt="${compose_root}/docker-compose.yml"
    if [ "$cf_alt" != "$compose_file" ]; then
        process_config_repo_take_if_sudo_invoker "$cf_alt"
        process_config_transfer_repo_path_to_invoking_user "$cf_alt"
    fi
    cf_alt="${REPO_ROOT}/docker-compose.yml"
    if [ "$cf_alt" != "$compose_file" ] && [ "$cf_alt" != "${compose_root}/docker-compose.yml" ]; then
        process_config_repo_take_if_sudo_invoker "$cf_alt"
        process_config_transfer_repo_path_to_invoking_user "$cf_alt"
    fi
    shopt -s nullglob
    local bf
    for bf in "${compose_file}.backup."*; do
        process_config_repo_take_if_sudo_invoker "$bf"
        process_config_transfer_repo_path_to_invoking_user "$bf"
    done
    shopt -u nullglob
    process_config_transfer_repo_path_to_invoking_user "$CERT_DIR"
    _process_config_chown_repo_tree_if_sudo_root "$WEB_TLS_HOST_DIR"
    _process_config_ensure_path_owned_by_invoking_user "${compose_root}/${DEFAULT_AGENT_LLM_CONFIG_DIR}"
    _process_config_ensure_path_owned_by_invoking_user "${compose_root}/${DEFAULT_USER_FOLDER_DIR}"
}

# Writes use ruamel.yaml (round-trip, preserves comments). Reads use yq when possible; Python fallbacks use ruamel.yaml only — not PyYAML (no python3-yaml package).
require_ruamel_yaml() {
    if ! python3 -c "import ruamel.yaml" 2>/dev/null; then
        print_error "ruamel.yaml is required to update configs.yaml without stripping comments."
        print_info "Install:  sudo apt install python3-ruamel.yaml"
        print_info "     or:  python3 -m pip install 'ruamel.yaml'  (use a venv on PEP 668 / externally-managed Python)"
        return 1
    fi
    return 0
}

# Merge PreSigningVerification.RelayerAPIURL (preserves file comments).
configs_yaml_merge_relayer_api_url() {
    local config_file="$1"
    local url="$2"
    require_ruamel_yaml || return 1
    RELAYER_MERGE_CFG="$config_file" RELAYER_MERGE_URL="$url" python3 << 'PYRELAYERMERGE'
import os
import sys
try:
    from ruamel.yaml import YAML
except ImportError:
    sys.stderr.write("configs.yaml: install ruamel.yaml (pip install --user 'ruamel.yaml')\n")
    sys.exit(1)

path = os.environ["RELAYER_MERGE_CFG"]
url = os.environ["RELAYER_MERGE_URL"].strip().rstrip("/")

yaml = YAML()
yaml.preserve_quotes = True
yaml.width = 4096
yaml.indent(mapping=2, sequence=4, offset=2)

with open(path, "r") as f:
    data = yaml.load(f)
if not isinstance(data, dict):
    sys.stderr.write("invalid yaml root (expected mapping)\n")
    sys.exit(1)

ps = data.get("PreSigningVerification")
if not isinstance(ps, dict):
    ps = {}
    data["PreSigningVerification"] = ps
ps["RelayerAPIURL"] = url

with open(path, "w") as f:
    yaml.dump(data, f)
PYRELAYERMERGE
}

# If ScannerAPIURLs is missing or empty [], set it from DEFAULT_SCANNER_API_URLS (preserves comments).
configs_yaml_merge_scanner_api_urls_if_empty() {
    local config_file="$1"
    require_ruamel_yaml || return 1
    local _lines
    _lines=$(printf '%s\n' "${DEFAULT_SCANNER_API_URLS[@]}")
    SCANNER_MERGE_CFG="$config_file" SCANNER_MERGE_LINES="$_lines" python3 << 'PYSCANNERMERGE'
import os
import sys
try:
    from ruamel.yaml import YAML
except ImportError:
    sys.stderr.write("configs.yaml: install ruamel.yaml\n")
    sys.exit(1)

path = os.environ["SCANNER_MERGE_CFG"]
raw = os.environ.get("SCANNER_MERGE_LINES", "")
defaults = [s.strip() for s in raw.splitlines() if s.strip()]
if not defaults:
    sys.exit(0)

yaml = YAML()
yaml.preserve_quotes = True
yaml.width = 4096
yaml.indent(mapping=2, sequence=4, offset=2)

with open(path, "r") as f:
    data = yaml.load(f)
if not isinstance(data, dict):
    sys.stderr.write("invalid yaml root\n")
    sys.exit(1)

existing = data.get("ScannerAPIURLs")
empty = False
if existing is None:
    empty = True
elif isinstance(existing, list):
    nonempty = [x for x in existing if x is not None and str(x).strip() and str(x).strip().lower() != "null"]
    empty = len(nonempty) == 0
else:
    empty = True

if empty:
    data["ScannerAPIURLs"] = defaults
    with open(path, "w") as f:
        yaml.dump(data, f)
PYSCANNERMERGE
}

# Count non-empty ScannerAPIURLs entries (yq when installed; else ruamel.yaml — provision requires python3+ruamel).
_configs_yaml_scanner_api_urls_nonempty_count() {
    local config_file="$1"
    if [ ! -f "$config_file" ]; then
        echo 0
        return 0
    fi
    if command -v yq &>/dev/null; then
        yq eval '(.ScannerAPIURLs // []) | map(select(. != null and . != "" and . != "null")) | length' "$config_file" 2>/dev/null || echo 0
        return 0
    fi
    require_ruamel_yaml || {
        echo 0
        return 0
    }
    SCANNER_CNT_CFG="$config_file" python3 << 'PYSCANNERCNT'
import os
import sys
try:
    from ruamel.yaml import YAML
except ImportError:
    print(0)
    sys.exit(0)
path = os.environ.get("SCANNER_CNT_CFG", "")
if not path:
    print(0)
    sys.exit(0)
yaml = YAML()
with open(path) as f:
    data = yaml.load(f)
if not isinstance(data, dict):
    print(0)
    sys.exit(0)
raw = data.get("ScannerAPIURLs")
if not isinstance(raw, list):
    print(0)
    sys.exit(0)
n = sum(1 for x in raw if x is not None and str(x).strip() and str(x).strip().lower() != "null")
print(n)
PYSCANNERCNT
}

# Print non-empty ScannerAPIURLs entries, one per line (for UFW source collection).
_configs_yaml_scanner_api_urls_lines() {
    local config_file="$1"
    if [ ! -f "$config_file" ]; then
        return 0
    fi
    if command -v yq &>/dev/null; then
        yq eval '.ScannerAPIURLs[]?' "$config_file" 2>/dev/null || true
        return 0
    fi
    require_ruamel_yaml || return 0
    SCANNER_LINES_CFG="$config_file" python3 << 'PYSCANNERLINES'
import os
import sys
try:
    from ruamel.yaml import YAML
except ImportError:
    sys.exit(0)
path = os.environ.get("SCANNER_LINES_CFG", "")
if not path:
    sys.exit(0)
yaml = YAML()
with open(path) as f:
    data = yaml.load(f)
if not isinstance(data, dict):
    sys.exit(0)
raw = data.get("ScannerAPIURLs")
if not isinstance(raw, list):
    sys.exit(0)
for x in raw:
    if x is None:
        continue
    s = str(x).strip()
    if s and s.lower() != "null":
        print(s)
PYSCANNERLINES
}

# Set EnableMcpChat and EnableAgentHooks to true when missing (preserves comments; does not override explicit false).
configs_yaml_merge_agent_chat_and_hooks_enabled() {
    local config_file="$1"
    local _out
    require_ruamel_yaml || return 1
    if ! _out=$(AGENT_FEATURES_MERGE_CFG="$config_file" python3 << 'PYAGENTFEATURES' 2>&1
import os
import sys
try:
    from ruamel.yaml import YAML
except ImportError:
    sys.stderr.write("configs.yaml: install ruamel.yaml\n")
    sys.exit(1)

path_cfg = os.environ.get("AGENT_FEATURES_MERGE_CFG", "").strip()
if not path_cfg:
    sys.exit(0)

yaml = YAML()
yaml.preserve_quotes = True
yaml.width = 4096
yaml.indent(mapping=2, sequence=4, offset=2)

with open(path_cfg, "r") as f:
    data = yaml.load(f)
if not isinstance(data, dict):
    sys.stderr.write("invalid yaml root\n")
    sys.exit(1)

merged = []
for key in ("EnableMcpChat", "EnableAgentHooks"):
    if key not in data or data[key] is None:
        data[key] = True
        merged.append(key)

if merged:
    with open(path_cfg, "w") as f:
        yaml.dump(data, f)
    print("merged:" + ",".join(merged), flush=True)
else:
    print("present", flush=True)
PYAGENTFEATURES
); then
        echo "$_out" >&2
        return 1
    fi
    local _last_line
    _last_line=$(echo "$_out" | tail -n 1)
    case "$_last_line" in
        merged:*)
            local _keys="${_last_line#merged:}"
            print_success "configs.yaml: enabled ${_keys//,/, } (defaults for agent chat and hooks)"
            ;;
        present)
            print_info "configs.yaml: EnableMcpChat and EnableAgentHooks already set (unchanged)"
            ;;
    esac
}

# Set AgentLlmConfigDir when missing or empty (preserves comments; skips if already set).
configs_yaml_merge_agent_llm_config_dir() {
    local config_file="$1"
    local dir="${2:-$DEFAULT_AGENT_LLM_CONFIG_DIR}"
    local _out
    require_ruamel_yaml || return 1
    if ! _out=$(AGENT_LLM_MERGE_CFG="$config_file" AGENT_LLM_MERGE_DIR="$dir" python3 << 'PYAGENTLLMMERGE' 2>&1
import os
import sys
try:
    from ruamel.yaml import YAML
except ImportError:
    sys.stderr.write("configs.yaml: install ruamel.yaml\n")
    sys.exit(1)

path_cfg = os.environ["AGENT_LLM_MERGE_CFG"]
agent_dir = os.environ.get("AGENT_LLM_MERGE_DIR", "").strip()
if not path_cfg or not agent_dir:
    sys.exit(0)

yaml = YAML()
yaml.preserve_quotes = True
yaml.width = 4096
yaml.indent(mapping=2, sequence=4, offset=2)

with open(path_cfg, "r") as f:
    data = yaml.load(f)
if not isinstance(data, dict):
    sys.stderr.write("invalid yaml root\n")
    sys.exit(1)

existing = data.get("AgentLlmConfigDir")
if existing is not None and str(existing).strip():
    print("present", flush=True)
    sys.exit(0)

data["AgentLlmConfigDir"] = agent_dir
with open(path_cfg, "w") as f:
    yaml.dump(data, f)
print("merged", flush=True)
PYAGENTLLMMERGE
); then
        echo "$_out" >&2
        return 1
    fi
    echo "$_out" | tail -n 1
}

# Set WireGuardEgress.EndpointHost to this node's public IP from nodeAddresses when missing (preserves comments).
configs_yaml_merge_wireguard_egress_endpoint_host() {
    local config_file="$1"
    local endpoint_host="$2"
    local _out
    if [ -z "$config_file" ] || [ -z "$endpoint_host" ]; then
        return 0
    fi
    require_ruamel_yaml || return 1
    if ! _out=$(WG_EGRESS_MERGE_CFG="$config_file" WG_EGRESS_MERGE_HOST="$endpoint_host" python3 << 'PYWGEGRESSMERGE' 2>&1
import os
import sys
try:
    from ruamel.yaml import YAML
    from ruamel.yaml.comments import CommentedMap
except ImportError:
    sys.stderr.write("configs.yaml: install ruamel.yaml\n")
    sys.exit(1)

path_cfg = os.environ["WG_EGRESS_MERGE_CFG"]
endpoint = os.environ.get("WG_EGRESS_MERGE_HOST", "").strip()
if not path_cfg or not endpoint:
    sys.exit(0)

yaml = YAML()
yaml.preserve_quotes = True
yaml.width = 4096
yaml.indent(mapping=2, sequence=4, offset=2)

with open(path_cfg, "r") as f:
    data = yaml.load(f)
if not isinstance(data, dict):
    sys.stderr.write("invalid yaml root\n")
    sys.exit(1)

wg = data.get("WireGuardEgress")
if wg is None:
    wg = CommentedMap()
    data["WireGuardEgress"] = wg
elif not isinstance(wg, dict):
    wg = CommentedMap()
    data["WireGuardEgress"] = wg

existing = str(wg.get("EndpointHost", "")).strip()
if existing == endpoint:
    print("present", flush=True)
    sys.exit(0)
if existing and existing != endpoint:
    print(f"conflict:{existing}", flush=True)
    sys.exit(0)

wg["EndpointHost"] = endpoint
with open(path_cfg, "w") as f:
    yaml.dump(data, f)
print(f"merged:{endpoint}", flush=True)
PYWGEGRESSMERGE
); then
        echo "$_out" >&2
        return 1
    fi
    _last_line=$(echo "$_out" | tail -n 1)
    case "$_last_line" in
        merged:*)
            print_success "configs.yaml: WireGuardEgress.EndpointHost set to ${_last_line#merged:} (this node's nodeAddresses IP)"
            ;;
        present)
            print_info "configs.yaml: WireGuardEgress.EndpointHost already matches this node (${endpoint_host})"
            ;;
        conflict:*)
            print_warning "configs.yaml: WireGuardEgress.EndpointHost is ${_last_line#conflict:} (not overwritten; expected ${endpoint_host} for this host)"
            ;;
    esac
}

# When ScannerAPIURLs is empty: interactive prompt (Enter = defaults), else merge defaults with a clear message.
# Uses /dev/tty like RelayerAPIURL so prompts work when stdin is not a TTY.
prompt_scanner_api_urls_if_empty() {
    local config_file="$1"
    if [ ! -f "$config_file" ]; then
        return 0
    fi

    local cnt=0
    cnt=$(_configs_yaml_scanner_api_urls_nonempty_count "$config_file")
    if [ "${cnt:-0}" -gt 0 ]; then
        return 0
    fi

    require_ruamel_yaml || return 1

    local default_display
    default_display=$(IFS=, ; echo "${DEFAULT_SCANNER_API_URLS[*]}")

    if _process_config_prompt_relayer_scanner_ok; then
        echo ""
        print_step "ScannerAPIURLs empty — UFW uses these hostnames/IPs for scoped rules on ScannerRelayerPort"
        print_info "Press Enter for the default list, or enter comma-separated HTTP(S) URLs (host matters for firewall; path/port ignored for allow rules)."
        local line=""
        while true; do
            read -r -p "ScannerAPIURLs [${default_display}]: " line < /dev/tty || true
            line="${line#"${line%%[![:space:]]*}"}"
            line="${line%"${line##*[![:space:]]}"}"
            if [ -z "$line" ]; then
                configs_yaml_merge_scanner_api_urls_if_empty "$config_file" || return 1
                print_success "Set ScannerAPIURLs in configs.yaml to defaults (edit if your scanner egress differs)"
                break
            fi
            local -a urls=()
            local part
            local _ifs="$IFS"
            IFS=','
            read -r -a _parts <<< "$line"
            IFS="$_ifs"
            for part in "${_parts[@]}"; do
                part="${part#"${part%%[![:space:]]*}"}"
                part="${part%"${part##*[![:space:]]}"}"
                [ -z "$part" ] && continue
                if ! printf '%s' "$part" | grep -qE '^https?://[^[:space:]]+'; then
                    print_error "Each URL must start with http:// or https:// (comma-separated), or press Enter for defaults"
                    continue 2
                fi
                part="${part%/}"
                urls+=("$part")
            done
            if [ ${#urls[@]} -eq 0 ]; then
                print_error "No valid URLs; press Enter for defaults or provide http(s)://..."
                continue
            fi
            local _lines
            _lines=$(printf '%s\n' "${urls[@]}")
            SCANNER_MERGE_CFG="$config_file" SCANNER_MERGE_LINES="$_lines" python3 << 'PYSCANNERMERGE'
import os
import sys
try:
    from ruamel.yaml import YAML
except ImportError:
    sys.stderr.write("configs.yaml: install ruamel.yaml\n")
    sys.exit(1)

path = os.environ["SCANNER_MERGE_CFG"]
raw = os.environ.get("SCANNER_MERGE_LINES", "")
defaults = [s.strip() for s in raw.splitlines() if s.strip()]
if not defaults:
    sys.exit(1)

yaml = YAML()
yaml.preserve_quotes = True
yaml.width = 4096
yaml.indent(mapping=2, sequence=4, offset=2)

with open(path, "r") as f:
    data = yaml.load(f)
if not isinstance(data, dict):
    sys.stderr.write("invalid yaml root\n")
    sys.exit(1)

data["ScannerAPIURLs"] = defaults
with open(path, "w") as f:
    yaml.dump(data, f)
PYSCANNERMERGE
            print_success "Set ScannerAPIURLs in configs.yaml (comments preserved)"
            break
        done
        echo ""
    else
        configs_yaml_merge_scanner_api_urls_if_empty "$config_file" || return 1
        print_info "Non-interactive: set ScannerAPIURLs to defaults ${default_display} (override in configs.yaml or set RELAYER flow interactively; see DEFAULT_SCANNER_API_URLS in process_config.sh)"
    fi
    return 0
}

# Find mosquitto.conf file
find_mosquitto_conf() {
    local script_dir="$(cd "$(dirname "$0")" && pwd)"
    local current_dir="$PWD"
    local repo_root="$script_dir"
    if [ ! -d "$repo_root/mosquitto/config" ] && [ -d "$script_dir/../mosquitto/config" ]; then
        repo_root="$(cd "$script_dir/.." && pwd)"
    fi
    
    local possible_paths=(
        "$repo_root/mosquitto/config/mosquitto.conf"
        "$current_dir/mosquitto/config/mosquitto.conf"
        "$current_dir/../mosquitto/config/mosquitto.conf"
        "$current_dir/mosquitto.conf"
        "/etc/mosquitto/mosquitto.conf"
        "/mosquitto/config/mosquitto.conf"
    )
    
    for path in "${possible_paths[@]}"; do
        if [ -f "$path" ]; then
            echo "$path"
            return 0
        fi
    done
    
    return 1
}

# Check if Let's Encrypt is configured in mosquitto.conf
is_letsencrypt_configured() {
    local conf_file="$1"
    
    if [ ! -f "$conf_file" ]; then
        return 1
    fi
    
    # Check if certfile points to Let's Encrypt directory (not commented out)
    if grep -E '^\s*certfile\s+/etc/letsencrypt' "$conf_file" 2>/dev/null | grep -qvE '^\s*#'; then
        return 0
    fi
    
    # Check if keyfile points to Let's Encrypt directory (not commented out)
    if grep -E '^\s*keyfile\s+/etc/letsencrypt' "$conf_file" 2>/dev/null | grep -qvE '^\s*#'; then
        return 0
    fi
    
    return 1
}

# Check if self-signed certificates are configured
is_self_signed_configured() {
    local conf_file="$1"
    
    if [ ! -f "$conf_file" ]; then
        return 1
    fi
    
    # Check if certfile points to self-signed cert directory (not commented out)
    if grep -E '^\s*certfile\s+.*/certs/.*\.(crt|pem)' "$conf_file" 2>/dev/null | grep -qvE '^\s*#' | grep -qE '/certs/'; then
        return 0
    fi
    
    return 1
}

# Extract Let's Encrypt certificate paths from mosquitto.conf
get_letsencrypt_paths() {
    local conf_file="$1"
    local certfile=""
    local keyfile=""
    
    if [ ! -f "$conf_file" ]; then
        return 1
    fi
    
    # Extract certfile path
    certfile=$(grep -E '^\s*certfile\s+' "$conf_file" 2>/dev/null | head -1 | sed -E 's/^\s*certfile\s+//' | sed 's/#.*$//' | xargs)
    
    # Extract keyfile path
    keyfile=$(grep -E '^\s*keyfile\s+' "$conf_file" 2>/dev/null | head -1 | sed -E 's/^\s*keyfile\s+//' | sed 's/#.*$//' | xargs)
    
    if [ -n "$certfile" ] && [ -n "$keyfile" ]; then
        echo "$certfile|$keyfile"
        return 0
    fi
    
    return 1
}

# Validate Let's Encrypt certificates
validate_letsencrypt_certs() {
    local conf_file="$1"
    
    if [ ! -f "$conf_file" ]; then
        return 0  # Skip if config not found
    fi
    
    if ! is_letsencrypt_configured "$conf_file"; then
        return 0  # Not using Let's Encrypt, skip validation
    fi
    
    # Check for conflicting configurations
    if is_self_signed_configured "$conf_file"; then
        print_warning "Both Let's Encrypt and self-signed certificates appear to be configured"
        print_info "Let's Encrypt configuration will be used (self-signed lines should be commented out)"
    fi
    
    print_step "Validating Let's Encrypt certificate configuration..."
    
    # Get certificate paths
    local paths=$(get_letsencrypt_paths "$conf_file")
    if [ -z "$paths" ]; then
        print_error "Let's Encrypt is configured but certificate paths could not be determined"
        print_info "Please check mosquitto.conf for certfile and keyfile directives"
        exit 1
    fi
    
    local certfile=$(echo "$paths" | cut -d'|' -f1)
    local keyfile=$(echo "$paths" | cut -d'|' -f2)
    
    # Check if certfile exists
    if [ ! -f "$certfile" ]; then
        print_error "Let's Encrypt certificate file not found: $certfile"
        echo ""
        print_info "Please ensure:"
        echo "  1. Certbot has been run to obtain the certificate"
        echo "  2. The certificate path in mosquitto.conf is correct"
        echo "  3. The certificate files are readable"
        echo ""
        print_info "To obtain a Let's Encrypt certificate, run:"
        echo "  sudo certbot certonly --standalone -d yourdomain.com"
        exit 1
    fi
    
    # Check if keyfile exists
    if [ ! -f "$keyfile" ]; then
        print_error "Let's Encrypt private key file not found: $keyfile"
        echo ""
        print_info "Please ensure:"
        echo "  1. Certbot has been run to obtain the certificate"
        echo "  2. The keyfile path in mosquitto.conf is correct"
        echo "  3. The key file is readable"
        exit 1
    fi
    
    print_success "Let's Encrypt certificate files found"
    print_info "  Certificate: $certfile"
    print_info "  Private key: $keyfile"
    
    # Validate certificate using openssl
    if command -v openssl &> /dev/null; then
        print_step "Validating certificate validity and expiration..."
        
        # Check certificate is valid
        if ! openssl x509 -in "$certfile" -noout -text >/dev/null 2>&1; then
            print_error "Let's Encrypt certificate file is invalid or corrupted: $certfile"
            exit 1
        fi
        
        # Check certificate expiration
        local expiry_date=$(openssl x509 -in "$certfile" -noout -enddate 2>/dev/null | cut -d= -f2)
        if [ -n "$expiry_date" ]; then
            local expiry_epoch=$(date -d "$expiry_date" +%s 2>/dev/null || date -j -f "%b %d %H:%M:%S %Y %Z" "$expiry_date" +%s 2>/dev/null)
            local current_epoch=$(date +%s)
            local days_until_expiry=$(( (expiry_epoch - current_epoch) / 86400 ))
            
            if [ $days_until_expiry -lt 0 ]; then
                print_error "Let's Encrypt certificate has EXPIRED"
                echo ""
                print_info "Certificate expired on: $expiry_date"
                print_info "Please renew the certificate:"
                echo "  sudo certbot renew"
                exit 1
            elif [ $days_until_expiry -lt 30 ]; then
                print_warning "Let's Encrypt certificate expires in $days_until_expiry days"
                print_info "Certificate expires on: $expiry_date"
                print_info "Consider renewing soon: sudo certbot renew"
            else
                print_success "Certificate is valid (expires in $days_until_expiry days)"
                print_info "Expiry date: $expiry_date"
            fi
        fi
        
        # Check certificate subject/domain
        local subject=$(openssl x509 -in "$certfile" -noout -subject 2>/dev/null | sed 's/.*CN=//' | cut -d'/' -f1)
        if [ -n "$subject" ]; then
            print_info "Certificate issued for: $subject"
        fi
    else
        print_warning "openssl not found - skipping certificate validation"
    fi
    
    # Check if certbot is installed (helpful for renewal)
    if command -v certbot &> /dev/null; then
        local certbot_version=$(certbot --version 2>/dev/null | head -1)
        print_success "certbot found: $certbot_version"
        print_info "To renew certificates: sudo certbot renew"
    else
        print_warning "certbot not found - certificate renewal may require manual setup"
        print_info "Install certbot: sudo apt-get install certbot (Ubuntu/Debian) or sudo yum install certbot (CentOS/RHEL)"
    fi
    
    print_success "Let's Encrypt certificate validation passed"
    return 0
}

# Check if openssl is installed
check_openssl() {
    if ! command -v openssl &> /dev/null; then
        print_error "openssl is not installed"
        echo "Please install openssl:"
        echo "  Ubuntu/Debian: sudo apt-get install openssl"
        echo "  CentOS/RHEL: sudo yum install openssl"
        echo "  macOS: openssl should be pre-installed"
        exit 1
    fi
    
    # Check openssl version
    OPENSSL_VERSION=$(openssl version | awk '{print $2}')
    print_success "openssl found (version $OPENSSL_VERSION)"
}

# Find configs.yaml file. Prints path if found, nothing if not. Always returns 0 so that
# main() can run "CONFIG_FILE=$(find_configs_yaml)" and then check [ -z "$CONFIG_FILE" ]
# without set -e exiting when the file is missing.
find_configs_yaml() {
    local script_dir="$(cd "$(dirname "$0")" && pwd)"
    local current_dir="$PWD"
    local repo_root="$script_dir"
    if [ ! -d "$repo_root/mosquitto/config" ] && [ -d "$script_dir/../mosquitto/config" ]; then
        repo_root="$(cd "$script_dir/.." && pwd)"
    fi

    # mpc-auth: configs.yaml next to script (console/); mpc-config: configs.yaml at repo root next to script
    local possible_paths=(
        "$script_dir/configs.yaml"
        "$repo_root/configs.yaml"
        "$current_dir/configs.yaml"
        "$current_dir/console/configs.yaml"
        "$repo_root/console/configs.yaml"
    )
    
    for path in "${possible_paths[@]}"; do
        if [ -f "$path" ]; then
            echo "$path"
            return 0
        fi
    done
    
    return 0
}

# If configs.yaml is missing, copy from configs-original.yaml next to the script or at repo root.
# Uses the same script_dir / repo_root logic as find_configs.yaml. Writes to script_dir/configs.yaml
# so the next find_configs_yaml() finds it.
ensure_configs_yaml_from_original() {
    local script_dir="$(cd "$(dirname "$0")" && pwd)"
    local repo_root="$script_dir"
    if [ ! -d "$repo_root/mosquitto/config" ] && [ -d "$script_dir/../mosquitto/config" ]; then
        repo_root="$(cd "$script_dir/.." && pwd)"
    fi

    local dest="$script_dir/configs.yaml"
    if [ -f "$dest" ]; then
        return 0
    fi

    local original_paths=(
        "$script_dir/configs-original.yaml"
        "$repo_root/configs-original.yaml"
        "$(pwd)/configs-original.yaml"
    )
    local orig=""
    for p in "${original_paths[@]}"; do
        if [ -f "$p" ]; then
            orig="$p"
            break
        fi
    done
    if [ -z "$orig" ]; then
        return 0
    fi

    if cp "$orig" "$dest"; then
        print_success "configs.yaml was missing; created it from configs-original.yaml"
        return 0
    fi
    print_error "Failed to copy $orig to $dest"
    return 1
}

# If Docker Compose project directory: ensure .env exists for `docker compose`.
# - Missing .env: copy .env.example → .env (mode 0600); merge from env only when both Mongo app + root passwords are set.
# - Existing .env: merge mongo keys from env only when both passwords are set and PROCESS_CONFIG_MERGE_DOTENV_FROM_ENV=1.
# PROCESS_CONFIG_SKIP_DOTENV_FROM_ENV=1 — disable this entire step.
_process_config_maybe_materialize_dotenv_from_environment() {
    local root="$1"

    case "${PROCESS_CONFIG_SKIP_DOTENV_FROM_ENV:-}" in
        1 | true | TRUE | yes | YES) return 0 ;;
    esac

    if [ ! -f "${root}/docker-compose.relay.yml" ] && [ ! -f "${root}/docker-compose.client.yml" ]; then
        return 0
    fi
    if [ ! -f "${root}/.env.example" ]; then
        print_warning "${root}/.env.example missing — cannot materialize .env."
        return 0
    fi

    local dotenv="${root}/.env"
    local both_mongo_secrets_set=false
    if [ -n "${MONGO_INITDB_ROOT_PASSWORD:-}" ] && [ -n "${MONGO_APP_PASSWORD:-}" ]; then
        both_mongo_secrets_set=true
    fi

    local merging=false

    if [ ! -f "$dotenv" ]; then
        if command -v install >/dev/null 2>&1; then
            if ! install -m 0600 "${root}/.env.example" "$dotenv"; then
                print_error "Failed to copy ${root}/.env.example → ${dotenv}"
                return 1
            fi
        elif ! cp "${root}/.env.example" "$dotenv"; then
            print_error "Failed to copy ${root}/.env.example → ${dotenv}"
            return 1
        else
            if ! chmod 0600 "$dotenv"; then
                print_warning "Could not chmod 0600 ${dotenv} — as the owner run: chmod u=rw,go= ${dotenv}"
            fi
        fi
        if [ "$both_mongo_secrets_set" = true ]; then
            print_success "Created ${dotenv} from .env.example (Mongo passwords set in environment)."
        else
            print_success "Created ${dotenv} from .env.example (legacy no-auth template — set passwords and MongodbUri when using Mongo auth)."
            _process_config_dotenv_chown_to_invoking_user "$root"
            return 0
        fi
    else
        if [ "$both_mongo_secrets_set" != true ]; then
            _process_config_dotenv_chown_to_invoking_user "$root"
            return 0
        fi
        if [ "${PROCESS_CONFIG_MERGE_DOTENV_FROM_ENV:-0}" != "1" ]; then
            print_info ".env already exists (${dotenv}) — skipping Mongo merge from env. Set PROCESS_CONFIG_MERGE_DOTENV_FROM_ENV=1 to overwrite mongo-related keys from the current environment."
            _process_config_dotenv_chown_to_invoking_user "$root"
            return 0
        fi
        merging=true
    fi

    if ! MCP_DOTENV_FILE="$dotenv" python3 <<'PY_MERGE_DOTENV'
import os
import re
import pathlib
from urllib.parse import quote

path = pathlib.Path(os.environ["MPC_DOTENV_FILE"])
assign = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$")


def pct(s):
    return quote(str(s), safe="")


def build_updates():
    out = {}
    for k in (
        "MONGO_INITDB_ROOT_USERNAME",
        "MONGO_INITDB_ROOT_PASSWORD",
        "MONGO_APP_USER",
        "MONGO_APP_PASSWORD",
        "MONGO_APP_DATABASE",
    ):
        v = os.environ.get(k)
        if v not in (None, ""):
            out[k] = v
    uri = os.environ.get("MongodbUri", "").strip()
    if uri:
        out["MongodbUri"] = uri
    elif os.environ.get("MONGO_APP_PASSWORD"):
        u = os.environ.get("MONGO_APP_USER", "").strip() or "mpcauth"
        p = os.environ.get("MONGO_APP_PASSWORD", "")
        db = os.environ.get("MONGO_APP_DATABASE", "").strip() or "DistributedAuth"
        out["MongodbUri"] = "mongodb://{}:{}@mongodb:27017/{}?authSource={}".format(pct(u), pct(p), pct(db), pct(db))
    return out


updates = build_updates()

raw = path.read_text(encoding="utf-8", errors="replace")

out_lines = []
seen = set()
for ln in raw.splitlines(keepends=False):
    m = assign.match(ln)
    if m:
        key, _val = m.group(1), m.group(2)
        if key in updates:
            out_lines.append("{}={}".format(key, updates[key]))
            seen.add(key)
            continue
    if "MongodbUri" in updates and ln.strip().startswith("#") and "MongodbUri=mongodb://" in ln:
        continue
    out_lines.append(ln)

suffix = []

for key in (
    "MONGO_INITDB_ROOT_USERNAME",
    "MONGO_INITDB_ROOT_PASSWORD",
    "MONGO_APP_USER",
    "MONGO_APP_PASSWORD",
    "MONGO_APP_DATABASE",
    "MongodbUri",
):

    if key in updates and key not in seen:
        suffix.append("{}={}".format(key, updates[key]))

final = "\n".join(out_lines).rstrip() + ("\n\n" + "\n".join(suffix) + "\n" if suffix else "\n")

path.write_text(final, encoding="utf-8")
PY_MERGE_DOTENV
    then
        print_error "Failed to merge environment into ${dotenv} (python3)."
        return 1
    fi

    if ! chmod 0600 "$dotenv"; then
        print_warning "Could not chmod 0600 ${dotenv} — as the file owner run: chmod u=rw,go= ${dotenv}"
    fi

    if [ "$merging" = true ]; then
        print_success "Updated Mongo-related entries in ${dotenv} from the current environment."
    fi
    _process_config_dotenv_chown_to_invoking_user "$root"
}

# .env is mode 0600; when created/updated via sudo it is root-owned and docker compose (as the login user) cannot read it.
_process_config_dotenv_chown_to_invoking_user() {
    local root="$1"
    local dotenv="${root}/.env"
    [ -f "$dotenv" ] || return 0
    process_config_transfer_repo_path_to_invoking_user "$dotenv"
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ] && [ "${EUID:-0}" -eq 0 ]; then
        chown "${PROCESS_CONFIG_REPO_UID}:${PROCESS_CONFIG_REPO_GID}" "$dotenv" 2>/dev/null || true
    fi
    chmod 0600 "$dotenv" 2>/dev/null || true
}


extract_ip_from_url() {
    local url="$1"
    # Remove protocol (http:// or https://)
    url="${url#http://}"
    url="${url#https://}"
    # Extract IP/hostname (everything before : or /)
    url="${url%%:*}"
    url="${url%%/*}"
    echo "$url"
}

# Check if IP is private/localhost (returns 0 if private, 1 if public)
is_private_ip() {
    local ip="$1"
    
    # Check for localhost variants
    if [ "$ip" = "localhost" ] || [ "$ip" = "127.0.0.1" ] || [ "$ip" = "::1" ]; then
        return 0
    fi
    
    # Check for IPv4 private ranges using pattern matching
    # 127.0.0.0/8 (localhost)
    if echo "$ip" | grep -qE '^127\.'; then
        return 0
    fi
    
    # 10.0.0.0/8 (private)
    if echo "$ip" | grep -qE '^10\.'; then
        return 0
    fi
    
    # 172.16.0.0/12 (private)
    if echo "$ip" | grep -qE '^172\.(1[6-9]|2[0-9]|3[01])\.'; then
        return 0
    fi
    
    # 192.168.0.0/16 (private)
    if echo "$ip" | grep -qE '^192\.168\.'; then
        return 0
    fi
    
    # 169.254.0.0/16 (link-local)
    if echo "$ip" | grep -qE '^169\.254\.'; then
        return 0
    fi
    
    # Check for IPv6 private/localhost
    if echo "$ip" | grep -qE '^(::1|fe80:|fc00:|fd00:)'; then
        return 0
    fi
    
    # If it's not a valid IP format, might be a hostname - allow it (will be resolved later)
    if ! echo "$ip" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        # It's likely a hostname, not an IP - allow it
        return 1
    fi
    
    # Public IP
    return 1
}

# Check if IP is a default example IP (should be replaced)
is_default_example_ip() {
    local ip="$1"
    
    # Default example IPs from configs.yaml
    case "$ip" in
        203.0.113.10|203.0.113.11|203.0.113.12)
            return 0  # Is default example
            ;;
        *)
            return 1  # Not a default example
            ;;
    esac
}

# Validate presign configuration fields
validate_presign_config() {
    local config_file="$1"
    
    if [ ! -f "$config_file" ]; then
        return 0  # Skip if config not found
    fi
    
    print_step "Validating presign configuration..."
    
    # Get presign config values
    local initiate_presigning=""
    local cache_size=""
    local min_threshold=""
    
    # Use simple grep/sed parsing as primary method (most reliable, no dependencies)
    # This works for simple YAML structures like these top-level fields
    initiate_presigning=$(grep -E '^\s*InitiatePreSigning\s*:' "$config_file" 2>/dev/null | sed -E 's/^\s*InitiatePreSigning\s*:\s*(true|false).*/\1/' | head -1)
    cache_size=$(grep -E '^\s*PreSigningCacheSize\s*:' "$config_file" 2>/dev/null | sed -E 's/^\s*PreSigningCacheSize\s*:\s*([0-9]+).*/\1/' | head -1)
    min_threshold=$(grep -E '^\s*PreSigningMinThreshold\s*:' "$config_file" 2>/dev/null | sed -E 's/^\s*PreSigningMinThreshold\s*:\s*([0-9]+).*/\1/' | head -1)
    
    # If grep/sed didn't find values, try yq if available
    if [ -z "$initiate_presigning" ] && [ -z "$cache_size" ] && [ -z "$min_threshold" ]; then
        if command -v yq &> /dev/null; then
            initiate_presigning=$(yq eval '.InitiatePreSigning' "$config_file" 2>/dev/null)
            cache_size=$(yq eval '.PreSigningCacheSize' "$config_file" 2>/dev/null)
            min_threshold=$(yq eval '.PreSigningMinThreshold' "$config_file" 2>/dev/null)
        elif command -v python3 &> /dev/null; then
            # Only use Python as last resort with strict timeout (ruamel.yaml, same as config merges)
            if python3 -c "import ruamel.yaml" 2>/dev/null; then
                # Use a simple one-liner with explicit timeout
                local py_script="/tmp/presign_$$.py"
                cat > "$py_script" << 'PYEOF'
import sys, os
try:
    from ruamel.yaml import YAML
except ImportError:
    sys.exit(1)
try:
    _ry = YAML()
    with open(os.environ['PRESIGN_CONFIG_FILE'], 'r') as f:
        d = _ry.load(f) or {}
    i = d.get('InitiatePreSigning')
    c = d.get('PreSigningCacheSize')
    t = d.get('PreSigningMinThreshold')
    if i is not None: print('INITIATE:' + ('true' if i else 'false'))
    if c is not None: print('CACHE:' + str(c))
    if t is not None: print('THRESHOLD:' + str(t))
except Exception:
    sys.exit(1)
PYEOF
                export PRESIGN_CONFIG_FILE="$config_file"
                local py_output=""
                if command -v timeout &> /dev/null; then
                    py_output=$(timeout 2 python3 "$py_script" 2>/dev/null)
                else
                    py_output=$(python3 "$py_script" 2>/dev/null & sleep 1; kill $! 2>/dev/null; wait $! 2>/dev/null; cat /tmp/presign_out_$$.txt 2>/dev/null || echo "")
                fi
                rm -f "$py_script" /tmp/presign_out_$$.txt 2>/dev/null
                unset PRESIGN_CONFIG_FILE
                
                if [ -n "$py_output" ]; then
                    initiate_presigning=$(echo "$py_output" | grep "^INITIATE:" | cut -d: -f2)
                    cache_size=$(echo "$py_output" | grep "^CACHE:" | cut -d: -f2)
                    min_threshold=$(echo "$py_output" | grep "^THRESHOLD:" | cut -d: -f2)
                fi
            fi
        fi
    fi
    
    # Validate PreSigningCacheSize if set
    if [ -n "$cache_size" ] && [ "$cache_size" != "null" ]; then
        if ! echo "$cache_size" | grep -qE '^[0-9]+$'; then
            print_error "Invalid PreSigningCacheSize: '$cache_size' (must be a positive integer)"
            exit 1
        fi
        cache_size=$((cache_size + 0))
        if [ $cache_size -lt 1 ] || [ $cache_size -gt 50 ]; then
            print_error "PreSigningCacheSize ($cache_size) must be between 1 and 50 (inclusive)"
            exit 1
        fi
        print_success "PreSigningCacheSize validation passed: $cache_size"
    fi
    
    # Validate PreSigningMinThreshold if set
    if [ -n "$min_threshold" ] && [ "$min_threshold" != "null" ]; then
        if ! echo "$min_threshold" | grep -qE '^[0-9]+$'; then
            print_error "Invalid PreSigningMinThreshold: '$min_threshold' (must be a positive integer)"
            exit 1
        fi
        min_threshold=$((min_threshold + 0))
        if [ $min_threshold -lt 1 ]; then
            print_error "PreSigningMinThreshold ($min_threshold) must be at least 1"
            exit 1
        fi
        
        # Validate min_threshold < cache_size if both are set
        if [ -n "$cache_size" ] && [ "$cache_size" != "null" ] && [ $min_threshold -ge $cache_size ]; then
            print_error "PreSigningMinThreshold ($min_threshold) must be less than PreSigningCacheSize ($cache_size)"
            exit 1
        fi
        print_success "PreSigningMinThreshold validation passed: $min_threshold"
    fi
    
    # Validate InitiatePreSigning if set
    if [ -n "$initiate_presigning" ] && [ "$initiate_presigning" != "null" ]; then
        if [ "$initiate_presigning" != "true" ] && [ "$initiate_presigning" != "false" ]; then
            print_error "Invalid InitiatePreSigning: '$initiate_presigning' (must be true or false)"
            exit 1
        fi
        print_success "InitiatePreSigning validation passed: $initiate_presigning"
        if [ "$initiate_presigning" = "true" ]; then
            print_info "InitiatePreSigning: automatic presign applies only to FROST keys (ed25519, bitcoin-taproot); CGGMP24 secp256k1 is skipped"
        fi
    fi
    
    print_success "Presign configuration validation passed"
}

# Validate Relayer API connection when PreSigningVerification is configured
validate_relayer_api_connection() {
    local config_file="$1"
    
    if [ ! -f "$config_file" ]; then
        return 0  # Skip if config not found
    fi
    
    print_step "Validating Relayer API configuration for pre-signing verification..."
    
    # Check if PreSigningVerification section exists
    local has_ps_verif=false
    local api_url=""
    
    # Use simple grep/sed parsing (most reliable, no dependencies)
    # Find PreSigningVerification section and extract values
    local in_ps_verif=false
    local ps_indent=""
    while IFS= read -r line; do
        # Check if we're entering PreSigningVerification section
        if echo "$line" | grep -qE '^\s*PreSigningVerification\s*:'; then
            in_ps_verif=true
            has_ps_verif=true
            ps_indent=$(echo "$line" | sed 's/[^ ].*//')
            continue
        fi
        
        # Check if we're leaving PreSigningVerification section (top-level key with same or less indent)
        if [ "$in_ps_verif" = true ]; then
            local current_indent=$(echo "$line" | sed 's/[^ ].*//')
            if [ -n "$current_indent" ] && [ "${#current_indent}" -le "${#ps_indent}" ] && echo "$line" | grep -qE '^\s*[A-Za-z_]+:'; then
                in_ps_verif=false
            fi
        fi
        
        # Extract RelayerAPIURL value (handle quoted and unquoted strings)
        if [ "$in_ps_verif" = true ] && [ -z "$api_url" ] && echo "$line" | grep -qE '^\s+RelayerAPIURL\s*:'; then
            # Try to extract URL - handle both quoted and unquoted
            api_url=$(echo "$line" | sed -E 's/^\s*RelayerAPIURL\s*:\s*["'\'']?([^"'\''#]+)["'\'']?.*/\1/' | sed 's/[[:space:]]*$//' | head -1)
            # Remove empty strings
            if [ "$api_url" = '""' ] || [ "$api_url" = "''" ] || [ -z "$api_url" ]; then
                api_url=""
            fi
        fi
    done < "$config_file"
    
    # Fallback to yq if grep didn't find values
    if [ "$has_ps_verif" = false ] || [ -z "$api_url" ]; then
        if command -v yq &> /dev/null; then
            has_ps_verif=$(yq eval '.PreSigningVerification != null' "$config_file" 2>/dev/null)
            api_url=$(yq eval '.PreSigningVerification.RelayerAPIURL' "$config_file" 2>/dev/null)
        fi
    fi
    
    # If PreSigningVerification section doesn't exist, skip validation
    if [ "$has_ps_verif" != "true" ]; then
        print_info "PreSigningVerification section not found - skipping Relayer API validation"
        return 0
    fi
    
    # Check required field
    if [ -z "$api_url" ] || [ "$api_url" = "null" ] || [ "$api_url" = "" ]; then
        print_error "PreSigningVerification is configured but RelayerAPIURL is missing"
        echo ""
        print_info "Please obtain the Relayer API URL from the DAO and update your configs.yaml:"
        echo "  PreSigningVerification:"
        echo "    RelayerAPIURL: \"https://relayer.example.com\""
        echo "    # or: RelayerAPIURL: \"http://203.0.113.10:8080\""
        echo ""
        print_warning "You can also set this via environment variable:"
        echo "  export RELAYER_API_URL=\"https://relayer.example.com\""
        echo ""
        print_error "Certificate generation aborted: Relayer API URL is not configured."
        exit 1
    fi
    
    # Remove trailing slash if present
    api_url=$(echo "$api_url" | sed 's|/$||')
    
    # Extract host and port from URL for connectivity check
    local api_host=""
    local api_port=""
    local api_protocol=""
    
    # Parse URL to extract host and port
    if echo "$api_url" | grep -qE '^https?://'; then
        # Extract protocol
        if echo "$api_url" | grep -qE '^https://'; then
            api_protocol="https"
            api_port="443"
        else
            api_protocol="http"
            api_port="80"
        fi
        
        # Remove protocol prefix
        local url_without_protocol=$(echo "$api_url" | sed 's|^https\?://||')
        
        # Extract host and port
        if echo "$url_without_protocol" | grep -q ':'; then
            api_host=$(echo "$url_without_protocol" | cut -d':' -f1)
            api_port=$(echo "$url_without_protocol" | cut -d':' -f2 | cut -d'/' -f1)
        else
            api_host=$(echo "$url_without_protocol" | cut -d'/' -f1)
        fi
    else
        # Assume http if no protocol specified
        api_protocol="http"
        api_port="80"
        if echo "$api_url" | grep -q ':'; then
            api_host=$(echo "$api_url" | cut -d':' -f1)
            api_port=$(echo "$api_url" | cut -d':' -f2 | cut -d'/' -f1)
        else
            api_host=$(echo "$api_url" | cut -d'/' -f1)
        fi
    fi
    
    # Pre-flight connectivity check: Test if we can reach the API host and port
    print_info "Performing connectivity check to $api_host:$api_port..."
    
    local connectivity_check_passed=false
    local connectivity_error=""
    
    # Try using nc (netcat) if available (most reliable)
    if command -v nc &> /dev/null; then
        local nc_output
        nc_output=$(timeout 5 nc -zv -w 3 "$api_host" "$api_port" 2>&1)
        local nc_exit=$?
        
        if [ $nc_exit -eq 0 ]; then
            connectivity_check_passed=true
            print_success "Network connectivity check passed: Port $api_port is reachable on $api_host"
        else
            # Capture the specific error message
            connectivity_error=$(echo "$nc_output" | grep -i "failed\|refused\|timeout\|unreachable" | head -1 || echo "Connection failed")
            print_warning "Network connectivity check failed: $connectivity_error"
            
            # Check if it's "Connection refused" vs "Connection timed out" vs "Host unreachable"
            if echo "$nc_output" | grep -qi "refused"; then
                print_info "Diagnosis: Host is reachable but port $api_port is not accepting connections"
                print_info "This could mean:"
                echo "  - API server is not running on port $api_port"
                echo "  - Firewall is blocking port $api_port"
                echo "  - Port number is incorrect"
            elif echo "$nc_output" | grep -qi "timeout\|timed out"; then
                print_info "Diagnosis: Connection attempt timed out"
                print_info "This could mean:"
                echo "  - Firewall is silently dropping packets"
                echo "  - Network routing issue"
                echo "  - Host is heavily loaded"
            elif echo "$nc_output" | grep -qi "unreachable\|No route"; then
                print_info "Diagnosis: Host is unreachable"
                print_info "This could mean:"
                echo "  - Incorrect host address"
                echo "  - Network routing issue"
                echo "  - Host is down"
            fi
        fi
    # Try using bash's /dev/tcp (works on most Linux systems)
    elif timeout 5 bash -c "echo > /dev/tcp/$api_host/$api_port" 2>/dev/null; then
        connectivity_check_passed=true
        print_success "Network connectivity check passed: Port $api_port is reachable on $api_host"
    else
        local bash_error=$?
        print_warning "Network connectivity check failed using /dev/tcp method"
        if [ $bash_error -eq 124 ]; then
            connectivity_error="Connection timed out"
        elif [ $bash_error -eq 1 ]; then
            connectivity_error="Connection refused"
        else
            connectivity_error="Connection failed (exit code: $bash_error)"
        fi
    fi
    
    # If connectivity check failed, still try the API endpoint test (might be HTTP/HTTPS specific)
    if [ "$connectivity_check_passed" != "true" ]; then
        print_warning "Pre-flight connectivity check failed, but will still attempt API endpoint test"
        print_info "Note: The API server might use HTTP/HTTPS which requires different connectivity checks"
    fi
    
    echo ""
    # Test API endpoint
    print_info "Testing Relayer API endpoint at $api_url..."
    
    # Check if curl is available
    if ! command -v curl &> /dev/null; then
        print_error "curl not found - cannot test API connection"
        print_error "curl is required for API connectivity testing."
        echo ""
        print_info "Please install curl:"
        echo "  Ubuntu/Debian: sudo apt-get install curl"
        echo "  CentOS/RHEL: sudo yum install curl"
        echo "  macOS: curl is usually pre-installed"
        echo ""
        print_error "Certificate generation aborted: curl is required for API connection testing."
        exit 1
    fi
    
    # Test API endpoint with multiple chain IDs
    # Try common chain IDs and succeed if any of them responds
    local test_chain_ids=(421614 97 11155111 1 42161 56)
    local http_code=""
    local response=""
    local successful_chain_id=""
    local last_error=""
    
    print_info "Testing Relayer API endpoint with multiple chain IDs..."
    
    for chain_id in "${test_chain_ids[@]}"; do
        local test_url="${api_url}/v1/mpc/chain_info?chain_id=${chain_id}"
        
        # Use timeout if available
        if command -v timeout &> /dev/null; then
            response=$(timeout 10 curl -s -w "\n%{http_code}" "$test_url" 2>&1)
            http_code=$(echo "$response" | tail -n 1)
            response=$(echo "$response" | sed '$d')
        elif command -v gtimeout &> /dev/null; then
            response=$(gtimeout 10 curl -s -w "\n%{http_code}" "$test_url" 2>&1)
            http_code=$(echo "$response" | tail -n 1)
            response=$(echo "$response" | sed '$d')
        else
            # Fallback: use curl's built-in timeout
            response=$(curl -s --max-time 10 -w "\n%{http_code}" "$test_url" 2>&1)
            http_code=$(echo "$response" | tail -n 1)
            response=$(echo "$response" | sed '$d')
        fi
        
        # Check HTTP response code
        if [ "$http_code" = "200" ]; then
            successful_chain_id="$chain_id"
            print_success "Relayer API connection successful! (chain_id: $chain_id)"
            print_info "Relayer API is accessible and responding correctly"
            break
        elif [ "$http_code" = "404" ] || [ "$http_code" = "400" ]; then
            # 404/400 means endpoint exists but chain_id may not be configured - that's OK for validation
            successful_chain_id="$chain_id"
            print_success "Relayer API connection successful! (chain_id: $chain_id returned $http_code)"
            print_info "Relayer API is accessible (endpoint responded, chain may not be configured - this is OK)"
            break
        elif [ -z "$http_code" ] || [ "$http_code" = "000" ]; then
            # Connection failed - try next chain ID
            last_error="$response"
            continue
        else
            # Other HTTP codes (e.g., 500, 503) - endpoint exists but may have issues
            # Still consider this a success for validation purposes
            successful_chain_id="$chain_id"
            print_warning "Relayer API returned HTTP $http_code for chain_id $chain_id"
            print_info "Endpoint exists and is responding (may indicate server issues, but API is accessible)"
            break
        fi
    done
    
    # Check if any chain ID succeeded
    if [ -z "$successful_chain_id" ]; then
        print_error "Failed to connect to Relayer API with any tested chain ID"
        echo ""
        print_info "Connection details:"
        echo "  API URL: $api_url"
        echo "  Tested chain IDs: ${test_chain_ids[*]}"
        echo ""
        print_warning "Possible issues:"
        echo "  1. API server is down or not running"
        echo "  2. Incorrect API URL (verify with DAO)"
        echo "  3. Network connectivity issue"
        echo "  4. Firewall is blocking connections"
        echo "  5. SSL/TLS certificate issue (if using https://)"
        echo ""
        if [ -n "$last_error" ]; then
            print_info "Last error details:"
            echo "$last_error"
            echo ""
        fi
        print_info "Please verify:"
        echo "  - API URL is correct (obtain from DAO)"
        echo "  - API server is accessible from this node"
        echo "  - Network connectivity: try 'curl $api_url/v1/mpc/chain_info?chain_id=97'"
        echo ""
        print_error "Certificate generation aborted: Relayer API connection test failed."
        exit 1
    fi
    
    print_success "Relayer API configuration validated successfully"
}

# Extract RelayerAPIURL from configs.yaml (empty if missing). Uses yq when available, else line scan (no PyYAML required).
_extract_relayer_api_url_from_config() {
    local config_file="$1"
    local api_url=""
    if [ ! -f "$config_file" ]; then
        echo ""
        return 0
    fi
    if command -v yq &>/dev/null; then
        api_url=$(yq eval '.PreSigningVerification.RelayerAPIURL // ""' "$config_file" 2>/dev/null || echo "")
        printf '%s' "$api_url" | tr -d '\r\n'
        return 0
    fi
    local in_ps_verif=false ps_indent=""
    while IFS= read -r line; do
        if echo "$line" | grep -qE '^\s*PreSigningVerification\s*:'; then
            in_ps_verif=true
            ps_indent=$(echo "$line" | sed 's/[^ ].*//')
            continue
        fi
        if [ "$in_ps_verif" = true ]; then
            local current_indent
            current_indent=$(echo "$line" | sed 's/[^ ].*//')
            if [ -n "$current_indent" ] && [ "${#current_indent}" -le "${#ps_indent}" ] && echo "$line" | grep -qE '^\s*[A-Za-z_]+:'; then
                in_ps_verif=false
            fi
        fi
        if [ "$in_ps_verif" = true ] && [ -z "$api_url" ] && echo "$line" | grep -qE '^\s+RelayerAPIURL\s*:'; then
            api_url=$(echo "$line" | sed -E 's/^\s*RelayerAPIURL\s*:\s*["'\'']?([^"'\''#]+)["'\'']?.*/\1/' | sed 's/[[:space:]]*$//' | head -1)
            if [ "$api_url" = '""' ] || [ "$api_url" = "''" ]; then
                api_url=""
            fi
        fi
    done < "$config_file"
    printf '%s' "$api_url" | tr -d '\r\n'
}

# True when interactive Relayer/Scanner prompts may run (TTY + not PROCESS_CONFIG_NONINTERACTIVE).
_process_config_prompt_relayer_scanner_ok() {
    case "${PROCESS_CONFIG_NONINTERACTIVE:-0}" in
        1|true|TRUE|yes|YES) return 1 ;;
    esac
    if [ -t 0 ] && [ -t 1 ] && [ -r /dev/tty ]; then
        return 0
    fi
    return 1
}

# When PreSigningVerification exists but RelayerAPIURL is empty: RELAYER_API_URL env, then DEFAULT_RELAYER_API_URL, or prompt (empty line = default).
# Also fills ScannerAPIURLs in configs.yaml when empty (DEFAULT_SCANNER_API_URLS).
prompt_relayer_api_url_if_missing() {
    local config_file="$1"

    if [ ! -f "$config_file" ]; then
        return 0
    fi

    local has_ps=false
    if command -v yq &>/dev/null; then
        has_ps=$(yq eval '.PreSigningVerification != null' "$config_file" 2>/dev/null || echo false)
    else
        if grep -qE '^[[:space:]]*PreSigningVerification[[:space:]]*:' "$config_file" 2>/dev/null; then
            has_ps=true
        fi
    fi
    if [ "$has_ps" != "true" ]; then
        return 0
    fi

    local api_url
    api_url=$(_extract_relayer_api_url_from_config "$config_file")
    if [ -n "${api_url//[[:space:]]/}" ] && [ "$api_url" != "null" ]; then
        prompt_scanner_api_urls_if_empty "$config_file" || return 1
        return 0
    fi

    local env_url="${RELAYER_API_URL:-}"
    env_url="${env_url#"${env_url%%[![:space:]]*}"}"
    env_url="${env_url%"${env_url##*[![:space:]]}"}"
    if [ -n "$env_url" ]; then
        env_url="${env_url%/}"
        configs_yaml_merge_relayer_api_url "$config_file" "$env_url" || return 1
        print_success "Set PreSigningVerification.RelayerAPIURL from RELAYER_API_URL environment variable"
        prompt_scanner_api_urls_if_empty "$config_file" || return 1
        return 0
    fi

    local url_in=""
    if _process_config_prompt_relayer_scanner_ok; then
        echo ""
        print_step "RelayerAPIURL missing — required when PreSigningVerification is configured"
        print_info "Obtain the relayer HTTP base URL from the DAO (serves /v1/mpc/chain_info). Not the same as MPC node addresses."
        print_info "Press Enter to use the default, or paste a URL."
        while true; do
            read -r -p "RelayerAPIURL [${DEFAULT_RELAYER_API_URL}]: " url_in < /dev/tty || true
            url_in="${url_in#"${url_in%%[![:space:]]*}"}"
            url_in="${url_in%"${url_in##*[![:space:]]}"}"
            if [ -z "$url_in" ]; then
                url_in="$DEFAULT_RELAYER_API_URL"
                break
            fi
            url_in="${url_in%/}"
            if ! printf '%s' "$url_in" | grep -qE '^https?://[^[:space:]]+'; then
                print_error "URL must start with http:// or https:// (or press Enter for default)"
                continue
            fi
            break
        done
    else
        url_in="$DEFAULT_RELAYER_API_URL"
        print_info "Non-interactive: setting PreSigningVerification.RelayerAPIURL to default ${DEFAULT_RELAYER_API_URL} (override with RELAYER_API_URL or set PROCESS_CONFIG_NONINTERACTIVE=0 to prompt; or edit configs.yaml)"
    fi

    configs_yaml_merge_relayer_api_url "$config_file" "$url_in" || return 1
    print_success "Wrote PreSigningVerification.RelayerAPIURL to configs.yaml (comments preserved)"
    prompt_scanner_api_urls_if_empty "$config_file" || return 1
    echo ""
    return 0
}

# Validate that default example IPs have been replaced
validate_no_default_ips() {
    local config_file="$1"
    
    if [ ! -f "$config_file" ]; then
        return 0  # Skip if config not found
    fi
    
    print_step "Checking that default example IPs have been replaced..."
    
    # Get all node addresses from config
    local node_addresses=()
    while IFS= read -r addr; do
        [ -n "$addr" ] && node_addresses+=("$addr")
    done < <(parse_node_addresses_from_yaml "$config_file")
    
    if [ ${#node_addresses[@]} -eq 0 ]; then
        return 0  # No addresses to validate
    fi
    
    local has_default=false
    local default_addresses=()
    
    for node_addr in "${node_addresses[@]}"; do
        local node_ip=$(extract_ip_from_url "$node_addr")
        
        # Skip empty IPs
        if [ -z "$node_ip" ]; then
            continue
        fi
        
        # Check if it's a default example IP
        if is_default_example_ip "$node_ip"; then
            has_default=true
            default_addresses+=("$node_addr (IP: $node_ip)")
        fi
    done
    
    if [ "$has_default" = true ]; then
        print_error "Found default example IP addresses in configs.yaml nodeAddresses"
        echo ""
        print_error "Default example addresses found (must be replaced with real IPs):"
        printf '  - %s\n' "${default_addresses[@]}"
        echo ""
        print_error "You must replace the default example IPs (203.0.113.10, 203.0.113.11, 203.0.113.12)"
        print_error "with the actual external IP addresses of your MPC nodes."
        echo ""
        print_info "Please update configs.yaml with your real node IP addresses before generating certificates."
        exit 1
    fi
    
    print_success "No default example IPs found - addresses appear to be configured"
}

# Validate that all node addresses in config are external IPs
validate_external_ips_only() {
    local config_file="$1"
    
    if [ ! -f "$config_file" ]; then
        return 0  # Skip if config not found
    fi

    # Deferred relay (0.0.0.0 first): peers may be private/LAN until the real relay IP is set (provision / NAT).
    if first_node_address_is_relay_placeholder "$config_file"; then
        print_info "First nodeAddresses host is ${NODE_ADDRESSES_RELAY_PLACEHOLDER_IPV4} (relay placeholder) — skipping public-IP-only validation for peer entries."
        return 0
    fi
    
    print_step "Validating that all node addresses are external IPs..."
    
    # Get all node addresses from config
    local node_addresses=()
    while IFS= read -r addr; do
        [ -n "$addr" ] && node_addresses+=("$addr")
    done < <(parse_node_addresses_from_yaml "$config_file")
    
    if [ ${#node_addresses[@]} -eq 0 ]; then
        return 0  # No addresses to validate
    fi
    
    local has_private=false
    local private_addresses=()
    
    for node_addr in "${node_addresses[@]}"; do
        local node_ip=$(extract_ip_from_url "$node_addr")
        
        # Skip empty IPs
        if [ -z "$node_ip" ]; then
            continue
        fi
        
        # Check if it's a private IP
        if is_private_ip "$node_ip"; then
            has_private=true
            private_addresses+=("$node_addr (IP: $node_ip)")
        fi
    done
    
    if [ "$has_private" = true ]; then
        print_error "Found private/localhost IP addresses in configs.yaml nodeAddresses"
        echo ""
        print_error "Private addresses found:"
        printf '  - %s\n' "${private_addresses[@]}"
        echo ""
        print_error "All node addresses in configs.yaml must use external (public) IP addresses."
        echo ""
        print_info "Private IP ranges that are NOT allowed:"
        echo "  - 127.0.0.0/8 (localhost)"
        echo "  - 10.0.0.0/8 (private)"
        echo "  - 172.16.0.0/12 (private)"
        echo "  - 192.168.0.0/16 (private)"
        echo "  - 169.254.0.0/16 (link-local)"
        echo "  - localhost, 127.0.0.1, ::1"
        echo ""
        print_info "Please update configs.yaml to use external IP addresses for all nodes."
        print_info "If nodes are behind NAT, use the public IP address or a public hostname."
        print_info "You can use hostnames (e.g., node1.example.com) which will be resolved to IPs."
        exit 1
    fi
    
    print_success "All node addresses are external IPs"
}

# Get local IP addresses
get_local_ips() {
    local ips=()
    
    # Try multiple methods to get local IPs
    # Method 1: hostname -I (Linux, most common)
    if command -v hostname &> /dev/null; then
        while IFS= read -r ip; do
            [ -n "$ip" ] && ips+=("$ip")
        done < <(hostname -I 2>/dev/null | tr ' ' '\n')
    fi
    
    # Method 2: ip addr (Linux)
    if command -v ip &> /dev/null; then
        while IFS= read -r ip; do
            [ -n "$ip" ] && ips+=("$ip")
        done < <(ip -4 addr show 2>/dev/null | grep -oP 'inet \K[\d.]+' 2>/dev/null)
    fi
    
    # Method 3: ifconfig (older systems)
    if command -v ifconfig &> /dev/null; then
        while IFS= read -r ip; do
            [ -n "$ip" ] && ips+=("$ip")
        done < <(ifconfig 2>/dev/null | grep -oP 'inet \K[\d.]+' 2>/dev/null)
    fi
    
    # Method 4: hostname (fallback, may return hostname instead of IP)
    if [ ${#ips[@]} -eq 0 ] && command -v hostname &> /dev/null; then
        local hostname_ip=$(hostname -i 2>/dev/null)
        [ -n "$hostname_ip" ] && ips+=("$hostname_ip")
    fi
    
    # Also check for localhost variants
    ips+=("127.0.0.1" "localhost" "::1")
    
    # Remove duplicates and return
    printf '%s\n' "${ips[@]}" | sort -u
}

# This machine's public IPv4 as seen on the internet (NAT / router: local interfaces are often 10/172.16/192.168).
# Used to match configs that list external IPs in nodeAddresses. Empty if lookup fails.
# Set SKIP_EXTERNAL_IP_LOOKUP=1 to disable (air-gapped / no outbound HTTPS).
get_external_ipv4_via_http() {
    if [ "${SKIP_EXTERNAL_IP_LOOKUP:-}" = "1" ]; then
        return 1
    fi
    local url ip
    for url in \
        "https://ipinfo.io/ip" \
        "https://api.ipify.org" \
        "https://ifconfig.me/ip"; do
        ip=""
        if command -v curl &>/dev/null; then
            ip=$(curl -fsS --connect-timeout 3 --max-time 10 "$url" 2>/dev/null || true)
        elif command -v wget &>/dev/null; then
            ip=$(wget -qO- --timeout=10 "$url" 2>/dev/null || true)
        else
            return 1
        fi
        ip=$(printf '%s' "$ip" | tr -d '\r' | head -n1 | tr -d '[:space:]')
        if echo "$ip" | grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then
            echo "$ip"
            return 0
        fi
    done
    return 1
}

# Check if IP matches (handles hostname resolution)
ip_matches() {
    local ip1="$1"
    local ip2="$2"
    
    # Direct match
    if [ "$ip1" = "$ip2" ]; then
        return 0
    fi
    
    # Check if one resolves to the other
    if command -v getent &> /dev/null; then
        local resolved=$(getent hosts "$ip1" 2>/dev/null | awk '{print $1}')
        if [ "$resolved" = "$ip2" ]; then
            return 0
        fi
        local resolved2=$(getent hosts "$ip2" 2>/dev/null | awk '{print $1}')
        if [ "$resolved2" = "$ip1" ]; then
            return 0
        fi
    fi
    
    return 1
}

# Parse YAML to extract node addresses (simple parser, handles basic YAML)
parse_node_addresses_from_yaml() {
    local config_file="$1"
    local addresses=()
    
    if [ ! -f "$config_file" ]; then
        return 1
    fi
    
    # Use yq if available (best option)
    if command -v yq &> /dev/null; then
        # Get all nodeAddresses from all MPC groups
        while IFS= read -r addr; do
            [ -n "$addr" ] && [ "$addr" != "null" ] && addresses+=("$addr")
        done < <(yq eval '.MPCGroups[].nodeAddresses | to_entries | .[].value' "$config_file" 2>/dev/null)
        if [ ${#addresses[@]} -gt 0 ]; then
            printf '%s\n' "${addresses[@]}"
            return 0
        fi
    fi
    
    # Use Python if available (good fallback)
    if command -v python3 &> /dev/null; then
        while IFS= read -r addr; do
            [ -n "$addr" ] && addresses+=("$addr")
        done < <(python3 -c "
import sys
try:
    from ruamel.yaml import YAML
except ImportError:
    sys.exit(1)
try:
    _ry = YAML()
    with open('$config_file', 'r') as f:
        data = _ry.load(f)
    for group in (data or {}).get('MPCGroups', []) or []:
        for addr in (group or {}).get('nodeAddresses', {}).values():
            if addr:
                print(addr)
except Exception:
    sys.exit(1)
" 2>/dev/null)
        if [ ${#addresses[@]} -gt 0 ]; then
            printf '%s\n' "${addresses[@]}"
            return 0
        fi
    fi
    
    # Fallback: simple grep/sed parsing (less robust but works for simple YAML)
    # Look for nodeAddresses section and extract URLs
    local in_node_addresses=false
    local indent_level=""
    
    while IFS= read -r line; do
        # Check if we're entering nodeAddresses section
        if echo "$line" | grep -qE '^\s*nodeAddresses:'; then
            in_node_addresses=true
            indent_level=$(echo "$line" | sed 's/[^ ].*//')
            continue
        fi
        
        # Check if we're leaving nodeAddresses section (less indented line)
        if [ "$in_node_addresses" = true ]; then
            current_indent=$(echo "$line" | sed 's/[^ ].*//')
            if [ -n "$current_indent" ] && [ "${#current_indent}" -le "${#indent_level}" ] && ! echo "$line" | grep -qE '^\s*[a-zA-Z_]+:'; then
                in_node_addresses=false
            fi
        fi
        
        # Extract URLs from nodeAddresses section
        if [ "$in_node_addresses" = true ] && echo "$line" | grep -qE 'http://|https://'; then
            local url=$(echo "$line" | sed -E 's/.*["'\'']([^"'\'']*http[^"'\'']*)["'\''].*/\1/' | grep -oE 'https?://[^"'\'' ]+')
            if [ -n "$url" ]; then
                addresses+=("$url")
            fi
        fi
    done < "$config_file"
    
    if [ ${#addresses[@]} -gt 0 ]; then
        printf '%s\n' "${addresses[@]}"
        return 0
    fi
    
    return 1
}

# Exit 0 if MPCGroups[0].nodeAddresses is missing, empty, or still uses documentation example IPs
# (203.0.113.10–12 in RFC 5737 TEST-NET-3 — any port). Do NOT match only the exact three URLs with :8080;
# that caused the fill prompt to be skipped when the port was edited to :8081 while IPs stayed examples.
# 1 if configured; 2 if no MPCGroups; 4 if ruamel.yaml is not installed (python3 -c "import ruamel.yaml" fails).
first_mpc_group_node_addresses_empty() {
    local config_file="$1"
    if ! command -v python3 &> /dev/null; then
        return 1
    fi
    python3 - "$config_file" << 'PYNAEMPTY'
import sys
try:
    from ruamel.yaml import YAML
    from urllib.parse import urlparse
except ImportError:
    sys.exit(4)  # distinct from 0=need fill, 1=configured, 2=no groups
path = sys.argv[1]

# Documentation-only IPs from configs-original / README — must be replaced for production.
DOC_EXAMPLE_IPV4 = frozenset({"203.0.113.10", "203.0.113.11", "203.0.113.12"})


def host_from_node_url(s):
    s = str(s).strip().strip('"').strip("'")
    if not s:
        return None
    if "://" in s:
        p = urlparse(s)
        if p.hostname:
            return p.hostname.lower()
        nl = (p.netloc or "").strip()
        if nl.startswith("["):
            return nl.split("]")[0].lstrip("[").lower()
        if ":" in nl:
            hostpart, _, maybe_port = nl.rpartition(":")
            if maybe_port.isdigit():
                return hostpart.lower()
        return None
    before = s.split("/")[0]
    if ":" in before:
        return before.split(":")[0].lower()
    return before.lower()


def has_documentation_example_ip(na):
    if not isinstance(na, dict):
        return False
    for v in na.values():
        if v is None or not str(v).strip():
            continue
        h = host_from_node_url(v)
        if h and h in DOC_EXAMPLE_IPV4:
            return True
    return False


_ry = YAML()
with open(path, "r") as f:
    d = _ry.load(f)
if not d:
    sys.exit(2)
groups = d.get("MPCGroups")
if not groups:
    sys.exit(2)
na = groups[0].get("nodeAddresses")
if na is None:
    sys.exit(0)
if not isinstance(na, dict):
    sys.exit(0)
if len(na) == 0:
    sys.exit(0)
if not any(v and str(v).strip() for v in na.values()):
    sys.exit(0)
if has_documentation_example_ip(na):
    sys.exit(0)
sys.exit(1)
PYNAEMPTY
}

# Strip whitespace, optional scheme/path, and trailing :port from user input (host or IPv4).
# Only strip :port when there is a single ':' (IPv4:port or hostname:port). Multiple colons = IPv6 — do not strip.
normalize_node_address_input() {
    local raw="$1"
    raw="${raw#"${raw%%[![:space:]]*}"}"
    raw="${raw%"${raw##*[![:space:]]}"}"
    raw="${raw#http://}"
    raw="${raw#https://}"
    raw="${raw%%/*}"
    raw="${raw%%\?*}"
    if [[ "$raw" == *:* ]]; then
        local ncolon
        ncolon=$(grep -o ':' <<< "$raw" | wc -l)
        ncolon="${ncolon//[[:space:]]/}"
        if [ "${ncolon:-0}" -eq 1 ]; then
            local after="${raw##*:}"
            if [[ "$after" =~ ^[0-9]+$ ]]; then
                raw="${raw%:*}"
            fi
        fi
    fi
    printf '%s' "$raw"
}

# Write MPCGroups[0].nodeAddresses as node1_key..nodeN_key -> http://HOST:PORT (PORT=MPC_NODE_HTTP_PORT). Replaces entire map.
# Args: config_file, path to temp file with one host/hostname per line (normalized).
write_mpcgroup0_node_addresses_from_host_lines_file() {
    local config_file="$1"
    local hosts_tmp="$2"
    require_ruamel_yaml || return 1
    if ! CONFIG_FILE_MERGE_NA="$config_file" HOSTS_LIST_FILE="$hosts_tmp" PORT_MERGE_NA="$MPC_NODE_HTTP_PORT" python3 << 'PYNA'
import os
import sys
try:
    from ruamel.yaml import YAML
    from ruamel.yaml.comments import CommentedMap
except ImportError:
    sys.stderr.write("configs.yaml: install ruamel.yaml (pip install --user 'ruamel.yaml')\n")
    sys.exit(1)

path = os.environ["CONFIG_FILE_MERGE_NA"]
hosts_path = os.environ["HOSTS_LIST_FILE"]
port = os.environ.get("PORT_MERGE_NA", "8081")
with open(hosts_path) as f:
    raw = f.read()
hosts = [ln.strip() for ln in raw.splitlines() if ln.strip()]

yaml = YAML()
yaml.preserve_quotes = True
yaml.width = 4096
yaml.indent(mapping=2, sequence=4, offset=2)

with open(path, "r") as f:
    data = yaml.load(f)
if not data or not data.get("MPCGroups"):
    raise SystemExit("no MPCGroups")

grp = data["MPCGroups"][0]
# Fresh CommentedMap in strict line order (node1_key..nodeN_key). In-place delete+assign on an
# existing map can confuse ruamel's ordering and YAML key order on dump (e.g. node10 before node2).
new_na = CommentedMap()
for i, h in enumerate(hosts, 1):
    k = f"node{i}_key"
    new_na[k] = f"http://{h}:{port}"
grp["nodeAddresses"] = new_na

if len(hosts) != len(new_na):
    raise SystemExit("internal: hosts/nodeAddresses length mismatch")

with open(path, "w") as f:
    yaml.dump(data, f)
PYNA
    then
        return 1
    fi
    return 0
}

# Print one hostname/host per line for MPCGroups[0].nodeAddresses (YAML insertion order).
# Writer above emits node1_key..nodeN_key in relay order; do not re-sort keys here (avoids confusion with IP order).
extract_ordered_hosts_mpcgroup0() {
    local config_file="$1"
    if [ ! -f "$config_file" ]; then
        return 1
    fi
    python3 - "$config_file" << 'PYEX'
import re
import sys
try:
    from ruamel.yaml import YAML
    from urllib.parse import urlparse
except ImportError:
    sys.exit(1)

def host_from_node_url(s):
    s = str(s).strip().strip('"').strip("'")
    if not s:
        return None
    if "://" in s:
        p = urlparse(s)
        if p.hostname:
            return p.hostname
        # Rare: hostname None — parse netloc (IPv4 host:port)
        nl = (p.netloc or "").strip()
        if nl.startswith("["):
            return nl.split("]")[0].lstrip("[")
        if ":" in nl:
            hostpart, _, maybe_port = nl.rpartition(":")
            if maybe_port.isdigit() and re.match(r"^(\d{1,3}\.){3}\d{1,3}$", hostpart):
                return hostpart
        return None
    before = s.split("/")[0]
    if ":" in before:
        return before.split(":")[0]
    return before

path = sys.argv[1]
_ry = YAML()
with open(path) as f:
    d = _ry.load(f) or {}
groups = d.get("MPCGroups") or []
if not groups:
    sys.exit(1)
na = groups[0].get("nodeAddresses")
if not isinstance(na, dict) or not na:
    sys.exit(1)
for k, v in na.items():
    if v is None:
        continue
    h = host_from_node_url(v)
    if h:
        print(h)
PYEX
}

# Interactive menu: add/remove nodes in MPCGroups[0].nodeAddresses (relay = first). Skipped if not a TTY or ruamel missing.
prompt_menu_edit_node_addresses() {
    local config_file="$1"
    if [ "${SKIP_NODE_ADDRESS_MENU:-}" = "1" ]; then
        return 0
    fi
    if [ ! -t 0 ] || [ ! -r /dev/tty ]; then
        return 0
    fi
    if ! command -v python3 &>/dev/null; then
        return 0
    fi
    if ! python3 -c "import ruamel.yaml" 2>/dev/null; then
        return 0
    fi

    local hosts_tmp hosts=() line norm lower choice
    if ! hosts_tmp=$(mktemp); then
        return 0
    fi
    if ! extract_ordered_hosts_mpcgroup0 "$config_file" >"$hosts_tmp" 2>/dev/null; then
        rm -f "$hosts_tmp"
        return 0
    fi
    mapfile -t hosts < "$hosts_tmp"
    rm -f "$hosts_tmp"
    if [ ${#hosts[@]} -eq 0 ]; then
        return 0
    fi

    while true; do
        echo ""
        print_step "nodeAddresses (optional edit)"
        print_info "Relay node = first entry. Use the same order on every machine's configs.yaml."
        echo ""
        local i=0
        for h in "${hosts[@]}"; do
            i=$((i + 1))
            echo "  [$i] http://${h}:${MPC_NODE_HTTP_PORT}  ($h)"
        done
        echo ""
        echo "  0) Continue without changes (default)"
        echo "  1) Add node(s) at end"
        echo "  2) Remove node(s) by number"
        echo ""
        read -r -p "Choice [0]: " choice < /dev/tty || true
        choice="${choice:-0}"
        choice="${choice//[[:space:]]/}"

        case "$choice" in
            0|"")
                echo ""
                return 0
                ;;
            1)
                echo ""
                local host_count_before=${#hosts[@]}
                print_info "Enter one public IP or hostname per line (or space-separated); type done or finished when finished (port :${MPC_NODE_HTTP_PORT} is added)."
                print_info "Same line OK: 203.0.113.10 finished"
                local line_add lower_add norm_add hh dup_add
                local -a tok_add
                while true; do
                    read -r -p "Add node host (or done): " line_add < /dev/tty || true
                    line_add="${line_add%$'\r'}"
                    lower_add=$(printf '%s' "$line_add" | tr '[:upper:]' '[:lower:]')
                    lower_add="${lower_add#"${lower_add%%[![:space:]]*}"}"
                    lower_add="${lower_add%"${lower_add##*[![:space:]]}"}"
                    if [ "$lower_add" = "done" ] || [ "$lower_add" = "finished" ]; then
                        break
                    fi
                    if [[ "$lower_add" =~ ^([^[:space:]]+)[[:space:]]+(finished|done)$ ]]; then
                        norm_add=$(normalize_node_address_input "${BASH_REMATCH[1]}")
                        if [ -n "$norm_add" ]; then
                            dup_add=false
                            for hh in "${hosts[@]}"; do
                                if [ "$hh" = "$norm_add" ]; then dup_add=true; break; fi
                            done
                            if [ "$dup_add" != true ]; then
                                hosts+=("$norm_add")
                                print_success "Queued node ${#hosts[@]}: $norm_add"
                            else
                                print_warning "Already in list: $norm_add"
                            fi
                        fi
                        break
                    fi
                    read -r -a tok_add <<< "$line_add"
                    if [ ${#tok_add[@]} -gt 1 ]; then
                        for fl in "${tok_add[@]}"; do
                            [ -z "${fl//[[:space:]]/}" ] && continue
                            lower_add=$(printf '%s' "$fl" | tr '[:upper:]' '[:lower:]')
                            if [ "$lower_add" = "finished" ] || [ "$lower_add" = "done" ]; then
                                break 2
                            fi
                            norm_add=$(normalize_node_address_input "$fl")
                            if [ -z "$norm_add" ]; then
                                print_warning "Skipped empty token"
                                continue
                            fi
                            dup_add=false
                            for hh in "${hosts[@]}"; do
                                if [ "$hh" = "$norm_add" ]; then dup_add=true; break; fi
                            done
                            if [ "$dup_add" = true ]; then
                                print_warning "Already in list: $norm_add"
                                continue
                            fi
                            hosts+=("$norm_add")
                            print_success "Queued node ${#hosts[@]}: $norm_add"
                        done
                        continue
                    fi
                    norm_add=$(normalize_node_address_input "$line_add")
                    if [ -z "$norm_add" ]; then
                        print_warning "Skipped empty line"
                        continue
                    fi
                    dup_add=false
                    for hh in "${hosts[@]}"; do
                        if [ "$hh" = "$norm_add" ]; then
                            dup_add=true
                            break
                        fi
                    done
                    if [ "$dup_add" = true ]; then
                        print_warning "Already in list: $norm_add"
                        continue
                    fi
                    hosts+=("$norm_add")
                    print_success "Queued node ${#hosts[@]}: $norm_add"
                done
                if [ ${#hosts[@]} -eq "$host_count_before" ]; then
                    print_info "No new nodes added."
                    continue
                fi
                hosts_tmp=$(mktemp)
                printf '%s\n' "${hosts[@]}" > "$hosts_tmp"
                if write_mpcgroup0_node_addresses_from_host_lines_file "$config_file" "$hosts_tmp"; then
                    rm -f "$hosts_tmp"
                    mapfile -t hosts < <(extract_ordered_hosts_mpcgroup0 "$config_file" 2>/dev/null || true)
                    print_success "Updated MPCGroups[0].nodeAddresses (${#hosts[@]} nodes)."
                else
                    rm -f "$hosts_tmp"
                    print_error "Failed to update nodeAddresses."
                    return 1
                fi
                ;;
            2)
                if [ ${#hosts[@]} -le 1 ]; then
                    print_warning "Cannot remove the only remaining node. Add another node first, then remove."
                    continue
                fi
                echo ""
                read -r -p "Number(s) to remove (e.g. 2 or 2 3), or 0 to cancel: " line < /dev/tty || true
                line="${line//,/ }"
                if [ -z "${line//[[:space:]]/}" ] || [ "$line" = "0" ]; then
                    continue
                fi
                local -a new_hosts=() remove_idx=()
                local tok err=0
                read -r -a remove_idx <<< "$line"
                for tok in "${remove_idx[@]}"; do
                    if ! [[ "$tok" =~ ^[0-9]+$ ]]; then
                        print_error "Invalid number: $tok"
                        err=1
                        break
                    fi
                    if [ "$tok" -lt 1 ] || [ "$tok" -gt ${#hosts[@]} ]; then
                        print_error "Out of range: $tok (1–${#hosts[@]})"
                        err=1
                        break
                    fi
                done
                if [ "$err" -ne 0 ]; then
                    continue
                fi
                local idx skip
                for idx in $(seq 1 ${#hosts[@]}); do
                    skip=false
                    for tok in "${remove_idx[@]}"; do
                        if [ "$idx" -eq "$tok" ]; then
                            skip=true
                            break
                        fi
                    done
                    if [ "$skip" = false ]; then
                        new_hosts+=("${hosts[$((idx - 1))]}")
                    fi
                done
                if [ ${#new_hosts[@]} -eq 0 ]; then
                    print_error "You must keep at least one node."
                    continue
                fi
                hosts_tmp=$(mktemp)
                printf '%s\n' "${new_hosts[@]}" > "$hosts_tmp"
                if write_mpcgroup0_node_addresses_from_host_lines_file "$config_file" "$hosts_tmp"; then
                    rm -f "$hosts_tmp"
                    mapfile -t hosts < <(extract_ordered_hosts_mpcgroup0 "$config_file" 2>/dev/null || true)
                    print_success "Updated MPCGroups[0].nodeAddresses (${#hosts[@]} nodes)."
                else
                    rm -f "$hosts_tmp"
                    print_error "Failed to update nodeAddresses."
                    return 1
                fi
                ;;
            *)
                print_warning "Invalid choice. Enter 0, 1, or 2."
                ;;
        esac
    done
}

# If first group's nodeAddresses is empty or only the default example URLs, prompt for IPs/hostnames and write http://HOST:MPC_NODE_HTTP_PORT entries.
prompt_fill_empty_node_addresses() {
    local config_file="$1"
    first_mpc_group_node_addresses_empty "$config_file"
    local ec=$?
    if [ "$ec" -eq 1 ]; then
        return 0
    fi
    if [ "$ec" -eq 4 ]; then
        print_error "ruamel.yaml is required to read nodeAddresses from configs.yaml. Install: sudo apt install python3-ruamel.yaml"
        return 1
    fi
    if [ "$ec" -eq 2 ]; then
        print_error "configs.yaml has no MPCGroups (or file is empty). Add at least one group before running this script."
        return 1
    fi
    
    if ! command -v python3 &> /dev/null; then
        print_error "python3 is required to fill empty nodeAddresses. Install python3 or edit configs.yaml manually."
        return 1
    fi
    
    if [ ! -r /dev/tty ]; then
        print_error "MPCGroups[0].nodeAddresses is empty or still the default example IPs (203.0.113.10–12). Edit configs.yaml or run this script in an interactive terminal."
        return 1
    fi
    
    echo ""
    print_step "nodeAddresses is empty — enter each node's public IP or hostname (or documentation examples to replace)"
    print_info "The template ships with an empty nodeAddresses map; add at least one peer before typing finished (first = relay when using a real relay IP)."
    print_info "The first address you enter is the RELAY NODE (runs the MQTT broker). Use the SAME order on every machine's configs.yaml."
    print_info "Port :${MPC_NODE_HTTP_PORT} is added automatically (http://...:${MPC_NODE_HTTP_PORT})."
    print_info "If your API listens on a different port, set MPC_NODE_HTTP_PORT at the top of this script (or edit configs.yaml afterward)."
    print_info "Enter one address per line (or space-separated on one line). When done: finished (or done)"
    print_info "You can also use the same line: 203.0.113.10 finished"
    echo ""
    
    local hosts=()
    local line norm lower h dup fl
    local -a tok
    while true; do
        read -r -p "Node IP or hostname (or 'finished' to save): " line < /dev/tty || true
        line="${line%$'\r'}"
        lower=$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]')
        lower="${lower#"${lower%%[![:space:]]*}"}"
        lower="${lower%"${lower##*[![:space:]]}"}"
        if [ "$lower" = "finished" ] || [ "$lower" = "done" ]; then
            break
        fi
        # Same line: "IP finished" or "host done"
        if [[ "$lower" =~ ^([^[:space:]]+)[[:space:]]+(finished|done)$ ]]; then
            norm=$(normalize_node_address_input "${BASH_REMATCH[1]}")
            if [ -n "$norm" ]; then
                dup=false
                for h in "${hosts[@]}"; do
                    if [ "$h" = "$norm" ]; then dup=true; break; fi
                done
                if [ "$dup" != true ]; then
                    hosts+=("$norm")
                    print_success "Added node ${#hosts[@]}: $norm (will become http://${norm}:${MPC_NODE_HTTP_PORT})"
                else
                    print_warning "Already in list: $norm"
                fi
            fi
            break
        fi
        read -r -a tok <<< "$line"
        if [ ${#tok[@]} -gt 1 ]; then
            for fl in "${tok[@]}"; do
                [ -z "${fl//[[:space:]]/}" ] && continue
                lower=$(printf '%s' "$fl" | tr '[:upper:]' '[:lower:]')
                if [ "$lower" = "finished" ] || [ "$lower" = "done" ]; then
                    break 2
                fi
                norm=$(normalize_node_address_input "$fl")
                if [ -z "$norm" ]; then
                    print_warning "Skipped empty token"
                    continue
                fi
                dup=false
                for h in "${hosts[@]}"; do
                    if [ "$h" = "$norm" ]; then dup=true; break; fi
                done
                if [ "$dup" = true ]; then
                    print_warning "Already in list: $norm"
                    continue
                fi
                hosts+=("$norm")
                print_success "Added node ${#hosts[@]}: $norm (will become http://${norm}:${MPC_NODE_HTTP_PORT})"
            done
            continue
        fi
        norm=$(normalize_node_address_input "$line")
        if [ -z "$norm" ]; then
            print_warning "Skipped empty line"
            continue
        fi
        dup=false
        for h in "${hosts[@]}"; do
            if [ "$h" = "$norm" ]; then
                dup=true
                break
            fi
        done
        if [ "$dup" = true ]; then
            print_warning "Already in list: $norm"
            continue
        fi
        hosts+=("$norm")
        print_success "Added node ${#hosts[@]}: $norm (will become http://${norm}:${MPC_NODE_HTTP_PORT})"
    done
    
    if [ ${#hosts[@]} -eq 0 ]; then
        print_error "No nodes entered. Enter at least one address before typing 'finished'."
        return 1
    fi
    
    local hosts_tmp
    hosts_tmp=$(mktemp)
    printf '%s\n' "${hosts[@]}" > "$hosts_tmp"
    
    if ! write_mpcgroup0_node_addresses_from_host_lines_file "$config_file" "$hosts_tmp"; then
        rm -f "$hosts_tmp"
        print_error "Failed to write nodeAddresses to configs.yaml (python3 / ruamel.yaml error)."
        return 1
    fi
    rm -f "$hosts_tmp"
    
    echo ""
    print_success "Wrote MPCGroups[0].nodeAddresses (${#hosts[@]} nodes, relay = first):"
    local i=0
    for h in "${hosts[@]}"; do
        i=$((i + 1))
        echo "  node${i}_key -> http://${h}:${MPC_NODE_HTTP_PORT}"
    done
    echo ""
    return 0
}

# True if configs.yaml has a valid NodeMgtKey (Ethereum) and/or valid PublicMgtKey (Ed25519 public, 64 hex).
verify_at_least_one_management_key() {
    local config_file="$1"
    if ! command -v python3 &> /dev/null; then
        return 1
    fi
    python3 - "$config_file" << 'PYVERIFY'
import sys, re
try:
    from ruamel.yaml import YAML
except ImportError:
    sys.exit(1)
path = sys.argv[1]
_ry = YAML()
with open(path, "r") as f:
    d = _ry.load(f) or {}
nk = d.get("NodeMgtKey")
pk = d.get("PublicMgtKey")
pk = "" if pk is None else str(pk).strip().strip('"').strip("'")

PLACEHOLDER_ETH = "1234567890abcdef1234567890abcdef12345678"

def eth_body_40(val):
    if val is None:
        return None
    if isinstance(val, int):
        return format(val & ((1 << 160) - 1), "040x").lower()
    s = str(val).strip().strip('"').strip("'")
    if not s:
        return None
    if s.startswith(("0x", "0X")):
        s = s[2:]
    s = re.sub(r"\s+", "", s)
    if not re.fullmatch(r"[0-9a-fA-F]{40}", s, re.I):
        return None
    return s.lower()

def valid_eth(val):
    b = eth_body_40(val)
    if b is None:
        return False
    return b != PLACEHOLDER_ETH

def valid_ed25519_pub(s):
    s = s.strip()
    if s.startswith(("0x", "0X")):
        s = s[2:]
    s = re.sub(r"\s+", "", s)
    if len(s) == 128 and re.fullmatch(r"[0-9a-fA-F]{128}", s):
        return False
    if not re.fullmatch(r"[0-9a-fA-F]{64}", s):
        return False
    try:
        bytes.fromhex(s)
    except ValueError:
        return False
    return True

ok_eth = valid_eth(nk)
ok_pub = valid_ed25519_pub(pk)
sys.exit(0 if (ok_eth or ok_pub) else 1)
PYVERIFY
}

# If PublicMgtKey in configs.yaml is an OpenSSH ssh-ed25519 line, rewrite it as 64 hex (ruamel round-trip).
normalize_openssh_public_mgt_key_in_yaml() {
    local config_file="$1"
    if ! command -v python3 &> /dev/null; then
        return 0
    fi
    local ossh_to_hex="${REPO_ROOT}/tools/openssh_ed25519_to_hex.py"
    if [ ! -f "$ossh_to_hex" ]; then
        ossh_to_hex="${SCRIPT_DIR}/tools/openssh_ed25519_to_hex.py"
    fi
    if [ ! -f "$ossh_to_hex" ]; then
        return 0
    fi
    local conv_msg
    conv_msg=$(
        OPENSSH_HEX_TOOL="$ossh_to_hex" CONFIG_NORM="$config_file" python3 2>&1 << 'PYNORMSSH'
import os
import re
import subprocess
import sys

try:
    from ruamel.yaml import YAML
except ImportError:
    sys.exit(0)

path = os.environ.get("CONFIG_NORM", "")
tool = os.environ.get("OPENSSH_HEX_TOOL", "")
if not path or not tool or not os.path.isfile(tool):
    sys.exit(0)

yaml = YAML()
yaml.preserve_quotes = True
yaml.width = 4096
yaml.indent(mapping=2, sequence=4, offset=2)

with open(path, "r") as f:
    data = yaml.load(f)
if not isinstance(data, dict):
    sys.exit(0)
pk = data.get("PublicMgtKey")
if pk is None:
    sys.exit(0)


def strip_outer_quotes(s: str) -> str:
    s = s.strip()
    while len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        s = s[1:-1].strip()
    return s


raw = strip_outer_quotes(str(pk))
if not raw:
    sys.exit(0)


def is_64_hex_pub(s: str) -> bool:
    t = strip_outer_quotes(s.strip())
    if t.startswith(("0x", "0X")):
        t = t[2:]
    t = re.sub(r"\s+", "", t)
    return bool(re.fullmatch(r"[0-9a-fA-F]{64}", t))


if is_64_hex_pub(raw):
    sys.exit(0)

line = raw.splitlines()[0].strip()
line = strip_outer_quotes(line)
if not line:
    sys.exit(0)
parts = line.split()
strict_openssh = bool(parts) and parts[0] == "ssh-ed25519"

proc = subprocess.run(
    [sys.executable, tool],
    input=line + "\n",
    text=True,
    capture_output=True,
)
if proc.returncode != 0:
    err = (proc.stderr or proc.stdout or "openssh_ed25519_to_hex.py failed").strip()
    if strict_openssh:
        sys.stderr.write(err + "\n")
        sys.exit(1)
    sys.exit(0)
hexout = proc.stdout.strip()
if len(hexout) != 64 or not re.fullmatch(r"[0-9a-f]{64}", hexout, re.I):
    sys.stderr.write("error: OpenSSH converter did not return 64 hex\n")
    sys.exit(1)

data["PublicMgtKey"] = hexout.lower()
with open(path, "w") as f:
    yaml.dump(data, f)
sys.stderr.write(
    "Converted PublicMgtKey from OpenSSH ssh-ed25519 (full line or base64 blob) to 64 hex in configs.yaml.\n"
)
sys.exit(0)
PYNORMSSH
    ) || {
        print_error "$conv_msg"
        return 1
    }
    if [ -n "$conv_msg" ]; then
        print_success "$conv_msg"
    fi
    return 0
}

# When PublicMgtKey is still empty after interactive prompts (or NodeMgtKey-only with skip), generate
# bootstrap_key/ed25519_private.hex + set PublicMgtKey + DeterministicNodeKey (DATABASE_BACKUP_RESTORE_PLAN §8).
# Also used for non-interactive installs (e.g. provision-node.sh): mpc-auth may require PublicMgtKey to derive nodeKey.
maybe_auto_bootstrap_public_mgt_key() {
    local config_file="$1"
    if ! command -v python3 &>/dev/null; then
        print_error "python3 is required to auto-provision PublicMgtKey when it is empty."
        return 1
    fi
    local pk_nonempty
    pk_nonempty=$(CONFIG_FILE_MGT="$config_file" python3 -c "
import os
from ruamel.yaml import YAML
try:
    _ry = YAML()
    with open(os.environ['CONFIG_FILE_MGT']) as f:
        d = _ry.load(f) or {}
    v = d.get('PublicMgtKey')
    v = '' if v is None else str(v).strip().strip('\"').strip(\"'\")
    print('1' if v else '0')
except Exception:
    print('0')
")
    local prov="${REPO_ROOT}/tools/bootstrap_key_provision.py"
    if [ ! -f "$prov" ]; then
        prov="${SCRIPT_DIR}/tools/bootstrap_key_provision.py"
    fi
    if [ ! -f "$prov" ]; then
        print_error "tools/bootstrap_key_provision.py was not found — cannot provision or sync Ed25519 bootstrap / DeterministicNodeKey."
        return 1
    fi
    # Always run bootstrap_key_provision.py: generates bootstrap when PublicMgtKey is empty; when preset (e.g. provision-node.sh
    # --public-mgt-key), syncs DeterministicNodeKey if bootstrap_key/ed25519_private.hex exists and matches PublicMgtKey.
    # PROVISION_DEFER_NODE_KEY_UNTIL_BOOTSTRAP=1 (set by provision-node.sh --public-mgt-key): if seed file is absent, set
    # DeterministicNodeKey true anyway so mpc-auth does not auto-generate a random nodeKey before bootstrap/restore.
    local bs_extra=()
    if [ "${PROVISION_DEFER_NODE_KEY_UNTIL_BOOTSTRAP:-0}" = "1" ]; then
        bs_extra+=(--defer-node-key-until-bootstrap)
    fi
    if [ "$pk_nonempty" = "0" ]; then
        echo ""
        print_step "PublicMgtKey is still empty — generating Ed25519 bootstrap identity (bootstrap_key/ + configs.yaml)"
        print_info "Enables deterministic nodeKey, encrypted DB backups, and POST /fetchBootstrapKey. Back up bootstrap_key/ securely."
    fi
    if ! python3 "$prov" "${bs_extra[@]}" "$config_file"; then
        print_error "bootstrap_key_provision.py failed (install: pip install cryptography 'ruamel.yaml')."
        return 1
    fi
    if [ "$pk_nonempty" = "0" ]; then
        print_success "Bootstrap management key provisioned."
    fi
    return 0
}

# Prompt for NodeMgtKey / PublicMgtKey when empty; require at least one valid key after prompts.
prompt_configure_management_keys() {
    local config_file="$1"
    
    if ! command -v python3 &> /dev/null; then
        print_warning "python3 not found — cannot validate or prompt for management keys; ensure at least one of NodeMgtKey or PublicMgtKey is set in configs.yaml."
        return 0
    fi
    
    if [ ! -r /dev/tty ]; then
        if verify_at_least_one_management_key "$config_file"; then
            maybe_auto_bootstrap_public_mgt_key "$config_file" || return 1
            return 0
        fi
        print_error "At least one of NodeMgtKey or PublicMgtKey must be set. Edit configs.yaml or run this script interactively."
        return 1
    fi

    # Valid key(s) already in configs.yaml (e.g. provision-node.sh) — do not prompt for optional second key.
    if verify_at_least_one_management_key "$config_file"; then
        maybe_auto_bootstrap_public_mgt_key "$config_file" || return 1
        return 0
    fi
    
    local set_node="" set_pub=""
    local nk_empty pk_empty
    nk_empty=$(CONFIG_FILE_MGT="$config_file" PH_ETH="$NODE_MGT_ETH_PLACEHOLDER" python3 -c "
import os, re
from ruamel.yaml import YAML
ph = os.environ.get('PH_ETH', '').strip()
if ph.startswith(('0x', '0X')):
    ph = ph[2:]
ph = ph.lower()

def eth_body_40(val):
    if val is None:
        return None
    if isinstance(val, int):
        h = format(val & ((1 << 160) - 1), '040x')
        return h.lower()
    s = str(val).strip().strip('\"').strip(\"'\")
    if not s:
        return None
    if s.startswith(('0x', '0X')):
        s = s[2:]
    s = re.sub(r'\s+', '', s)
    if not re.fullmatch(r'[0-9a-fA-F]{40}', s, re.I):
        return None
    return s.lower()

_ry = YAML()
with open(os.environ['CONFIG_FILE_MGT']) as f:
    d = _ry.load(f) or {}
v = d.get('NodeMgtKey')
h = eth_body_40(v)
if h is None:
    print('1')
else:
    print('1' if h == ph else '0')
")
    pk_empty=$(CONFIG_FILE_MGT="$config_file" python3 -c "
import os
from ruamel.yaml import YAML
_ry = YAML()
with open(os.environ['CONFIG_FILE_MGT']) as f:
    d = _ry.load(f) or {}
v = d.get('PublicMgtKey')
v = '' if v is None else str(v).strip().strip('\"').strip(\"'\")
print('1' if not v else '0')
")
    
    if [ "$nk_empty" = "1" ]; then
        echo ""
        print_step "NodeMgtKey is missing or still the default example address — optional Ethereum management address"
        print_info "Replace the placeholder with an address you control. It is used with EIP-191 personal_sign from your Ethereum wallet for management API calls."
        print_info "You do not have to set it if you will use Ed25519 management (PublicMgtKey) instead."
        print_info "Press Enter to skip and configure PublicMgtKey only (or add NodeMgtKey later)."
        echo ""
        local eth_in norm_eth
        while true; do
            read -r -p "Ethereum address (0x + 40 hex, or Enter to skip): " eth_in < /dev/tty || true
            eth_in="${eth_in#"${eth_in%%[![:space:]]*}"}"
            eth_in="${eth_in%"${eth_in##*[![:space:]]}"}"
            if [ -z "$eth_in" ]; then
                break
            fi
            norm_eth=$(printf '%s' "$eth_in" | PH_ETH="$NODE_MGT_ETH_PLACEHOLDER" python3 -c "
import sys, re, os
s = sys.stdin.read().strip()
if s.startswith(('0x', '0X')):
    s = s[2:]
if not re.fullmatch(r'[0-9a-fA-F]{40}', s):
    sys.exit(1)
low = s.lower()
ph = os.environ.get('PH_ETH', '').strip()
if ph.startswith(('0x', '0X')):
    ph = ph[2:]
ph = ph.lower()
if low == ph:
    sys.exit(2)
print('0x' + low)
" 2>/dev/null) || {
                ec=$?
                if [ "$ec" -eq 2 ]; then
                    print_error "That address is the default example from configs.yaml — enter your own Ethereum address."
                    continue
                fi
                print_error "Invalid Ethereum address (expected 0x + 40 hex digits, or 40 hex without prefix)."
                continue
            }
            set_node="$norm_eth"
            print_success "NodeMgtKey will be set to: $set_node"
            break
        done
    fi
    
    if [ "$pk_empty" = "1" ]; then
        echo ""
        print_step "PublicMgtKey is empty — optional Ed25519 public key (direct API management)"
        print_info "This lets you manage the node without Ethereum wallet signing (no EIP-191); scripts and AI agents can sign with the matching Ed25519 secret key."
        print_info "You can set both NodeMgtKey and PublicMgtKey, or add PublicMgtKey later in configs.yaml."
        print_info "Enter: (1) 64 hex (32-byte public key), or (2) full OpenSSH line (ssh-ed25519 AAAA... [comment]), or (3) the base64 blob only from that line (no type prefix / comment). Press Enter to skip if you use NodeMgtKey only."
        echo ""
        local pk_in norm_pk ec ossh_to_hex
        ossh_to_hex="${REPO_ROOT}/tools/openssh_ed25519_to_hex.py"
        if [ ! -f "$ossh_to_hex" ]; then
            ossh_to_hex="${SCRIPT_DIR}/tools/openssh_ed25519_to_hex.py"
        fi
        while true; do
            read -r -p "Ed25519 public key (64 hex, ssh-ed25519 line, or base64 blob, or Enter to skip): " pk_in < /dev/tty || true
            pk_in="${pk_in#"${pk_in%%[![:space:]]*}"}"
            pk_in="${pk_in%"${pk_in##*[![:space:]]}"}"
            if [ -z "$pk_in" ]; then
                break
            fi
            ec=0
            norm_pk=""
            # OpenSSH full line or base64-only middle field -> 64 hex (tools/openssh_ed25519_to_hex.py).
            if [ -f "$ossh_to_hex" ]; then
                norm_pk=$(printf '%s\n' "$pk_in" | python3 "$ossh_to_hex" 2>/dev/null) || ec=$?
                if [ "$ec" -eq 0 ] && [ -n "$norm_pk" ]; then
                    set_pub="$norm_pk"
                    print_success "PublicMgtKey will be set from OpenSSH / base64 input (64 hex, no 0x prefix in file)."
                    break
                fi
            fi
            ec=0
            norm_pk=$(printf '%s' "$pk_in" | python3 -c "
import sys, re
s = sys.stdin.read().strip()
if s.startswith(('0x', '0X')):
    s = s[2:]
s = re.sub(r'\s+', '', s)
if len(s) == 128 and re.fullmatch(r'[0-9a-fA-F]{128}', s):
    sys.exit(2)
if not re.fullmatch(r'[0-9a-fA-F]{64}', s):
    sys.exit(1)
try:
    bytes.fromhex(s)
except ValueError:
    sys.exit(1)
print(s.lower())
" 2>/dev/null) || ec=$?
            if [ "$ec" -eq 2 ]; then
                print_warning "That looks like a 128-hex Ed25519 *private* key (or seed+key material). Enter the *public* key only (64 hex), or an ssh-ed25519 line / base64 blob from the .pub file."
                continue
            fi
            if [ "$ec" -ne 0 ] || [ -z "$norm_pk" ]; then
                print_error "Invalid input: use 64 hex (public key), or ssh-ed25519 <base64> [comment], or the base64 key blob alone (tools/openssh_ed25519_to_hex.py)."
                continue
            fi
            set_pub="$norm_pk"
            print_success "PublicMgtKey will be set (64 hex, no 0x prefix in file)."
            break
        done
    fi
    
    if [ "$nk_empty" = "1" ] || [ -n "$set_node" ] || [ -n "$set_pub" ]; then
        require_ruamel_yaml || return 1
        CONFIG_FILE_MGT_MERGE="$config_file" MGT_NODE_VAL="${set_node:-}" MGT_PUB_VAL="${set_pub:-}" python3 << 'PYMGT'
import os
import re
import sys
try:
    from ruamel.yaml import YAML
except ImportError:
    sys.stderr.write("configs.yaml: install ruamel.yaml (pip install --user 'ruamel.yaml')\n")
    sys.exit(1)

path = os.environ["CONFIG_FILE_MGT_MERGE"]
node_v = (os.environ.get("MGT_NODE_VAL") or "").strip()
pub_v = (os.environ.get("MGT_PUB_VAL") or "").strip()
PLACEHOLDER_BODY = "1234567890abcdef1234567890abcdef12345678"

def eth_body_40(val):
    if val is None:
        return None
    if isinstance(val, int):
        return format(val & ((1 << 160) - 1), "040x").lower()
    s = str(val).strip().strip('"').strip("'")
    if not s:
        return None
    if s.startswith(("0x", "0X")):
        s = s[2:]
    s = re.sub(r"\s+", "", s)
    if not re.fullmatch(r"[0-9a-fA-F]{40}", s, re.I):
        return None
    return s.lower()

def is_placeholder_nk(val):
    b = eth_body_40(val)
    return b is not None and b == PLACEHOLDER_BODY

yaml = YAML()
yaml.preserve_quotes = True
yaml.width = 4096
yaml.indent(mapping=2, sequence=4, offset=2)

with open(path, "r") as f:
    data = yaml.load(f)
if not isinstance(data, dict):
    raise SystemExit("invalid yaml root")
if node_v:
    data["NodeMgtKey"] = node_v
elif is_placeholder_nk(data.get("NodeMgtKey")):
    data["NodeMgtKey"] = ""
if pub_v:
    data["PublicMgtKey"] = pub_v
with open(path, "w") as f:
    yaml.dump(data, f)
PYMGT
        print_success "Updated configs.yaml (management keys; comments preserved)."
        echo ""
    fi

    maybe_auto_bootstrap_public_mgt_key "$config_file" || return 1
    
    if ! verify_at_least_one_management_key "$config_file"; then
        print_error "You must configure at least one of: NodeMgtKey (valid Ethereum address) or PublicMgtKey (valid Ed25519 public key: 64 hex, ssh-ed25519 line, or OpenSSH base64 blob)."
        return 1
    fi
    return 0
}

# Get first node address from config (relay node = runs mosquitto when host is not NODE_ADDRESSES_RELAY_PLACEHOLDER_IPV4).
# All nodes must list nodeAddresses in the SAME order; the first entry is the relay node (or 0.0.0.0 = placeholder / client path until set).
get_first_node_address() {
    local config_file="$1"
    
    if [ ! -f "$config_file" ]; then
        return 1
    fi
    
    # Use yq if available (to_entries preserves document order in yq 4.x)
    if command -v yq &> /dev/null; then
        local first_addr=$(yq eval '.MPCGroups[0].nodeAddresses | to_entries | .[0].value' "$config_file" 2>/dev/null)
        if [ -n "$first_addr" ] && [ "$first_addr" != "null" ]; then
            echo "$first_addr"
            return 0
        fi
    fi
    
    # Use Python if available (good fallback)
    if command -v python3 &> /dev/null; then
        local first_addr=$(python3 -c "
import sys
try:
    from ruamel.yaml import YAML
except ImportError:
    sys.exit(1)
try:
    _ry = YAML()
    with open('$config_file', 'r') as f:
        data = _ry.load(f) or {}
    groups = data.get('MPCGroups', [])
    if groups:
        node_addresses = groups[0].get('nodeAddresses', {})
        if node_addresses:
            first_value = next(iter(node_addresses.values()))
            if first_value:
                print(first_value)
except Exception:
    sys.exit(1)
" 2>/dev/null)
        if [ -n "$first_addr" ]; then
            echo "$first_addr"
            return 0
        fi
    fi
    
    # Fallback: simple parsing
    local in_first_group=false
    local in_node_addresses=false
    local found_first=false
    
    while IFS= read -r line; do
        if echo "$line" | grep -qE '^\s*MPCGroups:'; then
            in_first_group=true
            continue
        fi
        
        if [ "$in_first_group" = true ] && echo "$line" | grep -qE '^\s*nodeAddresses:'; then
            in_node_addresses=true
            continue
        fi
        
        if [ "$in_node_addresses" = true ] && [ "$found_first" != true ] && echo "$line" | grep -qE 'http://|https://'; then
            local url=$(echo "$line" | sed -E 's/.*["'\'']([^"'\'']*http[^"'\'']*)["'\''].*/\1/' | grep -oE 'https?://[^"'\'' ]+')
            if [ -n "$url" ]; then
                echo "$url"
                return 0
            fi
        fi
        
        # Stop at next top-level key or next group
        if [ "$in_first_group" = true ] && echo "$line" | grep -qE '^\s*- ' && [ "$in_node_addresses" = true ]; then
            break
        fi
    done < "$config_file"
    
    return 1
}

# True if the first URL in MPCGroups[0].nodeAddresses uses NODE_ADDRESSES_RELAY_PLACEHOLDER_IPV4 as host (relay IP deferred).
first_node_address_is_relay_placeholder() {
    local config_file="$1"
    local first_url first_host
    first_url=$(get_first_node_address "$config_file" 2>/dev/null) || true
    if [ -z "$first_url" ] || [ "$first_url" = "null" ]; then
        return 1
    fi
    first_host=$(extract_host_from_url "$first_url")
    [ "$first_host" = "$NODE_ADDRESSES_RELAY_PLACEHOLDER_IPV4" ]
}

# Validate node IP against config
validate_node_ip() {
    local config_file="$1"
    
    if [ ! -f "$config_file" ]; then
        print_warning "Could not find configs.yaml - skipping IP validation" >&2
        print_info "Expected locations: console/configs.yaml or configs.yaml" >&2
        echo "false"
        return 0
    fi
    
    print_step "Validating node IP against MPC group configuration..." >&2
    
    # Get all node addresses from config
    local node_addresses=()
    while IFS= read -r addr; do
        [ -n "$addr" ] && node_addresses+=("$addr")
    done < <(parse_node_addresses_from_yaml "$config_file")
    
    if [ ${#node_addresses[@]} -eq 0 ]; then
        print_warning "No node addresses found in configs.yaml - skipping IP validation" >&2
        echo "false"
        return 0
    fi
    
    # Get first node address
    local first_node_addr=$(get_first_node_address "$config_file")
    local first_node_ip=""
    if [ -n "$first_node_addr" ]; then
        first_node_ip=$(extract_ip_from_url "$first_node_addr")
    fi

    local relay_placeholder_first=false
    if [ "$first_node_ip" = "$NODE_ADDRESSES_RELAY_PLACEHOLDER_IPV4" ]; then
        relay_placeholder_first=true
    fi
    
    # Get local IPs
    local local_ips=()
    while IFS= read -r ip; do
        [ -n "$ip" ] && local_ips+=("$ip")
    done < <(get_local_ips)
    
    if [ ${#local_ips[@]} -eq 0 ]; then
        print_warning "Could not determine local IP addresses - skipping validation" >&2
        echo "false"
        return 0
    fi
    
    # Check if any local IP matches any node address (this machine must be listed as a peer; relay placeholder first slot is OK)
    local found_match=false
    local matched_node_ip=""
    
    for local_ip in "${local_ips[@]}"; do
        for node_addr in "${node_addresses[@]}"; do
            local node_ip=$(extract_ip_from_url "$node_addr")
            if ip_matches "$local_ip" "$node_ip"; then
                found_match=true
                matched_node_ip="$node_ip"
                break 2
            fi
        done
    done

    # Behind NAT, nodeAddresses usually list the router's public IP while hostname -I is private — retry with HTTP "what is my IP".
    if [ "$found_match" != true ]; then
        local ext_ip
        ext_ip=$(get_external_ipv4_via_http) || true
        if [ -n "$ext_ip" ]; then
            print_info "No match on local interface addresses; trying public IP from HTTPS lookup: $ext_ip" >&2
            for node_addr in "${node_addresses[@]}"; do
                local node_ip=$(extract_ip_from_url "$node_addr")
                if ip_matches "$ext_ip" "$node_ip"; then
                    found_match=true
                    matched_node_ip="$node_ip"
                    local_ips+=("$ext_ip")
                    break
                fi
            done
        fi
    fi
    
    if [ "$found_match" != true ]; then
        print_error "Current node IP address is NOT in the MPC group nodeAddresses list"
        echo ""
        print_info "Local IP addresses detected:"
        printf '  - %s\n' "${local_ips[@]}"
        echo ""
        print_info "Node addresses in configs.yaml:"
        printf '  - %s\n' "${node_addresses[@]}"
        echo ""
        print_error "Certificate generation aborted."
        print_info "This script should only be run on a node that is part of the MPC group."
        print_info "Please ensure:"
        echo "  1. You are running this on a node listed in configs.yaml nodeAddresses"
        echo "  2. The node's public IP or hostname matches one of the entries (any position; first may be ${NODE_ADDRESSES_RELAY_PLACEHOLDER_IPV4} until the relay is set). Behind NAT, entries should be the external address; the script uses HTTPS (ipinfo.io/ip and fallbacks) when local interfaces do not match."
        echo "  3. Outbound HTTPS must be allowed for that lookup unless nodeAddresses use hostnames that resolve from this host; air-gapped: SKIP_EXTERNAL_IP_LOOKUP=1 and use resolvable hostnames."
        exit 1
    fi
    print_success "Node IP validation passed" >&2
    if [ "$relay_placeholder_first" = true ]; then
        print_info "First nodeAddresses host is ${NODE_ADDRESSES_RELAY_PLACEHOLDER_IPV4} (relay placeholder); this machine matched as a peer (${matched_node_ip:-non-first entry}) — client node path until the real relay IP is first." >&2
    fi
    
    # Debug output (to stderr so it's not captured by command substitution)
    echo "ℹ Debug: First node IP from config: ${first_node_ip:-<not found>}" >&2
    echo "ℹ Debug: Local IPs detected: ${local_ips[*]}" >&2
    
    # Check if it's the first node (relay node) and return result
    local is_first=false
    if [ "$relay_placeholder_first" = true ]; then
        is_first=false
    elif [ -n "$first_node_ip" ]; then
        for local_ip in "${local_ips[@]}"; do
            if ip_matches "$local_ip" "$first_node_ip"; then
                is_first=true
                echo "ℹ Debug: Matched local IP $local_ip with first node IP $first_node_ip" >&2
                break
            fi
        done
        if [ "$is_first" != true ]; then
            echo "ℹ Debug: Local IPs (${local_ips[*]}) do not match first node IP ($first_node_ip)" >&2
        fi
    else
        echo "⚠ Debug: Could not determine first node IP from config" >&2
    fi
    
    # Return whether this is the first node (relay node)
    if [ "$is_first" = true ]; then
        echo "true"
    else
        echo "false"
    fi
}

# Check if CAFile is configured correctly for client nodes
validate_client_cafile() {
    local config_file="$1"
    local expected_ca_path="$2"
    
    if [ ! -f "$config_file" ]; then
        return 1
    fi
    
    # Get CAFile from config
    local cafile=""
    
    # Use yq if available
    if command -v yq &> /dev/null; then
        cafile=$(yq eval '.MQTTTLS.CAFile' "$config_file" 2>/dev/null)
        if [ "$cafile" = "null" ] || [ -z "$cafile" ]; then
            cafile=""
        fi
    elif command -v python3 &> /dev/null; then
        cafile=$(python3 -c "
import sys
try:
    from ruamel.yaml import YAML
except ImportError:
    sys.exit(1)
try:
    _ry = YAML()
    with open('$config_file', 'r') as f:
        data = _ry.load(f) or {}
    mqtt_tls = data.get('MQTTTLS', {})
    cafile = mqtt_tls.get('CAFile', '')
    if cafile:
        print(cafile)
except Exception:
    sys.exit(1)
" 2>/dev/null)
    else
        # Fallback: simple grep
        cafile=$(grep -E '^\s*CAFile:' "$config_file" 2>/dev/null | head -1 | sed -E 's/^\s*CAFile:\s*["'\'']?([^"'\'']*)["'\'']?.*/\1/' | xargs)
    fi
    
    # Check if CAFile is set
    if [ -z "$cafile" ]; then
        return 1  # Not configured
    fi
    
    # Check if the file exists
    if [ ! -f "$cafile" ]; then
        return 2  # Configured but file doesn't exist
    fi
    
    # If expected path provided, check if it matches
    if [ -n "$expected_ca_path" ]; then
        # Normalize paths for comparison
        local normalized_cafile=$(readlink -f "$cafile" 2>/dev/null || echo "$cafile")
        local normalized_expected=$(readlink -f "$expected_ca_path" 2>/dev/null || echo "$expected_ca_path")
        
        if [ "$normalized_cafile" != "$normalized_expected" ]; then
            return 3  # Configured but path doesn't match expected
        fi
    fi
    
    # Validate it's a valid certificate
    if command -v openssl &> /dev/null; then
        if ! openssl x509 -in "$cafile" -noout -text >/dev/null 2>&1; then
            return 4  # File exists but is not a valid certificate
        fi
    fi
    
    return 0  # All good
}

# Check if running as root (usually not needed)
check_root() {
    if [ "$EUID" -eq 0 ]; then
        print_warning "Running as root — a normal user with sudo is usually enough; the script invokes sudo for UFW (unless --no-firewall) and some paths."
        print_info "Running the entire script as root is only needed in constrained environments."
        if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
            print_info "Repo-local outputs (configs.yaml, certs, docker-compose.yml, .env, bootstrap_key/) owned by root will be reassigned to ${SUDO_USER} when you finish successfully."
        fi
        case "${PROCESS_CONFIG_NONINTERACTIVE:-0}" in
            1|true|TRUE|yes|YES)
                print_info "PROCESS_CONFIG_NONINTERACTIVE: continuing as root."
                return 0
                ;;
        esac
        if [ ! -t 0 ] && [ ! -r /dev/tty ]; then
            print_info "No TTY: continuing as root."
            return 0
        fi
        local continue_root=""
        if [ -r /dev/tty ] && [ -w /dev/tty ]; then
            read -r -p "Continue anyway? (yes/no): " continue_root < /dev/tty || true
        else
            read -r -p "Continue anyway? (yes/no): " continue_root || true
        fi
        if [ "$continue_root" != "yes" ] && [ "$continue_root" != "y" ]; then
            print_info "Exiting. Please run as a regular user if you own the mosquitto/config directory"
            exit 0
        fi
    fi
}
# Check if user has sudo access (UFW by default, TLS dirs under root-owned paths, optional systemd helpers).
check_sudo_access() {
    # If running as root, sudo is not needed
    if [ "$EUID" -eq 0 ]; then
        return 0
    fi
    
    # Check if sudo command exists
    if ! command -v sudo &> /dev/null; then
        print_error "sudo command not found"
        print_error "This script uses sudo for the host firewall (UFW) by default and sometimes for TLS directories."
        echo ""
        print_info "Please install sudo or run this script as root. Use --no-firewall if you manage the host firewall yourself."
        echo ""
        print_info "To install sudo:"
        echo "  Ubuntu/Debian: sudo is usually pre-installed"
        echo "  If missing: apt-get install sudo"
        echo "  Then add your user to sudoers: usermod -aG sudo \$USER"
        exit 1
    fi
    
    # Test if user can use sudo (without password prompt if NOPASSWD is configured, or with prompt)
    # Use a simple command that requires sudo and doesn't change anything
    if ! sudo -n true 2>/dev/null && ! sudo -v 2>/dev/null; then
        print_error "Cannot use sudo - access denied or password required"
        print_error "This script uses sudo for UFW (unless --no-firewall) and for paths that are not user-writable."
        echo ""
        print_info "Please ensure:"
        echo "  1. Your user has sudo privileges"
        echo "  2. You can run 'sudo -v' successfully"
        echo "  3. Or run this script as root"
        echo ""
        print_info "To skip the UFW step (not recommended for production):  $0 --no-firewall"
        echo ""
        print_info "To check sudo access, try: sudo whoami"
        print_info "If prompted for a password, enter it when the script requests sudo access."
        exit 1
    fi
    
    # If we get here, sudo is available and working
    return 0
}

# Run check_sudo_access at most once per invocation (UFW, cert dirs, etc.).
_PROCESS_CONFIG_SUDO_VERIFIED=0
require_sudo_capable() {
    if [ "$EUID" -eq 0 ] || [ "$_PROCESS_CONFIG_SUDO_VERIFIED" = "1" ]; then
        return 0
    fi
    check_sudo_access
    _PROCESS_CONFIG_SUDO_VERIFIED=1
}

# Check if certificate directory exists and is writable (call only when generating MQTT TLS certs).
check_cert_dir() {
    local _cert_parent
    _cert_parent=$(dirname "$CERT_DIR")
    if [ "$EUID" -ne 0 ]; then
        if { [ -d "$CERT_DIR" ] && [ ! -w "$CERT_DIR" ]; } || { [ ! -d "$CERT_DIR" ] && [ ! -w "$_cert_parent" ]; }; then
            require_sudo_capable
        fi
    fi
    if [ ! -d "$_cert_parent" ]; then
        print_error "Certificate directory parent does not exist: $_cert_parent"
        exit 1
    fi

    if [ ! -d "$CERT_DIR" ]; then
        print_info "Creating certificate directory: $CERT_DIR"
        if ! mkdir -p "$CERT_DIR" 2>/dev/null; then
            print_error "Failed to create certificate directory: $CERT_DIR"
            echo ""
            print_info "If the directory is owned by another user (e.g., mosquitto service user),"
            echo "you may need to:"
            echo "  - Run with sudo: sudo ./process_config.sh"
            echo "  - Or change ownership: sudo chown -R \$USER:\$USER $_cert_parent"
            exit 1
        fi
        print_success "Certificate directory created"
    else
        print_success "Certificate directory exists: $CERT_DIR"
    fi

    # Check if directory is writable
    if [ ! -w "$CERT_DIR" ]; then
        print_error "Certificate directory is not writable: $CERT_DIR"
        echo ""
        print_info "Troubleshooting:"
        echo "  - Check ownership: ls -ld $CERT_DIR"
        echo "  - If owned by another user (e.g., mosquitto), you may need:"
        echo "    sudo chown -R \$USER:\$USER $CERT_DIR"
        echo "  - Or run with sudo: sudo ./process_config.sh"
        echo "  - After generating, ensure mosquitto can read the files:"
        echo "    sudo chown -R mosquitto:mosquitto $CERT_DIR  # if mosquitto runs as 'mosquitto' user"
        exit 1
    fi
    
    # Check directory ownership
    DIR_OWNER=$(stat -c '%U' "$CERT_DIR" 2>/dev/null || stat -f '%Su' "$CERT_DIR" 2>/dev/null)
    CURRENT_USER="$PROCESS_CONFIG_REPO_OWNER"
    if [ "$DIR_OWNER" != "$CURRENT_USER" ] && [ "$EUID" -ne 0 ]; then
        print_warning "Directory is owned by '$DIR_OWNER' but you are '$CURRENT_USER'"
        print_info "Files will be owned by you. If mosquitto runs as '$DIR_OWNER', you may need to:"
        echo "  sudo chown -R $DIR_OWNER:$DIR_OWNER $CERT_DIR"
    fi
}

# Mosquitto/MQTT broker TLS only (under mosquitto/config/certs). Returns 0 = generate/regenerate, 1 = keep existing.
# By default, if any of the MQTT TLS files already exist, skips generation (no overwrite) so protected/root-owned
# certs do not cause openssl failures. Use FORCE_REGENERATE_MQTT_CERTS=1 or --force-mqtt-certs to prompt for overwrite.
confirm_overwrite_mqtt_certs() {
    if [ ! -f "$CA_KEY" ] && [ ! -f "$CA_CRT" ] && [ ! -f "$SERVER_KEY" ] && [ ! -f "$SERVER_CRT" ]; then
        return 0
    fi
    print_info "Some Mosquitto (MQTT TLS) broker certificate files already exist (MQTT broker, e.g. port 8883 — not Browser HTTPS / webTLS):"
    [ -f "$CA_KEY" ] && echo "  - $CA_KEY"
    [ -f "$CA_CRT" ] && echo "  - $CA_CRT"
    [ -f "$SERVER_KEY" ] && echo "  - $SERVER_KEY"
    [ -f "$SERVER_CRT" ] && echo "  - $SERVER_CRT"
    echo ""
    if [ "${FORCE_REGENERATE_MQTT_CERTS:-0}" != "1" ]; then
        print_info "Leaving existing Mosquitto (MQTT TLS) files unchanged (not overwriting)."
        print_info "To replace them: remove the files above, run as a user that can write $CERT_DIR, or set FORCE_REGENERATE_MQTT_CERTS=1 / use --force-mqtt-certs (you will be asked to confirm)."
        return 1
    fi
    print_warning "Regeneration requested — existing Mosquitto (MQTT) TLS files will be replaced if you confirm."
    local overwrite=""
    case "${PROCESS_CONFIG_NONINTERACTIVE:-0}" in
        1|true|TRUE|yes|YES)
            overwrite="yes"
            print_info "PROCESS_CONFIG_NONINTERACTIVE: confirming Mosquitto TLS overwrite."
            ;;
        *)
            read -r -p "Overwrite these Mosquitto (MQTT) TLS files? (yes/no): " overwrite
            ;;
    esac
    if [ "$overwrite" != "yes" ] && [ "$overwrite" != "y" ]; then
        return 1
    fi
    print_info "Will overwrite existing Mosquitto (MQTT TLS) certificates"
    return 0
}

# After relay has a CA (new or existing): SSH copy or manual instructions.
relay_mqtt_ca_copy_or_manual_instructions() {
    local config_file="$1"
    if [ "$COPY_CERTS" != "true" ]; then
        echo ""
        print_info "Skipping automatic MQTT CA copy to clients (default; use --copy-certs to enable SSH copy)"
        
        local cafile=""
        if command -v yq &> /dev/null; then
            cafile=$(yq eval '.MQTTTLS.CAFile' "$config_file" 2>/dev/null)
            if [ "$cafile" = "null" ] || [ -z "$cafile" ]; then
                cafile=""
            fi
        elif command -v python3 &> /dev/null; then
            cafile=$(python3 -c "
import sys
try:
    from ruamel.yaml import YAML
except ImportError:
    sys.exit(1)
try:
    _ry = YAML()
    with open('$config_file', 'r') as f:
        data = _ry.load(f) or {}
    mqtt_tls = data.get('MQTTTLS', {})
    cafile = mqtt_tls.get('CAFile', '')
    if cafile:
        print(cafile)
except Exception:
    sys.exit(1)
" 2>/dev/null)
        fi
        
        if [ -n "$cafile" ] && [ "$cafile" != "" ]; then
            echo ""
            print_warning "MANUAL MQTT CA DISTRIBUTION"
            echo ""
            print_info "Automatic copy is off (default unless --copy-certs) and CAFile is configured; manually copy"
            print_info "the Mosquitto CA certificate to each client node in your MPC group."
            echo ""
            print_info "Steps to copy certificate to each client node:"
            echo ""
            echo "  1. Get the CA certificate file:"
            echo "     Location: $CA_CRT"
            echo ""
            echo "  2. Copy to each client node using one of these methods:"
            echo ""
            echo "     Method A - Using SCP:"
            echo "       scp $CA_CRT user@client-node-ip:/mosquitto/config/certs/ca.crt"
            echo ""
            echo "     Method B - Using rsync:"
            echo "       rsync -avz $CA_CRT user@client-node-ip:/mosquitto/config/certs/ca.crt"
            echo ""
            echo "     Method C - Manual transfer:"
            echo "       - Transfer the file securely to each client node operator"
            echo "       - Each operator copies it to: /mosquitto/config/certs/ca.crt"
            echo ""
            echo "  3. On each client node, ensure configs.yaml has:"
            echo "     MQTTTLS:"
            echo "       CAFile: \"/mosquitto/config/certs/ca.crt\""
            echo "     (or the path where the certificate was placed)"
            echo ""
            echo "  4. Verify file permissions on each client node:"
            echo "     chmod 644 /mosquitto/config/certs/ca.crt"
            echo ""
            print_info "MQTT CA file to share: $CA_CRT"
        else
            print_info "To manually copy the MQTT CA:"
            echo "  scp $CA_CRT user@node-ip:/mosquitto/config/certs/ca.crt"
        fi
    else
        echo ""
        copy_certs_to_nodes "$config_file" "$CA_CRT"
    fi
}

# Generate CA private key
generate_ca_key() {
    print_step "Generating Mosquitto (MQTT) CA private key..."
    if openssl genrsa -out "$CA_KEY" 2048 2>/dev/null; then
        print_success "CA private key generated: $CA_KEY"
        # Verify key was created
        if [ ! -f "$CA_KEY" ]; then
            print_error "CA private key file was not created"
            exit 1
        fi
        # Check key size
        KEY_SIZE=$(openssl rsa -in "$CA_KEY" -noout -text 2>/dev/null | grep "Private-Key:" | awk '{print $2}')
        if [ "$KEY_SIZE" != "(2048" ]; then
            print_warning "CA key size is not 2048 bits (got: $KEY_SIZE)"
        fi
    else
        print_error "Failed to generate CA private key"
        exit 1
    fi
}

# Generate CA certificate
generate_ca_cert() {
    print_step "Generating Mosquitto (MQTT) CA certificate..."
    if openssl req -new -x509 -days "$CERT_VALIDITY_DAYS" \
        -key "$CA_KEY" \
        -out "$CA_CRT" \
        -subj "/CN=MQTT-CA/O=Distributed-Auth/C=US" 2>/dev/null; then
        print_success "CA certificate generated: $CA_CRT"
        # Verify certificate
        if [ ! -f "$CA_CRT" ]; then
            print_error "CA certificate file was not created"
            exit 1
        fi
        # Validate certificate
        if openssl x509 -in "$CA_CRT" -noout -text >/dev/null 2>&1; then
            print_success "CA certificate is valid"
            CA_SUBJECT=$(openssl x509 -in "$CA_CRT" -noout -subject 2>/dev/null)
            print_info "CA Subject: $CA_SUBJECT"
        else
            print_error "Generated CA certificate is invalid"
            exit 1
        fi
    else
        print_error "Failed to generate CA certificate"
        exit 1
    fi
}

# Generate server private key
generate_server_key() {
    print_step "Generating Mosquitto broker TLS server private key..."
    if openssl genrsa -out "$SERVER_KEY" 2048 2>/dev/null; then
        print_success "Server private key generated: $SERVER_KEY"
        # Verify key was created
        if [ ! -f "$SERVER_KEY" ]; then
            print_error "Server private key file was not created"
            exit 1
        fi
    else
        print_error "Failed to generate server private key"
        exit 1
    fi
}

# Generate server certificate signing request
generate_server_csr() {
    print_step "Generating Mosquitto broker TLS certificate signing request..."
    if openssl req -new \
        -key "$SERVER_KEY" \
        -out "$SERVER_CSR" \
        -subj "/CN=mosquitto/O=Distributed-Auth/C=US" 2>/dev/null; then
        print_success "Server CSR generated: $SERVER_CSR"
        # Verify CSR was created
        if [ ! -f "$SERVER_CSR" ]; then
            print_error "Server CSR file was not created"
            exit 1
        fi
    else
        print_error "Failed to generate server CSR"
        exit 1
    fi
}

# Sign server certificate with CA
# Accepts optional config_file parameter to extract IP address for SANs
sign_server_cert() {
    local config_file="${1:-}"
    local server_ip=""
    local openssl_config=""
    
    # Extract IP address from config file if provided
    if [ -n "$config_file" ] && [ -f "$config_file" ]; then
        local first_addr=$(get_first_node_address "$config_file")
        if [ -n "$first_addr" ] && [ "$first_addr" != "null" ]; then
            server_ip=$(extract_ip_from_url "$first_addr")
            if [ "$server_ip" = "$NODE_ADDRESSES_RELAY_PLACEHOLDER_IPV4" ]; then
                server_ip=""
            fi
            if [ -n "$server_ip" ]; then
                print_info "Extracted broker IP address from config: $server_ip"
            fi
        fi
    fi
    
    print_step "Signing Mosquitto broker TLS server certificate with CA..."
    
    # Create temporary OpenSSL config file with SANs if IP is available
    if [ -n "$server_ip" ]; then
        openssl_config=$(mktemp)
        cat > "$openssl_config" <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req

[req_distinguished_name]

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
IP.1 = $server_ip
DNS.1 = mosquitto
EOF
        print_info "Including IP address $server_ip and DNS mosquitto in certificate SANs"
    fi
    
    # Sign certificate with or without SANs
    if [ -n "$openssl_config" ]; then
        # Sign with SANs
        if openssl x509 -req \
            -in "$SERVER_CSR" \
            -CA "$CA_CRT" \
            -CAkey "$CA_KEY" \
            -CAcreateserial \
            -out "$SERVER_CRT" \
            -days "$CERT_VALIDITY_DAYS" \
            -extensions v3_req \
            -extfile "$openssl_config" 2>/dev/null; then
            rm -f "$openssl_config"
            print_success "Server certificate signed with IP SAN: $SERVER_CRT"
        else
            rm -f "$openssl_config"
            print_error "Failed to sign server certificate"
            exit 1
        fi
    else
        # Sign without SANs (fallback)
    if openssl x509 -req \
        -in "$SERVER_CSR" \
        -CA "$CA_CRT" \
        -CAkey "$CA_KEY" \
        -CAcreateserial \
        -out "$SERVER_CRT" \
        -days "$CERT_VALIDITY_DAYS" 2>/dev/null; then
        print_success "Server certificate signed: $SERVER_CRT"
            print_warning "No IP address found in config - certificate will not validate IP connections"
        else
            print_error "Failed to sign server certificate"
            exit 1
        fi
    fi
    
        # Verify certificate was created
        if [ ! -f "$SERVER_CRT" ]; then
            print_error "Server certificate file was not created"
            exit 1
        fi
    
        # Validate certificate
        if openssl x509 -in "$SERVER_CRT" -noout -text >/dev/null 2>&1; then
            print_success "Server certificate is valid"
            SERVER_SUBJECT=$(openssl x509 -in "$SERVER_CRT" -noout -subject 2>/dev/null)
            print_info "Server Subject: $SERVER_SUBJECT"
        
        # Display SANs if present
        local sans=$(openssl x509 -in "$SERVER_CRT" -noout -text 2>/dev/null | grep -A1 "Subject Alternative Name" || true)
        if [ -n "$sans" ]; then
            print_info "Certificate SANs:"
            echo "$sans" | sed 's/^/  /'
        fi
        
            # Verify certificate is signed by CA
            if openssl verify -CAfile "$CA_CRT" "$SERVER_CRT" >/dev/null 2>&1; then
                print_success "Server certificate is properly signed by CA"
            else
                print_error "Server certificate verification failed"
                exit 1
            fi
        else
            print_error "Generated server certificate is invalid"
        exit 1
    fi
}

# Set proper permissions
set_permissions() {
    print_step "Setting certificate file permissions..."
    # CA key should be readable only by owner
    chmod 600 "$CA_KEY" 2>/dev/null || print_warning "Could not set permissions on $CA_KEY"
    # Server key should be readable only by owner
    chmod 600 "$SERVER_KEY" 2>/dev/null || print_warning "Could not set permissions on $SERVER_KEY"
    # Certificates can be readable by all (they're public)
    chmod 644 "$CA_CRT" 2>/dev/null || print_warning "Could not set permissions on $CA_CRT"
    chmod 644 "$SERVER_CRT" 2>/dev/null || print_warning "Could not set permissions on $SERVER_CRT"
    # Remove CSR (not needed after signing)
    rm -f "$SERVER_CSR" 2>/dev/null
    print_success "File permissions set"
}

# Display summary and next steps
display_summary() {
    echo ""
    print_success "Certificate generation completed successfully!"
    echo ""
    echo "Generated files:"
    echo "  - CA Certificate:     $CA_CRT"
    echo "  - CA Private Key:      $CA_KEY"
    echo "  - Server Certificate: $SERVER_CRT"
    echo "  - Server Private Key: $SERVER_KEY"
    echo ""
    print_info "Next steps:"
    echo "  1. Verify mosquitto.conf is configured to use these certificates:"
    echo "     - cafile $CA_CRT"
    echo "     - certfile $SERVER_CRT"
    echo "     - keyfile $SERVER_KEY"
    echo ""
    echo "  2. Share the CA certificate ($CA_CRT) with all nodes in your MPC group"
    echo "     Each node needs to set MQTTTLS.CAFile in configs.yaml to:"
    echo "     CAFile: \"$CA_CRT\""
    echo ""
    echo "  3. Update broker URLs in node configurations to use TLS:"
    echo "     Change from: tcp://broker-ip:1883"
    echo "     Change to:   ssl://broker-ip:8883  (or tls://broker-ip:8883)"
    echo ""
    echo "  4. Ensure mosquitto can read the certificate files:"
    echo "     If mosquitto runs as a different user (e.g., 'mosquitto' user), you may need:"
    echo "     sudo chown -R mosquitto:mosquitto $CERT_DIR"
    echo "     # Or if mosquitto runs as root: sudo chown -R root:root $CERT_DIR"
    echo ""
    echo "  5. Restart mosquitto to apply the new certificates:"
    echo "     sudo systemctl restart mosquitto"
    echo "     # or if using Docker: docker restart mosquitto"
    echo ""
    print_warning "IMPORTANT: Keep the private keys ($CA_KEY, $SERVER_KEY) secure and private!"
    print_warning "           Only share the CA certificate ($CA_CRT) with nodes in your group."
    echo ""
    print_info "How to run: as a normal user in a tree you can write to. The script calls sudo when required:"
    print_info "  default UFW (see Host firewall in --help). Running via sudo fixes repo-local ownership back to your user when paths were root-owned."
    print_info "  Use --no-firewall if you manage the host firewall yourself (sudo may still be needed for cert paths)."
    print_info "  Prefer sudo ./process_config.sh only when needed for firewall/systemd; repo artifacts default to your login user when SUDO_USER is set."
    print_info "Script location: console/process_config.sh"
    print_info "Certificate location: mosquitto/config/certs/"
}

# Extract IP/hostname from URL
extract_host_from_url() {
    local url="$1"
    # Remove protocol (http:// or https://)
    url="${url#http://}"
    url="${url#https://}"
    # Extract host:port and remove port
    echo "$url" | cut -d'/' -f1 | cut -d':' -f1
}

# Extract port from URL (defaults to 22 for SSH)
extract_port_from_url() {
    local url="$1"
    local port=$(echo "$url" | cut -d'/' -f1 | cut -d':' -f2)
    if [ -z "$port" ]; then
        echo "22"  # Default SSH port
    else
        echo "$port"
    fi
}

# Configure mqttBroker in configs.yaml (preserves comments using sed)
configure_mqtt_broker() {
    local config_file="$1"
    local is_relay_node="$2"
    
    if [ -z "$config_file" ] || [ ! -f "$config_file" ]; then
        print_warning "configs.yaml not found - skipping mqttBroker configuration"
        return 0
    fi
    
    # Get first node address (relay node's address)
    local first_node_addr=$(get_first_node_address "$config_file")
    if [ -z "$first_node_addr" ] || [ "$first_node_addr" = "null" ]; then
        print_warning "Could not determine first node address - skipping mqttBroker configuration"
        return 0
    fi
    
    # Extract host/IP from the first node address
    local first_node_host=$(extract_host_from_url "$first_node_addr")
    if [ -z "$first_node_host" ]; then
        print_warning "Could not extract host from first node address - skipping mqttBroker configuration"
        return 0
    fi
    if [ "$first_node_host" = "$NODE_ADDRESSES_RELAY_PLACEHOLDER_IPV4" ]; then
        print_info "First node address host is ${NODE_ADDRESSES_RELAY_PLACEHOLDER_IPV4} (relay placeholder) — skipping mqttBroker auto-configuration (set real nodeAddresses / mqttBroker after the relay IP is known)."
        return 0
    fi
    
    # Construct broker address (TLS on port 8883). Relay runs mosquitto in compose — mpc-auth must use the
    # Docker service name (configs-original.yaml documents tls://mosquitto:8883). Peer nodes keep WAN IP.
    local broker_addr
    if [ "$is_relay_node" = "true" ]; then
        broker_addr="ssl://mosquitto:8883"
        print_step "Configuring mqttBroker for relay node (Docker internal broker)..."
        print_info "Setting mqttBroker to: $broker_addr (peers use ssl://${first_node_host}:8883 on their nodes)"
    else
        broker_addr="ssl://${first_node_host}:8883"
        print_step "Configuring mqttBroker in configs.yaml..."
        print_info "Setting mqttBroker to: $broker_addr (derived from first node: $first_node_addr)"
    fi
    
    # Detect existing mqttBroker before relay/client branches (relay always overwrites WAN IP from DAO app).
    local existing_broker=""
    local mqtt_broker_exists=false
    if grep -qE '^\s*mqttBroker\s*:' "$config_file"; then
        mqtt_broker_exists=true
        existing_broker=$(awk '
            /^[[:space:]]*mqttBroker[[:space:]]*:/ {
                sub(/#.*$/, ""); sub(/^[[:space:]]*mqttBroker[[:space:]]*:[[:space:]]*/, ""); gsub(/^["'\'']?|["'\'']?[[:space:]]*$/, ""); gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print; exit
            }
        ' "$config_file" | xargs)
    fi

    if [ "$is_relay_node" = "true" ]; then
        if [ -n "$existing_broker" ] && [ "$existing_broker" = "$broker_addr" ]; then
            print_info "mqttBroker already set correctly for relay: $broker_addr"
            return 0
        fi
        if [ -n "$existing_broker" ] && [ "$existing_broker" != "$broker_addr" ]; then
            print_info "Relay: replacing mqttBroker $existing_broker → $broker_addr (DAO WAN IP is not reachable from inside the app container)"
        fi
    else
    # Client nodes: preserve user-specified mqttBroker when format is valid
        if [ -n "$existing_broker" ]; then
            # Validate the broker address format
            local protocol_valid=false
            local port_valid=false
            local protocol=""
            local port=""
            
            # Check protocol (should be ssl:// or tls://) - use awk to avoid any sed with URL
            if echo "$existing_broker" | grep -qE '^(ssl|tls)://'; then
                protocol_valid=true
                protocol=$(echo "$existing_broker" | awk 'match($0, /^(ssl|tls)/) { print substr($0, RSTART, RLENGTH); exit }')
            fi
            
            # Extract and check port (should be 8883 for TLS) - use awk to avoid any sed with URL
            if echo "$existing_broker" | grep -qE ':[0-9]+'; then
                port=$(echo "$existing_broker" | awk -F: 'NF>=2 && $NF ~ /^[0-9]+$/ { print $NF; exit }')
                if [ "$port" = "8883" ]; then
                    port_valid=true
                fi
            fi
            
            # Validate and warn if format is incorrect
            if [ "$protocol_valid" = false ] || [ "$port_valid" = false ]; then
                print_warning "mqttBroker format validation issues found:"
                if [ "$protocol_valid" = false ]; then
                    print_warning "  - Protocol should be 'ssl://' or 'tls://' (found: ${existing_broker%%://*})"
                fi
                if [ "$port_valid" = false ]; then
                    print_warning "  - Port should be 8883 for TLS (found: ${port:-not specified})"
                fi
                print_info "Recommended format: ssl://host:8883 or tls://host:8883"
                print_warning "Current value will be preserved, but may cause connection issues."
                print_info "To fix, update mqttBroker in configs.yaml to: $broker_addr"
            fi
            
            # If format is correct but value differs, just inform
            if [ "$protocol_valid" = true ] && [ "$port_valid" = true ] && [ "$existing_broker" != "$broker_addr" ]; then
                print_info "mqttBroker is already set to: $existing_broker (format is correct)"
                print_info "Keeping user-specified value. If you want to use the auto-derived value ($broker_addr),"
                print_info "please remove or update the mqttBroker field in configs.yaml manually."
            elif [ "$existing_broker" = "$broker_addr" ]; then
                print_info "mqttBroker already set correctly to: $broker_addr"
            fi
            
            return 0
        else
            # mqttBroker exists but is empty - we should update it
            print_info "mqttBroker field exists but is empty - will update it to: $broker_addr"
        fi
    fi
    
    # Try using ruamel.yaml (preserves comments) if available, otherwise use simple sed
    local ruamel_success=false
    if python3 -c "import ruamel.yaml" 2>/dev/null; then
        # Use ruamel.yaml which preserves comments
        local py_output=$(python3 << EOF 2>&1
import ruamel.yaml
import sys

try:
    yaml = ruamel.yaml.YAML()
    yaml.preserve_quotes = True
    yaml.width = 4096
    
    with open("$config_file", 'r') as f:
        data = yaml.load(f)
    
    if 'MPCGroups' not in data:
        data['MPCGroups'] = []
    
    updated = False
    force_relay = "$is_relay_node" == "true"
    for group in data.get('MPCGroups', []):
        mqtt_broker = group.get('mqttBroker')
        current = "" if mqtt_broker is None else str(mqtt_broker).strip()
        if force_relay:
            if current != "$broker_addr":
                group['mqttBroker'] = "$broker_addr"
                updated = True
        elif mqtt_broker is None or mqtt_broker == '' or current == '':
            group['mqttBroker'] = "$broker_addr"
            updated = True
    
    if updated:
        with open("$config_file", 'w') as f:
            yaml.dump(data, f)
        print("SUCCESS")
        sys.exit(0)
    else:
        print("NO_UPDATE_NEEDED")
        sys.exit(0)
except Exception as e:
    print(f"ERROR: {e}", file=sys.stderr)
    sys.exit(1)
EOF
)
        if [ $? -eq 0 ]; then
            if echo "$py_output" | grep -q "SUCCESS"; then
                print_success "Added/updated mqttBroker: $broker_addr (comments preserved)"
                ruamel_success=true
            elif echo "$py_output" | grep -q "NO_UPDATE_NEEDED"; then
                if [ "$is_relay_node" != "true" ] && [ "$mqtt_broker_exists" = true ] && [ -n "$existing_broker" ]; then
                    return 0
                else
                    print_warning "ruamel.yaml found no groups to update, trying sed/awk fallback..."
                fi
            fi
        else
            print_warning "Failed with ruamel.yaml: $py_output"
            print_warning "Trying sed fallback..."
        fi
    fi
    
    # If ruamel.yaml didn't succeed, use sed fallback
    if [ "$ruamel_success" != "true" ]; then
    
        # Fallback: Use sed for simple update/add (may not preserve all formatting but preserves comments)
        if [ "$mqtt_broker_exists" = false ]; then
        # Add mqttBroker after nodeAddresses block
        if grep -qE '^\s*nodeAddresses\s*:' "$config_file"; then
            # Find where nodeAddresses block ends and add there
            # This is a simple approach - finds the line after nodeAddresses that has less indentation
            awk -v broker="$broker_addr" '
            /^\s*nodeAddresses\s*:/ {
                print
                nodeaddr_indent = match($0, /^[[:space:]]*/)
                while ((getline > 0)) {
                    if (!/^\s*#/ && NF > 0) {
                        current_indent = match($0, /^[[:space:]]*/)
                        if (length(substr($0, 1, current_indent)) <= nodeaddr_indent) {
                            # End of nodeAddresses, add mqttBroker
                            indent_str = substr($0, 1, nodeaddr_indent)
                            print indent_str "mqttBroker: \"" broker "\""
                            print
                            next
                        }
                    }
                    print
                }
                # If we reach here, add at end
                indent_str = substr($0, 1, nodeaddr_indent)
                print indent_str "mqttBroker: \"" broker "\""
                next
            }
            { print }
            ' "$config_file" > "${config_file}.tmp" && mv "${config_file}.tmp" "$config_file"
        else
            print_warning "Could not find nodeAddresses - cannot auto-add mqttBroker"
            print_info "Please manually add to configs.yaml:"
            echo "  MPCGroups:"
            echo "    - mqttBroker: \"$broker_addr\""
            return 1
        fi
        
        if [ $? -eq 0 ] && [ -f "$config_file" ]; then
            rm -f "${config_file}.tmp"
            print_success "Added mqttBroker: $broker_addr"
        else
            print_warning "Failed to add mqttBroker"
            rm -f "${config_file}.tmp"
            return 1
        fi
        elif [ "$mqtt_broker_exists" = true ] && { [ -z "$existing_broker" ] || [ "$is_relay_node" = "true" ]; }; then
            # Empty mqttBroker, or relay forcing WAN → mosquitto — update line via awk (no sed so ssl:// in URL cannot break anything)
            local mqtt_line=$(grep -E '^\s*mqttBroker\s*:' "$config_file" | head -1)
            local comment_part=$(echo "$mqtt_line" | awk 'match($0, /#.*$/) { print substr($0, RSTART, RLENGTH) }')
            if awk -v broker="$broker_addr" -v comment="${comment_part:-}" '
                /^[[:space:]]*mqttBroker[[:space:]]*:/ {
                    match($0, /^[[:space:]]*/)
                    indent = substr($0, RSTART, RLENGTH)
                    suffix = (comment != "" ? " " comment : "")
                    print indent "mqttBroker: \"" broker "\"" suffix
                    next
                }
                { print }
            ' "$config_file" > "${config_file}.tmp" 2>/dev/null && mv "${config_file}.tmp" "$config_file"; then
                rm -f "${config_file}.tmp"
                print_success "Updated mqttBroker to: $broker_addr"
            else
                rm -f "${config_file}.tmp"
                print_warning "Failed to update mqttBroker - please update manually in configs.yaml"
            fi
        fi
    fi
    
    return 0
}

# True when docker-compose.yml defines the mosquitto service (relay template).
_process_config_compose_file_is_relay() {
    local compose_file="$1"
    [ -n "$compose_file" ] && [ -f "$compose_file" ] && grep -qE '^[[:space:]]{2}mosquitto:[[:space:]]*$' "$compose_file"
}

# True when relay MQTT TLS files needed by mosquitto and mpc-auth are all present.
_relay_mqtt_tls_certs_complete() {
    [ -f "$CA_CRT" ] && [ -f "$SERVER_CRT" ] && [ -f "$SERVER_KEY" ]
}

# True when server.crt includes DNS SAN mosquitto (required for ssl://mosquitto:8883 from the app container).
_relay_mqtt_server_cert_has_mosquitto_san() {
    [ -f "$SERVER_CRT" ] && command -v openssl >/dev/null 2>&1 && \
        openssl x509 -in "$SERVER_CRT" -noout -text 2>/dev/null | grep -qE 'DNS:mosquitto([^a-zA-Z0-9_-]|$)'
}

# Relay app uses mqttBroker ssl://<WAN-ip>:8883; from inside Docker that often fails without NAT hairpin.
# Map the relay WAN IP (first nodeAddresses host) to host-gateway so TLS still targets the public IP SAN.
apply_docker_compose_relay_mqtt_hairpin_extra_hosts() {
    local file="$1"
    local config_file="$2"
    local relay_ip=""
    if [ -z "$config_file" ] || [ ! -f "$config_file" ] || [ ! -f "$file" ]; then
        return 0
    fi
    relay_ip=$(get_first_node_address "$config_file" 2>/dev/null) || true
    if [ -n "$relay_ip" ] && [ "$relay_ip" != "null" ]; then
        relay_ip=$(extract_ip_from_url "$relay_ip")
    fi
    if [ -z "$relay_ip" ] || [ "$relay_ip" = "$NODE_ADDRESSES_RELAY_PLACEHOLDER_IPV4" ]; then
        print_info "docker-compose.yml: relay MQTT hairpin extra_hosts skipped (no real relay IP in configs.yaml yet)."
        return 0
    fi
    if ! command -v python3 &> /dev/null; then
        print_warning "python3 not found — could not set relay MQTT hairpin extra_hosts in docker-compose.yml"
        return 1
    fi
    local _hairpin_action
    _hairpin_action=$(
        COMPOSE_HAIRPIN_FILE="$file" COMPOSE_HAIRPIN_RELAY_IP="$relay_ip" python3 << 'PYHAIRPIN'
import os
import re
import sys

path = os.environ.get("COMPOSE_HAIRPIN_FILE", "")
relay_ip = (os.environ.get("COMPOSE_HAIRPIN_RELAY_IP") or "").strip()
BEGIN = "    # BEGIN mpc-config relay-mqtt-hairpin-extra-hosts"
END = "    # END mpc-config relay-mqtt-hairpin-extra-hosts"
if not path or not relay_ip:
    print("skip", flush=True)
    sys.exit(0)
if not re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", relay_ip):
    print("skip", flush=True)
    sys.exit(0)

try:
    with open(path, encoding="utf-8") as f:
        text = f.read()
except OSError:
    print("error_read", flush=True)
    sys.exit(1)

if BEGIN not in text or END not in text:
    print("no_marker", flush=True)
    sys.exit(0)

block = (
    f"{BEGIN} (process_config.sh adds relay WAN IP → host-gateway)\n"
    f"    extra_hosts:\n"
    f'      - "{relay_ip}:host-gateway"\n'
    f'      - "host.docker.internal:host-gateway"\n'
    f"{END}"
)
i0 = text.index(BEGIN)
i1 = text.index(END) + len(END)
new_text = text[:i0] + block + text[i1:]
try:
    with open(path, "w", encoding="utf-8") as f:
        f.write(new_text)
except OSError:
    print("error_write", flush=True)
    sys.exit(1)
print("ok", flush=True)
PYHAIRPIN
    )
    case "$_hairpin_action" in
        ok)
            print_success "docker-compose.yml: app extra_hosts maps ${relay_ip} → host-gateway (relay MQTT hairpin)."
            ;;
        no_marker)
            print_warning "docker-compose.yml: relay-mqtt-hairpin-extra-hosts markers missing — git pull mpc-config relay template."
            ;;
        skip) ;;
        *)
            print_warning "docker-compose.yml: could not merge relay MQTT hairpin extra_hosts."
            ;;
    esac
}

# Non-interactive path for host automation (systemd restart / pending-update): align docker-compose.yml
# with relay vs client role from configs.yaml; generate MQTT broker certs on relay promotion; demotion
# copies the client template (mosquitto removed — host update uses compose up --remove-orphans).
process_config_sync_compose_role_only() {
    local skip_agent_llm="${1:-true}"
    local app_image_override="${2:-}"
    local compose_dir script_dir compose_file
    local prev_relay=0 new_relay=0 changed=0 needs_full_stack=0
    local _agent_llm_compose_enable=1

    export PROCESS_CONFIG_NONINTERACTIVE="${PROCESS_CONFIG_NONINTERACTIVE:-1}"
    export SKIP_NODE_ADDRESS_MENU="${SKIP_NODE_ADDRESS_MENU:-1}"

    CONFIG_FILE=$(find_configs_yaml)
    if [ -z "$CONFIG_FILE" ]; then
        print_error "sync-compose-role: configs.yaml not found"
        return 1
    fi

    script_dir="$(cd "$(dirname "$0")" && pwd)"
    compose_dir="$script_dir"
    if [ -d "$script_dir/mosquitto/config" ]; then
        compose_dir="$script_dir"
    elif [ -f "$script_dir/../docker-compose.yml" ] || [ -f "$script_dir/../docker-compose.relay.yml" ]; then
        compose_dir="$(cd "$script_dir/.." && pwd)"
    else
        compose_dir="$(cd "$(dirname "$CONFIG_FILE")" && pwd)"
    fi
    compose_file="$compose_dir/docker-compose.yml"

    if _process_config_compose_file_is_relay "$compose_file"; then
        prev_relay=1
    fi

    IS_RELAY_NODE=$(validate_node_ip "$CONFIG_FILE")
    if [ "$IS_RELAY_NODE" = "true" ]; then
        new_relay=1
    fi

    if [ "$prev_relay" -ne "$new_relay" ]; then
        changed=1
        needs_full_stack=1
    fi

    BROWSER_LOOPBACK_READ_HTTP_ENABLED=0
    if command -v python3 &> /dev/null; then
        local _blr_infer
        _blr_infer=$(python3 -c "
import sys
try:
    from ruamel.yaml import YAML
except ImportError:
    print(0); raise SystemExit
p = sys.argv[1]
y = YAML()
with open(p) as f:
    d = y.load(f) or {}
b = d.get('BrowserLoopbackReadHTTP') if isinstance(d, dict) else None
port = int(b.get('Port') or 0) if isinstance(b, dict) else 0
print(1 if port > 0 else 0)
" "$CONFIG_FILE" 2>/dev/null) || _blr_infer=0
        if [ "$_blr_infer" = "1" ]; then
            BROWSER_LOOPBACK_READ_HTTP_ENABLED=1
        fi
    fi

    case "$skip_agent_llm" in
        true|1) _agent_llm_compose_enable=0 ;;
    esac

    configure_docker_compose "$IS_RELAY_NODE" "$BROWSER_LOOPBACK_READ_HTTP_ENABLED" "$app_image_override" "$CONFIG_FILE" "$_agent_llm_compose_enable"

    if [ "$IS_RELAY_NODE" = "true" ]; then
        configure_mqtt_broker "$CONFIG_FILE" "true"
        needs_full_stack=1
    fi

    if [ "$IS_RELAY_NODE" = "true" ]; then
        MOSQUITTO_CONF=$(find_mosquitto_conf)
        local _gen_mqtt_certs=false
        local _regen_server_san_only=false
        if [ -n "$MOSQUITTO_CONF" ] && is_letsencrypt_configured "$MOSQUITTO_CONF"; then
            print_info "sync-compose-role: Let's Encrypt configured — skipping self-signed MQTT cert generation."
        elif ! _relay_mqtt_tls_certs_complete; then
            print_info "sync-compose-role: MQTT broker TLS files incomplete in $CERT_DIR — generating."
            _gen_mqtt_certs=true
        elif confirm_overwrite_mqtt_certs; then
            _gen_mqtt_certs=true
        elif _relay_mqtt_tls_certs_complete && ! _relay_mqtt_server_cert_has_mosquitto_san; then
            print_info "sync-compose-role: server.crt missing DNS SAN mosquitto — regenerating server cert for ssl://mosquitto:8883."
            _regen_server_san_only=true
        fi
        if [ "$_gen_mqtt_certs" = true ]; then
            check_cert_dir
            print_step "sync-compose-role: generating Mosquitto (MQTT TLS) broker certificates..."
            generate_ca_key
            generate_ca_cert
            generate_server_key
            generate_server_csr
            sign_server_cert "$CONFIG_FILE"
            set_permissions
            _process_config_chown_repo_tree_if_sudo_root "$CERT_DIR"
            needs_full_stack=1
        elif [ "$_regen_server_san_only" = true ]; then
            check_cert_dir
            print_step "sync-compose-role: re-issuing Mosquitto server certificate (add DNS mosquitto SAN)..."
            generate_server_key
            generate_server_csr
            sign_server_cert "$CONFIG_FILE"
            set_permissions
            _process_config_chown_repo_tree_if_sudo_root "$CERT_DIR"
            needs_full_stack=1
        elif [ "$new_relay" -eq 1 ] && ! _relay_mqtt_tls_certs_complete; then
            print_warning "sync-compose-role: MQTT TLS certs still missing under $CERT_DIR — mosquitto will not serve TLS until you run process_config.sh on the relay."
            needs_full_stack=1
        fi
    fi

    if [ "$new_relay" -eq 1 ] && [ "$needs_full_stack" -eq 0 ]; then
        if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -qiE 'mosquitto'; then
            needs_full_stack=1
        fi
    fi

    if [ "$new_relay" -eq 1 ]; then
        echo "compose_role_sync: role=relay changed=${changed} needs_full_stack=${needs_full_stack}"
    else
        echo "compose_role_sync: role=client changed=${changed} needs_full_stack=${needs_full_stack}"
    fi

    _process_config_finalize_repo_ownership_after_sudo
    return 0
}

# Configure docker-compose.yml based on node type (relay or client).
# Uses two fixed files: docker-compose.relay.yml and docker-compose.client.yml.
# Copies the appropriate one to docker-compose.yml, then applies loopback port mapping (see apply_docker_compose_loopback_mapping).
# When script is in console/, look for compose files in script dir then in parent (repo root).
configure_docker_compose() {
    local is_relay_node="$1"
    local enable_loopback="${2:-0}"
    local app_image_override="${3:-}"
    local configs_yaml_path="${4:-}"
    local script_dir="$(cd "$(dirname "$0")" && pwd)"
    local compose_dir="$script_dir"
    if [ -d "$script_dir/mosquitto/config" ]; then
        compose_dir="$script_dir"
    elif [ -f "$script_dir/../docker-compose.yml" ]; then
        compose_dir="$(cd "$script_dir/.." && pwd)"
    fi
    local docker_compose_file="$compose_dir/docker-compose.yml"
    
    if [ "$is_relay_node" = "true" ]; then
        local template="$compose_dir/docker-compose.relay.yml"
        local node_type="RELAY"
    else
        local template="$compose_dir/docker-compose.client.yml"
        local node_type="CLIENT"
    fi
    
    print_step "Configuring docker-compose.yml for $node_type NODE..."
    
    if [ ! -f "$template" ]; then
        print_warning "Template not found: $template"
        print_info "Expected docker-compose.relay.yml and docker-compose.client.yml in $compose_dir"
        return 1
    fi
    
    # Backup current docker-compose.yml if it exists
    if [ -f "$docker_compose_file" ]; then
        local backup_file="${docker_compose_file}.backup.$(date +%Y%m%d_%H%M%S)"
        if cp "$docker_compose_file" "$backup_file" 2>/dev/null; then
            print_info "Backup created: $backup_file"
        fi
    fi
    
    if cp "$template" "$docker_compose_file" 2>/dev/null; then
        print_success "docker-compose.yml configured for $node_type node (copied from $(basename "$template"))"
        apply_docker_compose_loopback_mapping "$docker_compose_file" "$enable_loopback" || true
        if [ -n "$app_image_override" ]; then
            apply_docker_compose_mpc_auth_image "$docker_compose_file" "$app_image_override"
        fi
        apply_docker_compose_continuumdao_node_app "$docker_compose_file" "$configs_yaml_path" || true
        apply_docker_compose_continuum_mcp_server "$docker_compose_file" "$configs_yaml_path" || true
        apply_docker_compose_agent_llm_config_env "$docker_compose_file" "${5:-1}" || true
        apply_docker_compose_vpn_env "$docker_compose_file" || true
        apply_docker_compose_agent_llm_config_defaults_volume "$docker_compose_file" "${5:-1}" || true
        if [ "$is_relay_node" = "true" ]; then
            apply_docker_compose_relay_mqtt_hairpin_extra_hosts "$docker_compose_file" "$configs_yaml_path" || true
        fi
        process_config_repo_take_if_sudo_invoker "$docker_compose_file"
        shopt -s nullglob
        local _dcf_bak
        for _dcf_bak in "${docker_compose_file}.backup."*; do
            process_config_repo_take_if_sudo_invoker "$_dcf_bak"
        done
        shopt -u nullglob
    else
        print_warning "Failed to copy $template to docker-compose.yml"
        return 1
    fi
}

# After copying a compose template, replace the app image line (${MPC_AUTH_COMPOSE_APP_IMAGE:-…} or literal) with a concrete ref when MPC_AUTH_COMPOSE_APP_IMAGE is set.
apply_docker_compose_mpc_auth_image() {
    local file="$1"
    local new_image="$2"
    if [ -z "$new_image" ] || [ ! -f "$file" ]; then
        return 0
    fi
    if ! command -v python3 &> /dev/null; then
        print_warning "python3 not found — could not set docker-compose app image"
        return 1
    fi
    local _img_action
    _img_action=$(
        COMPOSE_APP_IMAGE_FILE="$file" COMPOSE_APP_IMAGE_REF="$new_image" python3 << 'PYIMG'
import os
import re
import sys

path = os.environ.get("COMPOSE_APP_IMAGE_FILE", "")
ref = os.environ.get("COMPOSE_APP_IMAGE_REF", "").strip()
if not path or not ref:
    print("skip", flush=True)
    sys.exit(0)
try:
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()
except OSError as e:
    sys.stderr.write(f"{path}: {e}\n")
    print("error", flush=True)
    sys.exit(1)

# Compose interpolation or literal continuumdao mpc-auth (docker-compose.*.yml templates).
_interp = re.compile(
    r"^\s*image:\s*\$\{MPC_AUTH_COMPOSE_APP_IMAGE:-continuumdao/mpc-auth[^}]*\}\s*$"
)
_literal = re.compile(r"^\s*image:\s*continuumdao/mpc-auth\S*\s*$")
changed = 0
out = []
for line in lines:
    raw = line.rstrip("\n")
    if _interp.match(raw) or _literal.match(raw):
        indent = line[: len(line) - len(line.lstrip(" \t"))]
        out.append(f"{indent}image: {ref}\n")
        changed += 1
    else:
        out.append(line)

if changed == 0:
    print("none", flush=True)
    sys.exit(0)
with open(path, "w", encoding="utf-8") as f:
    f.writelines(out)
print(f"ok:{changed}", flush=True)
PYIMG
    )
    case "$_img_action" in
        ok:*)
            print_success "docker-compose.yml: app image set to ${new_image} (${_img_action#ok:} line(s))."
            ;;
        none)
            print_warning "docker-compose.yml: no continuumdao mpc-auth app image line found (expected \${MPC_AUTH_COMPOSE_APP_IMAGE:-continuumdao/mpc-auth:…} or literal continuumdao/mpc-auth:…) — left unchanged."
            ;;
        skip|error)
            ;;
        *)
            print_warning "docker-compose.yml: unexpected image patch result (${_img_action})."
            ;;
    esac
}

# Replace the marked continuumdao-node-app (dashboard) block in docker-compose.yml from ContinuumdaoNodeApp in configs.yaml.
apply_docker_compose_continuumdao_node_app() {
    local file="$1"
    local config_file="${2:-}"
    if [ -z "$config_file" ] || [ ! -f "$config_file" ]; then
        print_warning "Skipping continuumdao-node-app compose merge (missing configs.yaml path)."
        return 0
    fi
    if [ ! -f "$file" ]; then
        print_warning "Skipping continuumdao-node-app compose merge (compose file missing)."
        return 0
    fi
    if ! command -v python3 &>/dev/null; then
        print_warning "python3 not found — could not merge ContinuumdaoNodeApp into docker-compose.yml"
        return 1
    fi
    local _na_action
    _na_action=$(
        MPC_NA_COMPOSE_PATH="$file" MPC_NA_CONFIG_PATH="$config_file" python3 <<'PYNA'
import os
import sys

try:
    from ruamel.yaml import YAML
except ImportError:
    print("no_ruamel", flush=True)
    sys.exit(1)

path_c = os.environ.get("MPC_NA_CONFIG_PATH", "")
path_compose = os.environ.get("MPC_NA_COMPOSE_PATH", "")
if not path_c or not path_compose:
    print("skip", flush=True)
    sys.exit(0)

BEGIN = "  # BEGIN mpc-config continuumdao-node-app\n"
END = "  # END mpc-config continuumdao-node-app\n"

DEFAULT_UPSTREAM_HOST = "app"

y = YAML()
with open(path_c, encoding="utf-8") as f:
    d = y.load(f) or {}

if not isinstance(d, dict):
    d = {}


def scalar_int(val, default):
    if val is None:
        return default
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def scalar_bool(val, default):
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    s = str(val).strip().lower()
    if s in ("0", "false", "no", "off", ""):
        return False
    if s in ("1", "true", "yes", "on"):
        return True
    return default


na = d.get("ContinuumdaoNodeApp")
enabled = True
image = "continuumdao/continuumdao-node-app"
tag = "latest"
host_port = 3333
plain_attach = True
disc_allow_private = True
upstream_host = ""

if na is None:
    pass  # defaults
elif isinstance(na, dict):
    enabled = scalar_bool(na.get("Enabled"), True)
    image = (na.get("Image") or image).strip() or image
    tag = (na.get("Tag") or tag).strip() or tag
    host_port = scalar_int(na.get("HostPort"), host_port)
    plain_attach = scalar_bool(na.get("EnablePlainHttpAttach"), True)
    disc_allow_private = scalar_bool(na.get("NodeReadDiscoveryAllowPrivate"), True)
    if na.get("NodeReadDiscoveryUpstreamHost") not in (None, ""):
        upstream_host = str(na.get("NodeReadDiscoveryUpstreamHost")).strip()
else:
    enabled = False

mgt_port = scalar_int(d.get("ManagementAPIsPort"), 8080)
pub_port = scalar_int(d.get("PublicDiscoveryPort"), 18080)
bh = d.get("BrowserHTTPS")
bh_port_raw = None
if isinstance(bh, dict):
    bh_port_raw = bh.get("Port")
if bh_port_raw is None or bh_port_raw == 0:
    bh_use = 8443
else:
    bh_use = scalar_int(bh_port_raw, 8443)

if host_port <= 0 or host_port > 65535:
    host_port = 3333


def yaml_sq(s):
    return "'" + str(s).replace("'", "''") + "'"


if not upstream_host:
    upstream_use = DEFAULT_UPSTREAM_HOST
else:
    upstream_use = upstream_host

try:
    with open(path_compose, encoding="utf-8") as f:
        text = f.read()
except OSError:
    print("error_read", flush=True)
    sys.exit(1)

if BEGIN not in text or END not in text:
    print("no_marker", flush=True)
    sys.exit(0)

i0 = text.index(BEGIN)
i1 = text.index(END) + len(END)

if enabled:
    plain_attach_env = '"1"' if plain_attach else '"0"'
    disc_allow_private_env = '"1"' if disc_allow_private else '"0"'

    dash = (
        f"{BEGIN}"
        f"  dashboard:\n"
        f'    image: {yaml_sq(image + ":" + tag)}\n'
        f"    restart: unless-stopped\n"
        f"    depends_on:\n"
        f"      app:\n"
        f"        condition: service_started\n"
        f"    environment:\n"
        f"      ENABLE_PLAIN_HTTP_ATTACH: {plain_attach_env}\n"
        f"      NODE_READ_DISCOVERY_ALLOW_PRIVATE: {disc_allow_private_env}\n"
        f"      NODE_READ_DISCOVERY_UPSTREAM_HOST: {yaml_sq(upstream_use)}\n"
        f'      DEFAULT_NODE_DISCOVERY_PORT: "{pub_port}"\n'
        f'      BROWSER_HTTPS_PORT: "{bh_use}"\n'
        f'      MANAGEMENT_API_PORT: "{mgt_port}"\n'
        f"    ports:\n"
        f'      - "{host_port}:3000"\n'
        f"    networks:\n"
        f"      - local-network\n"
        f"{END}"
    )
    new_text = text[:i0] + dash + text[i1:]
    action = "ok_on"
else:
    new_text = text[:i0] + text[i1:]
    action = "ok_off"

try:
    with open(path_compose, "w", encoding="utf-8") as f:
        f.write(new_text)
except OSError:
    print("error_write", flush=True)
    sys.exit(1)
print(action, flush=True)
PYNA
    )
    case "$_na_action" in
        ok_on)
            print_success "docker-compose.yml: continuumdao-node-app (dashboard) enabled from configs.yaml."
            ;;
        ok_off)
            print_info "docker-compose.yml: continuumdao-node-app (dashboard) disabled (ContinuumdaoNodeApp.Enabled: false)."
            ;;
        skip)
            ;;
        no_marker)
            print_warning "docker-compose.yml: no continuumdao-node-app markers — update templates or regenerate compose."
            ;;
        no_ruamel)
            print_warning "python3 ruamel.yaml missing — install python3-ruamel.yaml or pip install ruamel.yaml; ContinuumdaoNodeApp compose merge skipped."
            ;;
        error_read | error_write)
            print_warning "Could not merge ContinuumdaoNodeApp into docker-compose.yml (${_na_action})."
            ;;
        *)
            print_warning "Unexpected ContinuumdaoNodeApp compose merge result: ${_na_action}"
            ;;
    esac
}

# Replace the marked continuum-mcp-server block in docker-compose.yml from ContinuumMcpServer in configs.yaml.
apply_docker_compose_continuum_mcp_server() {
    local file="$1"
    local config_file="${2:-}"
    if [ -z "$config_file" ] || [ ! -f "$config_file" ]; then
        print_warning "Skipping continuum-mcp-server compose merge (missing configs.yaml path)."
        return 0
    fi
    if [ ! -f "$file" ]; then
        print_warning "Skipping continuum-mcp-server compose merge (compose file missing)."
        return 0
    fi
    if ! command -v python3 &>/dev/null; then
        print_warning "python3 not found — could not merge ContinuumMcpServer into docker-compose.yml"
        return 1
    fi
    local _mcp_action
    _mcp_action=$(
        MPC_MCP_COMPOSE_PATH="$file" MPC_MCP_CONFIG_PATH="$config_file" python3 <<'PYMCP'
import os
import sys

try:
    from ruamel.yaml import YAML
except ImportError:
    print("no_ruamel", flush=True)
    sys.exit(1)

path_c = os.environ.get("MPC_MCP_CONFIG_PATH", "")
path_compose = os.environ.get("MPC_MCP_COMPOSE_PATH", "")
if not path_c or not path_compose:
    print("skip", flush=True)
    sys.exit(0)

BEGIN = "  # BEGIN mpc-config continuum-mcp-server\n"
END = "  # END mpc-config continuum-mcp-server\n"

y = YAML()
with open(path_c, encoding="utf-8") as f:
    d = y.load(f) or {}

if not isinstance(d, dict):
    d = {}


def scalar_int(val, default):
    if val is None:
        return default
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def scalar_bool(val, default):
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    s = str(val).strip().lower()
    if s in ("0", "false", "no", "off", ""):
        return False
    if s in ("1", "true", "yes", "on"):
        return True
    return default


mcp = d.get("ContinuumMcpServer")
enabled = True
image = "continuumdao/continuum-mcp-server"
tag = "latest"
host_port = 8446
container_port = 8446
http_path = "/mcp"

if mcp is None:
    pass
elif isinstance(mcp, dict):
    enabled = scalar_bool(mcp.get("Enabled"), True)
    image = (mcp.get("Image") or image).strip() or image
    tag = (mcp.get("Tag") or tag).strip() or tag
    host_port = scalar_int(mcp.get("HostPort"), host_port)
    container_port = scalar_int(mcp.get("Port"), host_port)
    http_path = (mcp.get("HttpPath") or http_path).strip() or http_path
else:
    enabled = False

mgt_port = scalar_int(d.get("ManagementAPIsPort"), 8080)

if host_port <= 0 or host_port > 65535:
    host_port = 8446
if container_port <= 0 or container_port > 65535:
    container_port = host_port
if not http_path.startswith("/"):
    http_path = "/" + http_path


def yaml_sq(s):
    return "'" + str(s).replace("'", "''") + "'"


try:
    with open(path_compose, encoding="utf-8") as f:
        text = f.read()
except OSError:
    print("error_read", flush=True)
    sys.exit(1)

if BEGIN not in text or END not in text:
    print("no_marker", flush=True)
    sys.exit(0)

i0 = text.index(BEGIN)
i1 = text.index(END) + len(END)

if enabled:
    block = (
        f"{BEGIN}"
        f"  continuum-mcp:\n"
        f'    image: {yaml_sq(image + ":" + tag)}\n'
        f"    restart: unless-stopped\n"
        f"    depends_on:\n"
        f"      app:\n"
        f"        condition: service_started\n"
        f"    environment:\n"
        f'      MCP_HTTP_HOST: "0.0.0.0"\n'
        f'      MCP_HTTP_PORT: "{container_port}"\n'
        f'      MCP_HTTP_PATH: {yaml_sq(http_path)}\n'
        f'      MPC_AUTH_URL: "http://app"\n'
        f'      MPC_AUTH_PORT: "{mgt_port}"\n'
        f"    volumes:\n"
        f"      - ./added_keys:/app/added_keys\n"
        f"      - ./bootstrap_key:/app/bootstrap_key:ro\n"
        f"    ports:\n"
        f'      - "127.0.0.1:{host_port}:{container_port}"\n'
        f"    networks:\n"
        f"      - local-network\n"
        f"{END}"
    )
    new_text = text[:i0] + block + text[i1:]
    action = "ok_on"
else:
    new_text = text[:i0] + text[i1:]
    action = "ok_off"

try:
    with open(path_compose, "w", encoding="utf-8") as f:
        f.write(new_text)
except OSError:
    print("error_write", flush=True)
    sys.exit(1)
print(action, flush=True)
PYMCP
    )
    case "$_mcp_action" in
        ok_on)
            print_success "docker-compose.yml: continuum-mcp-server enabled from configs.yaml."
            ;;
        ok_off)
            print_info "docker-compose.yml: continuum-mcp-server disabled (ContinuumMcpServer.Enabled: false)."
            ;;
        skip) ;;
        no_marker)
            print_warning "docker-compose.yml: no continuum-mcp-server markers — update templates or regenerate compose."
            ;;
        no_ruamel)
            print_warning "python3 ruamel.yaml missing — ContinuumMcpServer compose merge skipped."
            ;;
        error_read | error_write)
            print_warning "Could not merge ContinuumMcpServer into docker-compose.yml (${_mcp_action})."
            ;;
        *)
            print_warning "Unexpected ContinuumMcpServer compose merge result: ${_mcp_action}"
            ;;
    esac
}

# Ensure or remove MPC_AUTH_AGENT_LLM_CONFIG_FILE in docker-compose app environment (matches configs.yaml + bind mount).
apply_docker_compose_agent_llm_config_env() {
    local file="$1"
    local enable="${2:-1}"
    local agent_path="${DEFAULT_AGENT_LLM_CONFIG_CONTAINER_FILE}"
    if [ ! -f "$file" ]; then
        return 0
    fi
    if ! command -v python3 &>/dev/null; then
        print_warning "python3 not found — could not adjust agent LLM config env in docker-compose.yml"
        return 1
    fi
    local _action
    _action=$(
        COMPOSE_AGENT_LLM_FILE="$file" COMPOSE_AGENT_LLM_ENABLE="$enable" COMPOSE_AGENT_LLM_PATH="$agent_path" python3 << 'PYCOMPOSEAGENT'
import os
import re
import sys

path = os.environ.get("COMPOSE_AGENT_LLM_FILE", "")
enable = os.environ.get("COMPOSE_AGENT_LLM_ENABLE", "1").strip() == "1"
agent_path = os.environ.get("COMPOSE_AGENT_LLM_PATH", "").strip()
env_key = "MPC_AUTH_AGENT_LLM_CONFIG_FILE"
line_active = f"      {env_key}: {agent_path}\n"
line_comment = f"      # {env_key}: {agent_path}\n"
pat = re.compile(r"^\s*#?\s*MPC_AUTH_AGENT_LLM_CONFIG_FILE:\s*")

if not path or not agent_path:
    print("skip", flush=True)
    sys.exit(0)

try:
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()
except OSError as e:
    sys.stderr.write(f"{path}: {e}\n")
    print("error", flush=True)
    sys.exit(1)

out = []
found = False
for line in lines:
    if pat.match(line):
        found = True
        if enable:
            out.append(line_active)
        continue
    out.append(line)

if enable and not found:
    inserted = False
    reboot_pat = re.compile(r"^\s*MPC_AUTH_PENDING_REBOOT_FILE:")
    for i, line in enumerate(out):
        if reboot_pat.match(line):
            out.insert(i + 1, line_active)
            inserted = True
            break
    if not inserted:
        pending_pat = re.compile(r"^\s*MPC_AUTH_DOCKER_PENDING_UPDATE_FILE:")
        for i, line in enumerate(out):
            if pending_pat.match(line):
                out.insert(i + 1, line_active)
                inserted = True
                break
    if not inserted:
        print("none", flush=True)
        sys.exit(0)
    action = "insert"
elif enable and found:
    action = "set"
elif not enable and found:
    action = "remove"
else:
    action = "noop"
    sys.exit(0)

with open(path, "w", encoding="utf-8") as f:
    f.writelines(out)
print(action, flush=True)
PYCOMPOSEAGENT
    )
    case "$_action" in
        set|insert)
            print_success "docker-compose.yml: MPC_AUTH_AGENT_LLM_CONFIG_FILE → ${agent_path}"
            ;;
        remove)
            print_info "docker-compose.yml: omitted MPC_AUTH_AGENT_LLM_CONFIG_FILE (--no-agent-llm-config-path)"
            ;;
        none)
            print_warning "docker-compose.yml: could not insert MPC_AUTH_AGENT_LLM_CONFIG_FILE (pending-update env lines missing)"
            ;;
        skip|noop) ;;
        error)
            print_warning "docker-compose.yml: failed to adjust agent LLM config env"
            return 1
            ;;
    esac
}

# Ensure MPC_AUTH_VPN_* env lines exist in docker-compose app environment (relay and client templates).
apply_docker_compose_vpn_env() {
    local file="$1"
    if [ ! -f "$file" ]; then
        return 0
    fi
    if ! command -v python3 &>/dev/null; then
        print_warning "python3 not found — could not adjust VPN env in docker-compose.yml"
        return 1
    fi
    local _action
    _action=$(
        COMPOSE_VPN_FILE="$file" python3 << 'PYCOMPOSEVPN'
import os
import re
import sys

path = os.environ.get("COMPOSE_VPN_FILE", "")
pending_line = "      MPC_AUTH_VPN_PENDING_FILE: /var/lib/mpc-auth-docker/pending-vpn.json\n"
state_line = "      MPC_AUTH_VPN_STATE_FILE: /var/lib/mpc-auth-docker/vpn-state.json\n"
egress_pending_line = "      MPC_AUTH_VPN_EGRESS_PENDING_FILE: /var/lib/mpc-auth-docker/pending-vpn-egress.json\n"
egress_state_line = "      MPC_AUTH_VPN_EGRESS_STATE_FILE: /var/lib/mpc-auth-docker/vpn-egress-state.json\n"
pat_pending = re.compile(r"^\s*#?\s*MPC_AUTH_VPN_PENDING_FILE:\s*")
pat_state = re.compile(r"^\s*#?\s*MPC_AUTH_VPN_STATE_FILE:\s*")
pat_egress_pending = re.compile(r"^\s*#?\s*MPC_AUTH_VPN_EGRESS_PENDING_FILE:\s*")
pat_egress_state = re.compile(r"^\s*#?\s*MPC_AUTH_VPN_EGRESS_STATE_FILE:\s*")
reboot_pat = re.compile(r"^\s*MPC_AUTH_PENDING_REBOOT_FILE:")

if not path:
    print("skip", flush=True)
    sys.exit(0)

try:
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()
except OSError as e:
    sys.stderr.write(f"{path}: {e}\n")
    print("error", flush=True)
    sys.exit(1)

out = []
found_pending = False
found_state = False
found_egress_pending = False
found_egress_state = False
changed = False
for line in lines:
    if pat_pending.match(line):
        found_pending = True
        if line != pending_line:
            changed = True
        out.append(pending_line)
        continue
    if pat_state.match(line):
        found_state = True
        if line != state_line:
            changed = True
        out.append(state_line)
        continue
    if pat_egress_pending.match(line):
        found_egress_pending = True
        if line != egress_pending_line:
            changed = True
        out.append(egress_pending_line)
        continue
    if pat_egress_state.match(line):
        found_egress_state = True
        if line != egress_state_line:
            changed = True
        out.append(egress_state_line)
        continue
    out.append(line)

if not found_pending or not found_state or not found_egress_pending or not found_egress_state:
    insert_at = None
    for i, line in enumerate(out):
        if reboot_pat.match(line):
            insert_at = i + 1
            break
    if insert_at is None:
        print("none", flush=True)
        sys.exit(0)
    block = []
    if not found_pending:
        block.append(pending_line)
    if not found_state:
        block.append(state_line)
    if not found_egress_pending:
        block.append(egress_pending_line)
    if not found_egress_state:
        block.append(egress_state_line)
    out[insert_at:insert_at] = block
    changed = True

if not changed:
    print("noop", flush=True)
    sys.exit(0)

with open(path, "w", encoding="utf-8") as f:
    f.writelines(out)
print("insert" if not (found_pending and found_state and found_egress_pending and found_egress_state) else "set", flush=True)
PYCOMPOSEVPN
    )
    case "$_action" in
        set|insert)
            print_success "docker-compose.yml: MPC_AUTH_VPN_* + MPC_AUTH_VPN_EGRESS_* env (relay and client compose)"
            ;;
        none)
            print_warning "docker-compose.yml: could not insert VPN env (MPC_AUTH_PENDING_REBOOT_FILE line missing)"
            ;;
        skip|noop) ;;
        error)
            print_warning "docker-compose.yml: failed to adjust VPN env"
            return 1
            ;;
    esac
}

_process_config_ensure_vpn_compose_env() {
    local cf="${REPO_ROOT}/docker-compose.yml"
    if [ ! -f "$cf" ]; then
        return 0
    fi
    apply_docker_compose_vpn_env "$cf" || true
}

# Bind-mount agent_llm_config.defaults so GET /listMcpServers and GET /listWebhooks see catalog updates after git pull.
apply_docker_compose_agent_llm_config_defaults_volume() {
    local file="$1"
    local enable="${2:-1}"
    local host_dir="./${DEFAULT_AGENT_LLM_CONFIG_BUNDLE_DIR}"
    local container_dir="${DEFAULT_AGENT_LLM_CONFIG_DEFAULTS_CONTAINER_DIR:-/app/agent_llm_config.defaults}"
    if [ ! -f "$file" ]; then
        return 0
    fi
    if ! command -v python3 &>/dev/null; then
        print_warning "python3 not found — could not adjust agent_llm_config.defaults bind-mount in docker-compose.yml"
        return 1
    fi
    local _action
    _action=$(
        COMPOSE_AGENT_DEFAULTS_FILE="$file" COMPOSE_AGENT_DEFAULTS_ENABLE="$enable" \
            COMPOSE_AGENT_DEFAULTS_HOST="$host_dir" COMPOSE_AGENT_DEFAULTS_CONTAINER="$container_dir" python3 << 'PYCOMPOSEAGENTDEFAULTS'
import os
import re
import sys

path = os.environ.get("COMPOSE_AGENT_DEFAULTS_FILE", "")
enable = os.environ.get("COMPOSE_AGENT_DEFAULTS_ENABLE", "1").strip() == "1"
host = os.environ.get("COMPOSE_AGENT_DEFAULTS_HOST", "./agent_llm_config.defaults").strip()
container = os.environ.get("COMPOSE_AGENT_DEFAULTS_CONTAINER", "/app/agent_llm_config.defaults").strip()
line_active = f"      - {host}:{container}:ro\n"
line_plain = f"      - {host}:{container}\n"
pat_defaults = re.compile(r"^\s*#?\s*-\s*\./agent_llm_config\.defaults:/app/agent_llm_config\.defaults")
pat_runtime = re.compile(r"^\s*#?\s*-\s*\./agent_llm_config:/app/agent_llm_config\s*$")

if not path or not host or not container:
    print("skip", flush=True)
    sys.exit(0)

try:
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()
except OSError as e:
    sys.stderr.write(f"{path}: {e}\n")
    print("error", flush=True)
    sys.exit(1)

if not enable:
    out = []
    removed = False
    for line in lines:
        if pat_defaults.match(line):
            removed = True
            continue
        out.append(line)
    if removed:
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(out)
        print("remove", flush=True)
    else:
        print("noop", flush=True)
    sys.exit(0)

for line in lines:
    if pat_defaults.match(line) and not line.lstrip().startswith("#"):
        print("already", flush=True)
        sys.exit(0)

out = []
inserted = False
for line in lines:
    out.append(line)
    if inserted:
        continue
    if pat_runtime.match(line):
        out.append("      # Repository catalog (MCP_servers.json, hooks/webhooks.json); host git pull updates this tree.\n")
        out.append(line_active)
        inserted = True

if not inserted:
    print("none", flush=True)
    sys.exit(0)

with open(path, "w", encoding="utf-8") as f:
    f.writelines(out)
print("insert", flush=True)
PYCOMPOSEAGENTDEFAULTS
    )
    case "$_action" in
        insert)
            print_success "docker-compose.yml: bind-mount ${host_dir} → ${container_dir} (catalog for MCP/webhooks)"
            ;;
        already)
            print_info "docker-compose.yml: agent_llm_config.defaults bind-mount already present"
            ;;
        remove)
            print_info "docker-compose.yml: removed agent_llm_config.defaults bind-mount (--no-agent-llm-config-path)"
            ;;
        none)
            print_warning "docker-compose.yml: could not insert agent_llm_config.defaults volume (./agent_llm_config:/app/agent_llm_config line missing)"
            ;;
        skip|noop) ;;
        error)
            print_warning "docker-compose.yml: failed to adjust agent_llm_config.defaults bind-mount"
            return 1
            ;;
    esac
}

_process_config_ensure_agent_llm_config_defaults_compose_volume() {
    if [ "${SKIP_AGENT_LLM_CONFIG_PATH:-false}" = true ]; then
        return 0
    fi
    local cf="${REPO_ROOT}/docker-compose.yml"
    if [ ! -f "$cf" ]; then
        return 0
    fi
    apply_docker_compose_agent_llm_config_defaults_volume "$cf" 1 || true
}

# After copying a compose template, uncomment or comment the loopback-only port line for BrowserLoopbackReadHTTP.
apply_docker_compose_loopback_mapping() {
    local file="$1"
    local enable="$2"
    local port="${DEFAULT_BROWSER_LOOPBACK_READ_HTTP_PORT:-8445}"
    if [ ! -f "$file" ]; then
        print_warning "docker-compose file not found: $file"
        return 1
    fi
    if ! command -v python3 &> /dev/null; then
        print_warning "python3 not found — could not adjust loopback port mapping in docker-compose.yml"
        return 1
    fi
    local _lc_action
    _lc_action=$(
        COMPOSE_LOOPBACK_FILE="$file" COMPOSE_LOOPBACK_ENABLE="$enable" COMPOSE_LOOPBACK_PORT="$port" python3 << 'PYCOMPOSE'
import os
import sys

path = os.environ.get("COMPOSE_LOOPBACK_FILE", "")
enable = os.environ.get("COMPOSE_LOOPBACK_ENABLE", "0").strip() == "1"
port = os.environ.get("COMPOSE_LOOPBACK_PORT", "8445").strip()
needle = f"127.0.0.1:{port}:{port}"
if not path or not needle:
    print("error", flush=True)
    sys.exit(1)
try:
    with open(path, "r") as f:
        lines = f.readlines()
except OSError as e:
    sys.stderr.write(f"{path}: {e}\n")
    print("error", flush=True)
    sys.exit(1)

has_needle = any(needle in line for line in lines)
action = "noop"

if has_needle:
    out = []
    for line in lines:
        if needle not in line:
            out.append(line)
            continue
        stripped = line.lstrip()
        if enable:
            if stripped.startswith("# ") and needle in stripped:
                out.append(f'      - "{needle}"\n')
                action = "uncomment"
            elif stripped.startswith('- "') and needle in stripped:
                out.append(line)
                action = "already_active"
            else:
                out.append(line)
        else:
            if stripped.startswith('- "') and needle in stripped:
                out.append(f'      # - "{needle}"\n')
                action = "comment"
            else:
                out.append(line)
    lines = out
elif not enable:
    # has_needle false, disabling: nothing to change
    pass
else:
    # Old docker-compose.yml (or hand-edited) with no loopback line: optionally insert after Browser HTTPS :8443 mapping.
    if enable:
        out = []
        inserted = False
        for line in lines:
            out.append(line)
            if inserted:
                continue
            st = line.lstrip()
            if st.startswith("- ") and "8443:8443" in line:
                out.append(
                    "      # Optional: loopback read HTTP (mpc-auth BrowserLoopbackReadHTTP) — same JWT routes without TLS in browser (SSH tunnel).\n"
                )
                out.append(f'      - "{needle}"\n')
                inserted = True
                action = "inserted"
        if not inserted:
            print("missing_anchor", flush=True)
            sys.exit(0)
        lines = out

with open(path, "w") as f:
    f.writelines(lines)
print(action, flush=True)
PYCOMPOSE
    )

    case "$_lc_action" in
        error)
            print_warning "Could not read or patch docker-compose.yml for loopback HTTP."
            ;;
        missing_anchor)
            print_warning "docker-compose.yml has no loopback line and no 8443:8443 port line to attach it after — add the mapping manually or update mpc-config templates and re-run."
            ;;
        inserted)
            print_success "docker-compose.yml: inserted loopback read HTTP mapping (127.0.0.1:${port}:${port}; file had no prior loopback line)."
            ;;
        uncomment|already_active)
            if [ "$enable" = "1" ]; then
                print_success "docker-compose.yml: loopback read HTTP enabled on host (127.0.0.1:${port}:${port} → container)."
            fi
            ;;
        comment)
            print_info "docker-compose.yml: loopback read HTTP port mapping commented out (disabled)."
            ;;
        noop)
            if [ "$enable" = "1" ]; then
                print_warning "docker-compose.yml: loopback enabled in configs but no ${port} mapping line was found or inserted — check your compose file."
            else
                print_info "docker-compose.yml: loopback read HTTP port mapping left unchanged (disabled / no loopback block)."
            fi
            ;;
    esac
}

# Interactive (or ENABLE_BROWSER_LOOPBACK_READ_HTTP / --enable-loopback-http) — sets BROWSER_LOOPBACK_READ_HTTP_ENABLED to 0 or 1.
prompt_browser_loopback_read_http() {
    if [ -n "${ENABLE_BROWSER_LOOPBACK_READ_HTTP+x}" ]; then
        case "$ENABLE_BROWSER_LOOPBACK_READ_HTTP" in
            1|yes|true|Y|y|YES|TRUE|on|ON)
                BROWSER_LOOPBACK_READ_HTTP_ENABLED=1
                ;;
            *)
                BROWSER_LOOPBACK_READ_HTTP_ENABLED=0
                ;;
        esac
        print_info "Browser loopback read HTTP (SSH tunnel / http://127.0.0.1): $([ "$BROWSER_LOOPBACK_READ_HTTP_ENABLED" = 1 ] && echo ENABLED || echo disabled) (from ENABLE_BROWSER_LOOPBACK_READ_HTTP)"
        return 0
    fi
    if [ ! -r /dev/tty ] || [ ! -w /dev/tty ]; then
        BROWSER_LOOPBACK_READ_HTTP_ENABLED=0
        if [ -n "${CONFIG_FILE:-}" ] && [ -f "$CONFIG_FILE" ] && command -v python3 &> /dev/null; then
            local _blr_infer
            _blr_infer=$(
                CONFIG_FILE_BLR_Q="$CONFIG_FILE" python3 << 'PYINF' 2>/dev/null || true
try:
    from ruamel.yaml import YAML
    import os
    p = os.environ.get("CONFIG_FILE_BLR_Q", "")
    if not p:
        print(0)
        raise SystemExit
    y = YAML()
    with open(p) as f:
        d = y.load(f) or {}
    b = d.get("BrowserLoopbackReadHTTP") if isinstance(d, dict) else None
    port = int(b.get("Port") or 0) if isinstance(b, dict) else 0
    print(1 if port > 0 else 0)
except Exception:
    print(0)
PYINF
            )
            if [ "$_blr_infer" = "1" ]; then
                BROWSER_LOOPBACK_READ_HTTP_ENABLED=1
                print_info "Browser loopback read HTTP: enabled (preserved from existing configs.yaml; non-interactive run). Use --disable-loopback-http to turn off."
                return 0
            fi
        fi
        print_info "Browser loopback read HTTP: disabled (no TTY; use --enable-loopback-http or ENABLE_BROWSER_LOOPBACK_READ_HTTP=1)"
        return 0
    fi
    echo ""
    print_step "Optional: loopback HTTP read API (DAO app over SSH tunnel)"
    print_info "Plain HTTP on 127.0.0.1 only — same JWT routes as Browser HTTPS; browser uses http://127.0.0.1 after ssh -L."
    print_info "This updates configs.yaml and docker-compose.yml automatically (no manual editing)."
    local _blr
    read -r -p "Enable loopback HTTP for this node? [Y/n]: " _blr < /dev/tty || true
    case "${_blr:-}" in
        [nN]*) BROWSER_LOOPBACK_READ_HTTP_ENABLED=0 ;;
        *) BROWSER_LOOPBACK_READ_HTTP_ENABLED=1 ;;
    esac
}

# Copy CA certificate to remote nodes
copy_certs_to_nodes() {
    local config_file="$1"
    local ca_cert="$2"
    
    if [ ! -f "$ca_cert" ]; then
        print_error "CA certificate file not found: $ca_cert"
        return 1
    fi
    
    print_step "Copying MQTT CA certificate to client nodes..."
    
    # Get all node addresses (excluding the first one, which is the relay node)
    local node_addresses=()
    local first_addr=$(get_first_node_address "$config_file")
    local first_host=""
    if [ -n "$first_addr" ]; then
        first_host=$(extract_host_from_url "$first_addr")
    fi
    
    while IFS= read -r addr; do
        [ -n "$addr" ] && [ "$addr" != "null" ] && node_addresses+=("$addr")
    done < <(parse_node_addresses_from_yaml "$config_file")
    
    if [ ${#node_addresses[@]} -eq 0 ]; then
        print_error "No node addresses found in configs.yaml"
        return 1
    fi
    
    local success_count=0
    local fail_count=0
    
    for node_addr in "${node_addresses[@]}"; do
        local node_host=$(extract_host_from_url "$node_addr")
        
        # Skip the first node (relay node - we're already on it)
        if [ "$node_host" = "$first_host" ]; then
            continue
        fi
        
        print_info "Copying certificate to $node_host..."
        
        # Try to determine remote path from configs.yaml or use default
        local remote_path="/mosquitto/config/certs/ca.crt"
        
        # Try to extract expected path from remote node's config (if accessible)
        # For now, use default path
        
        # Try SCP copy
        if command -v scp &> /dev/null; then
            # Try with current user
            if scp -o StrictHostKeyChecking=no -o ConnectTimeout=5 "$ca_cert" "${node_host}:${remote_path}" 2>/dev/null; then
                print_success "Successfully copied to $node_host:$remote_path"
                success_count=$((success_count + 1))
                continue
            fi
            
            # Try with root user
            if scp -o StrictHostKeyChecking=no -o ConnectTimeout=5 "$ca_cert" "root@${node_host}:${remote_path}" 2>/dev/null; then
                print_success "Successfully copied to root@$node_host:$remote_path"
                success_count=$((success_count + 1))
                continue
            fi
        fi
        
        # If SCP failed, provide manual instructions
        print_warning "Could not automatically copy to $node_host"
        print_info "  Manual copy required:"
        print_info "    scp $ca_cert user@$node_host:$remote_path"
        print_info "    Or use: rsync -avz $ca_cert user@$node_host:$remote_path"
        fail_count=$((fail_count + 1))
    done
    
    echo ""
    if [ $success_count -gt 0 ]; then
        print_success "Successfully copied certificate to $success_count node(s)"
    fi
    if [ $fail_count -gt 0 ]; then
        print_warning "Could not automatically copy to $fail_count node(s) - manual copy required"
        echo ""
        print_info "To manually copy certificates:"
        echo "  1. Use SCP: scp $ca_cert user@node-ip:/mosquitto/config/certs/ca.crt"
        echo "  2. Or use rsync: rsync -avz $ca_cert user@node-ip:/mosquitto/config/certs/ca.crt"
        echo "  3. Or transfer via secure file transfer method"
        echo ""
        print_info "After copying, ensure each node's configs.yaml has:"
        echo "  MQTTTLS:"
        echo "    CAFile: \"/mosquitto/config/certs/ca.crt\""
    fi
    
    return 0
}

# Public IP for this machine as listed in configs.yaml nodeAddresses (same match as validate_node_ip).
get_browser_https_node_ip() {
    local config_file="$1"
    local node_addresses=()
    local local_ips=()
    while IFS= read -r addr; do
        [ -n "$addr" ] && node_addresses+=("$addr")
    done < <(parse_node_addresses_from_yaml "$config_file")
    while IFS= read -r ip; do
        [ -n "$ip" ] && local_ips+=("$ip")
    done < <(get_local_ips)
    if [ ${#node_addresses[@]} -eq 0 ] || [ ${#local_ips[@]} -eq 0 ]; then
        return 1
    fi
    for local_ip in "${local_ips[@]}"; do
        for node_addr in "${node_addresses[@]}"; do
            local node_ip
            node_ip=$(extract_ip_from_url "$node_addr")
            if [ -n "$node_ip" ] && ip_matches "$local_ip" "$node_ip"; then
                echo "$node_ip"
                return 0
            fi
        done
    done
    local ext_ip
    ext_ip=$(get_external_ipv4_via_http) || true
    if [ -n "$ext_ip" ]; then
        for node_addr in "${node_addresses[@]}"; do
            local node_ip
            node_ip=$(extract_ip_from_url "$node_addr")
            if [ -n "$node_ip" ] && ip_matches "$ext_ip" "$node_ip"; then
                echo "$node_ip"
                return 0
            fi
        done
    fi
    return 1
}

# Generate browser HTTPS cert (IP SAN), write webTLS files, merge BrowserHTTPS into configs.yaml.
setup_browser_https() {
    local config_file="$1"
    local browser_ip
    browser_ip=$(get_browser_https_node_ip "$config_file") || {
        print_warning "Could not match this host to a node address — skipping Browser HTTPS setup"
        return 0
    }

    print_step "Browser HTTPS — web access / DAO app TLS (port 8443, webTLS/; separate from Mosquitto MQTT TLS)..."
    print_info "Using public IP from configs for certificate SAN: $browser_ip"

    if ! mkdir -p "$WEB_TLS_HOST_DIR" 2>/dev/null; then
        require_sudo_capable
        if sudo mkdir -p "$WEB_TLS_HOST_DIR" 2>/dev/null; then
            process_config_transfer_repo_path_to_invoking_user "$WEB_TLS_HOST_DIR"
        else
            print_error "Could not create $WEB_TLS_HOST_DIR"
            return 1
        fi
    fi

    local need_cert=true
    if [ -f "$BROWSER_HTTPS_CRT" ] && [ -f "$BROWSER_HTTPS_KEY" ]; then
        if [ "${FORCE_REGENERATE_BROWSER_HTTPS_CERTS:-0}" != "1" ]; then
            print_info "Browser HTTPS (webTLS) certificate files already exist — leaving them unchanged (not overwriting):"
            echo "  - $BROWSER_HTTPS_CRT"
            echo "  - $BROWSER_HTTPS_KEY"
            if openssl x509 -in "$BROWSER_HTTPS_CRT" -noout -text 2>/dev/null | grep -Fq "IP Address:${browser_ip}"; then
                print_success "Existing certificate includes SAN for IP $browser_ip"
            else
                print_warning "Existing certificate may not include SAN for IP $browser_ip — verify Browser HTTPS / Docker if connections fail"
                print_info "To regenerate: remove browser.crt/browser.key under $WEB_TLS_HOST_DIR or run with --force-browser-https-certs"
            fi
            need_cert=false
        else
            if openssl x509 -in "$BROWSER_HTTPS_CRT" -noout -text 2>/dev/null | grep -Fq "IP Address:${browser_ip}"; then
                need_cert=false
            else
                print_info "Regenerating Browser HTTPS (web) TLS cert — IP SAN mismatch or new IP (--force-browser-https-certs)"
            fi
        fi
    fi

    if [ "$need_cert" = true ]; then
        local sslcnf
        sslcnf=$(mktemp)
        cat > "$sslcnf" <<EOF
[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[ req_distinguished_name ]
CN = mpc-browser-https

[ v3_req ]
subjectAltName = @alt_names
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[ alt_names ]
IP.1 = $browser_ip
EOF
        if openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
            -keyout "$BROWSER_HTTPS_KEY" -out "$BROWSER_HTTPS_CRT" \
            -config "$sslcnf" -extensions v3_req 2>/dev/null; then
            rm -f "$sslcnf"
            chmod 600 "$BROWSER_HTTPS_KEY" 2>/dev/null || true
            chmod 644 "$BROWSER_HTTPS_CRT" 2>/dev/null || true
            _process_config_chown_repo_tree_if_sudo_root "$WEB_TLS_HOST_DIR"
            print_success "Browser HTTPS (web) certificate: $BROWSER_HTTPS_CRT"
        else
            rm -f "$sslcnf"
            print_error "Failed to generate Browser HTTPS (web) certificate"
            return 1
        fi
    else
        # With --force-browser-https-certs and SAN already matches, we only skipped regen — say so here.
        # When leaving existing files without --force, messages were already printed above.
        if [ "${FORCE_REGENERATE_BROWSER_HTTPS_CERTS:-0}" = "1" ]; then
            print_success "Browser HTTPS (web) certificate already valid for IP $browser_ip"
        fi
    fi

    if ! command -v python3 &> /dev/null; then
        print_warning "python3 not found — update configs.yaml BrowserHTTPS manually (see docs/internal/PROCESS_CONFIG_BROWSER_HTTPS.md)"
        return 0
    fi
    require_ruamel_yaml || return 1
    CONFIG_FILE_MERGE="$config_file" DEFAULT_ORIGIN_MERGE="$DEFAULT_BROWSER_HTTPS_ORIGIN" \
    DEFAULT_JWKS_MERGE="$DEFAULT_BROWSER_HTTPS_JWKS_URL" \
    DEFAULT_EXPECTED_ISSUER_MERGE="$DEFAULT_BROWSER_HTTPS_EXPECTED_ISSUER" \
    CONTAINER_CERT_MERGE="$BROWSER_HTTPS_CONTAINER_CERT" CONTAINER_KEY_MERGE="$BROWSER_HTTPS_CONTAINER_KEY" \
    python3 << 'PYMERGE'
import os
import sys
try:
    from ruamel.yaml import YAML
    from ruamel.yaml.comments import CommentedMap
except ImportError:
    sys.stderr.write("configs.yaml: install ruamel.yaml (pip install --user 'ruamel.yaml')\n")
    sys.exit(1)

path = os.environ["CONFIG_FILE_MERGE"]
default_origin = os.environ.get("DEFAULT_ORIGIN_MERGE", "https://mpa.continuumdao.org")
default_jwks = os.environ.get("DEFAULT_JWKS_MERGE", "https://mpa.continuumdao.org/api/node-read/jwks").strip()
default_expected_issuer = os.environ.get("DEFAULT_EXPECTED_ISSUER_MERGE", "https://mpa.continuumdao.org").strip()
cert = os.environ["CONTAINER_CERT_MERGE"]
key = os.environ["CONTAINER_KEY_MERGE"]

yaml = YAML()
yaml.preserve_quotes = True
yaml.width = 4096
yaml.indent(mapping=2, sequence=4, offset=2)

with open(path, "r") as f:
    data = yaml.load(f)
if data is None:
    data = {}
if not isinstance(data, dict):
    raise SystemExit("invalid yaml root")

bh = data.get("BrowserHTTPS")
if bh is None or not isinstance(bh, dict):
    bh = CommentedMap()
    data["BrowserHTTPS"] = bh

bh["Port"] = 8443
bh["CertFile"] = cert
bh["KeyFile"] = key
origins = bh.get("AllowedOrigins")
if not origins or not isinstance(origins, list) or len(origins) == 0:
    bh["AllowedOrigins"] = [default_origin]
bh["ExpectedAudience"] = bh.get("ExpectedAudience") or "mpc-node-read"
_ei = bh.get("ExpectedIssuer")
if _ei is None or (isinstance(_ei, str) and not str(_ei).strip()):
    bh["ExpectedIssuer"] = default_expected_issuer
bh["EnforceNodeIPClaim"] = bool(bh.get("EnforceNodeIPClaim", True))
_jw = bh.get("JWKSURL") or ""
jwks = _jw.strip() if isinstance(_jw, str) else str(_jw).strip()
if not jwks:
    jwks = default_jwks
bh["JWKSURL"] = jwks

with open(path, "w") as f:
    yaml.dump(data, f)
PYMERGE
    print_success "configs.yaml updated: BrowserHTTPS merged in place at end of file (header comments stay above the block; cert paths, AllowedOrigins, JWKSURL, ExpectedIssuer, ExpectedAudience, EnforceNodeIPClaim)"
    print_info "Defaults: JWKSURL=$DEFAULT_BROWSER_HTTPS_JWKS_URL, ExpectedIssuer=$DEFAULT_BROWSER_HTTPS_EXPECTED_ISSUER (Pattern B). Override in configs.yaml for standalone issuer (Pattern A). Docker: port 8443, volume ./webTLS/config/certs. See docs/internal/PROCESS_CONFIG_BROWSER_HTTPS.md"
}

# Writes BrowserLoopbackReadHTTP.Port and NodeIPForJWTMatch from the loopback prompt (no manual configs.yaml edits).
# Call after setup_browser_https so BrowserHTTPS is enabled first.
apply_browser_loopback_read_http_config() {
    local config_file="$1"
    local enable_loopback="${2:-0}"
    local port="${DEFAULT_BROWSER_LOOPBACK_READ_HTTP_PORT:-8445}"

    if ! command -v python3 &> /dev/null; then
        print_warning "python3 not found — cannot update BrowserLoopbackReadHTTP in configs.yaml"
        return 1
    fi
    require_ruamel_yaml || return 1

    local browser_ip=""
    if [ "$enable_loopback" = "1" ]; then
        browser_ip=$(get_browser_https_node_ip "$config_file") || browser_ip=""
        if [ -z "$browser_ip" ]; then
            print_warning "Could not match this host to a node address in configs.yaml — BrowserLoopbackReadHTTP.NodeIPForJWTMatch will be empty (JWT node_ip claim may need to match 127.0.0.1 or use DAO app public host field)."
        fi
    fi

    CONFIG_FILE_BLR="$config_file" ENABLE_BLR="$enable_loopback" BLR_PORT="$port" BROWSER_IP_BLR="$browser_ip" python3 << 'PYBLR'
import os
import sys
try:
    from ruamel.yaml import YAML
    from ruamel.yaml.comments import CommentedMap
except ImportError:
    sys.exit(1)

path = os.environ.get("CONFIG_FILE_BLR", "")
enable = os.environ.get("ENABLE_BLR", "0").strip() == "1"
try:
    port = int(os.environ.get("BLR_PORT", "8445").strip())
except ValueError:
    port = 8445
browser_ip = os.environ.get("BROWSER_IP_BLR", "").strip()

if not path:
    sys.exit(1)

yaml = YAML()
yaml.preserve_quotes = True
yaml.width = 4096
yaml.indent(mapping=2, sequence=4, offset=2)

with open(path, "r") as f:
    data = yaml.load(f)
if not isinstance(data, dict):
    data = {}
blr = data.get("BrowserLoopbackReadHTTP")
if blr is None or not isinstance(blr, dict):
    blr = CommentedMap()
    data["BrowserLoopbackReadHTTP"] = blr

if enable:
    blr["Port"] = port
    blr["NodeIPForJWTMatch"] = browser_ip
else:
    blr["Port"] = 0
    blr["NodeIPForJWTMatch"] = ""

with open(path, "w") as f:
    yaml.dump(data, f)
PYBLR

    if [ "$enable_loopback" = "1" ]; then
        print_success "configs.yaml: BrowserLoopbackReadHTTP enabled (Port ${port}, NodeIPForJWTMatch set for this node). Restart docker-compose to apply."
        print_info "See docs/internal/SSH_TUNNEL_LOOPBACK_HTTP.md"
    else
        print_info "configs.yaml: BrowserLoopbackReadHTTP disabled (Port 0)."
    fi
}

show_process_config_help() {
    echo "Usage: $0 [ARGUMENTS]"
    echo ""
    echo "Arguments:"
    echo "  --copy-certs      On the relay: after MQTT certs are generated, copy the CA to clients over SSH"
    echo "  --no-copy-certs   Do not copy via SSH (default); kept for explicit use / backward compatibility"
    echo "  --no-firewall     Skip the default host firewall step (ufw allow rules). Not recommended for production."
    echo "  --force-mqtt-certs              Prompt to overwrite existing mosquitto/config/certs/* (default: leave existing files)"
    echo "  --force-browser-https-certs     Allow regenerating webTLS/config/certs/browser.* when SAN/IP mismatches (default: leave existing files)"
    echo "  --enable-loopback-http          Enable SSH-tunnel loopback read HTTP (configs.yaml + docker-compose; non-interactive)"
    echo "  --disable-loopback-http         Disable loopback read HTTP (non-interactive)"
    echo "  --no-systemd                    Skip optional mpc-auth Docker systemd installer prompts (after firewall; before Relayer check — see mpc-config/systemd/README.md)."
    echo "  --no-agent-llm-config-path      Do not set AgentLlmConfigDir in configs.yaml, agent_llm_config bind-mount, or MPC_AUTH_AGENT_LLM_CONFIG_FILE in docker-compose.yml."
    echo "  --install-mpc-auth-systemd      Non-interactive: sudo-run systemd/install-mpc-auth-docker-systemd.sh (requires sudo; may prompt restart)."
    echo "  --sync-compose-role-only        Non-interactive: switch docker-compose.yml relay/client from configs.yaml (host systemd; may generate MQTT certs)."
    echo "  --help | -h | -help | help   Show this message (arguments above + relay/client behavior below)"
    echo ""
    echo "Environment (optional): FORCE_REGENERATE_MQTT_CERTS=1 / FORCE_REGENERATE_BROWSER_HTTPS_CERTS=1 same as the flags above."
    echo "  ENABLE_BROWSER_LOOPBACK_READ_HTTP=0|1 — loopback HTTP when not using an interactive TTY (or override the prompt)."
    echo "  DEFAULT_BROWSER_LOOPBACK_READ_HTTP_PORT — listener/host port (default 8445; must match docker-compose mapping)."
    echo "  UFW_OPEN_MANAGEMENT_PORT=1 — add ufw allow for ManagementAPIsPort (default: management port not opened in UFW)."
    echo "  APPLY_LOOPBACK_MONGO_OWNER_FW=0 — skip UFW after.rules patch that drops non-root → 127.0.0.1:Mongo (default: apply)."
    echo "  MONGO_LOOPBACK_FW_PORT=<n> — override published Mongo TCP port used in that drop rule (default 27017)."
    echo "  With docker-compose*.yml in the config dir: auto-copy .env.example → .env if .env is missing (even without MONGO_* in env)."
    echo "  With MONGO_INITDB_ROOT_PASSWORD + MONGO_APP_PASSWORD exported: merge those credentials into .env (and MongodbUri if absent — derived from user/pass/db)."
    echo "  PROCESS_CONFIG_MERGE_DOTENV_FROM_ENV=1 — also merge mongo-related keys into an existing .env (overwrite values from env)."
    echo "  PROCESS_CONFIG_SKIP_DOTENV_FROM_ENV=1 — disable .env creation/merge entirely."
    echo "  PROCESS_CONFIG_INSTALL_SYSTEMD=1 — same as --install-mpc-auth-systemd (non-interactive install)."
    echo "  PROCESS_CONFIG_NONINTERACTIVE=1 — skip optional prompts (RelayerAPIURL / ScannerAPIURLs use defaults when unset; root continue; second management key; MQTT overwrite if regenerating; UFW enable ask; systemd Y/n)."
    echo "  PROCESS_CONFIG_SKIP_AGENT_LLM_CONFIG_PATH=1 — same as --no-agent-llm-config-path."
    echo "  MPC_CONFIG_ROOT=/path/to/mpc-config — locate systemd/install-mpc-auth-docker-systemd.sh when the script runs"
    echo "    from mpc-auth (or any tree that does not include mpc-config/systemd next to repo root)."
    echo "  MPC_AUTH_COMPOSE_APP_IMAGE — full image reference for the app container. Templates use"
    echo "    \${MPC_AUTH_COMPOSE_APP_IMAGE:-continuumdao/mpc-auth:latest}; set this for a custom registry or tag."
    echo "    When set, process_config rewrites the generated compose app image line to this concrete ref."
    echo ""
    echo "This script validates configuration and generates certificates."
    echo ""
    echo "If PublicMgtKey in configs.yaml is an ssh-ed25519 line or OpenSSH base64 blob, it is rewritten to 64 hex (tools/openssh_ed25519_to_hex.py)."
    echo "If NodeMgtKey or PublicMgtKey is empty, the script prompts first (interactive TTY): Ethereum wallet / NodeMgtKey"
    echo "and/or Ed25519 public key (64 hex, ssh-ed25519 line, or base64 blob; tools/openssh_ed25519_to_hex.py)."
    echo "tools/bootstrap_key_provision.py runs for every configs.yaml:"
    echo "  - PublicMgtKey empty: creates bootstrap_key/ed25519_private.hex (0600), sets PublicMgtKey + DeterministicNodeKey."
    echo "  - PublicMgtKey preset (reinstall): if bootstrap_key/ed25519_private.hex exists and matches, sets DeterministicNodeKey."
    echo "  - PROVISION_DEFER_NODE_KEY_UNTIL_BOOTSTRAP=1 (provision-node.sh --public-mgt-key): seed absent → DeterministicNodeKey true,"
    echo "    bootstrap-pending (no random nodeKey) until seed or POST /postBootstrapKey."
    echo "Without a TTY when PublicMgtKey is still empty but NodeMgtKey is valid (e.g. provision-node.sh -k only),"
    echo "bootstrap_key_provision.py fills Ed25519 the same way."
    echo "Reinstall with an existing Ed25519 public key: install bootstrap_key/ed25519_private.hex before process_config completes"
    echo "so deterministic nodeKey aligns on fresh Mongo (scripts/provision-node.sh copies configs.yaml before process_config)."
    echo "At least one valid NodeMgtKey or PublicMgtKey is required before bootstrap_key_provision.py."
    echo ""
    echo "Then, if MPCGroups[0].nodeAddresses is empty or still uses the default 203.0.113.10–12 example IPs, the script prompts"
    echo "and writes http://...:${MPC_NODE_HTTP_PORT} URLs (first entry = relay; same order on all nodes)."
    echo "For automation, the first URL host may be ${NODE_ADDRESSES_RELAY_PLACEHOLDER_IPV4} (relay IP unknown until set in UI):"
    echo "  client path (no MQTT relay generation, no mqttBroker from first node) until first is real; this host must still appear in nodeAddresses as a peer (any slot)."
    echo "On later runs (interactive TTY), an optional menu (0=continue, 1=add, 2=remove) lets you edit node IPs."
    echo "Set SKIP_NODE_ADDRESS_MENU=1 to skip that menu (e.g. automation)."
    echo ""
    echo "If PreSigningVerification is set but RelayerAPIURL is empty, the script prompts for the URL"
    echo "(or use RELAYER_API_URL in the environment)."
    echo "If ScannerAPIURLs is empty, it prompts (Enter = defaults) for UFW-scoped ScannerRelayer rules."
    echo ""
    echo "Updates to configs.yaml require ruamel.yaml (e.g. apt install python3-ruamel.yaml, or pip in a venv)"
    echo "so the prototype file's comments are preserved on round-trip."
    echo "Auto-generated bootstrap keys (tools/bootstrap_key_provision.py) require: pip install cryptography"
    echo ""
    echo "On RELAY NODE (first node):"
    echo "  - Validates configuration"
    echo "  - Validates database connectivity (if PreSigningVerification is configured)"
    echo "  - Generates MQTT (mosquitto) certificates"
    echo "  - Enables Browser HTTPS: TLS cert in webTLS/config/certs, configs.yaml BrowserHTTPS, Docker 8443"
    echo "  - Prompts for SSH tunnel loopback HTTP [Y/n] interactive default: enable (or use --enable-loopback-http / ENABLE_BROWSER_LOOPBACK_READ_HTTP); updates configs.yaml and docker-compose.yml"
    echo "  - Does not copy CA to client nodes by default (use --copy-certs for automatic SSH copy)"
    echo ""
    echo "On CLIENT NODES:"
    echo "  - Validates configuration"
    echo "  - Validates database connectivity (if PreSigningVerification is configured)"
    echo "  - Validates CA certificate is configured correctly"
    echo "  - Generates Browser HTTPS cert for this node's IP + updates configs.yaml (MQTT CA only on relay)"
    echo ""
    echo "Note: Relayer API connectivity validation requires curl to be installed."
    echo "      If PreSigningVerification is configured, ensure RelayerAPIURL is set"
    echo "      in configs.yaml (obtain from the DAO)."
    echo ""
    echo "Host firewall:"
    echo "  By default this script runs a host firewall step (ufw when available), which requires sudo for ufw status/rules."
    echo "  Rules: allow SSH (22),"
    echo "  Browser HTTPS (8443), PublicDiscoveryPort (18080), ScannerRelayerPort (18081 if set),"
    echo "  ManagementAPIsPort (8080), relay MQTT (8883). ScannerRelayerPort uses *scoped* UFW rules when"
    echo "  PreSigningVerification.RelayerAPIURL and/or ScannerAPIURLs resolve to IPv4 (see configs.yaml)."
    echo "  ManagementAPIsPort is not opened in UFW by default; set UFW_OPEN_MANAGEMENT_PORT=1 if peers/operators need inbound HTTP to the management API."
    echo "  Loopback Mongo: after baseline rules, installs /etc/ufw/after.rules DROP for non-root → 127.0.0.1:Mongo (disable: APPLY_LOOPBACK_MONGO_OWNER_FW=0)."
    echo "  Peer egress VPN (wg-egress): opens UFW UDP WireGuardEgress.ListenPort (default 51830) and TCP+UDP ShadowsocksEgress.ListenPort (default 8390)."
    echo "  Also prints provider-panel reminders — cloud SG must allow the same ports (UDP 51830 direct; TCP+UDP 8390 when Shadowsocks egress is used)."
    echo "  If UFW is inactive, you are prompted (via /dev/tty) to run sudo ufw enable, or enable manually."
    echo "  Use --no-firewall to skip (not recommended for production / financial nodes)."
    echo ""
    echo "Optional mpc-auth Docker systemd helpers (Linux + systemd; after firewall, before Relayer API validation):"
    echo "  Prompts install or re-sync of mpc-config/systemd/ (daemon-reload) with [Y/n] default Yes;"
    echo "  After prompts, if units are on the host, automatically runs install-mpc-auth-docker-systemd.sh --no-env"
    echo "  so /usr/local/libexec/mpc-auth/*.sh matches this repo (git pull does not update libexec otherwise)."
    echo "  Skipped with --no-systemd or PROCESS_CONFIG_SKIP_SYSTEMD=1."
    echo "  When mpc-auth units exist on the host, also prompts to start mpc-auth-docker-restart.service"
    echo "  if a resolvable mpc-auth container exists ([Y/n] default Yes); skipped when Docker is down or no container yet."
    echo "  See systemd/README.md."
    echo ""
}

# Resolve RelayerAPIURL / ScannerAPIURLs entry to a UFW "from" source (IPv4 or IPv4 CIDR).
# Accepts full URLs (port in URL is ignored for firewall—only host matters), bare hostnames, IPv4, or x.x.x.x/nn.
_firewall_entry_to_ufw_source() {
    local raw="$1"
    python3 -c '
import sys, socket, urllib.parse, re
s = (sys.argv[1] or "").strip()
if not s:
    sys.exit(1)
if re.match(r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$", s):
    print(s)
    sys.exit(0)
if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", s):
    print(s)
    sys.exit(0)
u = s if "://" in s else "http://" + s
p = urllib.parse.urlparse(u)
h = p.hostname
if not h:
    sys.exit(1)
if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", h):
    print(h)
    sys.exit(0)
try:
    infos = socket.getaddrinfo(h, None, socket.AF_INET, socket.SOCK_STREAM)
    print(infos[0][4][0])
except Exception:
    sys.exit(1)
' "$raw" 2>/dev/null
}

# Collect unique IPv4/CIDR sources for ScannerRelayerPort from configs.yaml (RelayerAPIURL host + ScannerAPIURLs).
# When ScannerAPIURLs is empty, DEFAULT_SCANNER_API_URLS applies (see top of script).
_firewall_collect_scanner_relayer_sources() {
    local config_file="$1"
    local tmpf
    tmpf=$(mktemp) || return 1
    local ru line src _yaml_had_scanner
    _yaml_had_scanner=false
    ru=$(_extract_relayer_api_url_from_config "$config_file")
    ru="${ru//$'\r'/}"
    ru="${ru//$'\n'/}"
    if [[ -n "${ru//[[:space:]]/}" && "$ru" != "null" ]]; then
        src=$(_firewall_entry_to_ufw_source "$ru")
        [[ -n "$src" ]] && echo "$src" >>"$tmpf"
    fi
    while IFS= read -r line || [[ -n "$line" ]]; do
        line=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        [[ -z "$line" || "$line" == "null" ]] && continue
        _yaml_had_scanner=true
        src=$(_firewall_entry_to_ufw_source "$line")
        [[ -n "$src" ]] && echo "$src" >>"$tmpf"
    done < <(_configs_yaml_scanner_api_urls_lines "$config_file")
    if [[ "$_yaml_had_scanner" != "true" ]]; then
        for line in "${DEFAULT_SCANNER_API_URLS[@]}"; do
            [[ -z "${line//[[:space:]]/}" ]] && continue
            src=$(_firewall_entry_to_ufw_source "$line")
            [[ -n "$src" ]] && echo "$src" >>"$tmpf"
        done
    fi
    if [[ ! -s "$tmpf" ]]; then
        rm -f "$tmpf"
        return 1
    fi
    sort -u "$tmpf"
    rm -f "$tmpf"
}

# Read listener ports from configs.yaml root (same semantics as mpc-auth node). Uses ruamel.yaml so we do not
# depend on which `yq` binary is installed (mikefarah `yq eval` vs python-yq — the latter breaks `.ScannerRelayerPort`).
# Prints: ManagementAPIsPort|PublicDiscoveryPort|BrowserHTTPSFirewallPort|ScannerRelayerPort
_firewall_read_listener_ports_from_configs_yaml() {
    local config_file="$1"
    FW_PORTS_CFG="$config_file" python3 << 'PYFWPORTS'
import os
import sys
try:
    from ruamel.yaml import YAML
except ImportError:
    sys.exit(2)

path = os.environ.get("FW_PORTS_CFG", "")
if not path:
    sys.exit(1)

y = YAML()
with open(path) as f:
    d = y.load(f)
if not isinstance(d, dict):
    d = {}

def _scalar_int(v, default):
    if v is None:
        return default
    try:
        return int(v)
    except (TypeError, ValueError):
        return default

mgt = _scalar_int(d.get("ManagementAPIsPort"), 8080)
pub = _scalar_int(d.get("PublicDiscoveryPort"), 18080)
sr = _scalar_int(d.get("ScannerRelayerPort"), 0)
bh = d.get("BrowserHTTPS")
bp = None
if isinstance(bh, dict):
    bp = bh.get("Port")
# Match prior yq intent: missing or 0 → use 8443 for firewall allow line (Browser HTTPS listener default)
if bp is None or bp == 0:
    bh_fw = 8443
else:
    bh_fw = _scalar_int(bp, 8443)

print(f"{mgt}|{pub}|{bh_fw}|{sr}")
PYFWPORTS
}

# WireGuard admin + peer egress (wg-egress) ports from configs.yaml. Defaults match mpc-auth managementapi_vpn*.go.
# Prints: wg_admin_udp|ss_admin_tcp|wg_egress_udp|ss_egress_tcp
_firewall_read_vpn_ports_from_configs_yaml() {
    local config_file="$1"
    FW_VPN_PORTS_CFG="$config_file" python3 << 'PYFWVPNPORTS'
import os
import sys
try:
    from ruamel.yaml import YAML
except ImportError:
    sys.exit(2)

path = os.environ.get("FW_VPN_PORTS_CFG", "")
if not path:
    sys.exit(1)

y = YAML()
with open(path) as f:
    d = y.load(f)
if not isinstance(d, dict):
    d = {}

def _scalar_int(v, default):
    if v is None:
        return default
    try:
        return int(v)
    except (TypeError, ValueError):
        return default

def _section_port(section_key, field, default):
    sec = d.get(section_key)
    if isinstance(sec, dict):
        return _scalar_int(sec.get(field), default)
    return default

wg_admin = _section_port("WireGuard", "ListenPort", 51820)
ss_admin = _section_port("Shadowsocks", "ListenPort", 8388)
wg_egress = _section_port("WireGuardEgress", "ListenPort", 51830)
ss_egress = _section_port("ShadowsocksEgress", "ListenPort", 8390)
print(f"{wg_admin}|{ss_admin}|{wg_egress}|{ss_egress}")
PYFWVPNPORTS
}

# Enable UFW before config processing / firewall rules (--no-firewall skips entirely).
ensure_ufw_active_early() {
    local skip_firewall="$1"

    if [ "$skip_firewall" = "true" ]; then
        return 0
    fi

    require_sudo_capable

    print_step "UFW: ensure firewall is active (use --no-firewall to skip)"

    if ! command -v ufw >/dev/null 2>&1; then
        print_error "ufw is not installed. Install with: sudo apt install ufw"
        exit 1
    fi

    local ufw_full ufw_state
    ufw_full=$(sudo ufw status 2>&1) || {
        print_error "sudo ufw status failed. Ensure sudo works."
        exit 1
    }
    ufw_state=$(printf '%s\n' "$ufw_full" | head -1)
    print_info "UFW: ${ufw_state:-<no output>}"

    if echo "$ufw_state" | grep -qiE '^Status:[[:space:]]+active([[:space:]]|$)'; then
        print_info "UFW is already active."
        return 0
    fi

    print_info "UFW is inactive — allowing SSH (OpenSSH or 22/tcp), then enabling."
    if sudo ufw allow OpenSSH 2>/dev/null; then
        :
    elif sudo ufw allow 22/tcp 2>/dev/null; then
        :
    else
        print_error "Failed to add a UFW rule for SSH before enable (tried OpenSSH and 22/tcp)."
        exit 1
    fi

    if ! sudo ufw --force enable; then
        print_error "sudo ufw --force enable failed."
        exit 1
    fi

    ufw_full=$(sudo ufw status 2>&1) || {
        print_error "sudo ufw status failed after enable."
        exit 1
    }
    ufw_state=$(printf '%s\n' "$ufw_full" | head -1)
    if ! echo "$ufw_state" | grep -qiE '^Status:[[:space:]]+active([[:space:]]|$)'; then
        print_error "UFW is not active after enable. Output: ${ufw_state:-$ufw_full}"
        exit 1
    fi
    print_success "UFW is active (SSH allowed for remote admin)."
}

# Drop TCP OUTPUT from non-root OS users toward 127.0.0.1:$mongo_port (Compose Mongo bind). Persisted under
# /etc/ufw/after.rules; complements MongodbUri auth (mpc-auth docs-internal threat model).
_apply_loopback_mongodb_owner_firewall_via_ufw_after_rules() {
    local mongo_port="${MONGO_LOOPBACK_FW_PORT:-27017}"
    local skip_firewall="$1"

    case "${APPLY_LOOPBACK_MONGO_OWNER_FW:-1}" in
        0 | false | FALSE | no | NO) return 0 ;;
    esac

    if [ "$skip_firewall" = "true" ]; then
        return 0
    fi

    print_step "UFW after.rules: non-root outbound to localhost Mongo (${mongo_port}/tcp)"

    if ! command -v python3 >/dev/null 2>&1; then
        print_warning "python3 missing — skipping Mongo loopback owner rule (${mongo_port/tcp}; see PROCESS_CONFIG_FIREWALL.md)."
        return 0
    fi

    local ar="/etc/ufw/after.rules" mpc_tmp py_exit
    mpc_tmp=$(mktemp) || return 1
    # Expand path now: RETURN trap survives into caller (apply_process_config_firewall) and would
    # re-fire with an unbound local under set -u (load-install-progress.sh).
    # shellcheck disable=SC2064
    trap "rm -f \"${mpc_tmp}\"" RETURN

    py_exit=0
    MPC_LOOPBACK_TMP="$mpc_tmp" MPC_FW_PORT="$mongo_port" python3 <<'PYCODE'
import pathlib
import os
import sys

begin = "# BEGIN mpc-config-loopback-mongo-fw"
end = "# END mpc-config-loopback-mongo-fw"

port_s = os.environ["MPC_FW_PORT"]
# Numeric UID required: iptables-restore (ufw reload) does not reliably accept --uid-owner root.
# Chain must be ufw-after-output: ufw-init restores after.rules *before* user.rules (ufw-user-output
# does not exist yet), so -A ufw-user-output here fails iptables-restore (typically "line 35").
want_rule = "-A ufw-after-output -d 127.0.0.1/32 -p tcp --dport {} -m owner ! --uid-owner 0 -j DROP".format(port_s)
new_block_txt = "".join(["{}\n".format(begin), "# Host UIDs other than root: drop tcp toward Compose Mongo bind (127.0.0.1).\n", "{}\n".format(want_rule), "{}\n".format(end), "\n"])
rules_fp = pathlib.Path("/etc/ufw/after.rules")


def strip_block(text_data):
    frag, skip = [], False
    for ln in text_data.splitlines(keepends=True):
        s = ln.strip()
        if s == begin:
            skip = True
            continue
        if skip and s == end:
            skip = False
            continue
        if not skip:
            frag.append(ln)
    return "".join(frag)


def inject(text_data):
    lines = text_data.splitlines(keepends=True)
    out, scan, ok = [], False, False
    for ln in lines:
        if ln.strip() == "*filter":
            scan = True
        if scan and ln.strip() == "COMMIT":
            out.append(new_block_txt)
            scan, ok = False, True
        out.append(ln)
    return "".join(out), ok


try:
    raw = rules_fp.read_text(encoding="utf-8", errors="replace")
except OSError as e:
    sys.stderr.write("mpc-config: cannot read {}: {}\n".format(rules_fp, e))
    sys.exit(2)

if begin in raw and want_rule.strip() in raw:
    pathlib.Path(os.environ["MPC_LOOPBACK_TMP"]).write_text("", encoding="utf-8")
    sys.stdout.write("unchanged\n")
    sys.exit(0)

rewritten, injected = inject(strip_block(raw))
if not injected:
    sys.stderr.write(
        "mpc-config: no *filter COMMIT anchor in {}; add iptables DROP manually (PROCESS_CONFIG_FIREWALL.md).\n".format(rules_fp)
    )
    sys.exit(3)
if rewritten == raw:
    pathlib.Path(os.environ["MPC_LOOPBACK_TMP"]).write_text("", encoding="utf-8")
    sys.stdout.write("unchanged\n")
    sys.exit(0)
pathlib.Path(os.environ["MPC_LOOPBACK_TMP"]).write_text(rewritten, encoding="utf-8")
PYCODE
    py_exit=$?

    if [ "$py_exit" -ne 0 ]; then
        print_warning "Could not derive updated UFW rules for ${ar} (exit ${py_exit})."
        return 0
    fi

    if ! sudo test -s "$mpc_tmp"; then
        return 0
    fi

    if sudo cmp -s "$mpc_tmp" "$ar" 2>/dev/null; then
        return 0
    fi

    if ! sudo install -m 0644 -o root -g root "$mpc_tmp" "$ar"; then
        print_error "Failed to install updated $ar (sudo install)."
        return 1
    fi

    if ! sudo ufw reload; then
        print_error "sudo ufw reload failed after updating $ar — fix UFW manually."
        return 1
    fi
    print_success "Installed loopback Mongo owner-drop in $ar and reloaded UFW."
}

# ContinuumdaoNodeApp.Enabled + HostPort — for UFW allow on dashboard HTTP (HostPort maps host → container 3000).
_firewall_read_continuumdao_node_app_listen() {
    local config_file="$1"
    if [ -z "$config_file" ] || [ ! -f "$config_file" ]; then
        return 1
    fi
    if ! command -v python3 >/dev/null 2>&1; then
        return 1
    fi
    FW_NODE_APP_LISTEN_CFG="$config_file" python3 <<'PYFNA'
import os
import sys

try:
    from ruamel.yaml import YAML
except ImportError:
    sys.exit(2)

path = os.environ.get("FW_NODE_APP_LISTEN_CFG", "")
if not path:
    sys.exit(1)

y = YAML()
with open(path, encoding="utf-8") as f:
    d = y.load(f) or {}
if not isinstance(d, dict):
    d = {}


def scalar_int(val, default):
    if val is None:
        return default
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


def scalar_bool(val, default):
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    s = str(val).strip().lower()
    if s in ("0", "false", "no", "off", ""):
        return False
    if s in ("1", "true", "yes", "on"):
        return True
    return default


na = d.get("ContinuumdaoNodeApp")
enabled = True
host_port = 3333
if na is None:
    pass
elif isinstance(na, dict):
    enabled = scalar_bool(na.get("Enabled"), True)
    host_port = scalar_int(na.get("HostPort"), host_port)
else:
    enabled = False

if host_port <= 0 or host_port > 65535:
    host_port = 3333
print(f"{1 if enabled else 0}|{host_port}", flush=True)
PYFNA
}

apply_process_config_firewall() {
    local config_file="$1"
    local skip_firewall="$2"
    local is_relay="$3"

    if [ "$skip_firewall" = "true" ]; then
        print_warning "Host firewall step skipped (--no-firewall)."
        print_warning "Not recommended for production or financial MPC nodes—configure ufw/nftables or cloud security groups yourself."
        print_info "See: docs/internal/PROCESS_CONFIG_FIREWALL.md"
        return 0
    fi

    require_sudo_capable

    print_step "Host firewall (recommended for financial / MPC nodes)"

    local mgt_port pub_port bh_port sr_port
    local _pl
    if _pl=$(_firewall_read_listener_ports_from_configs_yaml "$config_file" 2>/dev/null) && [ -n "$_pl" ]; then
        IFS='|' read -r mgt_port pub_port bh_port sr_port <<< "$_pl"
    else
        # Fallback if ruamel.yaml missing: yq (mikefarah) — may fail if only python-yq is installed
        mgt_port=$(yq eval '.ManagementAPIsPort // 8080' "$config_file" 2>/dev/null || echo 8080)
        pub_port=$(yq eval '.PublicDiscoveryPort // 18080' "$config_file" 2>/dev/null || echo 18080)
        bh_port=$(yq eval '(.BrowserHTTPS // {}).Port // 8443' "$config_file" 2>/dev/null || echo 8443)
        sr_port=$(yq eval '.ScannerRelayerPort // 0' "$config_file" 2>/dev/null || echo 0)
        mgt_port="${mgt_port//[$'\t\r\n']/}"
        pub_port="${pub_port//[$'\t\r\n']/}"
        sr_port="${sr_port//[$'\t\r\n']/}"
        bh_port="${bh_port//[$'\t\r\n']/}"
        print_warning "Could not read ports via ruamel.yaml — using yq fallback (install: sudo apt install python3-ruamel.yaml)"
    fi
    # BOM / odd indent: last-chance grep for ScannerRelayerPort if still 0
    if [ -z "$sr_port" ] || [ "$sr_port" = "null" ] || [ "$sr_port" = "0" ]; then
        local _sr_grep
        _sr_grep=$(LC_ALL=C awk '/^[[:space:]]*ScannerRelayerPort:/ { sub(/#.*/,""); sub(/^[[:space:]]*ScannerRelayerPort:[[:space:]]*/, ""); gsub(/["'\'']/, ""); print; exit }' "$config_file" 2>/dev/null || true)
        _sr_grep="${_sr_grep//[$'\t\r\n']/}"
        if [ -n "$_sr_grep" ] && [ "$_sr_grep" != "null" ]; then
            sr_port="$_sr_grep"
        fi
    fi

    print_info "Ports from configs.yaml: ManagementAPIsPort=$mgt_port, PublicDiscoveryPort=$pub_port, BrowserHTTPS (firewall allow port)=$bh_port, ScannerRelayerPort=${sr_port:-0}"
    print_info "BrowserLoopbackReadHTTP (SSH tunnel) binds 127.0.0.1 in the container — no WAN UFW rule for that port; access is via ssh -L to localhost."
    print_info "Narrow inbound to scanner/DAO/relayer CIDRs in production; see docs/internal/PROCESS_CONFIG_FIREWALL.md"
    if [ "$is_relay" = "true" ]; then
        print_info "Relay node: MQTT broker TLS typically uses 8883/tcp (docker-compose)."
    fi

    if ! command -v ufw >/dev/null 2>&1; then
        print_error "ufw is not installed (expected active UFW). Install with: sudo apt install ufw"
        exit 1
    fi

    local ufw_state ufw_full
    # Capture stderr too — sudo may fail silently with 2>/dev/null and leave status empty.
    ufw_full=$(sudo ufw status 2>&1) || true
    ufw_state=$(printf '%s\n' "$ufw_full" | head -1)
    print_info "UFW: ${ufw_state:-<no output>}"
    if [ -z "$ufw_state" ]; then
        print_warning "Could not read UFW status (sudo may need a password, or ufw failed). Run: sudo ufw status"
    fi

    apply_one_ufw() {
        local port="$1"
        local note="$2"
        if [ -z "$port" ] || [ "$port" = "0" ]; then
            print_warning "Skipping UFW rule for invalid port (${port:-empty}) ($note)"
            return 0
        fi
        # Anchor to start of line so e.g. port 0 does not match 18080/tcp; ufw status lists as "8080/tcp ..."
        if sudo ufw status 2>/dev/null | grep -qE "^[[:space:]]*${port}/tcp"; then
            print_info "UFW rule already present for ${port}/tcp ($note)"
            return 0
        fi
        if sudo ufw allow "${port}/tcp" comment "$note" 2>/dev/null; then
            print_success "UFW: allowed ${port}/tcp ($note)"
        else
            print_warning "Could not add UFW rule for ${port}/tcp (need sudo?)"
        fi
    }

    apply_one_ufw_udp() {
        local port="$1"
        local note="$2"
        if [ -z "$port" ] || [ "$port" = "0" ]; then
            print_warning "Skipping UFW rule for invalid UDP port (${port:-empty}) ($note)"
            return 0
        fi
        if sudo ufw status 2>/dev/null | grep -qE "^[[:space:]]*${port}/udp"; then
            print_info "UFW rule already present for ${port}/udp ($note)"
            return 0
        fi
        if sudo ufw allow "${port}/udp" comment "$note" 2>/dev/null; then
            print_success "UFW: allowed ${port}/udp ($note)"
        else
            print_warning "Could not add UFW rule for ${port}/udp (need sudo?)"
        fi
    }

    apply_shadowsocks_ufw() {
        local port="$1"
        local note="$2"
        apply_one_ufw "$port" "$note"
        apply_one_ufw_udp "$port" "$note UDP"
    }

    # With IPV6=yes in /etc/default/ufw (Ubuntu default), each "ufw allow <port>/tcp" adds IPv4 + IPv6 rules.
    print_info "UFW baseline uses dual-stack when IPv6 is enabled (see /etc/default/ufw). Add v6-only rules manually if needed."

    # SSH first — avoid lockout if ufw is later enabled
    apply_one_ufw 22 "ssh"
    apply_one_ufw "$bh_port" "mpc-auth BrowserHTTPS"
    apply_one_ufw "$pub_port" "mpc-auth PublicDiscovery"
    local _na_fw _na_en _na_hp
    if _na_fw=$(_firewall_read_continuumdao_node_app_listen "$config_file"); then
        IFS='|' read -r _na_en _na_hp <<< "$_na_fw"
        if [ "$_na_en" = "1" ] && [ -n "$_na_hp" ] && [ "$_na_hp" != "0" ]; then
            if [ "$_na_hp" != "$bh_port" ] && [ "$_na_hp" != "$pub_port" ] && [ "$_na_hp" != "$mgt_port" ]; then
                apply_one_ufw "$_na_hp" "continuumdao-node-app dashboard"
            else
                print_info "UFW: continuumdao-node-app HostPort ${_na_hp} matches an existing mpc-auth listener port — no duplicate rule."
            fi
        fi
    fi
    # ScannerRelayerPort: open unless same port already covered by another listener rule above.
    # Include bh_port so we do not duplicate rules when BrowserHTTPS.Port == ScannerRelayerPort.
    if [ -n "$sr_port" ] && [ "$sr_port" != "0" ] && [ "$sr_port" != "null" ] \
        && [ "$sr_port" != "$pub_port" ] && [ "$sr_port" != "$mgt_port" ] && [ "$sr_port" != "$bh_port" ]; then
        if command -v python3 >/dev/null 2>&1; then
            local _sr_sources _sr_line _applied_sr
            _applied_sr=false
            _sr_sources=$(_firewall_collect_scanner_relayer_sources "$config_file") || _sr_sources=""
            if [[ -n "${_sr_sources//[[:space:]]/}" ]]; then
                while IFS= read -r _sr_line || [[ -n "${_sr_line:-}" ]]; do
                    [[ -z "${_sr_line//[[:space:]]/}" ]] && continue
                    if sudo ufw allow from "$_sr_line" to any port "$sr_port" proto tcp comment "mpc-auth ScannerRelayer scoped" 2>/dev/null; then
                        print_success "UFW: allow from $_sr_line to ${sr_port}/tcp (ScannerRelayer)"
                        _applied_sr=true
                    else
                        print_warning "Could not add UFW rule from $_sr_line to port $sr_port (need sudo?)"
                    fi
                done <<< "$_sr_sources"
            fi
            if [[ "$_applied_sr" != "true" ]]; then
                print_warning "No inbound sources resolved from RelayerAPIURL / ScannerAPIURLs — opening ${sr_port}/tcp to ANY (not recommended). Set PreSigningVerification.RelayerAPIURL and ScannerAPIURLs."
                apply_one_ufw "$sr_port" "mpc-auth ScannerRelayer (world — set RelayerAPIURL/ScannerAPIURLs)"
            fi
        else
            print_warning "python3 not found — cannot resolve RelayerAPIURL/ScannerAPIURLs; opening ${sr_port}/tcp to ANY."
            apply_one_ufw "$sr_port" "mpc-auth ScannerRelayer"
        fi
    fi
    if [ "${UFW_OPEN_MANAGEMENT_PORT:-0}" = "1" ]; then
        apply_one_ufw "$mgt_port" "mpc-auth ManagementAPI"
    else
        print_info "UFW: not opening ManagementAPI port ${mgt_port}/tcp (default). Set UFW_OPEN_MANAGEMENT_PORT=1 if inbound access is required, or rely on cloud SG / VPN."
    fi
    if [ "$is_relay" = "true" ]; then
        apply_one_ufw 8883 "mpc-auth MQTT TLS broker"
    fi

    local wg_admin_port ss_admin_port wg_egress_port ss_egress_port _vpn_pl
    wg_admin_port=51820
    ss_admin_port=8388
    wg_egress_port=51830
    ss_egress_port=8390
    if _vpn_pl=$(_firewall_read_vpn_ports_from_configs_yaml "$config_file" 2>/dev/null) && [ -n "$_vpn_pl" ]; then
        IFS='|' read -r wg_admin_port ss_admin_port wg_egress_port ss_egress_port <<< "$_vpn_pl"
    else
        print_warning "Could not read WireGuard/Shadowsocks ports via ruamel.yaml — using VPN defaults (51820/8388 admin, 51830/8390 egress)"
    fi
    print_info "VPN ports from configs.yaml: admin WG UDP=${wg_admin_port}, admin SS TCP+UDP=${ss_admin_port}, egress WG UDP=${wg_egress_port}, egress SS TCP+UDP=${ss_egress_port}"
    print_info "Admin VPN (wg0): UFW for UDP ${wg_admin_port} and Shadowsocks ${ss_admin_port} is also applied when POST /vpn/setEnabled runs host automation."
    apply_one_ufw_udp "$wg_egress_port" "Continuum peer egress WireGuard wg-egress"
    apply_shadowsocks_ufw "$ss_egress_port" "Continuum peer egress Shadowsocks"
    print_warning "Provider / cloud firewall (Contabo, Hetzner, AWS SG, etc.): allow inbound UDP ${wg_egress_port} for direct wg-egress."
    print_warning "Provider firewall: when using Shadowsocks egress, also allow inbound TCP+UDP ${ss_egress_port} (host blocks public UDP ${wg_egress_port} while obfuscation is active)."
    print_info "See systemd/README.md (WireGuard VPN — host firewall) and API_IMPLEMENTATION.md (peer egress VPN)."

    _apply_loopback_mongodb_owner_firewall_via_ufw_after_rules "$skip_firewall"

    print_info "UFW rules added (or already present). UFW status:"
    sudo ufw status numbered 2>/dev/null || true

    ufw_full=$(sudo ufw status 2>&1) || {
        print_error "Could not read UFW status after applying rules."
        exit 1
    }
    ufw_state=$(printf '%s\n' "$ufw_full" | head -1)
    if ! echo "$ufw_state" | grep -qiE '^Status:[[:space:]]+active([[:space:]]|$)'; then
        print_error "UFW is not active after applying rules (expected active). Status: ${ufw_state:-$ufw_full}"
        exit 1
    fi
    print_info "UFW active — inbound mpc-auth rules apply."
}

# If /etc/default/mpc-auth-docker exists (host has mpc-auth docker systemd helpers), keep
# MPC_AUTH_COMPOSE_WORKDIR aligned with this mpc-config checkout so pending-update automation can find compose
# after the operator moves or reclones the repo (systemd oneshots have no project cwd).
_process_config_sync_mpc_auth_docker_compose_workdir() {
    local cfg abs
    cfg=/etc/default/mpc-auth-docker
    [ -f "$cfg" ] || return 0
    # mpc-config checkout (moved/cloned); skip if this isn't a compose project root (e.g. mpc-auth console/ flow).
    if [ ! -f "${REPO_ROOT}/docker-compose.yml" ] && [ ! -f "${REPO_ROOT}/docker-compose.relay.yml" ] && [ ! -f "${REPO_ROOT}/docker-compose.client.yml" ]; then
        return 0
    fi
    abs="$(cd "${REPO_ROOT}" && pwd)"
    if ! command -v python3 >/dev/null 2>&1; then
        print_warning "python3 not found — set MPC_AUTH_COMPOSE_WORKDIR manually in ${cfg}: ${abs}"
        return 0
    fi
    if ! sudo -n true 2>/dev/null && ! sudo true; then
        print_warning "sudo required to update MPC_AUTH_COMPOSE_WORKDIR in ${cfg} — set manually: MPC_AUTH_COMPOSE_WORKDIR=${abs}"
        return 0
    fi
    # shellcheck disable=SC2310
    if sudo env MPC_AUTH_DOCKER_ENV_PATH="$cfg" MPC_AUTH_COMPOSE_ABS="$abs" python3 <<'PY'
import os
import pathlib
path = pathlib.Path(os.environ["MPC_AUTH_DOCKER_ENV_PATH"])
abs_val = os.environ["MPC_AUTH_COMPOSE_ABS"]
text = path.read_text(encoding="utf-8", errors="replace")
lines = text.splitlines(keepends=True)
key = "MPC_AUTH_COMPOSE_WORKDIR"
out = []
replaced = False
for line in lines:
    if line.lstrip().startswith(key + "="):
        if line.endswith("\r\n"):
            out.append(key + "=" + abs_val + "\r\n")
        elif line.endswith("\n"):
            out.append(key + "=" + abs_val + "\n")
        else:
            out.append(key + "=" + abs_val)
        replaced = True
    else:
        out.append(line)
if not replaced:
    if out and not (out[-1].endswith("\n") or out[-1].endswith("\r\n")):
        out.append("\n")
    out.append(key + "=" + abs_val + "\n")
path.write_text("".join(out), encoding="utf-8")
PY
    then
        print_success "Synced MPC_AUTH_COMPOSE_WORKDIR in ${cfg} → ${abs}"
    else
        print_warning "Could not write ${cfg} — set MPC_AUTH_COMPOSE_WORKDIR=${abs} manually."
    fi
}

# Sync ContinuumdaoNodeApp + ContinuumMcpServer image/tag and compose container names into /etc/default/mpc-auth-docker
# so mpc-auth-docker-update.sh can pull companion images when mpc-auth is updated.
_process_config_sync_mpc_auth_docker_dashboard_keys() {
    local config_file="$1"
    local cfg=/etc/default/mpc-auth-docker
    [ -f "$config_file" ] || return 0
    [ -f "$cfg" ] || return 0
    local abs=""
    if [ -f "${REPO_ROOT}/docker-compose.yml" ] || [ -f "${REPO_ROOT}/docker-compose.relay.yml" ] || [ -f "${REPO_ROOT}/docker-compose.client.yml" ]; then
        abs="$(cd "${REPO_ROOT}" && pwd)"
    elif [ -f "${REPO_ROOT}/../docker-compose.yml" ] || [ -f "${REPO_ROOT}/../docker-compose.relay.yml" ] || [ -f "${REPO_ROOT}/../docker-compose.client.yml" ]; then
        abs="$(cd "${REPO_ROOT}/.." && pwd)"
    else
        return 0
    fi
    if ! command -v python3 >/dev/null 2>&1; then
        return 0
    fi
    if ! sudo -n true 2>/dev/null && ! sudo true; then
        print_warning "sudo required to sync companion image keys in ${cfg} — dashboard/MCP pull on systemd update may be skipped."
        return 0
    fi
    # shellcheck disable=SC2310
    if sudo env MPC_DASH_CFG="$config_file" MPC_DASH_ENV="$cfg" MPC_DASH_PROJ="$(basename "$abs")" python3 <<'PYDASH'
import os
import pathlib

try:
    from ruamel.yaml import YAML
except ImportError:
    raise SystemExit(2)

cfg_path = pathlib.Path(os.environ["MPC_DASH_ENV"])
yaml_path = pathlib.Path(os.environ["MPC_DASH_CFG"])
proj = (os.environ.get("MPC_DASH_PROJ") or "mpc-config").strip() or "mpc-config"


def scalar_bool(val, default):
    if val is None:
        return default
    if isinstance(val, bool):
        return val
    s = str(val).strip().lower()
    if s in ("0", "false", "no", "off", ""):
        return False
    if s in ("1", "true", "yes", "on"):
        return True
    return default


y = YAML()
with open(yaml_path, encoding="utf-8") as f:
    d = y.load(f) or {}
if not isinstance(d, dict):
    d = {}

na = d.get("ContinuumdaoNodeApp")
enabled = True
image = "continuumdao/continuumdao-node-app"
tag = "latest"
if na is None:
    pass
elif isinstance(na, dict):
    enabled = scalar_bool(na.get("Enabled"), True)
    image = (na.get("Image") or image).strip() or image
    tag = (na.get("Tag") or tag).strip() or tag
else:
    enabled = False

if enabled:
    keys = {
        "MPC_AUTH_UPDATE_NODE_APP": "1",
        "NODE_APP_IMAGE": image,
        "NODE_APP_TAG": tag,
        "MPC_AUTH_NODE_APP_COMPOSE_SERVICE": "dashboard",
        "NODE_APP_CONTAINER_NAME": proj + "-dashboard-1",
    }
else:
    keys = {
        "MPC_AUTH_UPDATE_NODE_APP": "0",
        "NODE_APP_IMAGE": "",
        "NODE_APP_TAG": "",
        "MPC_AUTH_NODE_APP_COMPOSE_SERVICE": "dashboard",
        "NODE_APP_CONTAINER_NAME": proj + "-dashboard-1",
    }

mcp = d.get("ContinuumMcpServer")
mcp_enabled = True
mcp_image = "continuumdao/continuum-mcp-server"
mcp_tag = "latest"
if mcp is None:
    pass
elif isinstance(mcp, dict):
    mcp_enabled = scalar_bool(mcp.get("Enabled"), True)
    mcp_image = (mcp.get("Image") or mcp_image).strip() or mcp_image
    mcp_tag = (mcp.get("Tag") or mcp_tag).strip() or mcp_tag
else:
    mcp_enabled = False

if mcp_enabled:
    keys.update({
        "MPC_AUTH_UPDATE_MCP_SERVER": "1",
        "MCP_SERVER_IMAGE": mcp_image,
        "MCP_SERVER_TAG": mcp_tag,
        "MPC_AUTH_MCP_SERVER_COMPOSE_SERVICE": "continuum-mcp",
        "MCP_SERVER_CONTAINER_NAME": proj + "-continuum-mcp-1",
    })
else:
    keys.update({
        "MPC_AUTH_UPDATE_MCP_SERVER": "0",
        "MCP_SERVER_IMAGE": "",
        "MCP_SERVER_TAG": "",
        "MPC_AUTH_MCP_SERVER_COMPOSE_SERVICE": "continuum-mcp",
        "MCP_SERVER_CONTAINER_NAME": proj + "-continuum-mcp-1",
    })

text = cfg_path.read_text(encoding="utf-8", errors="replace")
lines = text.splitlines(keepends=True)
known = list(keys.keys())
repl = dict(keys)
present = dict.fromkeys(known, False)
out = []
for line in lines:
    lk = None
    s = line.lstrip()
    for k in known:
        if s.startswith(k + "="):
            lk = k
            break
    if lk is None:
        out.append(line)
        continue
    present[lk] = True
    nl = line.endswith("\r\n")
    frag = lk + "=" + repl[lk]
    out.append((frag + "\r\n") if nl else (frag + "\n"))
if not lines or not (lines[-1].endswith("\n") or lines[-1].endswith("\r\n")):
    out.append("\n")
for k in known:
    if not present[k]:
        out.append(k + "=" + repl[k] + "\n")

cfg_path.write_text("".join(out), encoding="utf-8")
PYDASH
    then
        print_success "Synced companion images → ${cfg} (NODE_APP_* / MCP_SERVER_* for mpc-auth-docker-update.sh)."
    else
        print_warning "Could not merge companion image keys into ${cfg} (missing ruamel.yaml or write failed)."
    fi
}

# Locate systemd/install-mpc-auth-docker-systemd.sh: same repo, sibling mpc-config, or MPC_CONFIG_ROOT (see process_config --help).
_process_config_resolve_mpc_auth_systemd_dir() {
    local cand rp
    if [ -n "${MPC_CONFIG_ROOT:-}" ]; then
        cand="${MPC_CONFIG_ROOT%/}/systemd"
        if [ -f "${cand}/install-mpc-auth-docker-systemd.sh" ]; then
            rp=$(cd "${cand}" && pwd)
            printf '%s\n' "$rp"
            return 0
        fi
        print_warning "MPC_CONFIG_ROOT set but missing ${cand}/install-mpc-auth-docker-systemd.sh — searching default paths."
    fi
    for cand in "${REPO_ROOT}/systemd" "${REPO_ROOT}/../mpc-config/systemd"; do
        [ -z "$cand" ] && continue
        [ -f "${cand}/install-mpc-auth-docker-systemd.sh" ] || continue
        rp=$(cd "${cand}" && pwd)
        printf '%s\n' "$rp"
        return 0
    done
    return 1
}

# systemd units run /usr/local/libexec/mpc-auth/*.sh — not the copies in this repo. After `git pull`, re-install
# with --no-env so host scripts and unit files match the checkout while preserving /etc/default/mpc-auth-docker.
_process_config_sync_mpc_auth_libexec_from_repo() {
    local skip_from_cli="$1"
    case "${PROCESS_CONFIG_SKIP_SYSTEMD:-}" in
        1|true|TRUE|yes|YES) return 0 ;;
    esac
    if [ "$skip_from_cli" = "true" ]; then
        return 0
    fi
    if [ ! -d /etc/systemd/system ]; then
        return 0
    fi
    if [ ! -f /etc/systemd/system/mpc-auth-docker-restart.service ] && [ ! -f /etc/systemd/system/mpc-auth-docker-pending-update.service ] && [ ! -f /etc/systemd/system/mpc-auth-docker-pending-reboot.service ] && [ ! -f /etc/systemd/system/mpc-auth-vpn-pending.path ]; then
        return 0
    fi
    local sd_root ins_script
    if ! sd_root="$(_process_config_resolve_mpc_auth_systemd_dir)"; then
        return 0
    fi
    ins_script="${sd_root}/install-mpc-auth-docker-systemd.sh"
    if [ ! -f "$ins_script" ]; then
        return 0
    fi
    print_step "Refreshing mpc-auth host scripts (/usr/local/libexec/mpc-auth/) from this repo"
    print_info "Running: sudo bash install-mpc-auth-docker-systemd.sh --no-env (preserves /etc/default/mpc-auth-docker)."
    # shellcheck disable=SC2024
    if sudo -n true 2>/dev/null || sudo true; then
        if sudo bash "$ins_script" --no-env; then
            print_success "Host mpc-auth libexec scripts and systemd units updated from ${sd_root}."
        else
            print_warning "install-mpc-auth-docker-systemd.sh --no-env failed. Run manually: sudo bash ${ins_script} --no-env"
        fi
    else
        print_warning "sudo not available here — after git pull run: sudo bash ${ins_script} --no-env"
    fi
}

# Optional mpc-auth Docker systemd units (mpc-config/systemd/). See systemd/README.md.
# Respects PROCESS_CONFIG_SKIP_SYSTEMD=1, PROCESS_CONFIG_INSTALL_SYSTEMD=1 (non-interactive install).
_process_config_prompt_mpc_auth_systemd_helpers() {
    local skip_from_cli="$1"
    local force_install_cli="$2"
    local sd_root ins_script

    case "${PROCESS_CONFIG_SKIP_SYSTEMD:-}" in
        1|true|TRUE|yes|YES) return 0 ;;
    esac
    if [ "$skip_from_cli" = "true" ]; then
        return 0
    fi

    if ! sd_root="$(_process_config_resolve_mpc_auth_systemd_dir)"; then
        print_warning "mpc-auth systemd installer not found (checked ${REPO_ROOT}/systemd, ${REPO_ROOT}/../mpc-config/systemd, \$MPC_CONFIG_ROOT/systemd) — skipping."
        print_info "Clone mpc-config next to this repo or set MPC_CONFIG_ROOT. See mpc-config/systemd/README.md"
        return 0
    fi
    ins_script="${sd_root}/install-mpc-auth-docker-systemd.sh"
    if [ ! -f "${REPO_ROOT}/systemd/install-mpc-auth-docker-systemd.sh" ]; then
        print_info "Using systemd helper bundle: ${sd_root}"
    fi
    if ! command -v systemctl >/dev/null 2>&1; then
        print_info "systemctl not available — skipping optional mpc-auth systemd helpers."
        return 0
    fi
    if [ ! -d /etc/systemd/system ]; then
        print_info "/etc/systemd/system not found — skipping optional mpc-auth systemd helpers."
        return 0
    fi

    local force_install=false
    if [ "$force_install_cli" = "true" ]; then
        force_install=true
    fi
    case "${PROCESS_CONFIG_INSTALL_SYSTEMD:-}" in
        1|true|TRUE|yes|YES) force_install=true ;;
    esac

    local __mpc_auth_line=""

    _mpc_auth_can_prompt_interactive() {
        case "${PROCESS_CONFIG_NONINTERACTIVE:-0}" in
            1|true|TRUE|yes|YES) return 1 ;;
        esac
        { [ -r /dev/tty ] && [ -w /dev/tty ]; } || [ -t 0 ]
    }

    _read_interactive_systemd() {
        local prompt="$1"
        __mpc_auth_line=""
        if { [ -r /dev/tty ] && [ -w /dev/tty ]; }; then
            IFS= read -r -p "$prompt" __mpc_auth_line </dev/tty || true
        elif [ -t 0 ]; then
            IFS= read -r -p "$prompt" __mpc_auth_line || true
        else
            return 1
        fi
    }

    _mpc_auth_units_installed_on_host() {
        [ -f /etc/systemd/system/mpc-auth-docker-restart.service ] \
            && [ -f /etc/systemd/system/mpc-auth-docker-update@.service ]
    }

    _run_mpc_auth_systemd_install() {
        # shellcheck disable=SC2024
        if sudo -n true 2>/dev/null || sudo true; then
            if sudo bash "$ins_script" "$@"; then
                print_success "mpc-auth systemd installer finished."
                _process_config_sync_mpc_auth_docker_compose_workdir
                return 0
            fi
            print_warning "mpc-auth systemd installer exited with an error."
            return 1
        fi
        print_warning "sudo required to install systemd units — skipping."
        return 1
    }

    _maybe_prompt_restart_mpc_auth_container() {
        if ! _mpc_auth_units_installed_on_host; then
            return 0
        fi
        if ! _mpc_auth_can_prompt_interactive; then
            return 0
        fi

        # Only offer restart when a target container exists. (Apr 2026 [Y/n] default made Enter run systemctl; fresh hosts
        # often have no Compose containers yet — restarting would always fail. Mirrors mpc-auth-docker-restart.sh resolution.)
        if ! command -v docker >/dev/null 2>&1; then
            print_info "docker not on PATH — skipping mpc-auth-docker-restart prompt."
            return 0
        fi
        if ! docker ps >/dev/null 2>&1; then
            print_info "Docker daemon unreachable — skipping mpc-auth-docker-restart prompt (start Docker and compose, then: sudo systemctl start mpc-auth-docker-restart.service)."
            return 0
        fi

        local CONTAINER resolved="" hits=()
        if [ -r /etc/default/mpc-auth-docker ]; then
            # shellcheck source=/dev/null
            . /etc/default/mpc-auth-docker
        fi
        CONTAINER="${MPC_AUTH_CONTAINER_NAME:-mpc-config-app-1}"

        case "${MPC_AUTH_RESTART_STRICT:-}" in
            1 | true | TRUE | yes | YES)
                if docker inspect "$CONTAINER" >/dev/null 2>&1; then
                    resolved="$CONTAINER"
                else
                    print_warning "MPC_AUTH_RESTART_STRICT is set but container \"$CONTAINER\" does not exist — skipping restart prompt."
                    return 0
                fi
                ;;
            *)
                if docker inspect "$CONTAINER" >/dev/null 2>&1; then
                    resolved="$CONTAINER"
                else
                    while IFS=$'\t' read -r cname img; do
                        case "$img" in
                            *mpc-auth*) hits+=("$cname") ;;
                        esac
                    done < <(docker ps -a --format '{{.Names}}\t{{.Image}}')
                    if [ "${#hits[@]}" -eq 1 ]; then
                        resolved="${hits[0]}"
                    fi
                fi
                ;;
        esac

        if [ -z "$resolved" ]; then
            if [ "${#hits[@]}" -gt 1 ]; then
                print_warning "Multiple *mpc-auth* image containers ($(IFS=,; echo "${hits[*]}")) — set MPC_AUTH_CONTAINER_NAME in /etc/default/mpc-auth-docker; skipping restart prompt."
            else
                print_info "No mpc-auth Docker container found — skipping restart prompt (after docker compose up: sudo systemctl start mpc-auth-docker-restart.service)."
            fi
            return 0
        fi

        local _rs
        echo ""
        print_warning "This runs: sudo systemctl start mpc-auth-docker-restart.service → docker restart (${resolved})."
        print_info "Default is Yes — Enter confirms (sudo may prompt for a password); type n or N to skip."
        _read_interactive_systemd "Start mpc-auth-docker-restart.service now? [Y/n]: " || true
        _rs="${__mpc_auth_line}"
        case "${_rs:-}" in
            [nN])
                print_info "Skipped. Later: sudo systemctl start mpc-auth-docker-restart.service"
                ;;
            *)
                # shellcheck disable=SC2024
                if sudo -n systemctl start mpc-auth-docker-restart.service 2>/dev/null || sudo systemctl start mpc-auth-docker-restart.service; then
                    print_success "Started mpc-auth-docker-restart.service (container restart)."
                else
                    print_warning "mpc-auth-docker-restart.service did not succeed: systemd ran the unit, but the restart script exited with an error (this is usually not a sudo/password issue)."
                    print_info "Common causes: no container matching MPC_AUTH_CONTAINER_NAME in /etc/default/mpc-auth-docker (Compose v2 default for this repo is often mpc-config-app-1; confirm with docker ps NAMES), Docker not running, or docker.sock permissions."
                    print_info "Check: sudo systemctl status mpc-auth-docker-restart.service"
                    print_info "Logs:  sudo journalctl -xeu mpc-auth-docker-restart.service"
                    if command -v journalctl >/dev/null 2>&1; then
                        local _jl=""
                        _jl=$(sudo journalctl -u mpc-auth-docker-restart.service -n 15 --no-pager 2>/dev/null || true)
                        if [ -n "${_jl}" ]; then
                            echo ""
                            print_info "Last journal lines:"
                            printf '%s\n' "$_jl"
                        fi
                    fi
                fi
                ;;
        esac
    }

    if [ "$force_install" = "true" ]; then
        print_step "Installing mpc-auth Docker systemd helpers (PROCESS_CONFIG_INSTALL_SYSTEMD / --install-mpc-auth-systemd)"
        if ! _run_mpc_auth_systemd_install; then
            print_info "See: ${sd_root}/README.md"
            _maybe_prompt_restart_mpc_auth_container
            print_info "Docs: systemd/README.md — maintenance API: GET /maintenance/restartGate"
            return 0
        fi
        _maybe_prompt_restart_mpc_auth_container
        print_info "Docs: systemd/README.md — maintenance API: GET /maintenance/restartGate"
        return 0
    fi

    if ! _mpc_auth_can_prompt_interactive; then
        print_info "No interactive terminal (/dev/tty or stdin tty) — skipping mpc-auth systemd prompts. Install manually: sudo bash ${ins_script}"
        print_info "Or set MPC_CONFIG_ROOT if the installer lives in another mpc-config clone."
        print_info "Docs: systemd/README.md"
        return 0
    fi

    print_step "Optional: mpc-auth Docker systemd helpers (daemon-reload is part of install; container restart is optional)"
    print_info "Bundled path: ${sd_root}"

    local _ans
    if _mpc_auth_units_installed_on_host; then
        print_info "mpc-auth systemd units are already installed under /etc/systemd/system/."
        _read_interactive_systemd "Re-copy unit files + scripts from this repo (--no-env keeps /etc/default/mpc-auth-docker) and run systemd daemon-reload? [Y/n]: " || true
        _ans="${__mpc_auth_line}"
        case "${_ans:-}" in
            [nN])
                print_info "Skipped re-sync. To update manually: sudo bash ${ins_script} --no-env"
                ;;
            *)
                _run_mpc_auth_systemd_install --no-env || print_info "Skipped re-sync after installer issue. To update manually: sudo bash ${ins_script} --no-env"
                ;;
        esac
    else
        _read_interactive_systemd "Install mpc-auth systemd helpers (mpc-auth-docker-restart, mpc-auth-docker-update@…; requires sudo)? [Y/n]: " || true
        _ans="${__mpc_auth_line}"
        case "${_ans:-}" in
            [nN])
                print_info "Skipped. Later: sudo bash ${ins_script}"
                ;;
            *)
                _run_mpc_auth_systemd_install || print_info "Install did not finish. Later: sudo bash ${ins_script}"
                ;;
        esac
    fi
    # Always offer restart when units exist ([Y/n]; n skips separately from installer/re-sync).
    _maybe_prompt_restart_mpc_auth_container
    echo ""
}

# Main execution
main() {
    local COPY_CERTS=false
    local SKIP_FIREWALL=false
    local SKIP_SYSTEMD=false
    local SKIP_AGENT_LLM_CONFIG_PATH=false
    local INSTALL_MPC_AUTH_SYSTEMD=false
    local SYNC_COMPOSE_ROLE_ONLY=false
    local COMPOSE_APP_IMAGE_REF="${MPC_AUTH_COMPOSE_APP_IMAGE:-}"

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --copy-certs)
                COPY_CERTS=true
                shift
                ;;
            --no-copy-certs)
                COPY_CERTS=false
                shift
                ;;
            --no-firewall)
                SKIP_FIREWALL=true
                shift
                ;;
            --force-mqtt-certs)
                FORCE_REGENERATE_MQTT_CERTS=1
                export FORCE_REGENERATE_MQTT_CERTS
                shift
                ;;
            --force-browser-https-certs)
                FORCE_REGENERATE_BROWSER_HTTPS_CERTS=1
                export FORCE_REGENERATE_BROWSER_HTTPS_CERTS
                shift
                ;;
            --enable-loopback-http)
                ENABLE_BROWSER_LOOPBACK_READ_HTTP=1
                export ENABLE_BROWSER_LOOPBACK_READ_HTTP
                shift
                ;;
            --disable-loopback-http)
                ENABLE_BROWSER_LOOPBACK_READ_HTTP=0
                export ENABLE_BROWSER_LOOPBACK_READ_HTTP
                shift
                ;;
            --no-systemd)
                SKIP_SYSTEMD=true
                shift
                ;;
            --no-agent-llm-config-path)
                SKIP_AGENT_LLM_CONFIG_PATH=true
                shift
                ;;
            --install-mpc-auth-systemd)
                INSTALL_MPC_AUTH_SYSTEMD=true
                shift
                ;;
            --sync-compose-role-only)
                SYNC_COMPOSE_ROLE_ONLY=true
                shift
                ;;
            --help|-h|-help|help)
                show_process_config_help
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                echo "Run with --help, -h, -help, or help for usage."
                exit 1
                ;;
        esac
    done

    if [ "$SYNC_COMPOSE_ROLE_ONLY" = true ]; then
        process_config_sync_compose_role_only "$SKIP_AGENT_LLM_CONFIG_PATH" "$COMPOSE_APP_IMAGE_REF"
        exit $?
    fi

    local _pc_skip_firewall=0 _pc_skip_systemd=0
    [ "$SKIP_FIREWALL" = true ] && _pc_skip_firewall=1
    if [ "$SKIP_SYSTEMD" = true ] || [ "${PROCESS_CONFIG_SKIP_SYSTEMD:-0}" = "1" ]; then
        _pc_skip_systemd=1
    fi
    if declare -F install_progress_register_pc_topics >/dev/null 2>&1; then
        install_progress_register_pc_topics "$_pc_skip_firewall" "$_pc_skip_systemd"
    fi
    
    echo "==========================================" >&2
    echo "MPC config: Mosquitto (MQTT) + Browser HTTPS (web) validation and certificates" >&2
    echo "==========================================" >&2
    echo "" >&2
    
    install_progress_topic_if_registered begin configure-node 2>/dev/null || true
    install_progress_topic_if_registered set configure-node 5 2>/dev/null || true
    # Require configs.yaml first (fail fast before any other checks)
    CONFIG_FILE=$(find_configs_yaml)
    if [ -z "$CONFIG_FILE" ]; then
        ensure_configs_yaml_from_original
        CONFIG_FILE=$(find_configs_yaml)
    fi
    if [ -z "$CONFIG_FILE" ]; then
        print_error "Could not find configs.yaml"
        print_info "Expected locations: next to this script (configs.yaml), repo root, ./configs.yaml, or ./console/configs.yaml"
        print_info "If configs-original.yaml is present, it will be copied to configs.yaml automatically; ensure the repo is complete."
        exit 1
    fi
    print_success "Found config: $CONFIG_FILE"
    echo ""

    _process_config_dotenv_chown_to_invoking_user "$(cd "$(dirname "$CONFIG_FILE")" && pwd)"
    _process_config_maybe_materialize_dotenv_from_environment "$(cd "$(dirname "$CONFIG_FILE")" && pwd)"

    configs_yaml_merge_agent_chat_and_hooks_enabled "$CONFIG_FILE" || exit 1

    case "${PROCESS_CONFIG_SKIP_AGENT_LLM_CONFIG_PATH:-}" in
        1|true|TRUE|yes|YES) SKIP_AGENT_LLM_CONFIG_PATH=true ;;
    esac
    if [ "$SKIP_AGENT_LLM_CONFIG_PATH" = false ]; then
        local _agent_llm_merge_result
        _agent_llm_merge_result=$(configs_yaml_merge_agent_llm_config_dir "$CONFIG_FILE" "$DEFAULT_AGENT_LLM_CONFIG_DIR") || exit 1
        _cfg_parent="$(cd "$(dirname "$CONFIG_FILE")" && pwd)"
        _process_config_mkdir_owned_by_invoking_user "${_cfg_parent}/${DEFAULT_AGENT_LLM_CONFIG_DIR}"
        _process_config_mkdir_owned_by_invoking_user "${_cfg_parent}/${DEFAULT_AGENT_LLM_CONFIG_DIR}/Skills"
        _process_config_mkdir_owned_by_invoking_user "${_cfg_parent}/${DEFAULT_AGENT_LLM_CONFIG_DIR}/cron"
        _process_config_mkdir_owned_by_invoking_user "${_cfg_parent}/${DEFAULT_AGENT_LLM_CONFIG_DIR}/cron/runs"
        _process_config_mkdir_owned_by_invoking_user "${_cfg_parent}/${DEFAULT_AGENT_LLM_CONFIG_DIR}/${DEFAULT_AGENT_HOOKS_REL}"
        _process_config_mkdir_owned_by_invoking_user "${_cfg_parent}/${DEFAULT_AGENT_LLM_CONFIG_DIR}/${DEFAULT_AGENT_HOOKS_REL}/runs"
        _process_config_mkdir_owned_by_invoking_user "${_cfg_parent}/${DEFAULT_USER_FOLDER_DIR}"
        _seed_agent_mcp_default_servers_file "${_cfg_parent}" || true
        _seed_agent_llm_runtime_readme "${_cfg_parent}" || true
        _seed_agent_skills_catalog "${_cfg_parent}" || true
        _seed_agent_hooks_catalog "${_cfg_parent}" || true
        _seed_agent_cron_catalog "${_cfg_parent}" "$CONFIG_FILE" || true
        _process_config_ensure_path_owned_by_invoking_user "${_cfg_parent}/${DEFAULT_AGENT_LLM_CONFIG_DIR}"
        _process_config_ensure_path_owned_by_invoking_user "${_cfg_parent}/${DEFAULT_USER_FOLDER_DIR}"
        case "$_agent_llm_merge_result" in
            merged)
                print_success "configs.yaml: set AgentLlmConfigDir → ${DEFAULT_AGENT_LLM_CONFIG_DIR} (host: ${_cfg_parent}/${DEFAULT_AGENT_LLM_CONFIG_DIR}/)"
                ;;
            present)
                print_info "configs.yaml: AgentLlmConfigDir already set (unchanged)"
                ;;
        esac
    else
        print_info "Skipping AgentLlmConfigDir in configs.yaml (--no-agent-llm-config-path)"
    fi
    install_progress_topic_if_registered set configure-node 15 2>/dev/null || true

    # Management keys before nodeAddresses so re-runs offer NodeMgtKey / PublicMgtKey when missing
    # (otherwise users only see the node IP flow first).
    normalize_openssh_public_mgt_key_in_yaml "$CONFIG_FILE" || exit 1
    prompt_configure_management_keys "$CONFIG_FILE" || exit 1

    prompt_fill_empty_node_addresses "$CONFIG_FILE" || exit 1

    prompt_menu_edit_node_addresses "$CONFIG_FILE" || exit 1
    install_progress_topic_if_registered set configure-node 30 2>/dev/null || true

    check_root
    check_openssl
    
    ensure_ufw_active_early "$SKIP_FIREWALL"

    # Validate configuration
    validate_no_default_ips "$CONFIG_FILE"
    validate_external_ips_only "$CONFIG_FILE"
    validate_presign_config "$CONFIG_FILE"
    install_progress_topic_if_registered set configure-node 45 2>/dev/null || true
    
    # Determine relay vs client and configure docker-compose FIRST (so client always gets mosquitto commented out)
    # before any step that might exit (e.g. Relayer API check). Otherwise a client would never reach configure_docker_compose.
    IS_RELAY_NODE=$(validate_node_ip "$CONFIG_FILE")
    if [ "$IS_RELAY_NODE" = "true" ]; then
        print_info "Detected as RELAY NODE (this machine is first in configs.yaml nodeAddresses) - mosquitto will be enabled"
    else
        print_info "Detected as CLIENT NODE (this machine is not first in configs.yaml nodeAddresses) - mosquitto will be commented out"
    fi
    if first_node_address_is_relay_placeholder "$CONFIG_FILE"; then
        print_info "First nodeAddresses entry uses ${NODE_ADDRESSES_RELAY_PLACEHOLDER_IPV4} as relay placeholder — MQTT relay steps stay disabled until first is the real relay IP (this machine is a peer elsewhere in the list)."
    fi

    local _this_node_ip=""
    _this_node_ip=$(get_browser_https_node_ip "$CONFIG_FILE") || true
    if [ -n "$_this_node_ip" ]; then
        configs_yaml_merge_wireguard_egress_endpoint_host "$CONFIG_FILE" "$_this_node_ip" || true
    else
        print_warning "Could not match this host to nodeAddresses — skipping WireGuardEgress.EndpointHost auto-set (set manually for peer egress client configs)"
    fi

    prompt_browser_loopback_read_http

    configure_mqtt_broker "$CONFIG_FILE" "$IS_RELAY_NODE"
    install_progress_topic_if_registered set configure-node 55 2>/dev/null || true

    local _agent_llm_compose_enable=1
    if [ "$SKIP_AGENT_LLM_CONFIG_PATH" = true ]; then
        _agent_llm_compose_enable=0
    fi
    configure_docker_compose "$IS_RELAY_NODE" "$BROWSER_LOOPBACK_READ_HTTP_ENABLED" "$COMPOSE_APP_IMAGE_REF" "$CONFIG_FILE" "$_agent_llm_compose_enable"
    install_progress_topic_if_registered set configure-node 70 2>/dev/null || true

    setup_browser_https "$CONFIG_FILE"
    apply_browser_loopback_read_http_config "$CONFIG_FILE" "$BROWSER_LOOPBACK_READ_HTTP_ENABLED"
    install_progress_topic_if_registered set configure-node 80 2>/dev/null || true

    prompt_relayer_api_url_if_missing "$CONFIG_FILE" || exit 1

    apply_process_config_firewall "$CONFIG_FILE" "$SKIP_FIREWALL" "$IS_RELAY_NODE"
    install_progress_topic_if_registered set configure-node 88 2>/dev/null || true

    # Optional mpc-auth Docker systemd installs/restarts (orthogonal to Relayer connectivity). Runs *before*
    # validate_relayer_api_connection so Relayer/network failures cannot skip these prompts entirely.
    # Sync workdir before install so a fresh /etc/default gets COMPOSE_WORKDIR even if install overwrites the file.
    _process_config_sync_mpc_auth_docker_compose_workdir
    _process_config_prompt_mpc_auth_systemd_helpers "$SKIP_SYSTEMD" "$INSTALL_MPC_AUTH_SYSTEMD"
    _process_config_sync_mpc_auth_docker_compose_workdir
    _process_config_sync_mpc_auth_docker_dashboard_keys "$CONFIG_FILE"
    _process_config_ensure_agent_llm_config_defaults_compose_volume
    _process_config_ensure_vpn_compose_env
    _process_config_sync_mpc_auth_libexec_from_repo "$SKIP_SYSTEMD"
    install_progress_topic_if_registered set configure-node 92 2>/dev/null || true

    # Validate Relayer API connection (MANDATORY for relay before certificate generation; may exit 1 on failure)
    validate_relayer_api_connection "$CONFIG_FILE"
    install_progress_topic_if_registered set configure-node 98 2>/dev/null || true
    
    if [ "$IS_RELAY_NODE" = "true" ]; then
        # ========================================
        # RELAY NODE (MQTT Broker) PATH
        # ========================================
        echo ""
        echo "=========================================="
        print_success "You are running this on the MQTT RELAY NODE"
        echo "=========================================="
        echo ""
        print_info "This node is the first node in the MPC group and should run the MQTT broker."
        print_info "The script validates configuration, sets up Browser HTTPS (webTLS) if applicable, then Mosquitto (MQTT TLS) certs on the relay if needed."
        echo ""
        
        # Find and validate mosquitto.conf
        MOSQUITTO_CONF=$(find_mosquitto_conf)
        if [ -n "$MOSQUITTO_CONF" ]; then
            validate_letsencrypt_certs "$MOSQUITTO_CONF"
            
            # Only generate self-signed certs if Let's Encrypt is not configured
            if ! is_letsencrypt_configured "$MOSQUITTO_CONF"; then
                if confirm_overwrite_mqtt_certs; then
                    check_cert_dir
                    print_step "Generating self-signed Mosquitto (MQTT TLS) certificates for the broker..."
                    generate_ca_key
                    generate_ca_cert
                    generate_server_key
                    generate_server_csr
                    sign_server_cert "$CONFIG_FILE"
                    set_permissions
                    _process_config_chown_repo_tree_if_sudo_root "$CERT_DIR"
                    
                    echo ""
                    echo "=========================================="
                    print_success "Mosquitto (MQTT TLS) broker certificate generation complete!"
                    echo "=========================================="
                    echo ""
                    print_info "IMPORTANT: Share the MQTT CA certificate ($CA_CRT) with all client nodes for TLS to the broker."
                    echo ""
                    print_warning "Next steps for the RELAY NODE (Mosquitto / MQTT):"
                    echo ""
                    echo "  1. Copy the CA certificate file to each client node:"
                    echo "     File to share: $CA_CRT"
                    echo ""
                    echo "  2. Send this file to each node operator in your MPC group"
                    echo "     They need to:"
                    echo "     a. Copy the file to their node (e.g., to /mosquitto/config/certs/ca.crt)"
                    echo "     b. Update their configs.yaml:"
                    echo "        MQTTTLS:"
                    echo "          CAFile: \"/mosquitto/config/certs/ca.crt\""
                    echo "        (or the path where they placed the file)"
                    echo ""
                    echo "  3. Ensure mosquitto can read the certificate files:"
                    echo "     sudo chown -R mosquitto:mosquitto $CERT_DIR  # if mosquitto runs as 'mosquitto' user"
                    echo ""
                    echo "  4. Restart mosquitto to apply the new certificates:"
                    echo "     sudo systemctl restart mosquitto"
                    echo "     # or if using Docker: docker restart mosquitto"
                    echo ""
                    print_info "MQTT CA certificate location: $CA_CRT"
                    print_warning "Keep the MQTT private keys ($CA_KEY, $SERVER_KEY) secure and private!"
                    relay_mqtt_ca_copy_or_manual_instructions "$CONFIG_FILE"
                else
                    echo ""
                    print_info "Keeping existing Mosquitto (MQTT TLS) files in $CERT_DIR (no overwrite)."
                    print_info "Browser HTTPS (webTLS, port 8443) is separate and was already handled earlier in this run."
                    relay_mqtt_ca_copy_or_manual_instructions "$CONFIG_FILE"
                fi
            else
                print_success "Let's Encrypt is configured - no self-signed certificates needed"
                print_info "Configuration validation complete for relay node"
            fi
        else
            print_warning "Could not find mosquitto.conf"
            print_info "Proceeding with self-signed Mosquitto (MQTT TLS) certificate generation..."
            if confirm_overwrite_mqtt_certs; then
                check_cert_dir
                generate_ca_key
                generate_ca_cert
                generate_server_key
                generate_server_csr
                sign_server_cert "$CONFIG_FILE"
                set_permissions
                _process_config_chown_repo_tree_if_sudo_root "$CERT_DIR"
                
                echo ""
                print_warning "Next steps (Mosquitto / MQTT):"
                echo "  1. Configure mosquitto.conf to use these certificates"
                echo "  2. Share MQTT CA $CA_CRT with all client nodes"
                relay_mqtt_ca_copy_or_manual_instructions "$CONFIG_FILE"
            else
                echo ""
                print_info "Keeping existing Mosquitto (MQTT TLS) files in $CERT_DIR (no overwrite)."
                print_info "Browser HTTPS (webTLS, port 8443) is separate and was already handled earlier in this run."
                relay_mqtt_ca_copy_or_manual_instructions "$CONFIG_FILE"
            fi
        fi
    else
        # ========================================
        # CLIENT NODE PATH (Validation Only)
        # ========================================
        echo ""
        echo "=========================================="
        print_info "You are running this on a CLIENT NODE"
        echo "=========================================="
        echo ""
        print_info "This node is a client in the MPC group and connects to the MQTT broker."
        print_info "Configuration validation has been completed."
        echo ""
        print_info "Note: Mosquitto (MQTT TLS) CA is issued on the relay (first node). Browser HTTPS (webTLS) is generated per-node when you run this script."
        print_info "Obtain the MQTT CA from the relay operator (relay runs process_config.sh; use --copy-certs there for SSH copy)."
        echo ""
        
        # Create certificate directory on client nodes if it doesn't exist
        print_step "Ensuring certificate directory exists..."
        # Host path: <repo root>/mosquitto/config/certs — same as docker-compose ./mosquitto/config:/mosquitto/config
        local script_dir="$(cd "$(dirname "$0")" && pwd)"
        local repo_root="$script_dir"
        if [ ! -d "$repo_root/mosquitto/config" ] && [ -d "$script_dir/../mosquitto/config" ]; then
            repo_root="$(cd "$script_dir/.." && pwd)"
        fi
        local cert_dir_path="$repo_root/mosquitto/config/certs"
        
        print_info "Using project mosquitto TLS directory: $cert_dir_path"
        print_info "(Place relay's ca.crt here for the container path /mosquitto/config/certs/ca.crt.)"
        
        local ownership_changed=false
        
        if [ ! -d "$cert_dir_path" ]; then
            print_info "Creating certificate directory: $cert_dir_path"
            # Try without sudo first (if user has permissions)
            if mkdir -p "$cert_dir_path" 2>/dev/null; then
                print_success "Certificate directory created: $cert_dir_path"
                chmod 755 "$cert_dir_path" 2>/dev/null || true
            # Try with sudo if regular mkdir failed
            elif sudo mkdir -p "$cert_dir_path" 2>/dev/null; then
                print_success "Certificate directory created (with sudo): $cert_dir_path"
                sudo chmod 755 "$cert_dir_path" 2>/dev/null || true
                process_config_transfer_repo_path_to_invoking_user "$cert_dir_path"
                # shellcheck disable=SC2312
                if [ "$(stat -c '%u' "$cert_dir_path" 2>/dev/null)" = "${PROCESS_CONFIG_REPO_UID}" ]; then
                    print_success "Directory ownership changed to ${PROCESS_CONFIG_REPO_OWNER} - you can copy files without sudo"
                    ownership_changed=true
                else
                    print_warning "Could not change directory ownership - you may need sudo to copy certificates"
                fi
            else
                print_warning "Could not create certificate directory: $cert_dir_path"
                print_info "You need to create it manually with appropriate permissions:"
                echo "  sudo mkdir -p $cert_dir_path"
                echo "  sudo chmod 755 $cert_dir_path"
                echo "  sudo chown ${PROCESS_CONFIG_REPO_OWNER}:${PROCESS_CONFIG_REPO_OWNER} $cert_dir_path"
            fi
        else
            print_success "Certificate directory exists: $cert_dir_path"
            # Check if writable
            if [ ! -w "$cert_dir_path" ]; then
                print_warning "Certificate directory is not writable by current user"
                print_info "Attempting to change ownership to ${PROCESS_CONFIG_REPO_OWNER}..."
                process_config_transfer_repo_path_to_invoking_user "$cert_dir_path"
                # shellcheck disable=SC2312
                if [ "$(stat -c '%u' "$cert_dir_path" 2>/dev/null)" = "${PROCESS_CONFIG_REPO_UID}" ]; then
                    print_success "Directory ownership changed to ${PROCESS_CONFIG_REPO_OWNER} - you can now copy files without sudo"
                    ownership_changed=true
                else
                    print_warning "Could not change directory ownership"
                    print_info "You will need sudo to copy the certificate file:"
                    echo "  sudo scp relay-node-user@RELAY_NODE_IP:/mosquitto/config/certs/ca.crt $cert_dir_path/ca.crt"
                    echo "  # Or copy to a temporary location first, then move with sudo:"
                    echo "  scp relay-node-user@RELAY_NODE_IP:/mosquitto/config/certs/ca.crt /tmp/ca.crt"
                    echo "  sudo mv /tmp/ca.crt $cert_dir_path/ca.crt"
                fi
            else
                print_info "Certificate directory is writable - ready to receive CA certificate"
            fi
        fi
        echo ""
        
        # Validate CA certificate configuration on client nodes
        MOSQUITTO_CONF=$(find_mosquitto_conf)
        local expected_ca_path=""
        
        if [ -n "$MOSQUITTO_CONF" ] && ! is_letsencrypt_configured "$MOSQUITTO_CONF"; then
            # Extract expected CA path from mosquitto.conf
            expected_ca_path=$(grep -E '^\s*cafile\s+' "$MOSQUITTO_CONF" 2>/dev/null | head -1 | sed -E 's/^\s*cafile\s+//' | sed 's/#.*$//' | xargs)
        fi
        
        # If no expected path from mosquitto.conf, use default
        if [ -z "$expected_ca_path" ]; then
            expected_ca_path="$CA_CRT"
        fi
        
        print_step "Validating CA certificate configuration..."
        
        # validate_client_cafile uses return 1–4 for status, not hard failures (avoid set -e on $()).
        local validation_result=""
        local exit_code=0
        validation_result=$(validate_client_cafile "$CONFIG_FILE" "$expected_ca_path" 2>&1) || exit_code=$?
        
        case $exit_code in
            0)
                print_success "CA certificate is configured correctly!"
                echo ""
                print_info "Your configs.yaml has MQTTTLS.CAFile set and the certificate file exists."
                if [ -n "$expected_ca_path" ]; then
                    print_info "Expected CA certificate path: $expected_ca_path"
                fi
                echo ""
                print_success "Client node configuration is valid. You are ready to connect to the MQTT broker."
                ;;
            1)
                print_warning "CA certificate is NOT configured in configs.yaml"
                echo ""
                print_info "Obtain the CA certificate from the relay operator (relay runs process_config.sh; use --copy-certs there for SSH copy)."
                print_info "After the relay node runs ./process_config.sh, ensure:"
                echo "  1. The CA certificate file exists at: $expected_ca_path"
                echo "  2. Your configs.yaml has:"
                echo "     MQTTTLS:"
                echo "       CAFile: \"$expected_ca_path\""
                ;;
            2)
                print_warning "CA certificate path is configured but the file does NOT exist"
                echo ""
                print_info "Your configs.yaml specifies a CA certificate, but the file is missing."
                print_info "Obtain the CA certificate from the relay operator (relay runs process_config.sh; use --copy-certs there for SSH copy)."
                print_info "If the file is still missing after the relay node runs the script,"
                print_info "manually copy it from the relay node:"
                echo "  scp relay-node:/mosquitto/config/certs/ca.crt $expected_ca_path"
                ;;
            3)
                print_warning "CA certificate is configured but path may not match the relay node's certificate"
                echo ""
                print_info "Your configs.yaml has a CA certificate configured, but it may not be the correct one."
                print_info "Expected path: $expected_ca_path"
                print_info "Please verify you have the correct CA certificate from the relay node."
                ;;
            4)
                print_error "CA certificate file exists but is NOT a valid certificate"
                echo ""
                print_info "The file specified in configs.yaml exists but is corrupted or invalid."
                print_info "Please obtain a valid CA certificate from the relay node operator."
                exit 1
                ;;
            *)
                print_warning "Could not validate CA certificate configuration"
                print_info "Please ensure MQTTTLS.CAFile is set correctly in configs.yaml"
                ;;
        esac
        
        print_success "Client node configuration validation complete"
        echo ""
        print_info "═══════════════════════════════════════════════════════════════"
        print_info "NEXT STEP: Copy CA Certificate from Relay Node"
        print_info "═══════════════════════════════════════════════════════════════"
        echo ""
        print_info "The certificate directory has been created at: $cert_dir_path"
        if [ "$ownership_changed" = true ]; then
            print_success "Directory ownership has been set to your user - no sudo needed for copying files"
        fi
        print_info "You must now copy the CA certificate file from the relay node:"
        echo ""
        print_info "1. On the RELAY NODE (first node), the CA certificate is located at:"
        echo "   /mosquitto/config/certs/ca.crt"
        echo ""
        if [ "$ownership_changed" = true ] || [ -w "$cert_dir_path" ]; then
            print_info "2. Copy it to this CLIENT NODE using scp (no sudo needed):"
            echo "   scp relay-node-user@RELAY_NODE_IP:/mosquitto/config/certs/ca.crt $cert_dir_path/ca.crt"
        else
            print_info "2. Copy it to this CLIENT NODE using one of these methods:"
            echo ""
            echo "   Option A - Copy to temp first, then move with sudo:"
            echo "   scp relay-node-user@RELAY_NODE_IP:/mosquitto/config/certs/ca.crt /tmp/ca.crt"
            echo "   sudo mv /tmp/ca.crt $cert_dir_path/ca.crt"
            echo ""
            echo "   Option B - Using sudo scp (if your sudo allows it):"
            echo "   sudo scp relay-node-user@RELAY_NODE_IP:/mosquitto/config/certs/ca.crt $cert_dir_path/ca.crt"
        fi
        echo ""
        print_info "3. After copying, verify the certificate file exists:"
        echo "   ls -l $cert_dir_path/ca.crt"
        echo ""
        print_info "4. Update your configs.yaml to reference the certificate:"
        echo "   MQTTTLS:"
        echo "     CAFile: \"$cert_dir_path/ca.crt\""
        echo ""
        print_info "Replace 'RELAY_NODE_IP' with the actual IP address of your relay node."
        print_info "Replace 'relay-node-user' with the SSH username on the relay node."
        echo "" >&2
    fi

    install_progress_topic_if_registered done configure-node 2>/dev/null || true
    _process_config_finalize_repo_ownership_after_sudo
}

# Run main function (pass through CLI arguments)
main "$@"

