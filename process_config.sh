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

# HTTP port written into nodeAddresses URLs (management API); default Docker mapping is often 8080—set to match your deployment.
MPC_NODE_HTTP_PORT=8081

# Default example NodeMgtKey in configs.yaml — treated like unset (must be replaced for a real deployment).
NODE_MGT_ETH_PLACEHOLDER="0x1234567890abcdef1234567890abcdef12345678"

# Functions
print_error() {
    echo -e "${RED}ERROR: $1${NC}" >&2
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

print_step() {
    echo -e "\n${BLUE}==> $1${NC}"
}

# PyYAML safe_load/dump strips all comments. ruamel.yaml round-trips the prototype configs.yaml.
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

# Extract IP address from URL (http://ip:port or https://ip:port)
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

# Get threshold value from first MPC group
get_threshold_from_yaml() {
    local config_file="$1"
    
    if [ ! -f "$config_file" ]; then
        return 1
    fi
    
    # Use yq if available
    if command -v yq &> /dev/null; then
        local threshold=$(yq eval '.MPCGroups[0].threshold' "$config_file" 2>/dev/null)
        if [ -n "$threshold" ] && [ "$threshold" != "null" ]; then
            echo "$threshold"
            return 0
        fi
    fi
    
    # Use Python if available
    if command -v python3 &> /dev/null; then
        local threshold=$(python3 -c "
import yaml
import sys
try:
    with open('$config_file', 'r') as f:
        data = yaml.safe_load(f)
        groups = data.get('MPCGroups', [])
        if groups:
            threshold = groups[0].get('threshold')
            if threshold is not None:
                print(threshold)
except Exception:
    sys.exit(1)
" 2>/dev/null)
        if [ -n "$threshold" ]; then
            echo "$threshold"
            return 0
        fi
    fi
    
    # Fallback: simple grep parsing
    while IFS= read -r line; do
        if echo "$line" | grep -qE '^\s*threshold:\s*[0-9]+'; then
            local threshold=$(echo "$line" | grep -oE '[0-9]+' | head -1)
            if [ -n "$threshold" ]; then
                echo "$threshold"
                return 0
            fi
        fi
    done < "$config_file"
    
    return 1
}

# Validate threshold is less than number of nodes
validate_threshold() {
    local config_file="$1"
    
    if [ ! -f "$config_file" ]; then
        return 0  # Skip if config not found
    fi
    
    print_step "Validating threshold value..."
    
    # Get number of nodes
    local node_addresses=()
    while IFS= read -r addr; do
        [ -n "$addr" ] && node_addresses+=("$addr")
    done < <(parse_node_addresses_from_yaml "$config_file")
    
    local num_nodes=${#node_addresses[@]}
    
    if [ $num_nodes -eq 0 ]; then
        print_warning "No node addresses found - skipping threshold validation"
        return 0
    fi
    
    # Get threshold
    local threshold=$(get_threshold_from_yaml "$config_file")
    
    if [ -z "$threshold" ]; then
        print_warning "Could not determine threshold value - skipping validation"
        return 0
    fi
    
    # Validate threshold is a positive integer
    if ! echo "$threshold" | grep -qE '^[0-9]+$'; then
        print_error "Invalid threshold value: '$threshold' (must be a positive integer)"
        exit 1
    fi
    
    # Convert to integer for comparison
    threshold=$((threshold + 0))
    num_nodes=$((num_nodes + 0))
    
    # Check threshold < number of nodes (strictly less than)
    # In threshold cryptography, threshold + 1 nodes must agree, so threshold must be < number of nodes
    if [ $threshold -ge $num_nodes ]; then
        print_error "Threshold ($threshold) must be less than number of nodes ($num_nodes)"
        echo ""
        print_error "The threshold must be strictly less than the number of nodes in the group."
        print_error "In threshold cryptography, threshold + 1 nodes must agree to perform operations."
        print_info "Current configuration:"
        echo "  - Number of nodes: $num_nodes"
        echo "  - Threshold: $threshold"
        echo ""
        print_info "Valid examples:"
        echo "  - 2 nodes: threshold = 1 (requires 2 nodes to agree)"
        echo "  - 3 nodes: threshold = 1 or 2 (requires 2 or 3 nodes to agree)"
        echo "  - 4 nodes: threshold = 1, 2, or 3 (requires 2, 3, or 4 nodes to agree)"
        echo ""
        print_info "Please update the threshold in configs.yaml to be < $num_nodes"
        exit 1
    fi
    
    # Check threshold is at least 1
    if [ $threshold -lt 1 ]; then
        print_error "Threshold ($threshold) must be at least 1"
        echo ""
        print_info "Please update the threshold in configs.yaml to be at least 1"
        exit 1
    fi
    
    print_success "Threshold validation passed (threshold: $threshold, nodes: $num_nodes)"
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
            # Only use Python as last resort with strict timeout
            if python3 -c "import yaml" 2>/dev/null; then
                # Use a simple one-liner with explicit timeout
                local py_script="/tmp/presign_$$.py"
                cat > "$py_script" << 'PYEOF'
import yaml, sys, os
try:
    with open(os.environ['PRESIGN_CONFIG_FILE'], 'r') as f:
        d = yaml.safe_load(f) or {}
    i = d.get('InitiatePreSigning')
    c = d.get('PreSigningCacheSize')
    t = d.get('PreSigningMinThreshold')
    if i is not None: print('INITIATE:' + ('true' if i else 'false'))
    if c is not None: print('CACHE:' + str(c))
    if t is not None: print('THRESHOLD:' + str(t))
except: sys.exit(1)
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

# When PreSigningVerification exists but RelayerAPIURL is empty, prompt (or use RELAYER_API_URL) before validate_relayer_api_connection.
prompt_relayer_api_url_if_missing() {
    local config_file="$1"
    
    if ! command -v python3 &> /dev/null; then
        return 0
    fi
    if [ ! -f "$config_file" ]; then
        return 0
    fi
    
    local need_url
    need_url=$(RELAYER_CFG="$config_file" python3 << 'PYRELAYERNEED'
import os, yaml
path = os.environ["RELAYER_CFG"]
with open(path, "r") as f:
    d = yaml.safe_load(f) or {}
ps = d.get("PreSigningVerification")
if ps is None or not isinstance(ps, dict):
    print("no")
    raise SystemExit(0)
u = ps.get("RelayerAPIURL")
if u is None:
    print("yes")
elif isinstance(u, str) and not u.strip():
    print("yes")
else:
    print("no")
PYRELAYERNEED
)
    need_url=$(printf '%s' "$need_url" | tr -d '\r\n')
    if [ "$need_url" != "yes" ]; then
        return 0
    fi
    
    local env_url="${RELAYER_API_URL:-}"
    env_url="${env_url#"${env_url%%[![:space:]]*}"}"
    env_url="${env_url%"${env_url##*[![:space:]]}"}"
    if [ -n "$env_url" ]; then
        env_url="${env_url%/}"
        configs_yaml_merge_relayer_api_url "$config_file" "$env_url" || return 1
        print_success "Set PreSigningVerification.RelayerAPIURL from RELAYER_API_URL environment variable"
        return 0
    fi
    
    if [ ! -r /dev/tty ]; then
        print_error "PreSigningVerification is configured but RelayerAPIURL is empty."
        print_info "Set RELAYER_API_URL before running this script, or edit configs.yaml and add:"
        echo "  PreSigningVerification:"
        echo "    RelayerAPIURL: \"https://your-relayer-host:port\""
        return 1
    fi
    
    echo ""
    print_step "RelayerAPIURL missing — required when PreSigningVerification is configured"
    print_info "Obtain the relayer HTTP base URL from the DAO (serves /v1/mpc/chain_info). Not the same as MPC node addresses."
    local url_in=""
    while true; do
        read -r -p "RelayerAPIURL (https://... or http://host:port): " url_in < /dev/tty || true
        url_in="${url_in#"${url_in%%[![:space:]]*}"}"
        url_in="${url_in%"${url_in##*[![:space:]]}"}"
        if [ -z "$url_in" ]; then
            print_warning "RelayerAPIURL cannot be empty while PreSigningVerification is configured. Try again or remove that block from configs.yaml."
            continue
        fi
        url_in="${url_in%/}"
        if ! printf '%s' "$url_in" | grep -qE '^https?://[^[:space:]]+'; then
            print_error "URL must start with http:// or https:// (e.g. https://relayer.example.com:8080)"
            continue
        fi
        configs_yaml_merge_relayer_api_url "$config_file" "$url_in" || return 1
        print_success "Wrote PreSigningVerification.RelayerAPIURL to configs.yaml (comments preserved)"
        echo ""
        return 0
    done
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
import yaml
import sys
try:
    with open('$config_file', 'r') as f:
        data = yaml.safe_load(f)
        for group in data.get('MPCGroups', []):
            for addr in group.get('nodeAddresses', {}).values():
                if addr:
                    print(addr)
except Exception as e:
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

# Exit 0 if MPCGroups[0].nodeAddresses is missing, empty, or only the default example URLs (203.0.113.10–12:8080);
# 1 if configured; 2 if no MPCGroups.
first_mpc_group_node_addresses_empty() {
    local config_file="$1"
    if ! command -v python3 &> /dev/null; then
        return 1
    fi
    python3 - "$config_file" << 'PYNAEMPTY'
import yaml, sys
path = sys.argv[1]
PLACEHOLDER_URLS = frozenset(
    (
        "http://203.0.113.10:8080",
        "http://203.0.113.11:8080",
        "http://203.0.113.12:8080",
    )
)

def norm_node_url(u):
    s = str(u).strip().strip('"').strip("'")
    return s.lower()

def is_only_placeholder_node_addresses(na):
    if not isinstance(na, dict) or len(na) != 3:
        return False
    vals = []
    for v in na.values():
        if v is None or not str(v).strip():
            return False
        vals.append(norm_node_url(v))
    return len(vals) == 3 and frozenset(vals) == PLACEHOLDER_URLS

with open(path, "r") as f:
    d = yaml.safe_load(f)
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
if is_only_placeholder_node_addresses(na):
    sys.exit(0)
sys.exit(1)
PYNAEMPTY
}

# Strip whitespace, optional scheme/path, and trailing :port from user input (host or IPv4).
normalize_node_address_input() {
    local raw="$1"
    raw="${raw#"${raw%%[![:space:]]*}"}"
    raw="${raw%"${raw##*[![:space:]]}"}"
    raw="${raw#http://}"
    raw="${raw#https://}"
    raw="${raw%%/*}"
    raw="${raw%%\?*}"
    if [[ "$raw" == *:* ]]; then
        local after="${raw##*:}"
        if [[ "$after" =~ ^[0-9]+$ ]]; then
            raw="${raw%:*}"
        fi
    fi
    printf '%s' "$raw"
}

# If first group's nodeAddresses is empty or only the default example URLs, prompt for IPs/hostnames and write http://HOST:MPC_NODE_HTTP_PORT entries.
prompt_fill_empty_node_addresses() {
    local config_file="$1"
    first_mpc_group_node_addresses_empty "$config_file"
    local ec=$?
    if [ "$ec" -eq 1 ]; then
        return 0
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
        print_error "MPCGroups[0].nodeAddresses is empty or still the default example (203.0.113.10–12:8080). Edit configs.yaml or run this script in an interactive terminal."
        return 1
    fi
    
    echo ""
    print_step "nodeAddresses is empty or still the default example IPs — enter each node's public IP or hostname"
    print_info "Replace 203.0.113.10 / .11 / .12 (documentation examples) with your real public IPs or hostnames."
    print_info "The first address you enter is the RELAY NODE (runs the MQTT broker). Use the SAME order on every machine's configs.yaml."
    print_info "Port :${MPC_NODE_HTTP_PORT} is added automatically (http://...:${MPC_NODE_HTTP_PORT})."
    print_info "If your API listens on a different port, set MPC_NODE_HTTP_PORT at the top of this script (or edit configs.yaml afterward)."
    print_info "Enter one address per line. When you are done, type: finished (or done)"
    echo ""
    
    local hosts=()
    local line norm lower
    while true; do
        read -r -p "Node IP or hostname (or 'finished' to save): " line < /dev/tty || true
        lower=$(printf '%s' "$line" | tr '[:upper:]' '[:lower:]')
        lower="${lower#"${lower%%[![:space:]]*}"}"
        lower="${lower%"${lower##*[![:space:]]}"}"
        if [ "$lower" = "finished" ] || [ "$lower" = "done" ]; then
            break
        fi
        norm=$(normalize_node_address_input "$line")
        if [ -z "$norm" ]; then
            print_warning "Skipped empty line"
            continue
        fi
        local dup=false
        local h
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
    
    require_ruamel_yaml || return 1
    
    local hosts_tmp
    hosts_tmp=$(mktemp)
    printf '%s\n' "${hosts[@]}" > "$hosts_tmp"
    
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
    hosts = [ln.strip() for ln in f if ln.strip()]

yaml = YAML()
yaml.preserve_quotes = True
yaml.width = 4096
yaml.indent(mapping=2, sequence=4, offset=2)

with open(path, "r") as f:
    data = yaml.load(f)
if not data or not data.get("MPCGroups"):
    raise SystemExit("no MPCGroups")

grp = data["MPCGroups"][0]
na = grp.get("nodeAddresses")
if na is None:
    na = CommentedMap()
    grp["nodeAddresses"] = na
elif not isinstance(na, dict):
    na = CommentedMap()
    grp["nodeAddresses"] = na

new_keys = []
for i, h in enumerate(hosts, 1):
    k = f"node{i}_key"
    new_keys.append(k)
    na[k] = f"http://{h}:{port}"
for k in list(na.keys()):
    if k not in new_keys:
        del na[k]

with open(path, "w") as f:
    yaml.dump(data, f)
PYNA
    then
        rm -f "$hosts_tmp"
        print_error "Failed to write nodeAddresses to configs.yaml (python3 / PyYAML error)."
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
import yaml, sys, re
path = sys.argv[1]
with open(path, "r") as f:
    d = yaml.safe_load(f) or {}
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

# Prompt for NodeMgtKey / PublicMgtKey when empty; require at least one valid key after prompts.
prompt_configure_management_keys() {
    local config_file="$1"
    
    if ! command -v python3 &> /dev/null; then
        print_warning "python3 not found — cannot validate or prompt for management keys; ensure at least one of NodeMgtKey or PublicMgtKey is set in configs.yaml."
        return 0
    fi
    
    if [ ! -r /dev/tty ]; then
        if verify_at_least_one_management_key "$config_file"; then
            return 0
        fi
        print_error "At least one of NodeMgtKey or PublicMgtKey must be set. Edit configs.yaml or run this script interactively."
        return 1
    fi
    
    local set_node="" set_pub=""
    local nk_empty pk_empty
    nk_empty=$(CONFIG_FILE_MGT="$config_file" PH_ETH="$NODE_MGT_ETH_PLACEHOLDER" python3 -c "
import yaml, os, re
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

with open(os.environ['CONFIG_FILE_MGT']) as f:
    d = yaml.safe_load(f) or {}
v = d.get('NodeMgtKey')
h = eth_body_40(v)
if h is None:
    print('1')
else:
    print('1' if h == ph else '0')
")
    pk_empty=$(CONFIG_FILE_MGT="$config_file" python3 -c "
import yaml, os
with open(os.environ['CONFIG_FILE_MGT']) as f:
    d = yaml.safe_load(f) or {}
v = d.get('PublicMgtKey')
v = '' if v is None else str(v).strip().strip('\"').strip(\"'\")
print('1' if not v else '0')
")
    
    if [ "$nk_empty" = "1" ]; then
        echo ""
        print_step "NodeMgtKey is missing or still the default example address — optional Ethereum (MetaMask) management address"
        print_info "Replace the placeholder with an address you control. It is used with MetaMask (or any Ethereum wallet) and EIP-191 personal_sign for management API calls."
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
        print_step "PublicMgtKey is empty — optional Ed25519 public key (non-MetaMask management)"
        print_info "This lets you manage the node without MetaMask (no EIP-191); scripts and AI agents can sign with the matching Ed25519 secret key."
        print_info "You can set both NodeMgtKey and PublicMgtKey, or add PublicMgtKey later in configs.yaml."
        print_info "Enter the 64-hex-character Ed25519 public key (32 bytes). Press Enter to skip if you use NodeMgtKey only."
        echo ""
        local pk_in norm_pk ec
        while true; do
            read -r -p "Ed25519 public key (64 hex, or Enter to skip): " pk_in < /dev/tty || true
            pk_in="${pk_in#"${pk_in%%[![:space:]]*}"}"
            pk_in="${pk_in%"${pk_in##*[![:space:]]}"}"
            if [ -z "$pk_in" ]; then
                break
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
                print_warning "That looks like a 128-hex Ed25519 *private* key (or seed+key material). Enter the *public* key only (64 hex)."
                continue
            fi
            if [ "$ec" -ne 0 ] || [ -z "$norm_pk" ]; then
                print_error "Invalid Ed25519 public key (expected 64 hex characters)."
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
    
    if ! verify_at_least_one_management_key "$config_file"; then
        print_error "You must configure at least one of: NodeMgtKey (valid Ethereum address) or PublicMgtKey (valid Ed25519 public key, 64 hex)."
        return 1
    fi
    return 0
}

# Get first node address from config (relay node = runs mosquitto).
# All nodes must list nodeAddresses in the SAME order; the first entry is the relay node.
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
import yaml
import sys
try:
    with open('$config_file', 'r') as f:
        data = yaml.safe_load(f)
        groups = data.get('MPCGroups', [])
        if groups:
            node_addresses = groups[0].get('nodeAddresses', {})
            if node_addresses:
                # First value = relay node (order must be same on all nodes)
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

# Validate node IP against config
validate_node_ip() {
    local config_file="$1"
    
    if [ ! -f "$config_file" ]; then
        print_warning "Could not find configs.yaml - skipping IP validation"
        print_info "Expected locations: console/configs.yaml or configs.yaml"
        return 0  # Don't fail if config not found
    fi
    
    print_step "Validating node IP against MPC group configuration..." >&2
    
    # Get all node addresses from config
    local node_addresses=()
    while IFS= read -r addr; do
        [ -n "$addr" ] && node_addresses+=("$addr")
    done < <(parse_node_addresses_from_yaml "$config_file")
    
    if [ ${#node_addresses[@]} -eq 0 ]; then
        print_warning "No node addresses found in configs.yaml - skipping IP validation"
        return 0
    fi
    
    # Get first node address
    local first_node_addr=$(get_first_node_address "$config_file")
    local first_node_ip=""
    if [ -n "$first_node_addr" ]; then
        first_node_ip=$(extract_ip_from_url "$first_node_addr")
    fi
    
    # Get local IPs
    local local_ips=()
    while IFS= read -r ip; do
        [ -n "$ip" ] && local_ips+=("$ip")
    done < <(get_local_ips)
    
    if [ ${#local_ips[@]} -eq 0 ]; then
        print_warning "Could not determine local IP addresses - skipping validation"
        return 0
    fi
    
    # Check if any local IP matches any node address
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
        echo "  2. The node's IP address matches one of the addresses in the configuration"
        exit 1
    fi
    
    print_success "Node IP validation passed" >&2
    
    # Debug output (to stderr so it's not captured by command substitution)
    echo "ℹ Debug: First node IP from config: ${first_node_ip:-<not found>}" >&2
    echo "ℹ Debug: Local IPs detected: ${local_ips[*]}" >&2
    
    # Check if it's the first node (relay node) and return result
    local is_first=false
    if [ -n "$first_node_ip" ]; then
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
import yaml
import sys
try:
    with open('$config_file', 'r') as f:
        data = yaml.safe_load(f)
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
        print_warning "Running as root - this is usually not necessary"
        print_info "The script can typically be run as a regular user if you own the directory"
        read -p "Continue anyway? (yes/no): " continue_root
        if [ "$continue_root" != "yes" ] && [ "$continue_root" != "y" ]; then
            print_info "Exiting. Please run as a regular user if you own the mosquitto/config directory"
            exit 0
        fi
    fi
}

# Check if user has sudo access (required for client nodes to create /mosquitto/config/certs)
check_sudo_access() {
    # If running as root, sudo is not needed
    if [ "$EUID" -eq 0 ]; then
        return 0
    fi
    
    # Check if sudo command exists
    if ! command -v sudo &> /dev/null; then
        print_error "sudo command not found"
        print_error "This script requires sudo access to create the certificate directory on client nodes."
        echo ""
        print_info "Please install sudo or run this script as root."
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
        print_error "This script requires sudo access to create the certificate directory on client nodes."
        echo ""
        print_info "Please ensure:"
        echo "  1. Your user has sudo privileges"
        echo "  2. You can run 'sudo -v' successfully"
        echo "  3. Or run this script as root"
        echo ""
        print_info "To check sudo access, try: sudo whoami"
        print_info "If prompted for a password, enter it when the script requests sudo access."
        exit 1
    fi
    
    # If we get here, sudo is available and working
    return 0
}

# Check if certificate directory exists and is writable
check_cert_dir() {
    if [ ! -d "$(dirname "$0")" ]; then
        print_error "Certificate directory parent does not exist: $(dirname "$0")"
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
            echo "  - Or change ownership: sudo chown -R \$USER:$(dirname "$0")"
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
        echo "    sudo chown -R \$USER:$USER $(dirname "$0")"
        echo "  - Or run with sudo: sudo ./process_config.sh"
        echo "  - After generating, ensure mosquitto can read the files:"
        echo "    sudo chown -R mosquitto:mosquitto $CERT_DIR  # if mosquitto runs as 'mosquitto' user"
        exit 1
    fi
    
    # Check directory ownership
    DIR_OWNER=$(stat -c '%U' "$CERT_DIR" 2>/dev/null || stat -f '%Su' "$CERT_DIR" 2>/dev/null)
    CURRENT_USER=$(whoami)
    if [ "$DIR_OWNER" != "$CURRENT_USER" ] && [ "$EUID" -ne 0 ]; then
        print_warning "Directory is owned by '$DIR_OWNER' but you are '$CURRENT_USER'"
        print_info "Files will be owned by you. If mosquitto runs as '$DIR_OWNER', you may need to:"
        echo "  sudo chown -R $DIR_OWNER:$DIR_OWNER $CERT_DIR"
    fi
}

# Mosquitto/MQTT broker TLS only (under mosquitto/config/certs). Returns 0 = regenerate, 1 = keep existing.
confirm_overwrite_mqtt_certs() {
    if [ ! -f "$CA_KEY" ] && [ ! -f "$CA_CRT" ] && [ ! -f "$SERVER_KEY" ] && [ ! -f "$SERVER_CRT" ]; then
        return 0
    fi
    print_warning "Some Mosquitto (MQTT TLS) broker certificate files already exist — these are for the MQTT broker (e.g. port 8883), not for Browser HTTPS (webTLS, port 8443):"
    [ -f "$CA_KEY" ] && echo "  - $CA_KEY"
    [ -f "$CA_CRT" ] && echo "  - $CA_CRT"
    [ -f "$SERVER_KEY" ] && echo "  - $SERVER_KEY"
    [ -f "$SERVER_CRT" ] && echo "  - $SERVER_CRT"
    echo ""
    read -p "Overwrite these Mosquitto (MQTT) TLS files? (yes/no): " overwrite
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
import yaml
import sys
try:
    with open('$config_file', 'r') as f:
        data = yaml.safe_load(f)
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
EOF
        print_info "Including IP address $server_ip in certificate SANs"
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
    print_info "Note: This script typically does NOT need to be run as root/sudo."
    print_info "      Only use sudo if the directory is owned by another user (e.g., mosquitto service)."
    print_info ""
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
    
    # Construct broker address (TLS on port 8883)
    local broker_addr="ssl://${first_node_host}:8883"
    
    print_step "Configuring mqttBroker in configs.yaml..."
    print_info "Setting mqttBroker to: $broker_addr (derived from first node: $first_node_addr)"
    
    # Check if mqttBroker is already set by the user
    local existing_broker=""
    local mqtt_broker_exists=false
    if grep -qE '^\s*mqttBroker\s*:' "$config_file"; then
        mqtt_broker_exists=true
        # Extract existing value via awk (no sed - avoids any chance of URL like ssl:// breaking sed)
        existing_broker=$(awk '
            /^[[:space:]]*mqttBroker[[:space:]]*:/ {
                sub(/#.*$/, ""); sub(/^[[:space:]]*mqttBroker[[:space:]]*:[[:space:]]*/, ""); gsub(/^["'\'']?|["'\'']?[[:space:]]*$/, ""); gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print; exit
            }
        ' "$config_file" | xargs)
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
    # Update all groups (only if not already set or if set to empty)
    for group in data.get('MPCGroups', []):
        mqtt_broker = group.get('mqttBroker')
        # Update if not set, empty string, or None
        if mqtt_broker is None or mqtt_broker == '' or str(mqtt_broker).strip() == '':
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
                # Check if it's because mqttBroker already has a value
                if [ "$mqtt_broker_exists" = true ] && [ -n "$existing_broker" ]; then
                    # Already handled above, just return
                    return 0
                else
                    print_warning "ruamel.yaml found no groups to update, trying sed fallback..."
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
        # Add mqttBroker after threshold if it exists, otherwise after nodeAddresses
        if grep -qE '^\s*threshold\s*:' "$config_file"; then
            # Add after threshold (use awk to avoid sed issues with / and " in broker_addr e.g. ssl://host:8883)
            awk -v broker="$broker_addr" '
                /^[[:space:]]*threshold[[:space:]]*:/ { print; print "    mqttBroker: \"" broker "\""; next }
                { print }
            ' "$config_file" > "${config_file}.tmp" && mv "${config_file}.tmp" "$config_file"
        elif grep -qE '^\s*nodeAddresses\s*:' "$config_file"; then
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
            print_warning "Could not find threshold or nodeAddresses - cannot auto-add mqttBroker"
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
        elif [ "$mqtt_broker_exists" = true ] && [ -z "$existing_broker" ]; then
            # mqttBroker exists but is empty - update line via awk (no sed so ssl:// in URL cannot break anything)
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
                print_success "Updated empty mqttBroker to: $broker_addr"
            else
                rm -f "${config_file}.tmp"
                print_warning "Failed to update mqttBroker - please update manually in configs.yaml"
            fi
        fi
    fi
    
    return 0
}

# Configure docker-compose.yml based on node type (relay or client).
# Uses two fixed files: docker-compose.relay.yml and docker-compose.client.yml.
# Copies the appropriate one to docker-compose.yml (no sed/awk on the active file).
# When script is in console/, look for compose files in script dir then in parent (repo root).
configure_docker_compose() {
    local is_relay_node="$1"
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
    else
        print_warning "Failed to copy $template to docker-compose.yml"
        return 1
    fi
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
        if sudo mkdir -p "$WEB_TLS_HOST_DIR" 2>/dev/null; then
            sudo chown "$(whoami):$(whoami)" "$WEB_TLS_HOST_DIR" 2>/dev/null || true
        else
            print_error "Could not create $WEB_TLS_HOST_DIR"
            return 1
        fi
    fi

    local need_cert=true
    if [ -f "$BROWSER_HTTPS_CRT" ] && [ -f "$BROWSER_HTTPS_KEY" ]; then
        if openssl x509 -in "$BROWSER_HTTPS_CRT" -noout -text 2>/dev/null | grep -Fq "IP Address:${browser_ip}"; then
            need_cert=false
        else
            print_info "Regenerating Browser HTTPS (web) TLS cert — IP SAN mismatch or new IP (not MQTT certs)"
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
            print_success "Browser HTTPS (web) certificate: $BROWSER_HTTPS_CRT"
        else
            rm -f "$sslcnf"
            print_error "Failed to generate Browser HTTPS (web) certificate"
            return 1
        fi
    else
        print_success "Browser HTTPS (web) certificate already valid for IP $browser_ip"
    fi

    if ! command -v python3 &> /dev/null; then
        print_warning "python3 not found — update configs.yaml BrowserHTTPS manually (see docs-internal/railway-browser-https-deployment.md)"
        return 0
    fi
    require_ruamel_yaml || return 1
    CONFIG_FILE_MERGE="$config_file" DEFAULT_ORIGIN_MERGE="$DEFAULT_BROWSER_HTTPS_ORIGIN" \
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
if "ExpectedIssuer" not in bh:
    bh["ExpectedIssuer"] = ""
bh["EnforceNodeIPClaim"] = bool(bh.get("EnforceNodeIPClaim", True))
_jw = bh.get("JWKSURL") or ""
jwks = _jw.strip() if isinstance(_jw, str) else str(_jw).strip()
if jwks:
    bh["JWKSURL"] = jwks

with open(path, "w") as f:
    yaml.dump(data, f)
PYMERGE
    print_success "configs.yaml updated: BrowserHTTPS block written (comments preserved; cert paths, AllowedOrigins, ExpectedAudience, EnforceNodeIPClaim)"
    print_warning "JWKSURL is required for RS256 (see node/configs.go Enabled()). If it is not set in configs.yaml, the 8443 listener will not start."
    print_info "AllowedOrigins: https://mpa.continuumdao.org (edit if your browser Origin differs). Docker: port 8443, volume ./webTLS/config/certs. See docs-internal/railway-browser-https-deployment.md"
}

show_process_config_help() {
    echo "Usage: $0 [ARGUMENTS]"
    echo ""
    echo "Arguments:"
    echo "  --copy-certs      On the relay: after MQTT certs are generated, copy the CA to clients over SSH"
    echo "  --no-copy-certs   Do not copy via SSH (default); kept for explicit use / backward compatibility"
    echo "  --help | -h | -help | help   Show this message (arguments above + relay/client behavior below)"
    echo ""
    echo "This script validates configuration and generates certificates."
    echo ""
    echo "If MPCGroups[0].nodeAddresses is empty or still the default 203.0.113.10–12:8080 examples, the script prompts"
    echo "and writes http://...:${MPC_NODE_HTTP_PORT} URLs (first entry = relay; same order on all nodes)."
    echo ""
    echo "If NodeMgtKey or PublicMgtKey is empty, the script may prompt: Ethereum (MetaMask) and/or"
    echo "Ed25519 public key for non-MetaMask management. At least one valid key is required."
    echo ""
    echo "If PreSigningVerification is set but RelayerAPIURL is empty, the script prompts for the URL"
    echo "(or use RELAYER_API_URL in the environment)."
    echo ""
    echo "Updates to configs.yaml require ruamel.yaml (e.g. apt install python3-ruamel.yaml, or pip in a venv)"
    echo "so the prototype file's comments are preserved; plain PyYAML dump would strip them."
    echo ""
    echo "On RELAY NODE (first node):"
    echo "  - Validates configuration"
    echo "  - Validates database connectivity (if PreSigningVerification is configured)"
    echo "  - Generates MQTT (mosquitto) certificates"
    echo "  - Enables Browser HTTPS: TLS cert in webTLS/config/certs, configs.yaml BrowserHTTPS, Docker 8443"
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
}

# Main execution
main() {
    local COPY_CERTS=false
    
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
    
    echo "=========================================="
    echo "MPC config: Mosquitto (MQTT) + Browser HTTPS (web) validation and certificates"
    echo "=========================================="
    echo ""
    
    # Require configs.yaml first (fail fast before any other checks)
    CONFIG_FILE=$(find_configs_yaml)
    if [ -z "$CONFIG_FILE" ]; then
        print_error "Could not find configs.yaml"
        print_info "Expected locations: next to this script (configs.yaml), repo root, ./configs.yaml, or ./console/configs.yaml"
        exit 1
    fi
    print_success "Found config: $CONFIG_FILE"
    echo ""
    
    prompt_fill_empty_node_addresses "$CONFIG_FILE" || exit 1
    
    prompt_configure_management_keys "$CONFIG_FILE" || exit 1
    
    check_root
    check_openssl
    
    # Check sudo access early (needed for client nodes to create /mosquitto/config/certs)
    check_sudo_access
    
    # Validate configuration
    validate_no_default_ips "$CONFIG_FILE"
    validate_external_ips_only "$CONFIG_FILE"
    validate_threshold "$CONFIG_FILE"
    validate_presign_config "$CONFIG_FILE"
    
    # Determine relay vs client and configure docker-compose FIRST (so client always gets mosquitto commented out)
    # before any step that might exit (e.g. Relayer API check). Otherwise a client would never reach configure_docker_compose.
    IS_RELAY_NODE=$(validate_node_ip "$CONFIG_FILE")
    if [ "$IS_RELAY_NODE" = "true" ]; then
        print_info "Detected as RELAY NODE (this machine is first in configs.yaml nodeAddresses) - mosquitto will be enabled"
    else
        print_info "Detected as CLIENT NODE (this machine is not first in configs.yaml nodeAddresses) - mosquitto will be commented out"
    fi
    
    configure_mqtt_broker "$CONFIG_FILE" "$IS_RELAY_NODE"
    configure_docker_compose "$IS_RELAY_NODE"

    setup_browser_https "$CONFIG_FILE"
    
    prompt_relayer_api_url_if_missing "$CONFIG_FILE" || exit 1
    
    # Validate Relayer API connection (MANDATORY for relay before certificate generation; may exit 1 on failure)
    validate_relayer_api_connection "$CONFIG_FILE"
    
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
                check_cert_dir
                if confirm_overwrite_mqtt_certs; then
                    print_step "Generating self-signed Mosquitto (MQTT TLS) certificates for the broker..."
                    generate_ca_key
                    generate_ca_cert
                    generate_server_key
                    generate_server_csr
                    sign_server_cert "$CONFIG_FILE"
                    set_permissions
                    
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
            check_cert_dir
            if confirm_overwrite_mqtt_certs; then
                generate_ca_key
                generate_ca_cert
                generate_server_key
                generate_server_csr
                sign_server_cert "$CONFIG_FILE"
                set_permissions
                
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
        
        local current_user=$(whoami)
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
                # Change ownership to current user so they can copy files without sudo
                if sudo chown "$current_user:$current_user" "$cert_dir_path" 2>/dev/null; then
                    print_success "Directory ownership changed to $current_user - you can copy files without sudo"
                    ownership_changed=true
                else
                    print_warning "Could not change directory ownership - you may need sudo to copy certificates"
                fi
            else
                print_warning "Could not create certificate directory: $cert_dir_path"
                print_info "You need to create it manually with appropriate permissions:"
                echo "  sudo mkdir -p $cert_dir_path"
                echo "  sudo chmod 755 $cert_dir_path"
                echo "  sudo chown $current_user:$current_user $cert_dir_path"
            fi
        else
            print_success "Certificate directory exists: $cert_dir_path"
            # Check if writable
            if [ ! -w "$cert_dir_path" ]; then
                print_warning "Certificate directory is not writable by current user"
                print_info "Attempting to change ownership to $current_user..."
                if sudo chown "$current_user:$current_user" "$cert_dir_path" 2>/dev/null; then
                    print_success "Directory ownership changed to $current_user - you can now copy files without sudo"
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
        
        # Validate CAFile configuration
        local validation_result
        validation_result=$(validate_client_cafile "$CONFIG_FILE" "$expected_ca_path" 2>&1)
        local exit_code=$?
        
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
        echo ""
    fi
}

# Run main function (pass through CLI arguments)
main "$@"

