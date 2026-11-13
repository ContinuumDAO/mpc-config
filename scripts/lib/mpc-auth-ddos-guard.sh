#!/usr/bin/env bash
# Connection caps for MPA Wallet public TCP listeners.
#
# Docker accepts published ports in FORWARD / DOCKER-USER, which UFW INPUT
# rules never see. This script rebuilds an MPC-GUARD chain and appends a jump
# from DOCKER-USER (never -I) so the wg0 egress RETURN installed by
# mpc-auth-vpn-wg0-hooks.sh stays first. SSH is capped on INPUT for NEW
# packets on the WAN interface only.
#
# WireGuard, Shadowsocks, loopback, docker bridges, wg0, and wg-egress are not
# capped. An enabled udp2raw listen port is skipped so fake-TCP VPN transport
# is not treated as Browser HTTPS.
#
# Usage:
#   mpc-auth-ddos-guard.sh [--config /path/configs.yaml] [--dry-run]
#   mpc-auth-ddos-guard.sh [--config /path/configs.yaml] --print-plan
#
# --print-plan writes CAP, SCANCAP, SCANDROP, SSH, and IGNORE lines and does
# not touch iptables or fail2ban. Desktop host tools consume that plan.
# Exit 0 applied (or dry-run / plan printed). Exit 2 when firewalld is active
# and nothing was installed. Exit 1 on error.

set -euo pipefail

DRY_RUN=0
PRINT_PLAN=0
CONFIG="${MPC_AUTH_DDOS_CONFIG:-}"

usage() {
	echo "usage: $0 [--config configs.yaml] [--dry-run|--print-plan]" >&2
	exit 2
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--config)
		CONFIG="${2:-}"
		shift 2
		;;
	--dry-run)
		DRY_RUN=1
		shift
		;;
	--print-plan)
		PRINT_PLAN=1
		shift
		;;
	-h | --help) usage ;;
	*) usage ;;
	esac
done

if [[ -r /etc/default/mpc-auth-docker ]]; then
	# shellcheck source=/dev/null
	. /etc/default/mpc-auth-docker
fi

if [[ -z "$CONFIG" ]]; then
	workdir="${MPC_AUTH_COMPOSE_WORKDIR:-${MPC_AUTH_COMPOSE_DIR:-}}"
	if [[ -n "$workdir" && -f "${workdir}/configs.yaml" ]]; then
		CONFIG="${workdir}/configs.yaml"
	else
		here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
		if [[ -f "${here}/../../configs.yaml" ]]; then
			CONFIG="$(cd "${here}/../.." && pwd)/configs.yaml"
		fi
	fi
fi

if [[ -z "$CONFIG" || ! -f "$CONFIG" ]]; then
	echo "mpc-auth-ddos-guard: configs.yaml not found (pass --config or set MPC_AUTH_COMPOSE_WORKDIR)" >&2
	exit 1
fi

if [[ "$PRINT_PLAN" -eq 1 ]]; then
	export MPC_AUTH_DDOS_PRINT_PLAN=1
fi

if [[ "$PRINT_PLAN" -eq 0 ]] && command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
	echo "mpc-auth-ddos-guard: firewalld is active. This guard is UFW/iptables-only and was not applied." >&2
	exit 2
fi

if [[ "$PRINT_PLAN" -eq 0 && "$DRY_RUN" -eq 0 && "${EUID:-$(id -u)}" -ne 0 ]]; then
	exec sudo -E "$0" --config "$CONFIG"
fi

plan_file="$(mktemp)"
trap 'rm -f "$plan_file"' EXIT

MPC_AUTH_DDOS_CONFIG="$CONFIG" python3 - "$plan_file" <<'PY'
import os, re, socket, subprocess, sys, urllib.parse

try:
    from ruamel.yaml import YAML
except ImportError:
    sys.stderr.write("mpc-auth-ddos-guard: python3-ruamel.yaml is required\n")
    sys.exit(1)

out_path = sys.argv[1]
cfg_path = os.environ["MPC_AUTH_DDOS_CONFIG"]

def scalar_int(val, default):
    if val is None or val == "":
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

def section_port(data, key, default):
    sec = data.get(key)
    if isinstance(sec, dict) and sec.get("ListenPort") not in (None, ""):
        return scalar_int(sec.get("ListenPort"), default)
    return default

def section_cidr(data, key, default):
    sec = data.get(key)
    if isinstance(sec, dict):
        raw = sec.get("VpnNetworkCidr")
        if raw is not None and str(raw).strip():
            return str(raw).strip()
    return default

def unit_active(name):
    try:
        r = subprocess.run(["systemctl", "is-active", "--quiet", name], check=False)
    except (FileNotFoundError, OSError):
        return False
    return r.returncode == 0

def listen_port_from_env_file(path, fallback):
    if path and os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    stripped = line.strip()
                    if not stripped.startswith("LISTEN_PORT"):
                        continue
                    _, _, raw = stripped.partition("=")
                    raw = raw.strip().strip('"').strip("'")
                    if raw.isdigit():
                        return int(raw)
        except OSError:
            pass
    return fallback

def host_of(raw):
    s = "" if raw is None else str(raw).strip()
    if not s or s.lower() == "null":
        return ""
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$", s):
        return s
    if "://" not in s:
        s = "http://" + s
    try:
        return urllib.parse.urlparse(s).hostname or ""
    except ValueError:
        return ""

def ipv4_literal(host):
    return bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", host or ""))

def resolve_source(raw):
    host = host_of(raw)
    if not host:
        return ""
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$", host) or ipv4_literal(host):
        return host
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror:
        sys.stderr.write("mpc-auth-ddos-guard: could not resolve %s\n" % host)
        return ""
    if not infos:
        return ""
    return infos[0][4][0]

y = YAML()
with open(cfg_path, encoding="utf-8") as fh:
    data = y.load(fh) or {}
if not isinstance(data, dict):
    data = {}

wan = os.environ.get("MPC_AUTH_DDOS_WAN_IF", "").strip()
if not wan:
    try:
        route = subprocess.check_output(["ip", "-4", "route", "show", "default"], text=True)
    except (FileNotFoundError, subprocess.CalledProcessError, OSError):
        route = ""
    m = re.search(r"\bdev\s+(\S+)", route)
    if m:
        wan = m.group(1)
print_plan = os.environ.get("MPC_AUTH_DDOS_PRINT_PLAN") == "1"
if wan in ("", "wg0", "wg-egress"):
    if print_plan:
        wan = wan or "-"
    else:
        sys.stderr.write(
            "mpc-auth-ddos-guard: WAN interface is %s — refusing to install caps that would match VPN traffic\n"
            % (wan or "unset")
        )
        sys.exit(1)

pub = scalar_int(data.get("PublicDiscoveryPort"), 18080)
sr = scalar_int(data.get("ScannerRelayerPort"), 18081)
bh = data.get("BrowserHTTPS")
bh_port = 8443
if isinstance(bh, dict) and bh.get("Port") not in (None, "", 0):
    bh_port = scalar_int(bh.get("Port"), 8443)

dash_port = 0
na = data.get("ContinuumdaoNodeApp")
dash_enabled = True
if na is None:
    dash_port = 3333
elif isinstance(na, dict):
    dash_enabled = scalar_bool(na.get("Enabled"), True)
    dash_port = scalar_int(na.get("HostPort"), 3333) if dash_enabled else 0
else:
    dash_enabled = False
if dash_port <= 0 or dash_port > 65535:
    dash_port = 0

admin_dir = os.environ.get("MPC_AUTH_UDP2RAW_SRC_DIR", "/var/lib/mpc-auth-docker/udp2raw")
egress_dir = os.environ.get("MPC_AUTH_UDP2RAW_EGRESS_SRC_DIR", "/var/lib/mpc-auth-docker/udp2raw-egress")
admin_fallback = scalar_int(os.environ.get("MPC_AUTH_UDP2RAW_LISTEN_PORT"), section_port(data, "Udp2raw", 443))
egress_fallback = scalar_int(
    os.environ.get("MPC_AUTH_UDP2RAW_EGRESS_LISTEN_PORT"),
    section_port(data, "Udp2rawEgress", 8443),
)
skip = set()
if unit_active("mpc-auth-udp2raw.service"):
    port = listen_port_from_env_file(os.path.join(admin_dir, "server.env"), admin_fallback)
    if 0 < port <= 65535:
        skip.add(port)
        sys.stderr.write(
            "mpc-auth-ddos-guard: udp2raw admin is active on TCP %s — not capping that port\n" % port
        )
if unit_active("mpc-auth-udp2raw-egress.service"):
    port = listen_port_from_env_file(os.path.join(egress_dir, "server.env"), egress_fallback)
    if 0 < port <= 65535:
        skip.add(port)
        sys.stderr.write(
            "mpc-auth-ddos-guard: udp2raw egress is active on TCP %s — not capping that port\n" % port
        )

# Higher rank wins when two roles share a port (dashboard on the discovery port stays at the HTTP cap).
rank = {"disc": 1, "mqtt": 2, "http": 3}
caps = {}

def add_cap(port, kind):
    if not isinstance(port, int) or port <= 0 or port > 65535 or port == 22:
        return
    if port in skip:
        sys.stderr.write(
            "mpc-auth-ddos-guard: leaving TCP %s uncapped because udp2raw is listening there\n" % port
        )
        return
    prev = caps.get(port)
    if prev is None or rank[kind] > rank[prev]:
        caps[port] = kind

add_cap(pub, "disc")
add_cap(bh_port, "http")
if dash_enabled and dash_port:
    add_cap(dash_port, "http")
add_cap(8883, "mqtt")

limits = {
    "http": (80, "30/sec", 60),
    "disc": (40, "20/sec", 40),
    "mqtt": (16, "2/sec", 8),
}

def iter_node_urls(node_addresses):
    if isinstance(node_addresses, dict):
        return [v for v in node_addresses.values()]
    if isinstance(node_addresses, list):
        return list(node_addresses)
    return []

peers = []
seen_peer = set()
for group in data.get("MPCGroups") or []:
    if not isinstance(group, dict):
        continue
    for raw in iter_node_urls(group.get("nodeAddresses")):
        ip = resolve_source(raw)
        if ip and ip not in seen_peer:
            seen_peer.add(ip)
            peers.append(ip)

# Same source set as process_config.sh: RelayerAPIURL plus ScannerAPIURLs,
# and DEFAULT_SCANNER_API_URLS when the scanner list is missing or empty.
scanner_entries = []
raw_scanners = data.get("ScannerAPIURLs")
if isinstance(raw_scanners, list):
    for item in raw_scanners:
        if item is None:
            continue
        text = str(item).strip()
        if text and text.lower() != "null":
            scanner_entries.append(text)
if not scanner_entries:
    scanner_entries.append("https://scanner1.continuumdao.org")

relayer = ""
ps = data.get("PreSigningVerification")
if isinstance(ps, dict) and ps.get("RelayerAPIURL") not in (None, ""):
    relayer = str(ps.get("RelayerAPIURL")).strip()

scan_sources = []
seen_src = set()
for raw in ([relayer] if relayer and relayer.lower() != "null" else []) + scanner_entries:
    src = resolve_source(raw)
    if src and src not in seen_src:
        seen_src.add(src)
        scan_sources.append(src)

lines = ["WAN=%s" % wan]
for port in sorted(caps):
    above, rate, burst = limits[caps[port]]
    lines.append("CAP=%s %s %s %s" % (port, above, rate, burst))

scan_shared = sr in caps or sr in skip or sr == 22
if sr and 0 < sr <= 65535 and sr not in skip and not scan_shared:
    if scan_sources:
        above, rate, burst = limits["disc"]
        for src in scan_sources:
            lines.append("SCANCAP=%s %s %s %s %s" % (sr, above, rate, burst, src))
        lines.append("SCANDROP=%s" % sr)
    else:
        sys.stderr.write(
            "mpc-auth-ddos-guard: no scanner/relayer sources resolved — TCP %s stays world-open with a per-IP cap\n" % sr
        )
        above, rate, burst = limits["disc"]
        lines.append("CAP=%s %s %s %s" % (sr, above, rate, burst))
elif sr and scan_shared and sr not in skip:
    sys.stderr.write(
        "mpc-auth-ddos-guard: ScannerRelayerPort %s is shared with another listener — not applying a source allowlist\n" % sr
    )

lines.append("SSH=22 10 10/minute 10")
ignore = ["127.0.0.1/8", "::1", section_cidr(data, "WireGuard", "10.8.0.0/24"), section_cidr(data, "WireGuardEgress", "10.9.0.0/24")]
ignore.extend(peers)
seen_ign = set()
for item in ignore:
    if item and item not in seen_ign:
        seen_ign.add(item)
        lines.append("IGNORE=%s" % item)

with open(out_path, "w", encoding="utf-8") as fh:
    fh.write("\n".join(lines) + "\n")
PY

if [[ "$PRINT_PLAN" -eq 1 ]]; then
	cat "$plan_file"
	exit 0
fi

WAN=""
declare -a CAPS=()
declare -a SCANCAPS=()
declare -a SCANDROPS=()
SSH_SPEC=""
declare -a IGNORES=()
while IFS= read -r line || [[ -n "$line" ]]; do
	[[ -z "$line" ]] && continue
	case "$line" in
	WAN=*) WAN="${line#WAN=}" ;;
	CAP=*) CAPS+=("${line#CAP=}") ;;
	SCANCAP=*) SCANCAPS+=("${line#SCANCAP=}") ;;
	SCANDROP=*) SCANDROPS+=("${line#SCANDROP=}") ;;
	SSH=*) SSH_SPEC="${line#SSH=}" ;;
	IGNORE=*) IGNORES+=("${line#IGNORE=}") ;;
	*)
		echo "mpc-auth-ddos-guard: bad plan line: $line" >&2
		exit 1
		;;
	esac
done <"$plan_file"

if [[ -z "$WAN" ]]; then
	echo "mpc-auth-ddos-guard: plan did not include a WAN interface" >&2
	exit 1
fi

# Print a rule in dry-run. Apply with the xtables lock so Docker and wg-quick
# cannot interleave. -w is not part of the match, so dry-run output stays the
# rule a reviewer compares against DOCKER-USER order.
ipt() {
	local bin="$1"
	shift
	if [[ "$DRY_RUN" -eq 1 ]]; then
		printf '%s' "$bin"
		local arg
		for arg in "$@"; do
			printf ' %s' "$arg"
		done
		printf '\n'
		return 0
	fi
	"$bin" -w 5 "$@"
}

drop_jumps() {
	local bin="$1"
	local chain="$2"
	local target="$3"
	if [[ "$DRY_RUN" -eq 1 ]]; then
		ipt "$bin" -D "$chain" -j "$target"
		return 0
	fi
	while "$bin" -w 5 -D "$chain" -j "$target" 2>/dev/null; do
		:
	done
}

ensure_chain() {
	local bin="$1"
	local chain="$2"
	if [[ "$DRY_RUN" -eq 1 ]]; then
		ipt "$bin" -N "$chain"
		ipt "$bin" -F "$chain"
		return 0
	fi
	"$bin" -w 5 -N "$chain" 2>/dev/null || true
	"$bin" -w 5 -F "$chain"
}

hash_name() {
	# iptables hashlimit names are short; family digit + port stays unique.
	local family="$1"
	local port="$2"
	printf '%s%s' "$family" "$port"
}

add_cap_rules() {
	local bin="$1"
	local chain="$2"
	local mask="$3"
	local family="$4"
	local port="$5"
	local above="$6"
	local rate="$7"
	local burst="$8"
	local extra_src="${9:-}"
	local -a src=()
	if [[ -n "$extra_src" ]]; then
		src=(-s "$extra_src")
	fi
	ipt "$bin" -A "$chain" -p tcp --dport "$port" "${src[@]}" -m connlimit --connlimit-above "$above" --connlimit-mask "$mask" -j DROP
	ipt "$bin" -A "$chain" -p tcp --dport "$port" "${src[@]}" -m conntrack --ctstate NEW -m hashlimit \
		--hashlimit-above "$rate" --hashlimit-burst "$burst" --hashlimit-mode srcip --hashlimit-srcmask "$mask" \
		--hashlimit-name "$(hash_name "$family" "$port")" -j DROP
}

apply_docker_guard() {
	local bin="$1"
	local mask="$2"
	local family="$3"
	ensure_chain "$bin" MPC-GUARD
	ipt "$bin" -A MPC-GUARD -i lo -j RETURN
	ipt "$bin" -A MPC-GUARD -i docker0 -j RETURN
	ipt "$bin" -A MPC-GUARD -i br-+ -j RETURN
	ipt "$bin" -A MPC-GUARD -i wg0 -j RETURN
	ipt "$bin" -A MPC-GUARD -i wg-egress -j RETURN
	ipt "$bin" -A MPC-GUARD ! -i "$WAN" -j RETURN
	local spec port above rate burst
	for spec in "${CAPS[@]+"${CAPS[@]}"}"; do
		# shellcheck disable=SC2086
		read -r port above rate burst <<<"$spec"
		add_cap_rules "$bin" MPC-GUARD "$mask" "$family" "$port" "$above" "$rate" "$burst"
	done
	local src
	for spec in "${SCANCAPS[@]+"${SCANCAPS[@]}"}"; do
		[[ "$bin" == "ip6tables" ]] && continue
		read -r port above rate burst src <<<"$spec"
		add_cap_rules "$bin" MPC-GUARD "$mask" "$family" "$port" "$above" "$rate" "$burst" "$src"
		ipt "$bin" -A MPC-GUARD -p tcp --dport "$port" -s "$src" -j RETURN
	done
	for port in "${SCANDROPS[@]+"${SCANDROPS[@]}"}"; do
		ipt "$bin" -A MPC-GUARD -p tcp --dport "$port" -j DROP
	done
	if [[ "$DRY_RUN" -eq 1 ]]; then
		ipt "$bin" -N DOCKER-USER
	elif ! "$bin" -w 5 -L DOCKER-USER -n >/dev/null 2>&1; then
		"$bin" -w 5 -N DOCKER-USER 2>/dev/null || true
	fi
	drop_jumps "$bin" DOCKER-USER MPC-GUARD
	ipt "$bin" -A DOCKER-USER -j MPC-GUARD
}

apply_ssh_guard() {
	local bin="$1"
	local mask="$2"
	local family="$3"
	[[ -n "$SSH_SPEC" ]] || return 0
	local port above rate burst
	read -r port above rate burst <<<"$SSH_SPEC"
	ensure_chain "$bin" MPC-GUARD-IN
	ipt "$bin" -A MPC-GUARD-IN -p tcp --dport "$port" -m conntrack --ctstate NEW -i "$WAN" \
		-m connlimit --connlimit-above "$above" --connlimit-mask "$mask" -j DROP
	ipt "$bin" -A MPC-GUARD-IN -p tcp --dport "$port" -m conntrack --ctstate NEW -i "$WAN" \
		-m hashlimit --hashlimit-above "$rate" --hashlimit-burst "$burst" --hashlimit-mode srcip \
		--hashlimit-srcmask "$mask" --hashlimit-name "$(hash_name "$family" "$port")" -j DROP
	drop_jumps "$bin" INPUT MPC-GUARD-IN
	if [[ "$DRY_RUN" -eq 1 ]]; then
		ipt "$bin" -I INPUT 1 -j MPC-GUARD-IN
		return 0
	fi
	"$bin" -w 5 -I INPUT 1 -j MPC-GUARD-IN
}

ipv6_docker_ready() {
	if [[ "$DRY_RUN" -eq 1 ]]; then
		command -v ip6tables >/dev/null 2>&1 && ip6tables -L DOCKER-USER -n >/dev/null 2>&1
		return $?
	fi
	command -v ip6tables >/dev/null 2>&1 && ip6tables -w 5 -L DOCKER-USER -n >/dev/null 2>&1
}

if [[ "$DRY_RUN" -eq 0 ]] && ! command -v iptables >/dev/null 2>&1; then
	echo "mpc-auth-ddos-guard: iptables is not installed" >&2
	exit 1
fi

apply_docker_guard iptables 32 4
apply_ssh_guard iptables 32 4
if ipv6_docker_ready; then
	apply_docker_guard ip6tables 128 6
	apply_ssh_guard ip6tables 128 6
elif [[ "$DRY_RUN" -eq 0 ]] && command -v ip6tables >/dev/null 2>&1; then
	# SSH is not a Docker port. Cap it on IPv6 even when Docker has no v6 chain.
	apply_ssh_guard ip6tables 128 6 || true
fi

ignore_line="${IGNORES[*]-}"
jail_dir="/etc/fail2ban/jail.d"
jail_file="${jail_dir}/mpc-auth-sshd.local"
jail_body="$(cat <<EOF
# Generated by mpc-auth-ddos-guard.sh. Re-run the guard after nodeAddresses or VPN CIDRs change.
# sshd only: app ports are capped in MPC-GUARD. Do not add a mosquitto or recidive jail here.
[sshd]
enabled = true
port = ssh
filter = sshd
backend = systemd
maxretry = 6
findtime = 10m
bantime = 1h
ignoreip = ${ignore_line}
EOF
)"

if [[ "$DRY_RUN" -eq 1 ]]; then
	printf '# fail2ban %s\n%s\n' "$jail_file" "$jail_body"
	exit 0
fi

if ! command -v fail2ban-client >/dev/null 2>&1; then
	if command -v apt-get >/dev/null 2>&1; then
		DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban || {
			echo "mpc-auth-ddos-guard: fail2ban install failed; SSH is still capped in MPC-GUARD-IN" >&2
		}
	else
		echo "mpc-auth-ddos-guard: fail2ban is not installed; SSH is still capped in MPC-GUARD-IN" >&2
	fi
fi

if command -v fail2ban-client >/dev/null 2>&1; then
	mkdir -p "$jail_dir"
	printf '%s\n' "$jail_body" >"$jail_file"
	chmod 0644 "$jail_file"
	if command -v systemctl >/dev/null 2>&1; then
		systemctl enable fail2ban >/dev/null 2>&1 || true
		systemctl restart fail2ban >/dev/null 2>&1 || systemctl start fail2ban >/dev/null 2>&1 || true
	fi
	fail2ban-client reload >/dev/null 2>&1 || true
	echo "mpc-auth-ddos-guard: sshd jail written to ${jail_file}" >&2
fi

echo "mpc-auth-ddos-guard: MPC-GUARD appended on DOCKER-USER for WAN ${WAN}" >&2
