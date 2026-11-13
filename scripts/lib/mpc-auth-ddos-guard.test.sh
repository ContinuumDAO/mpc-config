#!/usr/bin/env bash
# Dry-run checks for mpc-auth-ddos-guard.sh. Does not change iptables.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
guard="${root}/mpc-auth-ddos-guard.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fail() {
	printf 'mpc-auth-ddos-guard.test.sh: %s\n' "$*" >&2
	exit 1
}

cat >"${tmp}/configs.yaml" <<'EOF'
PublicDiscoveryPort: 18080
ScannerRelayerPort: 18081
BrowserHTTPS:
  Port: 8443
ContinuumdaoNodeApp:
  Enabled: true
  HostPort: 3333
ScannerAPIURLs:
  - "203.0.113.50"
PreSigningVerification:
  RelayerAPIURL: "https://198.51.100.20:8443"
MPCGroups:
  - nodeAddresses:
      node001_key: "http://198.51.100.10:8080"
      node002_key: "http://198.51.100.11:8080"
EOF

out="$(MPC_AUTH_DDOS_WAN_IF=eth0 "$guard" --config "${tmp}/configs.yaml" --dry-run 2>"${tmp}/err")"

assert_in() {
	local haystack="$1" needle="$2"
	if ! printf '%s\n' "$haystack" | grep -F -q -- "$needle"; then
		printf '%s\n' "$haystack" >&2
		fail "missing: $needle"
	fi
}

assert_not() {
	local haystack="$1" needle="$2"
	if printf '%s\n' "$haystack" | grep -F -q -- "$needle"; then
		fail "unexpected: $needle"
	fi
}

# VPN return rules stay ahead of any drop, and the Docker jump is append-only.
return_line="$(printf '%s\n' "$out" | grep -n -F -- '-i wg0 -j RETURN' | head -1 | cut -d: -f1)"
drop_line="$(printf '%s\n' "$out" | grep -n -F -- '-j DROP' | head -1 | cut -d: -f1)"
[[ -n "$return_line" && -n "$drop_line" && "$return_line" -lt "$drop_line" ]] || fail "wg0 RETURN is not before the first DROP"
assert_in "$out" "iptables -A DOCKER-USER -j MPC-GUARD"
assert_not "$out" "iptables -I DOCKER-USER"
assert_in "$out" "-i wg-egress -j RETURN"
assert_in "$out" "-i lo -j RETURN"
assert_in "$out" "-i docker0 -j RETURN"
assert_in "$out" "-i br-+ -j RETURN"
assert_not "$out" "--dport 51820"
assert_not "$out" "--dport 8388"
assert_not "$out" "--dport 9001"

# Under the cap, a normal connection does not match connlimit-above or hashlimit-above.
assert_in "$out" "-p tcp --dport 8443 -m connlimit --connlimit-above 80 --connlimit-mask 32 -j DROP"
assert_in "$out" "-p tcp --dport 8443 -m conntrack --ctstate NEW -m hashlimit --hashlimit-above 30/sec --hashlimit-burst 60"
assert_in "$out" "-p tcp --dport 3333 -m connlimit --connlimit-above 80"
assert_in "$out" "-p tcp --dport 18080 -m connlimit --connlimit-above 40"
assert_in "$out" "-p tcp --dport 8883 -m connlimit --connlimit-above 16"
assert_in "$out" "-p tcp --dport 18081 -s 203.0.113.50 -m connlimit --connlimit-above 40"
assert_in "$out" "-p tcp --dport 18081 -s 198.51.100.20 -j RETURN"
allow_line="$(printf '%s\n' "$out" | grep -n -F -- '-p tcp --dport 18081 -s 203.0.113.50 -j RETURN' | head -1 | cut -d: -f1)"
deny_line="$(printf '%s\n' "$out" | grep -n -F -- '-p tcp --dport 18081 -j DROP' | head -1 | cut -d: -f1)"
[[ -n "$allow_line" && -n "$deny_line" && "$allow_line" -lt "$deny_line" ]] || fail "scanner allow RETURN is not before the world DROP"

# 8443 has no unconditional drop (only the cap matches).
if printf '%s\n' "$out" | grep -E -- '-p tcp --dport 8443 -j DROP$' >/dev/null; then
	fail "8443 has an unconditional DROP"
fi

assert_in "$out" "iptables -A MPC-GUARD-IN -p tcp --dport 22 -m conntrack --ctstate NEW -i eth0 -m connlimit --connlimit-above 10"
assert_in "$out" "iptables -I INPUT 1 -j MPC-GUARD-IN"
assert_in "$out" "maxretry = 6"
assert_in "$out" "findtime = 10m"
assert_in "$out" "bantime = 1h"
assert_in "$out" "ignoreip = 127.0.0.1/8 ::1 10.8.0.0/24 10.9.0.0/24 198.51.100.10 198.51.100.11"
assert_not "$out" "[mosquitto]"
assert_not "$out" "[recidive]"

plan="$(MPC_AUTH_DDOS_WAN_IF=eth0 "$guard" --config "${tmp}/configs.yaml" --print-plan 2>"${tmp}/plan.err")"
assert_in "$plan" "WAN=eth0"
assert_in "$plan" "CAP=8443 80 30/sec 60"
assert_in "$plan" "CAP=8883 16 2/sec 8"
assert_in "$plan" "SCANCAP=18081 40 20/sec 40 203.0.113.50"
assert_in "$plan" "SCANDROP=18081"
assert_in "$plan" "SSH=22 10 10/minute 10"
assert_in "$plan" "IGNORE=198.51.100.10"
assert_not "$plan" "iptables"
vpnplan="$(MPC_AUTH_DDOS_WAN_IF=wg0 "$guard" --config "${tmp}/configs.yaml" --print-plan 2>"${tmp}/vpnplan.err")"
assert_in "$vpnplan" "WAN=wg0"
assert_in "$vpnplan" "CAP=18080 40 20/sec 40"

# Enabled udp2raw egress on 8443 must not be capped.
mkdir -p "${tmp}/bin"
cat >"${tmp}/bin/systemctl" <<'EOF'
#!/bin/sh
if [ "$1" = "is-active" ]; then
	shift
	[ "$1" = "--quiet" ] && shift
	if [ "$1" = "mpc-auth-udp2raw-egress.service" ]; then
		exit 0
	fi
	exit 3
fi
exit 1
EOF
chmod 0755 "${tmp}/bin/systemctl"
u2="$(PATH="${tmp}/bin:${PATH}" MPC_AUTH_DDOS_WAN_IF=eth0 "$guard" --config "${tmp}/configs.yaml" --dry-run 2>"${tmp}/u2err")"
if printf '%s\n' "$u2" | grep -F -q -- '--dport 8443'; then
	fail "udp2raw egress port 8443 was capped"
fi
grep -F -q "udp2raw egress is active on TCP 8443" "${tmp}/u2err" || fail "missing udp2raw skip note"
assert_in "$u2" "--dport 18080"
assert_in "$u2" "--dport 3333"

# firewalld is refused without installing rules.
cat >"${tmp}/bin/systemctl" <<'EOF'
#!/bin/sh
if [ "$1" = "is-active" ]; then
	shift
	[ "$1" = "--quiet" ] && shift
	if [ "$1" = "firewalld" ]; then
		exit 0
	fi
	exit 3
fi
exit 1
EOF
set +e
PATH="${tmp}/bin:${PATH}" MPC_AUTH_DDOS_WAN_IF=eth0 "$guard" --config "${tmp}/configs.yaml" --dry-run >"${tmp}/fw.out" 2>"${tmp}/fw.err"
rc=$?
set -e
[[ "$rc" -eq 2 ]] || fail "firewalld exit $rc, want 2"
grep -F -q "UFW/iptables-only" "${tmp}/fw.err" || fail "missing firewalld message"
[[ ! -s "${tmp}/fw.out" ]] || fail "firewalld dry-run printed rules"

printf 'mpc-auth-ddos-guard.test.sh: ok\n'
