#!/usr/bin/env bash
# Renders the pf anchor from the shared plan. Does not load pf or use sudo.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fw="${root}/mpc-auth-firewall-macos.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fail() {
	printf 'mpc-auth-firewall-macos.test.sh: %s\n' "$*" >&2
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
EOF

out="$(bash "$fw" --print-anchor --interface en0 --config "${tmp}/configs.yaml")"

assert_in() {
	if ! printf '%s\n' "$out" | grep -F -q -- "$1"; then
		printf '%s\n' "$out" >&2
		fail "missing: $1"
	fi
}

assert_not() {
	if printf '%s\n' "$out" | grep -F -q -- "$1"; then
		printf '%s\n' "$out" >&2
		fail "unexpected: $1"
	fi
}

assert_in "pass in quick on en0 inet proto tcp from any to any port 8443 flags S/SA keep state (max-src-conn 80, max-src-conn-rate 30/1)"
assert_in "block in quick on en0 inet proto tcp from any to any port 8443 flags S/SA"
assert_in "pass in quick on en0 inet proto tcp from any to any port 8883 flags S/SA keep state (max-src-conn 16, max-src-conn-rate 2/1)"
assert_in "pass in quick on en0 inet proto tcp from any to any port 22 flags S/SA keep state (max-src-conn 10, max-src-conn-rate 10/60)"
assert_in "pass in quick on en0 inet proto tcp from { 198.51.100.20, 203.0.113.50 } to any port 18081 flags S/SA keep state (max-src-conn 40, max-src-conn-rate 20/1)"
assert_in "block in quick on en0 inet6 proto tcp from any to any port 18081 flags S/SA"
assert_not "utun"
assert_not "flush"
assert_not "on wg0"

allow="$(printf '%s\n' "$out" | grep -n -F 'from { 198.51.100.20, 203.0.113.50 }' | head -1 | cut -d: -f1)"
deny="$(printf '%s\n' "$out" | grep -n -F 'block in quick on en0 inet proto tcp from any to any port 18081' | head -1 | cut -d: -f1)"
[[ -n "$allow" && -n "$deny" && "$allow" -lt "$deny" ]] || fail "scanner pass is not before the 18081 block"

printf 'mpc-auth-firewall-macos.test.sh: ok\n'
