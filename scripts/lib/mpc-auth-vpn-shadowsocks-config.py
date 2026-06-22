#!/usr/bin/env python3
"""Reference Shadowsocks VPN config generator for mpc-auth (port logic to Go).

Generates:
  - ssserver.json (host, written by mpc-auth on first obfuscated enable)
  - sslocal tunnel JSON (client download)
  - WireGuard client .conf with localhost Endpoint + reduced MTU
  - ss:// URI for mobile clients

Usage:
  python3 mpc-auth-vpn-shadowsocks-config.py server --password SECRET [--port 8388]
  python3 mpc-auth-vpn-shadowsocks-config.py client --endpoint-host 203.0.113.1 --password SECRET \\
      [--server-port 8388] [--local-port 51821] [--wg-port 51820] [--wg-conf PATH]
"""
from __future__ import annotations

import argparse
import base64
import json
import secrets
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote

DEFAULT_METHOD = "chacha20-ietf-poly1305"
DEFAULT_SS_PORT = 8388
DEFAULT_LOCAL_TUNNEL_PORT = 51821
DEFAULT_WG_PORT = 51820
DEFAULT_WG_MTU = 1280


def generate_password(length: int = 32) -> str:
    return secrets.token_urlsafe(length)


def build_ssserver_config(
    password: str,
    *,
    listen_port: int = DEFAULT_SS_PORT,
    method: str = DEFAULT_METHOD,
) -> dict[str, Any]:
    return {
        "servers": [
            {
                "server": "0.0.0.0",
                "server_port": listen_port,
                "password": password,
                "method": method,
                "mode": "tcp_and_udp",
            }
        ]
    }


def build_sslocal_tunnel_config(
    endpoint_host: str,
    password: str,
    *,
    server_port: int = DEFAULT_SS_PORT,
    method: str = DEFAULT_METHOD,
    local_port: int = DEFAULT_LOCAL_TUNNEL_PORT,
    forward_address: str = "127.0.0.1",
    forward_port: int = DEFAULT_WG_PORT,
) -> dict[str, Any]:
    return {
        "server": endpoint_host,
        "server_port": server_port,
        "password": password,
        "method": method,
        "locals": [
            {
                "protocol": "tunnel",
                "mode": "udp_only",
                "local_address": "127.0.0.1",
                "local_port": local_port,
                "forward_address": forward_address,
                "forward_port": forward_port,
            }
        ],
    }


def build_shadowsocks_uri(
    endpoint_host: str,
    password: str,
    *,
    server_port: int = DEFAULT_SS_PORT,
    method: str = DEFAULT_METHOD,
) -> str:
    userinfo = f"{method}:{password}".encode()
    encoded = base64.urlsafe_b64encode(userinfo).decode().rstrip("=")
    host = endpoint_host
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"ss://{encoded}@{host}:{server_port}/"


def patch_wireguard_client_for_obfuscation(
    wg_conf: str,
    *,
    local_tunnel_port: int = DEFAULT_LOCAL_TUNNEL_PORT,
    mtu: int = DEFAULT_WG_MTU,
) -> str:
    lines = wg_conf.splitlines()
    out: list[str] = []
    in_interface = False
    in_peer = False
    has_mtu = False
    for line in lines:
        stripped = line.strip()
        if stripped == "[Interface]":
            in_interface = True
            in_peer = False
            out.append(line)
            continue
        if stripped == "[Peer]":
            in_interface = False
            in_peer = True
            out.append(line)
            continue
        if in_interface and stripped.lower().startswith("mtu"):
            out.append(f"MTU = {mtu}")
            has_mtu = True
            continue
        if in_peer and stripped.lower().startswith("endpoint"):
            out.append(f"Endpoint = 127.0.0.1:{local_tunnel_port}")
            continue
        out.append(line)
    if in_interface or not has_mtu:
        # Insert MTU after [Interface] if missing
        patched: list[str] = []
        inserted_mtu = False
        for line in out:
            patched.append(line)
            if not inserted_mtu and line.strip() == "[Interface]":
                patched.append(f"MTU = {mtu}")
                inserted_mtu = True
        out = patched
    header = (
        "# WireGuard client config — obfuscated via Shadowsocks tunnel.\n"
        "# 1) Run: sslocal -c cont-ss.json\n"
        f"# 2) Then: wg-quick up this file (Endpoint uses 127.0.0.1:{local_tunnel_port})\n"
    )
    return header + "\n".join(out) + "\n"


def setup_instructions(*, local_port: int = DEFAULT_LOCAL_TUNNEL_PORT) -> str:
    return (
        "Shadowsocks obfuscation setup:\n"
        "1. Install shadowsocks-rust (sslocal) on your client machine.\n"
        "2. Save sslocal JSON and run: sslocal -c cont-ss.json\n"
        f"3. Activate WireGuard (Endpoint 127.0.0.1:{local_port}).\n"
        "4. Keep sslocal running while the VPN is active.\n"
    )


def cmd_server(args: argparse.Namespace) -> int:
    cfg = build_ssserver_config(
        args.password,
        listen_port=args.port,
        method=args.method,
    )
    text = json.dumps(cfg, indent=2) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


def cmd_client(args: argparse.Namespace) -> int:
    local_cfg = build_sslocal_tunnel_config(
        args.endpoint_host,
        args.password,
        server_port=args.server_port,
        method=args.method,
        local_port=args.local_port,
        forward_port=args.wg_port,
    )
    bundle = {
        "shadowsocksLocalConfigText": json.dumps(local_cfg, indent=2) + "\n",
        "shadowsocksUri": build_shadowsocks_uri(
            args.endpoint_host,
            args.password,
            server_port=args.server_port,
            method=args.method,
        ),
        "setupInstructions": setup_instructions(local_port=args.local_port),
        "localTunnelPort": args.local_port,
        "shadowsocksListenPort": args.server_port,
        "shadowsocksMethod": args.method,
    }
    if args.wg_conf:
        wg_text = Path(args.wg_conf).read_text(encoding="utf-8")
        bundle["wireGuardConfigText"] = patch_wireguard_client_for_obfuscation(
            wg_text,
            local_tunnel_port=args.local_port,
            mtu=args.mtu,
        )
        bundle["filename"] = "cont-full.conf"
    bundle["shadowsocksLocalFilename"] = "cont-ss.json"
    sys.stdout.write(json.dumps(bundle, indent=2) + "\n")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_server = sub.add_parser("server", help="Emit ssserver.json")
    p_server.add_argument("--password", required=True)
    p_server.add_argument("--port", type=int, default=DEFAULT_SS_PORT)
    p_server.add_argument("--method", default=DEFAULT_METHOD)
    p_server.add_argument("-o", "--output")
    p_server.set_defaults(func=cmd_server)

    p_client = sub.add_parser("client", help="Emit client bundle JSON")
    p_client.add_argument("--endpoint-host", required=True)
    p_client.add_argument("--password", required=True)
    p_client.add_argument("--server-port", type=int, default=DEFAULT_SS_PORT)
    p_client.add_argument("--local-port", type=int, default=DEFAULT_LOCAL_TUNNEL_PORT)
    p_client.add_argument("--wg-port", type=int, default=DEFAULT_WG_PORT)
    p_client.add_argument("--method", default=DEFAULT_METHOD)
    p_client.add_argument("--mtu", type=int, default=DEFAULT_WG_MTU)
    p_client.add_argument("--wg-conf", help="Existing WG client conf to patch")
    p_client.set_defaults(func=cmd_client)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
