#!/usr/bin/env python3
"""Forward the admin VPN management port without trusting the peer's Host.

WireGuard peers reach 10.8.0.1:8080. A raw TCP forward would deliver
Host: localhost to the node, and the node treats that as a local caller of
POST /signLocalEd25519Message. This proxy forces Host to the VPN address and
sets X-Continuum-Vpn-Peer: 1.
"""

from __future__ import annotations

import os
import select
import socket
import sys

VPN_PEER_HEADER = "X-Continuum-Vpn-Peer"
MAX_HEADER = 64 * 1024
MAX_BODY = 32 * 1024 * 1024


def _bind_host() -> str:
    return os.environ.get("MPC_AUTH_VPN_BIND", "10.8.0.1").strip() or "10.8.0.1"


def _port() -> int:
    return int(os.environ.get("MPC_AUTH_VPN_MGMT_PORT", "8080"))


def _target() -> tuple[str, int]:
    host = os.environ.get("MPC_AUTH_VPN_MGMT_TARGET", "127.0.0.1").strip() or "127.0.0.1"
    port = int(os.environ.get("MPC_AUTH_VPN_MGMT_TARGET_PORT", str(_port())))
    return host, port


def _read_headers(conn: socket.socket) -> bytes:
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        if len(buf) > MAX_HEADER:
            raise ValueError("request headers too large")
        chunk = conn.recv(4096)
        if not chunk:
            raise ValueError("client closed before headers")
        buf.extend(chunk)
    return bytes(buf)


def rewrite_request(raw: bytes, public_host: str) -> tuple[bytes, bool]:
    """Return (bytes to send upstream, websocket upgrade).

    raw is the bytes read from the client, starting at the request line.
    Bytes after the first request's body are not expected: Connection: close
    is forced except for a WebSocket upgrade, which is spliced after the headers.
    """
    split_at = raw.find(b"\r\n\r\n")
    if split_at < 0:
        raise ValueError("missing header terminator")
    head = raw[:split_at].decode("iso-8859-1")
    rest = raw[split_at + 4 :]
    lines = head.split("\r\n")
    if not lines or not lines[0]:
        raise ValueError("missing request line")
    upgrade = False
    content_length = 0
    out: list[str] = [lines[0]]
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if not sep:
            continue
        lname = name.strip().lower()
        if lname in ("host", "connection", "keep-alive", "proxy-connection", "te", "trailer"):
            continue
        if lname == VPN_PEER_HEADER.lower():
            continue
        if lname == "content-length":
            content_length = int(value.strip() or "0")
            if content_length < 0 or content_length > MAX_BODY:
                raise ValueError("content-length out of range")
        if lname == "transfer-encoding":
            raise ValueError("chunked requests are not accepted on the VPN proxy")
        if lname == "upgrade" and value.strip().lower() == "websocket":
            upgrade = True
        out.append(line)
    out.append(f"Host: {public_host}")
    out.append(f"{VPN_PEER_HEADER}: 1")
    if upgrade:
        out.append("Connection: Upgrade")
        rewritten = ("\r\n".join(out) + "\r\n\r\n").encode("iso-8859-1") + rest
        return rewritten, True
    out.append("Connection: close")
    header_bytes = ("\r\n".join(out) + "\r\n\r\n").encode("iso-8859-1")
    if len(rest) > content_length:
        rest = rest[:content_length]
    return header_bytes + rest, False


def _read_body(conn: socket.socket, first: bytes, content_length: int) -> bytes:
    split_at = first.find(b"\r\n\r\n")
    have = first[split_at + 4 :]
    while len(have) < content_length:
        chunk = conn.recv(min(65536, content_length - len(have)))
        if not chunk:
            break
        have += chunk
    return have[:content_length]


def _content_length(header_blob: bytes) -> int:
    head = header_blob[: header_blob.find(b"\r\n\r\n")].decode("iso-8859-1", "replace")
    for line in head.split("\r\n")[1:]:
        name, sep, value = line.partition(":")
        if sep and name.strip().lower() == "content-length":
            return int(value.strip() or "0")
    return 0


def _is_upgrade(header_blob: bytes) -> bool:
    head = header_blob[: header_blob.find(b"\r\n\r\n")].decode("iso-8859-1", "replace")
    for line in head.split("\r\n")[1:]:
        name, sep, value = line.partition(":")
        if sep and name.strip().lower() == "upgrade" and value.strip().lower() == "websocket":
            return True
    return False


def _splice(left: socket.socket, right: socket.socket) -> None:
    sockets = [left, right]
    while sockets:
        readable, _, _ = select.select(sockets, [], [], 300)
        if not readable:
            return
        for src in readable:
            dst = right if src is left else left
            try:
                data = src.recv(65536)
            except OSError:
                return
            if not data:
                return
            try:
                dst.sendall(data)
            except OSError:
                return


def handle_client(client: socket.socket, public_host: str, target: tuple[str, int]) -> None:
    client.settimeout(60)
    raw = _read_headers(client)
    if not _is_upgrade(raw):
        need = _content_length(raw)
        body = _read_body(client, raw, need)
        split_at = raw.find(b"\r\n\r\n")
        raw = raw[: split_at + 4] + body
    upstream_bytes, upgrade = rewrite_request(raw, public_host)
    upstream = socket.create_connection(target, timeout=30)
    try:
        upstream.sendall(upstream_bytes)
        if upgrade:
            client.settimeout(None)
            upstream.settimeout(None)
            _splice(client, upstream)
            return
        upstream.settimeout(120)
        while True:
            data = upstream.recv(65536)
            if not data:
                break
            client.sendall(data)
    finally:
        upstream.close()


def serve(bind: str, port: int, target: tuple[str, int]) -> None:
    public_host = f"{bind}:{port}"
    family = socket.AF_INET6 if ":" in bind else socket.AF_INET
    server = socket.socket(family, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((bind, port))
    server.listen(64)
    while True:
        client, _addr = server.accept()
        try:
            handle_client(client, public_host, target)
        except Exception:
            try:
                client.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass
        finally:
            client.close()


def _self_test() -> None:
    backend = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    backend.bind(("127.0.0.1", 0))
    backend.listen(1)
    backend_port = backend.getsockname()[1]

    def serve_one() -> None:
        conn, _ = backend.accept()
        data = b""
        while b"\r\n\r\n" not in data:
            data += conn.recv(4096)
        # Echo the request headers as the response body.
        body = data.split(b"\r\n\r\n", 1)[0]
        extra = data.split(b"\r\n\r\n", 1)[1]
        length = 0
        for line in body.decode("iso-8859-1").split("\r\n"):
            if line.lower().startswith("content-length:"):
                length = int(line.split(":", 1)[1].strip())
        while len(extra) < length:
            extra += conn.recv(4096)
        payload = body + b"\r\n\r\n" + extra[:length]
        resp = b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: " + str(len(payload)).encode() + b"\r\n\r\n" + payload
        conn.sendall(resp)
        conn.close()

    import threading

    threading.Thread(target=serve_one, daemon=True).start()

    proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy.bind(("127.0.0.1", 0))
    proxy.listen(1)
    proxy_port = proxy.getsockname()[1]

    def serve_proxy() -> None:
        conn, _ = proxy.accept()
        os.environ["MPC_AUTH_VPN_BIND"] = "10.8.0.1"
        os.environ["MPC_AUTH_VPN_MGMT_PORT"] = "8080"
        handle_client(conn, "10.8.0.1:8080", ("127.0.0.1", backend_port))
        conn.close()

    threading.Thread(target=serve_proxy, daemon=True).start()

    client = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
    req = (
        "POST /signLocalEd25519Message HTTP/1.1\r\n"
        "Host: localhost\r\n"
        f"{VPN_PEER_HEADER}: 0\r\n"
        "Content-Length: 2\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
        "{}"
    ).encode()
    client.sendall(req)
    resp = b""
    while True:
        chunk = client.recv(4096)
        if not chunk:
            break
        resp += chunk
    client.close()
    text = resp.decode("iso-8859-1")
    if "Host: 10.8.0.1:8080" not in text:
        raise SystemExit(f"host was not rewritten: {text!r}")
    if f"{VPN_PEER_HEADER}: 1" not in text:
        raise SystemExit(f"vpn peer header missing: {text!r}")
    if "Host: localhost" in text or f"{VPN_PEER_HEADER}: 0" in text:
        raise SystemExit(f"client host survived: {text!r}")
    if "\r\n\r\n{}" not in text:
        raise SystemExit(f"body was not forwarded: {text!r}")
    print("mpc-auth-vpn-mgmt-proxy self-test ok")


def main() -> None:
    if "--self-test" in sys.argv[1:]:
        _self_test()
        return
    serve(_bind_host(), _port(), _target())


if __name__ == "__main__":
    main()
