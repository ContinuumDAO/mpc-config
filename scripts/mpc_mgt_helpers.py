"""
Shared helpers for MPC management API calls and Ed25519 signing (compact JSON).

Used by keygen_messaging_agent_poll.py and mpc_event_listener.py.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "Missing dependency: install with $MPA_PATH/.venv/bin/pip install -r scripts/requirements-keygen-agent.txt "
        "(see docs/skill/SKILL.md Python dependencies)"
    ) from e

DEFAULT_AUTH_KEY_FILENAME = "mpc_auth_ed25519"


def resolve_ed25519_private_key_file() -> Path:
    """
    Path to the Ed25519 management private key on disk.

    - If ``AUTH_KEY_PATH`` is **unset**, use ``~/.ssh / AUTH_KEY_FILENAME`` (default basename
      **mpc_auth_ed25519**).
    - If ``AUTH_KEY_PATH`` is set, it must be a **directory**; the key file is
      ``AUTH_KEY_PATH / AUTH_KEY_FILENAME`` (PEM or OpenSSH).

    If ``AUTH_KEY_PATH`` points to an existing **file**, this raises ``SystemExit`` — use the
    parent directory and set ``AUTH_KEY_FILENAME`` to the key basename.
    """
    path_s = os.environ.get("AUTH_KEY_PATH", "").strip()
    name = (os.environ.get("AUTH_KEY_FILENAME") or "").strip() or DEFAULT_AUTH_KEY_FILENAME

    if not path_s:
        return Path.home() / ".ssh" / name

    base = Path(path_s).expanduser()
    if base.is_file():
        raise SystemExit(
            "AUTH_KEY_PATH must be a directory containing the Ed25519 private key, "
            "not the path to the key file. Set AUTH_KEY_PATH to the parent directory and "
            f"AUTH_KEY_FILENAME to the file basename (default {DEFAULT_AUTH_KEY_FILENAME!r})."
        )
    return base / name


def compact_json(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def resolve_mpc_auth_base(mpc_auth_url: str, management_port: str | int | None) -> str:
    base = (mpc_auth_url or "").strip()
    if not base:
        raise RuntimeError("MPC_AUTH_URL is required")
    p = urllib.parse.urlparse(base)
    if not p.scheme or not p.netloc:
        raise RuntimeError("MPC_AUTH_URL must include scheme and host, e.g. http://127.0.0.1")
    if p.port is not None:
        return base.rstrip("/")
    port = str(management_port or "").strip()
    if not port:
        raise RuntimeError("MANAGEMENT_PORT is required when MPC_AUTH_URL has no port")
    try:
        int(port, 10)
    except ValueError as e:
        raise RuntimeError("MANAGEMENT_PORT must be numeric") from e
    return urllib.parse.urlunparse(p._replace(netloc=f"{p.netloc}:{port}")).rstrip("/")


def api_code(resp: dict[str, Any]) -> Any:
    """Management API envelope: ``code`` or ``Code`` (prefer ``code`` when both exist)."""
    if not isinstance(resp, dict):
        return None
    if "code" in resp:
        return resp["code"]
    return resp.get("Code")


def api_error(resp: dict[str, Any]) -> Any:
    """Management API envelope: ``error`` or ``Error``."""
    if not isinstance(resp, dict):
        return None
    if "error" in resp:
        return resp["error"]
    return resp.get("Error")


def api_data(resp: dict[str, Any]) -> Any:
    """Management API envelope: ``data`` or ``Data`` (prefer ``data`` when both exist)."""
    if not isinstance(resp, dict):
        return None
    if "data" in resp:
        return resp["data"]
    return resp.get("Data")


def http_json(
    method: str,
    base: str,
    path: str,
    *,
    query: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    url = base.rstrip("/") + path
    if query:
        q = urllib.parse.urlencode(query)
        url = f"{url}?{q}"
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        raw = compact_json(body).encode("utf-8")
        data = raw
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            payload = resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {e.code} {path}: {err_body}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Request failed {path}: {e}") from e
    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid JSON from {path}: {payload[:500]}") from e
    c = api_code(parsed)
    if c is not None and c != 0:
        raise RuntimeError(
            f"API error {path}: {api_error(parsed)!r} data={api_data(parsed)!r}"
        )
    return parsed


def http_json_any_code(
    method: str,
    base: str,
    path: str,
    *,
    query: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Same as http_json but does not raise on non-zero API code (for polling)."""
    url = base.rstrip("/") + path
    if query:
        q = urllib.parse.urlencode(query)
        url = f"{url}?{q}"
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        raw = compact_json(body).encode("utf-8")
        data = raw
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            payload = resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {e.code} {path}: {err_body}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Request failed {path}: {e}") from e
    try:
        return json.loads(payload)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid JSON from {path}: {payload[:500]}") from e


def load_ed25519_private_key() -> Ed25519PrivateKey:
    seed_hex = os.environ.get("MPC_MGT_ED25519_SEED_HEX", "").strip()
    if seed_hex:
        if seed_hex.startswith("0x"):
            seed_hex = seed_hex[2:]
        raw = bytes.fromhex(seed_hex)
        if len(raw) != 32:
            raise SystemExit("MPC_MGT_ED25519_SEED_HEX must be 64 hex chars (32 bytes)")
        return Ed25519PrivateKey.from_private_bytes(raw)

    key_path = resolve_ed25519_private_key_file()
    if not key_path.is_file():
        raise SystemExit(
            f"Ed25519 private key not found at {key_path}. "
            "Set AUTH_KEY_PATH (directory), optional AUTH_KEY_FILENAME (default "
            f"{DEFAULT_AUTH_KEY_FILENAME!r}), or MPC_MGT_ED25519_SEED_HEX."
        )
    blob = key_path.read_bytes()
    key = None
    try:
        k = serialization.load_pem_private_key(blob, password=None)
        if isinstance(k, Ed25519PrivateKey):
            key = k
    except ValueError:
        pass
    if key is None:
        try:
            k = serialization.load_ssh_private_key(blob, password=None)
            if isinstance(k, Ed25519PrivateKey):
                key = k
        except ValueError:
            pass
    if key is None:
        raise SystemExit(f"Key file {key_path} is not an Ed25519 private key (PEM or OpenSSH)")
    return key


def public_key_64_hex(priv: Ed25519PrivateKey) -> str:
    return priv.public_key().public_bytes_raw().hex()


def sign_compact_json_empty_field(
    priv: Ed25519PrivateKey, body: dict[str, Any], empty_field: str
) -> str:
    """Sign UTF-8 compact JSON of body with empty_field set to \"\"."""
    sign_me = dict(body)
    sign_me[empty_field] = ""
    message = compact_json(sign_me).encode("utf-8")
    sig = priv.sign(message)
    return sig.hex()


def get_ed25519_nonce(base: str, pub_hex: str) -> int:
    nonce_resp = http_json(
        "GET",
        base,
        "/getPublicMgtKeyNonce",
        query={"publicKey": pub_hex},
    )
    data = api_data(nonce_resp)
    if isinstance(data, dict) and "nonce" in data:
        nonce = data["nonce"]
    elif isinstance(data, int):
        nonce = data
    else:
        raise RuntimeError(f"Unexpected getPublicMgtKeyNonce payload: {nonce_resp!r}")
    if not isinstance(nonce, int):
        raise RuntimeError(f"Nonce is not an integer: {nonce!r}")
    return nonce
