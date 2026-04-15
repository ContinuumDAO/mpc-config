#!/usr/bin/env python3
"""
checkSignRequestReady (client-side)

Decide whether a multi-agree sign request is ready for POST /triggerSignRequestById without calling
GET /isSignRequestReadyById (useful when that endpoint is wrong on older mpc-auth builds).

Uses:
  GET /getSignRequestById?id=...
  GET /getKeyGenResultById?id=<KeyGenRequestId>
  GET /getSignResultById?id=...

Logic mirrors the intended server rules: multi-agree, threshold+1 entries in SigList, not shelved/blocked,
and no complete sign result yet (single: any usable result from getSignResultById code 0; batch: all batch
slots filled when code 0). Status \"success\" after agreement is not treated as blocking.

Requires only the Python standard library.

Example:
  python3 scripts/checkSignRequestReady.py --sign-request-id Sign20260111003720999cf104d0f \\
    --mpc-auth-url http://127.0.0.1 --management-port 8080
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

_HTTP_UA = "checkSignRequestReady/1.0 (Python-urllib)"
DEFAULT_MPC_AUTH_URL = "http://127.0.0.1"
DEFAULT_MANAGEMENT_PORT = "8080"


def resolve_mpc_auth_base(mpc_auth_url: str, management_port: str | int | None) -> str:
    base = (mpc_auth_url or "").strip()
    if not base:
        raise ValueError("mpc_auth_url cannot be empty")
    p = urllib.parse.urlparse(base)
    if not p.scheme or not p.netloc:
        raise ValueError("mpc_auth_url must include scheme and host, e.g. http://127.0.0.1")
    if p.port is not None:
        return base.rstrip("/")
    port = str(management_port or "").strip()
    if not port:
        raise ValueError("management_port is required when mpc_auth_url has no port")
    int(port, 10)
    netloc = f"{p.netloc}:{port}"
    return urllib.parse.urlunparse(p._replace(netloc=netloc)).rstrip("/")


def http_get_json(url: str) -> dict:
    req = urllib.request.Request(
        url,
        method="GET",
        headers={"Accept": "application/json", "User-Agent": _HTTP_UA},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        raise ValueError(f"HTTP {e.code}: {body or e.reason}") from e
    except urllib.error.URLError as e:
        raise ValueError(f"Request failed: {e.reason}") from e
    return json.loads(raw)


def _api_code(resp: dict) -> Any:
    """Management API envelope: ``code`` or ``Code`` (stdlib-only; mirrors mpc_mgt_helpers)."""
    if "code" in resp:
        return resp["code"]
    return resp.get("Code")


def _api_error(resp: dict) -> Any:
    if "error" in resp:
        return resp["error"]
    return resp.get("Error")


def _api_data(resp: dict) -> Any:
    if "data" in resp:
        return resp["data"]
    return resp.get("Data")


def unwrap_api_response(resp: dict, what: str):
    c = _api_code(resp)
    if c is not None and c != 0:
        err = _api_error(resp) or str(resp)
        raise ValueError(f"{what} failed (code={c}): {err}")
    return _api_data(resp)


def pick_str(d: dict, *keys: str):
    for k in keys:
        if k in d:
            return d[k]
    lower = {str(a).lower(): b for a, b in d.items()}
    for k in keys:
        lk = k.lower()
        if lk in lower:
            return lower[lk]
    return None


def pick_int(d: dict, *keys: str) -> int | None:
    v = pick_str(d, *keys)
    if v is None:
        return None
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    try:
        return int(str(v).strip(), 10)
    except ValueError:
        return None


def sig_list_len(d: dict) -> int:
    sl = pick_str(d, "SigList", "sigList")
    if isinstance(sl, dict):
        return len(sl)
    return 0


def fetch_sign_result_status(mpc_base: str, request_id: str) -> tuple[str, dict | None, str | None]:
    """
    Returns (kind, data_or_none, error_message).
    kind: \"none\" | \"ok\" | \"http_error\"
    """
    q = urllib.parse.urlencode({"id": request_id})
    url = f"{mpc_base.rstrip('/')}/getSignResultById?{q}"
    try:
        resp = http_get_json(url)
    except ValueError as e:
        return "http_error", None, str(e)
    code = _api_code(resp)
    if code != 0:
        return "none", None, str(_api_error(resp) or "")
    data = _api_data(resp)
    if not isinstance(data, dict):
        return "none", None, None
    return "ok", data, None


def signing_fully_done(sign_req: dict, sig_data: dict | None) -> bool:
    """True if MPC signing is complete enough that trigger is not needed."""
    if sig_data is None:
        return False
    batch = bool(pick_str(sign_req, "BatchSignRequest", "batchSignRequest"))
    msg_hashes = sign_req.get("MessageHashes") or sign_req.get("messageHashes") or []
    if batch and isinstance(msg_hashes, list) and len(msg_hashes) >= 2:
        entries = sig_data.get("batchsignatures") or sig_data.get("BatchSignatures") or []
        size = pick_int(sig_data, "batchsize", "BatchSize") or 0
        if size <= 0:
            size = len(msg_hashes)
        if len(entries) < size:
            return False
        for e in entries:
            if not isinstance(e, dict):
                return False
            r = e.get("sigr") or e.get("SigR") or ""
            if not str(r).strip():
                return False
        return True
    r = pick_str(sig_data, "sigr", "sigR", "SigR")
    eth = pick_str(sig_data, "ethereumsignature", "ethereumSignature", "EthereumSignature")
    return bool(str(r or "").strip()) or bool(str(eth or "").strip())


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Check trigger readiness via getSignRequestById + getKeyGenResultById + getSignResultById."
    )
    ap.add_argument("--sign-request-id", required=True, help="Sign request id (Sign... )")
    ap.add_argument(
        "--mpc-auth-url",
        default=os.environ.get("MPC_AUTH_URL") or DEFAULT_MPC_AUTH_URL,
    )
    ap.add_argument(
        "--management-port",
        default=os.environ.get("MANAGEMENT_PORT") or DEFAULT_MANAGEMENT_PORT,
    )
    args = ap.parse_args()
    mpc = resolve_mpc_auth_base(args.mpc_auth_url, args.management_port)
    rid = args.sign_request_id.strip()

    out: dict = {"requestId": rid, "ready": False, "reason": "", "agreeingCount": 0, "requiredAgreements": 0}

    try:
        q = urllib.parse.urlencode({"id": rid})
        sr_resp = http_get_json(f"{mpc}/getSignRequestById?{q}")
        sr = unwrap_api_response(sr_resp, "getSignRequestById")
        if not isinstance(sr, dict):
            raise ValueError("getSignRequestById: expected data object")
    except (ValueError, OSError, json.JSONDecodeError) as e:
        out["reason"] = str(e)
        print(json.dumps(out, indent=2))
        sys.exit(1)

    status = (pick_str(sr, "status", "Status") or "").strip().lower()
    if status in ("shelved", "blocked"):
        out["reason"] = f"sign request status is {status!r}"
        print(json.dumps(out, indent=2))
        sys.exit(0)

    keygen_id = pick_str(sr, "KeyGenRequestId", "keyGenRequestId")
    if not keygen_id:
        out["reason"] = "missing KeyGenRequestId on sign request"
        print(json.dumps(out, indent=2))
        sys.exit(1)

    try:
        kg_q = urllib.parse.urlencode({"id": str(keygen_id).strip()})
        kg_resp = http_get_json(f"{mpc}/getKeyGenResultById?{kg_q}")
        kg = unwrap_api_response(kg_resp, "getKeyGenResultById")
        if not isinstance(kg, dict):
            raise ValueError("getKeyGenResultById: expected data object")
    except (ValueError, OSError, json.JSONDecodeError) as e:
        out["reason"] = str(e)
        print(json.dumps(out, indent=2))
        sys.exit(1)

    msg_check = (pick_str(kg, "MsgCheck", "msgCheck") or "").strip().lower()
    threshold = pick_int(kg, "Threshold", "threshold")
    if threshold is None:
        out["reason"] = "could not read threshold from keygen result"
        print(json.dumps(out, indent=2))
        sys.exit(1)

    if msg_check != "multi-agree":
        out["reason"] = f"MsgCheck is {msg_check!r} (only multi-agree uses this readiness check)"
        print(json.dumps(out, indent=2))
        sys.exit(0)

    required = int(threshold) + 1
    agree_n = sig_list_len(sr)
    out["agreeingCount"] = agree_n
    out["requiredAgreements"] = required

    if agree_n < required:
        out["reason"] = f"need at least {required} agreeing nodes (threshold+1), have {agree_n}"
        print(json.dumps(out, indent=2))
        sys.exit(0)

    kind, sig_data, sig_err = fetch_sign_result_status(mpc, rid)
    if kind == "http_error":
        out["reason"] = f"getSignResultById: {sig_err}"
        print(json.dumps(out, indent=2))
        sys.exit(1)

    if kind == "ok" and signing_fully_done(sr, sig_data):
        out["reason"] = "sign result already present (MPC signing complete)"
        print(json.dumps(out, indent=2))
        sys.exit(0)

    if kind == "http_error":
        out["ready"] = True
        out["reason"] = (
            f"threshold+1 agreements met; could not query getSignResultById ({sig_err}); "
            "you may still POST /triggerSignRequestById if the MPC job has not finished"
        )
        print(json.dumps(out, indent=2))
        sys.exit(0)

    out["ready"] = True
    if kind == "ok":
        out["reason"] = (
            "threshold+1 agreements met; sign result incomplete (e.g. batch) — ok to POST /triggerSignRequestById"
        )
    else:
        out["reason"] = "threshold+1 agreements met; no sign result yet — ok to POST /triggerSignRequestById"
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, json.JSONDecodeError) as e:
        print(json.dumps({"ready": False, "reason": str(e)}, indent=2), file=sys.stderr)
        sys.exit(1)
