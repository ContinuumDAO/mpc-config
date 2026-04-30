#!/usr/bin/env python3
"""Merge selected keys from planned YAML into an existing configs.yaml using ruamel (preserves comments on untouched structure).

Shipped in **mpc-config** so operators can bind-mount this file over the copy baked into the **mpc-auth** image
(see ``docker-compose.*.yml``). Uses rename-or-copy install so Docker bind-mounted ``configs.yaml`` does not hit
``EBUSY`` from ``os.replace``.

Usage:
  python3 apply_planned_configs_ruamel.py --base configs.yaml --planned planned.yaml --out configs.yaml [--dry-run]

Requires: ruamel.yaml (see Docker image or apt install python3-ruamel.yaml).
"""
from __future__ import annotations

import argparse
import errno
import shutil
import sys
from io import StringIO
from pathlib import Path

try:
    from ruamel.yaml import YAML
except ImportError:
    print("ruamel.yaml is required (e.g. pip install 'ruamel.yaml')", file=sys.stderr)
    sys.exit(2)


def dumps_to_string(yml: YAML, data: dict) -> str:
    buf = StringIO()
    yml.dump(data, buf)
    return buf.getvalue()


def _bootstrap_public_mgt_slot_empty(base: dict) -> bool:
    v = base.get("PublicMgtKey")
    if v is None:
        return True
    if isinstance(v, str):
        return v.strip() == ""
    return False


def merge_planned_into_base(base: dict, planned: dict) -> None:
    """Whitelist merge: NodeMgtKey; PublicMgtKey only if absent in base (first-time bootstrap);
    MPCGroups[0] nodeAddresses/mqttBroker/keyList/groupId."""
    if "NodeMgtKey" in planned:
        base["NodeMgtKey"] = planned["NodeMgtKey"]
    if "PublicMgtKey" in planned:
        # Do not overwrite an existing bootstrap Ed25519 public key — server enforces same rule.
        if _bootstrap_public_mgt_slot_empty(base):
            base["PublicMgtKey"] = planned["PublicMgtKey"]
    pp = planned.get("MPCGroups")
    if not isinstance(pp, list) or len(pp) < 1:
        return
    g0p = pp[0]
    if not isinstance(g0p, dict):
        return
    bp = base.get("MPCGroups")
    if not isinstance(bp, list) or len(bp) < 1:
        base["MPCGroups"] = [{}]
        bp = base["MPCGroups"]
    g0b = bp[0]
    if not isinstance(g0b, dict):
        g0b = {}
        bp[0] = g0b
    if "nodeAddresses" in g0p:
        g0b["nodeAddresses"] = g0p["nodeAddresses"]
    if "mqttBroker" in g0p:
        g0b["mqttBroker"] = g0p["mqttBroker"]
    if "keyList" in g0p:
        g0b["keyList"] = g0p["keyList"]
    if "groupId" in g0p:
        g0b["groupId"] = g0p["groupId"]
    bp[0] = g0b


def _install_tmp_over_dest(tmp_path: Path, dest_path: Path) -> None:
    """Atomic rename when possible; fall back to copy + unlink.

    Docker bind mounts (and some fused/network FS setups) reject ``rename(tmp, configs.yaml)``
    with ``EBUSY`` (errno 16). Overwriting the destination file in place avoids that.
    """
    try:
        tmp_path.replace(dest_path)
        return
    except OSError as exc:
        if exc.errno not in (errno.EBUSY, errno.EXDEV):
            raise
    try:
        shutil.copyfile(tmp_path, dest_path)
    finally:
        tmp_path.unlink(missing_ok=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--planned", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--dry-run", action="store_true")
    ns = ap.parse_args()
    base_path = Path(ns.base).resolve()
    planned_path = Path(ns.planned).resolve()
    out_path = Path(ns.out).resolve()

    y = YAML()
    y.preserve_quotes = True
    base_doc = None
    if base_path.is_file():
        with base_path.open("r", encoding="utf-8") as f:
            base_doc = y.load(f)
    if base_doc is None:
        base_doc = {}
    if not isinstance(base_doc, dict):
        print("base YAML root must be a mapping", file=sys.stderr)
        return 1

    with planned_path.open("r", encoding="utf-8") as f:
        planned_doc = y.load(f) or {}
    if not isinstance(planned_doc, dict):
        print("planned YAML root must be a mapping", file=sys.stderr)
        return 1

    merge_planned_into_base(base_doc, planned_doc)

    yw = YAML()
    yw.default_flow_style = False
    yw.indent(mapping=2, sequence=4, offset=2)
    if ns.dry_run:
        yw.dump(base_doc, sys.stdout)
        return 0

    text = dumps_to_string(yw, base_doc)
    tmp = out_path.with_suffix(out_path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    _install_tmp_over_dest(tmp, out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
