#!/usr/bin/env python3
"""
Selectable cron periods for **mpc_event_listener.py** / **keygen_messaging_agent_poll.py**
(Open Claw Gateway ``--every`` or system crontab).

Allowed intervals (fixed set):

- Minutes: 1, 5, 10, 30, 60
- Hours: 2, 4, 6, 8, 10, 12, 24

Examples::

  python3 scripts/mpc_cron_schedules.py
  python3 scripts/mpc_cron_schedules.py --json
  python3 scripts/mpc_cron_schedules.py --interactive
"""

from __future__ import annotations

import argparse
import json
import sys

# Open Claw: https://docs.openclaw.ai/cron — duration strings like 1m, 2h
# Crontab: five-field (minute hour dom month dow); comments note semantics.

SCHEDULES: list[dict[str, str]] = [
    # minutes
    {"key": "1m", "label": "Every 1 minute", "openclaw_every": "1m", "crontab": "* * * * *"},
    {"key": "5m", "label": "Every 5 minutes", "openclaw_every": "5m", "crontab": "*/5 * * * *"},
    {"key": "10m", "label": "Every 10 minutes", "openclaw_every": "10m", "crontab": "*/10 * * * *"},
    {"key": "30m", "label": "Every 30 minutes", "openclaw_every": "30m", "crontab": "*/30 * * * *"},
    {
        "key": "60m",
        "label": "Every 60 minutes / hourly (at minute 0)",
        "openclaw_every": "1h",
        "crontab": "0 * * * *",
    },
    # hours
    {"key": "2h", "label": "Every 2 hours", "openclaw_every": "2h", "crontab": "0 */2 * * *"},
    {"key": "4h", "label": "Every 4 hours", "openclaw_every": "4h", "crontab": "0 */4 * * *"},
    {"key": "6h", "label": "Every 6 hours", "openclaw_every": "6h", "crontab": "0 */6 * * *"},
    {"key": "8h", "label": "Every 8 hours", "openclaw_every": "8h", "crontab": "0 */8 * * *"},
    {"key": "10h", "label": "Every 10 hours", "openclaw_every": "10h", "crontab": "0 */10 * * *"},
    {"key": "12h", "label": "Every 12 hours", "openclaw_every": "12h", "crontab": "0 */12 * * *"},
    {
        "key": "24h",
        "label": "Every 24 hours (daily at 00:00 server local time)",
        "openclaw_every": "24h",
        "crontab": "0 0 * * *",
    },
]

KEY_BY_SHORT: dict[str, dict[str, str]] = {row["key"]: row for row in SCHEDULES}


def print_table() -> None:
    print("Selectable schedules (use one row when configuring the timer)\n")
    print(f"{'#':<4} {'key':<6} {'Open Claw --every':<18} {'crontab (5-field)':<22} label")
    print("-" * 100)
    for i, row in enumerate(SCHEDULES, start=1):
        print(
            f"{i:<4} {row['key']:<6} {repr(row['openclaw_every']):<18} {row['crontab']:<22} {row['label']}"
        )
    print(
        "\nOpen Claw example: openclaw cron add --name mpc-events --every "
        f'"{SCHEDULES[0]["openclaw_every"]}" --session isolated ...'
    )


def run_interactive() -> None:
    if not sys.stdin.isatty():
        raise SystemExit("--interactive requires a TTY")
    print_table()
    raw = input("\nEnter row number (1–{}): ".format(len(SCHEDULES))).strip()
    try:
        n = int(raw, 10)
    except ValueError as e:
        raise SystemExit("Invalid number") from e
    if n < 1 or n > len(SCHEDULES):
        raise SystemExit("Number out of range")
    row = SCHEDULES[n - 1]
    print("\nSelected:", file=sys.stderr)
    print(json.dumps(row, indent=2))
    print(
        f'\nUse: --every "{row["openclaw_every"]}"\n   or crontab: {row["crontab"]}',
        file=sys.stderr,
    )


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", action="store_true", help="Print SCHEDULES as JSON")
    ap.add_argument(
        "--interactive",
        "-i",
        action="store_true",
        help="Print table and prompt for a row number (TTY)",
    )
    ap.add_argument(
        "--key",
        metavar="KEY",
        help="Lookup one schedule by key (e.g. 5m, 2h) and print JSON",
    )
    args = ap.parse_args()

    if args.key:
        row = KEY_BY_SHORT.get(args.key.strip().lower())
        if not row:
            raise SystemExit(f"Unknown key {args.key!r}; use --json to list keys")
        print(json.dumps(row, indent=2))
        return

    if args.json:
        print(json.dumps(SCHEDULES, indent=2))
        return

    if args.interactive:
        run_interactive()
        return

    print_table()


if __name__ == "__main__":
    main()
