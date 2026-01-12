#!/usr/bin/env python3

# SPDX-License-Identifier: MPL-2.0

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path


LINE_RE = re.compile(
    r"^\s*(?P<comm>.+)-(?P<pid>\d+)\s+\[(?P<cpu>\d+)\]\s+"
    r"[dN\.\w]+\s+(?P<ts>\d+\.\d+):\s+(?P<event>[A-Za-z0-9_:]+):"
)


def to_ns(ts_sec: str) -> int:
    return int(float(ts_sec) * 1_000_000_000.0)


def map_event(raw: str) -> str | None:
    # Support both "event" and "subsystem:event" formats.
    evt = raw.split(":")[-1]
    if (
        evt == "sys_enter_sendto"
        or evt == "sys_enter_sendmsg"
        or "_sys_send" in evt
    ):
        return "SYS_ENTER_SEND"
    if (
        evt == "sys_exit_recvfrom"
        or evt == "sys_exit_recvmsg"
        or "_sys_recv" in evt
    ):
        return "SYS_EXIT_RECV"
    if "_tx" in evt:
        return "TX_OUT"
    if "_rx" in evt:
        return "RX_IN"
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_path", required=True)
    ap.add_argument("--out", dest="out_path", required=True)
    ap.add_argument("--side", required=True, choices=["host", "guest"])
    args = ap.parse_args()

    in_path = Path(args.in_path)
    out_path = Path(args.out_path)

    rows = []
    with in_path.open() as f:
        for line in f:
            m = LINE_RE.match(line)
            if not m:
                continue
            raw_event = m.group("event")
            mapped = map_event(raw_event)
            if mapped is None:
                continue
            pid = int(m.group("pid"))
            cpu = int(m.group("cpu"))
            ts_ns = to_ns(m.group("ts"))
            comm = m.group("comm").strip()
            rows.append(
                {
                    "ts_ns": ts_ns,
                    "side": args.side,
                    "event": mapped,
                    "probe": raw_event,
                    "pid": pid,
                    "tid": pid,
                    "cpu": cpu,
                    "comm": comm,
                }
            )

    rows.sort(key=lambda x: x["ts_ns"])

    with out_path.open("w", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=["ts_ns", "side", "event", "probe", "pid", "tid", "cpu", "comm"],
        )
        w.writeheader()
        for r in rows:
            w.writerow(r)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
