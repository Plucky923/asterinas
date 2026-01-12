#!/usr/bin/env python3

# SPDX-License-Identifier: MPL-2.0

"""
Compute 5-stage vsock communication decomposition from user/kernel CSVs.

Assumptions:
1. One in-flight ping-pong (strict request-response alternation).
2. Single benchmark flow during capture.
3. Kernel events are primarily aligned by user timestamp anchors, then by
   nearest-order matching for transport events.
"""

from __future__ import annotations

import argparse
import csv
import math
import random
import statistics
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Sequence, Tuple


@dataclass
class ClientRow:
    seq: int
    send_pre_ns: int
    send_post_ns: int
    recv_ret_ns: int
    rtt_ns: int


@dataclass
class ServerRow:
    seq: int
    req_recv_ret_ns: int
    resp_send_pre_ns: int
    resp_send_post_ns: int


@dataclass
class KernelRow:
    ts_ns: int
    side: str
    event: str
    probe: str
    pid: int
    tid: int
    cpu: int
    comm: str


def read_client_csv(path: Path) -> List[ClientRow]:
    rows: List[ClientRow] = []
    with path.open() as f:
        r = csv.DictReader(f)
        for row in r:
            rows.append(
                ClientRow(
                    seq=int(row["seq"]),
                    send_pre_ns=int(row["send_pre_ns"]),
                    send_post_ns=int(row["send_post_ns"]),
                    recv_ret_ns=int(row["recv_ret_ns"]),
                    rtt_ns=int(row["rtt_ns"]),
                )
            )
    rows.sort(key=lambda x: x.seq)
    return rows


def read_server_csv(path: Path) -> List[ServerRow]:
    rows: List[ServerRow] = []
    with path.open() as f:
        r = csv.DictReader(f)
        for row in r:
            rows.append(
                ServerRow(
                    seq=int(row["seq"]),
                    req_recv_ret_ns=int(row["req_recv_ret_ns"]),
                    resp_send_pre_ns=int(row["resp_send_pre_ns"]),
                    resp_send_post_ns=int(row["resp_send_post_ns"]),
                )
            )
    rows.sort(key=lambda x: x.seq)
    return rows


def dedup_client_rows(rows: Sequence[ClientRow]) -> Tuple[List[ClientRow], int]:
    by_seq: Dict[int, ClientRow] = {}
    dup = 0
    for r in rows:
        old = by_seq.get(r.seq)
        if old is None:
            by_seq[r.seq] = r
            continue
        dup += 1
        # Keep the row with later completion timestamp.
        if r.recv_ret_ns >= old.recv_ret_ns:
            by_seq[r.seq] = r
    out = sorted(by_seq.values(), key=lambda x: x.seq)
    return out, dup


def dedup_server_rows(rows: Sequence[ServerRow]) -> Tuple[List[ServerRow], int]:
    by_seq: Dict[int, ServerRow] = {}
    dup = 0
    for r in rows:
        old = by_seq.get(r.seq)
        if old is None:
            by_seq[r.seq] = r
            continue
        dup += 1
        # Keep the row with later response send timestamp.
        if r.resp_send_post_ns >= old.resp_send_post_ns:
            by_seq[r.seq] = r
    out = sorted(by_seq.values(), key=lambda x: x.seq)
    return out, dup


def read_kernel_csv(path: Path) -> List[KernelRow]:
    rows: List[KernelRow] = []
    with path.open() as f:
        r = csv.DictReader(f)
        for row in r:
            rows.append(
                KernelRow(
                    ts_ns=int(row["ts_ns"]),
                    side=row["side"],
                    event=row["event"],
                    probe=row["probe"],
                    pid=int(row["pid"]),
                    tid=int(row["tid"]),
                    cpu=int(row["cpu"]),
                    comm=row["comm"],
                )
            )
    rows.sort(key=lambda x: x.ts_ns)
    return rows


def percentile(sorted_vals: Sequence[float], p: float) -> float:
    if not sorted_vals:
        return float("nan")
    if p <= 0:
        return sorted_vals[0]
    if p >= 100:
        return sorted_vals[-1]
    idx = (len(sorted_vals) - 1) * p / 100.0
    lo = int(math.floor(idx))
    hi = int(math.ceil(idx))
    if lo == hi:
        return sorted_vals[lo]
    frac = idx - lo
    return sorted_vals[lo] * (1.0 - frac) + sorted_vals[hi] * frac


def fit_clock_transform(client_rows: Sequence[ClientRow], server_rows: Sequence[ServerRow]) -> Tuple[float, float, Dict[str, float]]:
    """
    Estimate guest->host transform:
      host_ts ~= (guest_ts - b) / (1 + m)
    where offset(host_mid) = m*host_mid + b
    """
    n = min(len(client_rows), len(server_rows))
    if n < 100:
        raise ValueError("need >=100 rows to fit host-guest clock mapping")

    delays: List[float] = []
    offsets: List[float] = []
    host_mid: List[float] = []

    for i in range(n):
        c = client_rows[i]
        s = server_rows[i]
        h0 = float(c.send_pre_ns)
        h3 = float(c.recv_ret_ns)
        g1 = float(s.req_recv_ret_ns)
        g2 = float(s.resp_send_pre_ns)
        # NTP-like estimator
        off = ((g1 - h0) + (g2 - h3)) / 2.0
        dly = (h3 - h0) - (g2 - g1)
        delays.append(dly)
        offsets.append(off)
        host_mid.append((h0 + h3) / 2.0)

    # Low-delay subset for robust offset fit (20% percentile)
    order = sorted(range(n), key=lambda i: delays[i])
    keep = max(50, int(0.2 * n))
    idxs = order[:keep]

    xs = [host_mid[i] for i in idxs]
    ys = [offsets[i] for i in idxs]

    x_mean = statistics.fmean(xs)
    y_mean = statistics.fmean(ys)
    denom = sum((x - x_mean) ** 2 for x in xs)
    if denom <= 0.0:
        m = 0.0
    else:
        m = sum((x - x_mean) * (y - y_mean) for x, y in zip(xs, ys)) / denom
    b = y_mean - m * x_mean

    residuals = [abs(y - (m * x + b)) for x, y in zip(xs, ys)]
    residuals_sorted = sorted(residuals)
    mad = percentile(residuals_sorted, 50)
    p95 = percentile(residuals_sorted, 95)

    quality = {
        "fit_samples": float(keep),
        "mad_ns": float(mad),
        "p95_ns": float(p95),
        "drift_m": float(m),
        "offset_b_ns": float(b),
    }
    return m, b, quality


def guest_to_host(guest_ns: float, m: float, b: float) -> float:
    return (guest_ns - b) / (1.0 + m)


def collect_event_times(rows: Sequence[KernelRow], event: str) -> List[int]:
    return [r.ts_ns for r in rows if r.event == event]


def match_first_after(starts: Sequence[int], candidates: Sequence[int]) -> List[int]:
    """
    Greedy one-to-one match:
    for each start, pick the first candidate >= start.
    """
    out: List[int] = []
    j = 0
    m = len(candidates)
    for s in starts:
        while j < m and candidates[j] < s:
            j += 1
        if j >= m:
            break
        out.append(candidates[j])
        j += 1
    return out


def match_last_before(ends: Sequence[int], candidates: Sequence[int]) -> List[int]:
    """
    Greedy one-to-one match:
    for each end, pick the last candidate <= end (without reusing old candidates).
    """
    out: List[int] = []
    j = 0
    m = len(candidates)
    for e in ends:
        best = -1
        while j < m and candidates[j] <= e:
            best = j
            j += 1
        if best >= 0:
            out.append(candidates[best])
    return out


def bootstrap_ci(values: Sequence[float], reps: int = 2000, seed: int = 12345) -> Tuple[float, float]:
    if not values:
        return (float("nan"), float("nan"))
    rng = random.Random(seed)
    n = len(values)
    means: List[float] = []
    for _ in range(reps):
        sample = [values[rng.randrange(n)] for _ in range(n)]
        means.append(statistics.fmean(sample))
    means.sort()
    lo = percentile(means, 2.5)
    hi = percentile(means, 97.5)
    return (lo, hi)


def summarize(values: Sequence[float]) -> Dict[str, float]:
    if not values:
        return {
            "count": 0.0,
            "mean": float("nan"),
            "median": float("nan"),
            "p90": float("nan"),
            "p99": float("nan"),
            "ci95_lo": float("nan"),
            "ci95_hi": float("nan"),
        }
    s = sorted(values)
    ci_lo, ci_hi = bootstrap_ci(values)
    return {
        "count": float(len(values)),
        "mean": float(statistics.fmean(values)),
        "median": float(percentile(s, 50)),
        "p90": float(percentile(s, 90)),
        "p99": float(percentile(s, 99)),
        "ci95_lo": float(ci_lo),
        "ci95_hi": float(ci_hi),
    }


def write_csv(path: Path, headers: Sequence[str], rows: Sequence[Dict[str, float]]) -> None:
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(headers))
        w.writeheader()
        for r in rows:
            w.writerow(r)


def main() -> int:
    p = argparse.ArgumentParser(description="Analyze 5-stage vsock decomposition")
    p.add_argument("--client-csv", required=True)
    p.add_argument("--server-csv", required=True)
    p.add_argument("--host-kernel-csv", required=True)
    p.add_argument("--guest-kernel-csv", required=True)
    p.add_argument("--out-dir", required=True)
    p.add_argument("--max-neg-ns", type=float, default=20000.0, help="max tolerated negative jitter (ns)")
    args = p.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    client_rows_raw = read_client_csv(Path(args.client_csv))
    server_rows_raw = read_server_csv(Path(args.server_csv))
    host_k = read_kernel_csv(Path(args.host_kernel_csv))
    guest_k = read_kernel_csv(Path(args.guest_kernel_csv))

    if not client_rows_raw or not server_rows_raw:
        print("ERROR: empty user csv input", file=sys.stderr)
        return 1

    client_rows, client_dup = dedup_client_rows(client_rows_raw)
    server_rows, server_dup = dedup_server_rows(server_rows_raw)

    if client_dup > 0 or server_dup > 0:
        print(
            "WARN: duplicate seq detected and deduplicated: "
            f"client_dup={client_dup} server_dup={server_dup} "
            f"(client_raw={len(client_rows_raw)} -> {len(client_rows)}, "
            f"server_raw={len(server_rows_raw)} -> {len(server_rows)})",
            file=sys.stderr,
        )

    m, b, fit_quality = fit_clock_transform(client_rows, server_rows)

    client_send_pre = [c.send_pre_ns for c in client_rows]
    client_recv_ret = [c.recv_ret_ns for c in client_rows]
    server_req_recv_ret = [s.req_recv_ret_ns for s in server_rows]
    server_resp_send_pre = [s.resp_send_pre_ns for s in server_rows]

    # Request (Host -> Guest) streams
    h_send_in_raw = collect_event_times(host_k, "SYS_ENTER_SEND")
    h_tx_out_raw = collect_event_times(host_k, "TX_OUT")
    g_rx_in_raw = collect_event_times(guest_k, "RX_IN")
    g_recv_exit_raw = collect_event_times(guest_k, "SYS_EXIT_RECV")

    # Anchor syscall events to user timestamps to resist syscall noise.
    h_send_in = match_first_after(client_send_pre, h_send_in_raw)
    g_recv_exit = match_last_before(server_req_recv_ret, g_recv_exit_raw)

    # Robust matching to tolerate extra transport events (e.g. credit/control packets).
    h_tx_out = match_first_after(h_send_in, h_tx_out_raw)
    g_rx_in = match_last_before(g_recv_exit, g_rx_in_raw)

    # Response (Guest -> Host) streams
    g_send_in_raw = collect_event_times(guest_k, "SYS_ENTER_SEND")
    g_tx_out_raw = collect_event_times(guest_k, "TX_OUT")
    h_rx_in_raw = collect_event_times(host_k, "RX_IN")
    h_recv_exit_raw = collect_event_times(host_k, "SYS_EXIT_RECV")

    g_send_in = match_first_after(server_resp_send_pre, g_send_in_raw)
    h_recv_exit = match_last_before(client_recv_ret, h_recv_exit_raw)
    g_tx_out = match_first_after(g_send_in, g_tx_out_raw)
    h_rx_in = match_last_before(h_recv_exit, h_rx_in_raw)

    n_req = min(len(client_rows), len(server_rows), len(h_send_in), len(h_tx_out), len(g_rx_in), len(g_recv_exit))
    n_rsp = min(len(client_rows), len(server_rows), len(g_send_in), len(g_tx_out), len(h_rx_in), len(h_recv_exit))

    if n_req == 0 or n_rsp == 0:
        print("ERROR: insufficient events to decompose request/response", file=sys.stderr)
        print(
            "counts: "
            f"client={len(client_rows)} server={len(server_rows)} "
            f"(raw client={len(client_rows_raw)} raw server={len(server_rows_raw)}) "
            f"h_send_in={len(h_send_in)} h_tx_out={len(h_tx_out)} "
            f"g_rx_in={len(g_rx_in)} g_recv_exit={len(g_recv_exit)} "
            f"g_send_in={len(g_send_in)} g_tx_out={len(g_tx_out)} "
            f"h_rx_in={len(h_rx_in)} h_recv_exit={len(h_recv_exit)} "
            f"(raw: h_send_in={len(h_send_in_raw)} h_tx_out={len(h_tx_out_raw)} "
            f"g_rx_in={len(g_rx_in_raw)} g_recv_exit={len(g_recv_exit_raw)} "
            f"g_send_in={len(g_send_in_raw)} g_tx_out={len(g_tx_out_raw)} "
            f"h_rx_in={len(h_rx_in_raw)} h_recv_exit={len(h_recv_exit_raw)})",
            file=sys.stderr,
        )
        return 1

    seq_rows: List[Dict[str, float]] = []
    neg_req = 0
    neg_rsp = 0

    # request: host->guest
    for i in range(n_req):
        c = client_rows[i]
        s = server_rows[i]

        t_h_u_send_pre = float(c.send_pre_ns)
        t_h_k_send_in = float(h_send_in[i])
        t_h_k_tx_out = float(h_tx_out[i])
        t_g_k_rx_in_h = guest_to_host(float(g_rx_in[i]), m, b)
        t_g_k_recv_exit_h = guest_to_host(float(g_recv_exit[i]), m, b)
        t_g_u_recv_ret_h = guest_to_host(float(s.req_recv_ret_ns), m, b)

        t1 = t_h_k_send_in - t_h_u_send_pre
        t2 = t_h_k_tx_out - t_h_k_send_in
        t3 = t_g_k_rx_in_h - t_h_k_tx_out
        t4 = t_g_k_recv_exit_h - t_g_k_rx_in_h
        t5 = t_g_u_recv_ret_h - t_g_k_recv_exit_h

        if min(t1, t2, t3, t4, t5) < -args.max_neg_ns:
            neg_req += 1
            continue

        seq_rows.append(
            {
                "seq": float(c.seq),
                "direction": "host_to_guest",
                "T1_ns": t1,
                "T2_ns": t2,
                "T3_ns": t3,
                "T4_ns": t4,
                "T5_ns": t5,
                "T_total_ns": t1 + t2 + t3 + t4 + t5,
                "RTT_user_ns": float(c.rtt_ns),
                "residual_ns": float(c.rtt_ns) - (t1 + t2 + t3 + t4 + t5),
            }
        )

    # response: guest->host (mirror)
    for i in range(n_rsp):
        c = client_rows[i]
        s = server_rows[i]

        t_g_u_send_pre_h = guest_to_host(float(s.resp_send_pre_ns), m, b)
        t_g_k_send_in_h = guest_to_host(float(g_send_in[i]), m, b)
        t_g_k_tx_out_h = guest_to_host(float(g_tx_out[i]), m, b)
        t_h_k_rx_in = float(h_rx_in[i])
        t_h_k_recv_exit = float(h_recv_exit[i])
        t_h_u_recv_ret = float(c.recv_ret_ns)

        t1 = t_g_k_send_in_h - t_g_u_send_pre_h
        t2 = t_g_k_tx_out_h - t_g_k_send_in_h
        t3 = t_h_k_rx_in - t_g_k_tx_out_h
        t4 = t_h_k_recv_exit - t_h_k_rx_in
        t5 = t_h_u_recv_ret - t_h_k_recv_exit

        if min(t1, t2, t3, t4, t5) < -args.max_neg_ns:
            neg_rsp += 1
            continue

        seq_rows.append(
            {
                "seq": float(s.seq),
                "direction": "guest_to_host",
                "T1_ns": t1,
                "T2_ns": t2,
                "T3_ns": t3,
                "T4_ns": t4,
                "T5_ns": t5,
                "T_total_ns": t1 + t2 + t3 + t4 + t5,
                "RTT_user_ns": float(c.rtt_ns),
                "residual_ns": float(c.rtt_ns) - (t1 + t2 + t3 + t4 + t5),
            }
        )

    if not seq_rows:
        print("ERROR: no valid decomposed rows after quality filtering", file=sys.stderr)
        print(
            "filtering_stats: "
            f"n_request_pairs={n_req} dropped_negative_request={neg_req} "
            f"n_response_pairs={n_rsp} dropped_negative_response={neg_rsp} "
            f"max_neg_ns={args.max_neg_ns}",
            file=sys.stderr,
        )
        return 1

    seq_path = out_dir / "segments_seq.csv"
    with seq_path.open("w", newline="") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "seq",
                "direction",
                "T1_ns",
                "T2_ns",
                "T3_ns",
                "T4_ns",
                "T5_ns",
                "T_total_ns",
                "RTT_user_ns",
                "residual_ns",
            ],
        )
        w.writeheader()
        for row in seq_rows:
            w.writerow(row)

    # Summary
    summary_rows: List[Dict[str, float]] = []
    for direction in ("host_to_guest", "guest_to_host"):
        drows = [r for r in seq_rows if r["direction"] == direction]
        if not drows:
            continue
        for key in ("T1_ns", "T2_ns", "T3_ns", "T4_ns", "T5_ns", "T_total_ns", "residual_ns"):
            vals = [float(r[key]) for r in drows]
            s = summarize(vals)
            summary_rows.append(
                {
                    "direction": direction,
                    "metric": key,
                    "count": s["count"],
                    "mean": s["mean"],
                    "median": s["median"],
                    "p90": s["p90"],
                    "p99": s["p99"],
                    "ci95_lo": s["ci95_lo"],
                    "ci95_hi": s["ci95_hi"],
                }
            )

    write_csv(
        out_dir / "segments_summary.csv",
        ["direction", "metric", "count", "mean", "median", "p90", "p99", "ci95_lo", "ci95_hi"],
        summary_rows,
    )

    # Audit/quality file
    quality_path = out_dir / "quality_report.txt"
    with quality_path.open("w") as f:
        f.write("clock_fit\n")
        f.write(f"  drift_m={fit_quality['drift_m']:.6e}\n")
        f.write(f"  offset_b_ns={fit_quality['offset_b_ns']:.3f}\n")
        f.write(f"  mad_ns={fit_quality['mad_ns']:.3f}\n")
        f.write(f"  p95_ns={fit_quality['p95_ns']:.3f}\n")
        f.write(f"  fit_samples={int(fit_quality['fit_samples'])}\n")
        f.write("\n")
        f.write("event_counts\n")
        f.write(f"  client_rows_raw={len(client_rows_raw)}\n")
        f.write(f"  client_rows_dedup={len(client_rows)}\n")
        f.write(f"  client_rows_dup={client_dup}\n")
        f.write(f"  server_rows_raw={len(server_rows_raw)}\n")
        f.write(f"  server_rows_dedup={len(server_rows)}\n")
        f.write(f"  server_rows_dup={server_dup}\n")
        f.write(f"  host SYS_ENTER_SEND={len(h_send_in)}\n")
        f.write(f"  host TX_OUT={len(h_tx_out)}\n")
        f.write(f"  host RX_IN={len(h_rx_in)}\n")
        f.write(f"  host SYS_EXIT_RECV={len(h_recv_exit)}\n")
        f.write(f"  guest SYS_ENTER_SEND={len(g_send_in)}\n")
        f.write(f"  guest TX_OUT={len(g_tx_out)}\n")
        f.write(f"  guest RX_IN={len(g_rx_in)}\n")
        f.write(f"  guest SYS_EXIT_RECV={len(g_recv_exit)}\n")
        f.write("  raw host SYS_ENTER_SEND=%d\n" % len(h_send_in_raw))
        f.write("  raw host TX_OUT=%d\n" % len(h_tx_out_raw))
        f.write("  raw host RX_IN=%d\n" % len(h_rx_in_raw))
        f.write("  raw host SYS_EXIT_RECV=%d\n" % len(h_recv_exit_raw))
        f.write("  raw guest SYS_ENTER_SEND=%d\n" % len(g_send_in_raw))
        f.write("  raw guest TX_OUT=%d\n" % len(g_tx_out_raw))
        f.write("  raw guest RX_IN=%d\n" % len(g_rx_in_raw))
        f.write("  raw guest SYS_EXIT_RECV=%d\n" % len(g_recv_exit_raw))
        f.write("\n")
        f.write("pairing\n")
        f.write(f"  n_request_pairs={n_req}\n")
        f.write(f"  n_response_pairs={n_rsp}\n")
        f.write(f"  dropped_negative_request={neg_req}\n")
        f.write(f"  dropped_negative_response={neg_rsp}\n")
        f.write(f"  final_rows={len(seq_rows)}\n")

    print(f"Wrote {seq_path}")
    print(f"Wrote {out_dir / 'segments_summary.csv'}")
    print(f"Wrote {quality_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
