"""Round scheduling, aggregation, calibrated counter analysis, and Markdown/CSV reporting."""

from __future__ import annotations

import csv
from dataclasses import dataclass
import io
import json
from pathlib import Path
import random
import statistics
from typing import Iterable

from .schema import CaseRecord, CaseSpec, SandboxStats, VmRunRecord


@dataclass(frozen=True)
class SummaryStats:
    count: int
    median: float
    mean: float
    min_val: float
    max_val: float


def schedule_rounds(targets: list[str], rounds: int, seed: int) -> list[list[str]]:
    """Generate per-round shuffled target execution orders with a fixed RNG seed."""
    if rounds <= 0:
        raise ValueError("rounds must be positive")
    if not targets:
        raise ValueError("targets must not be empty")
    rng = random.Random(seed)
    schedule: list[list[str]] = []
    for _ in range(rounds):
        order = list(targets)
        rng.shuffle(order)
        schedule.append(order)
    return schedule


def compute_stats(values: Iterable[float]) -> SummaryStats:
    """Compute count, median, mean, min, and max for a non-empty sequence."""
    vals = list(values)
    if not vals:
        raise ValueError("cannot compute stats of empty values")
    return SummaryStats(
        count=len(vals),
        median=float(statistics.median(vals)),
        mean=float(statistics.fmean(vals)),
        min_val=float(min(vals)),
        max_val=float(max(vals)),
    )


def _fmt_stat(st: SummaryStats | None) -> str:
    if st is None:
        return "N/A"
    return f"{st.median:.3f} [{st.min_val:.3f}, {st.max_val:.3f}] (mean {st.mean:.3f})"


def _ratio(num: SummaryStats | None, den: SummaryStats | None) -> str:
    if num is None or den is None or den.median == 0.0:
        return "N/A"
    return f"{num.median / den.median:.2f}x"


def write_records_jsonl(records: Iterable[CaseRecord], out_path: Path) -> None:
    """Write all CaseRecords to a JSONL file."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec.to_dict(), sort_keys=True) + "\n")


def write_vm_runs_jsonl(vm_runs: Iterable[VmRunRecord], out_path: Path) -> None:
    """Write all VmRunRecords (QEMU cmdlines, TIDs, QMP pinning) to JSONL."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for run in vm_runs:
            f.write(json.dumps(run.to_dict(), sort_keys=True) + "\n")


def _analyze_series(
    cases: dict[str, CaseSpec],
    records: list[CaseRecord],
    targets: list[str],
    expected_rounds: int | None,
) -> tuple[
    dict[tuple[str, str], list[float]],
    dict[tuple[str, str], list[CaseRecord]],
    dict[str, str],
    list[CaseRecord],
]:
    valid_vals: dict[tuple[str, str], list[float]] = {}
    invalid_by_series: dict[tuple[str, str], list[CaseRecord]] = {}
    skipped_notes: dict[str, str] = {}
    all_invalid: list[CaseRecord] = []

    for rec in records:
        if rec.skipped:
            skipped_notes[rec.case_id] = rec.skip_reason
            continue
        if not rec.valid or rec.value is None:
            all_invalid.append(rec)
            invalid_by_series.setdefault((rec.case_id, rec.target), []).append(rec)
            continue
        valid_vals.setdefault((rec.case_id, rec.target), []).append(rec.value)

    if expected_rounds is not None:
        for case_id in cases:
            if case_id in skipped_notes:
                continue
            for t in targets:
                vals = valid_vals.get((case_id, t), [])
                invs = invalid_by_series.get((case_id, t), [])
                if (vals or invs) and len(vals) < expected_rounds and not invs:
                    # Mark incomplete series as invalid so partial runs are never shown as OK.
                    invalid_by_series.setdefault((case_id, t), [])
    return valid_vals, invalid_by_series, skipped_notes, all_invalid


def _series_status(
    case_id: str,
    target: str,
    valid_vals: dict[tuple[str, str], list[float]],
    invalid_by_series: dict[tuple[str, str], list[CaseRecord]],
    expected_rounds: int | None,
) -> tuple[str, str]:
    invs = invalid_by_series.get((case_id, target))
    vals = valid_vals.get((case_id, target), [])
    if invs:
        reasons = "; ".join(
            f"R{r.round_idx}: {', '.join(r.invalid_reasons) or 'invalid'}"
            for r in invs[:2]
        )
        return "INVALID", reasons
    if expected_rounds is not None and (case_id, target) in invalid_by_series:
        return "INCOMPLETE", f"got {len(vals)}/{expected_rounds} rounds"
    if expected_rounds is not None and vals and len(vals) < expected_rounds:
        return "INCOMPLETE", f"got {len(vals)}/{expected_rounds} rounds"
    if not vals:
        return "MISSING", "no samples"
    return "OK", ""


def _calibrated_counter_rows(
    cases: dict[str, CaseSpec],
    records: list[CaseRecord],
) -> list[dict[str, object]]:
    """Compute per-case per-target calibrated SandboxStats and rusage medians."""
    noop_by_key: dict[tuple[int, str], SandboxStats] = {}
    for rec in records:
        if rec.case_id == "selfcheck.noop" and rec.sandbox_stats is not None and rec.valid:
            noop_by_key[(rec.round_idx, rec.target)] = rec.sandbox_stats

    grouped: dict[tuple[str, str], list[CaseRecord]] = {}
    for rec in records:
        if rec.skipped or not rec.valid:
            continue
        grouped.setdefault((rec.case_id, rec.target), []).append(rec)

    rows: list[dict[str, object]] = []
    for case_id in cases:
        for (cid, target), recs in sorted(grouped.items()):
            if cid != case_id:
                continue
            minflts = [float(r.minflt_delta) for r in recs]
            utimes = [float(r.ru_utime_us) for r in recs]
            stimes = [float(r.ru_stime_us) for r in recs]
            timing_vals = [float(r.timing_minflt_delta) for r in recs if r.timing_minflt_delta is not None]

            row: dict[str, object] = {
                "case_id": case_id,
                "target": target,
                "n": len(recs),
                "minflt_median": statistics.median(minflts),
                "timing_minflt_median": statistics.median(timing_vals) if len(timing_vals) == len(recs) else None,
                "utime_us_median": statistics.median(utimes),
                "stime_us_median": statistics.median(stimes),
                "syscalls_cal_median": None,
                "page_faults_cal_median": None,
                "vm_flushes_cal_median": None,
                "fpu_saves_cal_median": None,
                "virqs_cal_median": None,
                "forced_yields_cal_median": None,
                "non_sysret_cal_median": None,
            }

            if target.startswith("K"):
                k_recs = [r for r in recs if r.sandbox_stats is not None]
                if len(k_recs) == len(recs):
                    def _cal_med(field: str) -> float | None:
                        vals: list[float] = []
                        for r in k_recs:
                            assert r.sandbox_stats is not None
                            raw = getattr(r.sandbox_stats, field)
                            if raw is None:
                                return None
                            if r.case_id == "selfcheck.noop":
                                vals.append(float(raw))
                            else:
                                noop = noop_by_key.get((r.round_idx, r.target))
                                base = getattr(noop, field) if noop is not None else 0
                                if base is None:
                                    return None
                                vals.append(float(max(0, raw - base)))
                        return float(statistics.median(vals)) if vals else None

                    row["syscalls_cal_median"] = _cal_med("syscalls")
                    row["page_faults_cal_median"] = _cal_med("page_faults")
                    row["vm_flushes_cal_median"] = _cal_med("vm_flushes")
                    row["fpu_saves_cal_median"] = _cal_med("fpu_saves")
                    row["virqs_cal_median"] = _cal_med("virqs")
                    row["forced_yields_cal_median"] = _cal_med("forced_yields")
                    row["non_sysret_cal_median"] = _cal_med("non_sysret")
            rows.append(row)
    return rows


def render_calibrated_stats_markdown(
    cases: dict[str, CaseSpec],
    records: list[CaseRecord],
) -> str:
    """Render per-case rusage and noop-calibrated Kernelet counter analysis."""
    rows = _calibrated_counter_rows(cases, records)
    if not rows:
        return ""
    lines = [
        "## Per-Case Calibrated Counter & Rusage Analysis (Medians)",
        "",
        "| Case ID | Target | n | `minflt` | `timing_minflt` | `utime_us` | `stime_us` | `syscalls (cal)` | `page_faults (cal)` | `vm_flushes (cal)` | `fpu_saves (cal)` | `virqs (cal)` | `forced_yields (cal)` | `non_sysret (cal)` |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]

    def _f(v: object) -> str:
        if v is None:
            return "N/A"
        return f"{float(v):.0f}"

    for r in rows:
        lines.append(
            "| " + " | ".join([
                f"`{r['case_id']}`",
                str(r["target"]),
                str(r["n"]),
                _f(r["minflt_median"]),
                _f(r["timing_minflt_median"]),
                _f(r["utime_us_median"]),
                _f(r["stime_us_median"]),
                _f(r["syscalls_cal_median"]),
                _f(r["page_faults_cal_median"]),
                _f(r["vm_flushes_cal_median"]),
                _f(r["fpu_saves_cal_median"]),
                _f(r["virqs_cal_median"]),
                _f(r["forced_yields_cal_median"]),
                _f(r["non_sysret_cal_median"]),
            ]) + " |"
        )
    lines.append("")
    return "\n".join(lines)


def render_calibrated_stats_csv(
    cases: dict[str, CaseSpec],
    records: list[CaseRecord],
) -> str:
    """Render per-case rusage and noop-calibrated Kernelet counter medians as CSV."""
    rows = _calibrated_counter_rows(cases, records)
    buf = io.StringIO()
    writer = csv.writer(buf)
    cols = [
        "case_id",
        "target",
        "n",
        "minflt_median",
        "timing_minflt_median",
        "utime_us_median",
        "stime_us_median",
        "syscalls_cal_median",
        "page_faults_cal_median",
        "vm_flushes_cal_median",
        "fpu_saves_cal_median",
        "virqs_cal_median",
        "forced_yields_cal_median",
        "non_sysret_cal_median",
    ]
    writer.writerow(cols)
    for r in rows:
        writer.writerow(["" if r[c] is None else r[c] for c in cols])
    return buf.getvalue()


def render_markdown_report(
    cases: dict[str, CaseSpec],
    records: list[CaseRecord],
    targets: list[str],
    *,
    title: str = "Kernelet Evaluation Summary",
    expected_rounds: int | None = None,
    aborted_reason: str | None = None,
) -> str:
    """Render a fail-closed Markdown summary table with Median, [min, max], Mean, K/L, and K/A."""
    valid_vals, invalid_by_series, skipped_notes, all_invalid = _analyze_series(
        cases, records, targets, expected_rounds
    )

    lines: list[str] = [f"# {title}", ""]
    if aborted_reason or all_invalid or invalid_by_series:
        lines.append(
            f"> **RUN STATUS: INVALID / INCOMPLETE** — {len(all_invalid)} invalid record(s)"
            + (f" ({aborted_reason})" if aborted_reason else "")
            + ". Series with invalid or missing rounds are marked `INVALID`/`INCOMPLETE` and excluded from ratios."
        )
        lines.append("")
    if skipped_notes:
        lines.append(
            f"> **COVERAGE NOTICE:** {len(skipped_notes)} declared case(s) were skipped (`auto_skip` / coverage gap); this run is not a full-matrix pass for skipped items."
        )
        lines.append("")

    header = ["Case ID", "Unit", "Direction"]
    for t in targets:
        header.append(f"{t} Median [min, max] (Mean)")
    if "K" in targets and "L" in targets:
        header.append("K / L")
    if "K" in targets and "A" in targets:
        header.append("K / A")

    lines.append("| " + " | ".join(header) + " |")
    lines.append("|" + "|".join(["---"] * len(header)) + "|")

    for case_id, spec in cases.items():
        if case_id in skipped_notes:
            direction = "higher better" if spec.higher_is_better else "lower better"
            row = [f"`{case_id}`", spec.unit, direction]
            for _ in targets:
                row.append(f"SKIPPED ({skipped_notes[case_id]})")
            if "K" in targets and "L" in targets:
                row.append("SKIPPED")
            if "K" in targets and "A" in targets:
                row.append("SKIPPED")
            lines.append("| " + " | ".join(row) + " |")
            continue

        stats_by_target: dict[str, SummaryStats | None] = {}
        status_by_target: dict[str, tuple[str, str]] = {}
        any_present = False
        for t in targets:
            st_code, st_msg = _series_status(
                case_id, t, valid_vals, invalid_by_series, expected_rounds
            )
            status_by_target[t] = (st_code, st_msg)
            if st_code != "MISSING":
                any_present = True
            if st_code == "OK":
                stats_by_target[t] = compute_stats(valid_vals[(case_id, t)])
            else:
                stats_by_target[t] = None
        if not any_present:
            continue

        direction = "higher better" if spec.higher_is_better else "lower better"
        row = [f"`{case_id}`", spec.unit, direction]
        for t in targets:
            st_code, st_msg = status_by_target[t]
            if st_code == "OK":
                row.append(_fmt_stat(stats_by_target[t]))
            elif st_code == "MISSING":
                row.append("MISSING")
            else:
                row.append(f"{st_code} ({st_msg})")
        if "K" in targets and "L" in targets:
            if status_by_target["K"][0] == "OK" and status_by_target["L"][0] == "OK":
                row.append(_ratio(stats_by_target.get("K"), stats_by_target.get("L")))
            else:
                row.append("INVALID")
        if "K" in targets and "A" in targets:
            if status_by_target["K"][0] == "OK" and status_by_target["A"][0] == "OK":
                row.append(_ratio(stats_by_target.get("K"), stats_by_target.get("A")))
            else:
                row.append("INVALID")
        lines.append("| " + " | ".join(row) + " |")

    lines.append("")
    cal_md = render_calibrated_stats_markdown(cases, records)
    if cal_md:
        lines.append(cal_md)

    if skipped_notes:
        lines.append("## Skipped Cases & Known Coverage Gaps")
        lines.append("")
        for cid, reason in skipped_notes.items():
            lines.append(f"- `{cid}`: {reason}")
        lines.append("")

    return "\n".join(lines)


def render_csv_report(
    cases: dict[str, CaseSpec],
    records: list[CaseRecord],
    targets: list[str],
    *,
    expected_rounds: int | None = None,
) -> str:
    """Render aggregated per-case, per-target statistics as CSV (fail-closed on invalid/incomplete)."""
    valid_vals, invalid_by_series, skipped_notes, _ = _analyze_series(
        cases, records, targets, expected_rounds
    )

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "case_id",
            "group",
            "suite",
            "target",
            "unit",
            "higher_is_better",
            "status",
            "n",
            "median",
            "mean",
            "min",
            "max",
        ]
    )
    for case_id, spec in cases.items():
        for t in targets:
            if case_id in skipped_notes:
                writer.writerow(
                    [
                        case_id,
                        spec.group,
                        spec.suite,
                        t,
                        spec.unit,
                        spec.higher_is_better,
                        f"SKIPPED:{skipped_notes[case_id]}",
                        0,
                        "",
                        "",
                        "",
                        "",
                    ]
                )
                continue
            st_code, st_msg = _series_status(
                case_id, t, valid_vals, invalid_by_series, expected_rounds
            )
            if st_code == "MISSING":
                continue
            if st_code != "OK":
                vals = valid_vals.get((case_id, t), [])
                writer.writerow(
                    [
                        case_id,
                        spec.group,
                        spec.suite,
                        t,
                        spec.unit,
                        spec.higher_is_better,
                        f"{st_code}:{st_msg}",
                        len(vals),
                        "",
                        "",
                        "",
                        "",
                    ]
                )
                continue
            vals = valid_vals[(case_id, t)]
            st = compute_stats(vals)
            writer.writerow(
                [
                    case_id,
                    spec.group,
                    spec.suite,
                    t,
                    spec.unit,
                    spec.higher_is_better,
                    "OK",
                    st.count,
                    f"{st.median:.6f}",
                    f"{st.mean:.6f}",
                    f"{st.min_val:.6f}",
                    f"{st.max_val:.6f}",
                ]
            )
    return buf.getvalue()
