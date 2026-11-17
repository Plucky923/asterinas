from __future__ import annotations

import math
import re

from .schema import CaseRecord, CaseSpec, SandboxStats


_BAD_KERNEL_RE = re.compile(
    r"(?:^|\n)\s*(?:\[[^\]]+\]\s*)?(?:BUG:|WARNING:|Oops:|Kernel panic|"
    r"INIT: delete_module .* failed|INIT: failed|unable to handle kernel)",
    re.MULTILINE,
)


def check_kernel_log_clean(kernel_log: str) -> list[str]:
    """Return violations if the kernel/serial log reports BUG/WARNING/Oops/unload failure."""
    matches = _BAD_KERNEL_RE.findall(kernel_log)
    if not matches:
        return []
    sample = matches[0].strip()
    return [f"kernel/host log error detected ({len(matches)}x): {sample!r}"]


def validate_case_record(
    spec: CaseSpec,
    record: CaseRecord,
    *,
    kernel_log: str = "",
    noop_stats: SandboxStats | None = None,
) -> tuple[bool, list[str]]:
    """Validate a single CaseRecord against fail-closed invariants."""
    if record.skipped:
        return True, []

    reasons: list[str] = []
    inv = spec.invariants

    if record.rc != 0:
        reasons.append(f"non-zero exit code: rc={record.rc}")

    if record.value is None or not math.isfinite(record.value) or record.value < 0.0:
        reasons.append(f"missing or invalid parsed metric value: {record.value!r}")
    elif (spec.higher_is_better or spec.suite in ("lmbench", "will-it-scale", "stress-ng")) and record.value <= 0.0:
        reasons.append(f"non-positive benchmark metric value: {record.value!r} {spec.unit}")

    if inv.forbid_migration:
        if not record.cpu_obs_ok:
            reasons.append("CPU affinity/migration procfs observation failed or incomplete")
        if record.migrated:
            reasons.append("unexpected CPU migration outside allowed set")
        if record.cpu_start not in spec.cpus:
            reasons.append(f"cpu_start={record.cpu_start} not in allowed {spec.cpus}")
        if record.cpu_end not in spec.cpus:
            reasons.append(f"cpu_end={record.cpu_end} not in allowed {spec.cpus}")

    if inv.forbid_thp:
        if record.target.startswith("L"):
            if not record.thp_obs_ok or record.thp_fault_alloc_delta is None:
                reasons.append("missing /proc/vmstat thp_fault_alloc or sysfs THP policy observation on Linux")
            elif record.thp_fault_alloc_delta > 0:
                reasons.append(
                    f"THP allocation occurred: thp_fault_alloc_delta={record.thp_fault_alloc_delta}"
                )
            if record.thp_policy is not None and "[never]" not in record.thp_policy:
                reasons.append(
                    f"Linux guest THP policy is not [never]: {record.thp_policy!r}"
                )
        elif record.target.startswith("K"):
            hm = record.host_meta
            if hm is None:
                reasons.append("missing HOST_CASE_META host THP/grant observation on Kernelet target")
            else:
                if not hm.host_thp_obs_ok or hm.host_thp_fault_alloc_delta is None:
                    reasons.append("missing host /proc/vmstat thp_fault_alloc or sysfs THP policy on Kernelet host")
                elif hm.host_thp_fault_alloc_delta > 0:
                    reasons.append(
                        f"host THP allocation occurred during {record.target}: "
                        f"host_thp_fault_alloc_delta={hm.host_thp_fault_alloc_delta}"
                    )
                if hm.host_thp_policy is not None and "[never]" not in hm.host_thp_policy:
                    reasons.append(
                        f"Kernelet host THP policy is not [never]: {hm.host_thp_policy!r}"
                    )
            if record.thp_fault_alloc_delta is not None and record.thp_fault_alloc_delta > 0:
                reasons.append(
                    f"THP allocation occurred: thp_fault_alloc_delta={record.thp_fault_alloc_delta}"
                )
        else:
            # Native Asterinas (`A`) supports 4 KiB pages only and must not report Linux THP allocations.
            if record.thp_policy is not None or (
                record.thp_fault_alloc_delta is not None and record.thp_fault_alloc_delta > 0
            ):
                reasons.append(
                    f"unexpected THP reporting on native Asterinas: "
                    f"policy={record.thp_policy!r}, delta={record.thp_fault_alloc_delta!r}"
                )

    if inv.max_vdso_syscalls is not None and record.value is not None:
        if record.value > float(inv.max_vdso_syscalls):
            reasons.append(
                f"vDSO fallback syscalls={record.value:.0f} > max {inv.max_vdso_syscalls}"
            )

    if inv.max_timing_faults is not None:
        if record.timing_minflt_delta is None or record.timing_majflt_delta is None:
            reasons.append("missing timing-window page fault observation")
        else:
            total_timing_flt = record.timing_minflt_delta + record.timing_majflt_delta
            if total_timing_flt > inv.max_timing_faults:
                reasons.append(
                    f"timing-window page faults={total_timing_flt} "
                    f"(min={record.timing_minflt_delta}, maj={record.timing_majflt_delta}) "
                    f"> max {inv.max_timing_faults}"
                )

    if inv.min_timing_stage_faults is not None:
        stage_idx = inv.timing_stage_index if inv.timing_stage_index is not None else 0
        if not record.timing_stages or stage_idx < 0 or stage_idx >= len(record.timing_stages):
            reasons.append(
                f"missing timing stage {stage_idx} in LMBENCH_TIMING_RUSAGE "
                f"(stages={len(record.timing_stages)})"
            )
        else:
            stage = record.timing_stages[stage_idx]
            if not stage.valid or stage.intervals <= 0:
                reasons.append(
                    f"invalid timing stage {stage_idx}: valid={stage.valid}, intervals={stage.intervals}"
                )
            elif stage.minflt < inv.min_timing_stage_faults:
                reasons.append(
                    f"insufficient timing stage {stage_idx} minor faults on {record.target}: "
                    f"{stage.minflt} < {inv.min_timing_stage_faults}"
                )

    if record.target.startswith("K") and record.sandbox_stats is None:
        reasons.append("missing STATS_JSON for Kernelet target")

    if inv.min_minor_faults > 0:
        if record.minflt_delta < inv.min_minor_faults:
            reasons.append(
                f"insufficient minor faults on {record.target}: "
                f"{record.minflt_delta} < {inv.min_minor_faults}"
            )
        if record.target.startswith("K") and record.sandbox_stats is not None:
            base_pf = noop_stats.page_faults if noop_stats is not None else 0
            adj_pf = max(0, record.sandbox_stats.page_faults - base_pf)
            if adj_pf < inv.min_minor_faults:
                reasons.append(
                    f"insufficient sandbox page_faults on {record.target}: "
                    f"{adj_pf} < {inv.min_minor_faults}"
                )

    if record.sandbox_stats is not None:
        st = record.sandbox_stats
        expected_pt_mode = 1 if record.target == "K_vma" else 0
        if record.target.startswith("K") and st.pt_mode != expected_pt_mode:
            reasons.append(
                f"unexpected pt_mode={st.pt_mode} for {record.target} (expected {expected_pt_mode})"
            )
        if record.target.startswith("K") and st.syscalls is None:
            reasons.append("missing syscalls counter in STATS_JSON")
        if (
            record.target.startswith("K")
            and record.audit_mode
            and spec.case_id != "selfcheck.noop"
            and (st.syscalls is None or st.syscalls <= 0)
        ):
            reasons.append(f"audit run captured unexpected syscalls={st.syscalls!r}")
        if record.target.startswith("K"):
            if st.grant_grains_allocated is None or st.grant_grains_freed is None:
                reasons.append("missing grant grain allocation/reclamation counters in STATS_JSON")
            elif st.grant_grains_allocated <= 0 or st.grant_grains_allocated != st.grant_grains_freed:
                reasons.append(
                    f"Grant grain leak/mismatch: allocated={st.grant_grains_allocated}, "
                    f"freed={st.grant_grains_freed}"
                )
            hm = record.host_meta
            if hm is not None:
                if not hm.grant_accounting_ok:
                    reasons.append("endovisor /sys/class/misc/endovisor/grant_accounting unreadable")
                elif any(
                    val != 0
                    for val in (
                        hm.live_sandboxes,
                        hm.live_grant_grains,
                        hm.live_meta_pages,
                        hm.live_kstack_pages,
                        hm.live_shared_pages,
                    )
                ):
                    reasons.append(
                        f"unreclaimed endovisor resources after sandbox exit: "
                        f"sandboxes={hm.live_sandboxes}, grains={hm.live_grant_grains}, "
                        f"meta_pages={hm.live_meta_pages}, kstack_pages={hm.live_kstack_pages}, "
                        f"shared_pages={hm.live_shared_pages}"
                    )
        if st.exit_kind != 0 or st.exit_code != 0:
            reasons.append(
                f"kernelet sandbox failed: exit_kind={st.exit_kind}, "
                f"exit_code={st.exit_code}, msg={st.exit_msg!r}"
            )
        if inv.max_fpu_saves is not None:
            base_fpu = noop_stats.fpu_saves if noop_stats is not None else 0
            adj_fpu = max(0, st.fpu_saves - base_fpu)
            if adj_fpu > inv.max_fpu_saves:
                reasons.append(
                    f"excess FPU saves: adjusted={adj_fpu} > max={inv.max_fpu_saves}"
                )
        if inv.max_non_sysret is not None:
            if st.non_sysret is None:
                reasons.append("missing non_sysret observation in STATS_JSON")
            elif noop_stats is not None and noop_stats.non_sysret is None:
                reasons.append("missing non_sysret observation in noop baseline")
            else:
                base_ns = noop_stats.non_sysret if noop_stats is not None else 0
                adj_ns = max(0, st.non_sysret - base_ns)
                if adj_ns > inv.max_non_sysret:
                    reasons.append(
                        f"excess non-SYSRET returns: adjusted={adj_ns} > max={inv.max_non_sysret}"
                    )
        if inv.require_vm_balance and st.vm_creates != st.vm_destroys:
            reasons.append(
                f"VmSpace leak: vm_creates={st.vm_creates} != vm_destroys={st.vm_destroys}"
            )

    if kernel_log:
        reasons.extend(check_kernel_log_clean(kernel_log))

    return len(reasons) == 0, reasons
