"""Command-line entrypoint for poc/eval orchestration, verification, profiling, and reporting."""

from __future__ import annotations

import argparse
import datetime
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from .build_guard import (
    check_kernel_config,
    compute_component_input_hash,
    generate_and_write_archive,
    synthesize_build_manifest,
    verify_build_freshness,
    write_build_inputs_manifest,
    write_component_receipt,
)
from .invariants import check_kernel_log_clean, validate_case_record
from .perf_sym import (
    parse_perf_script_stacks,
    render_flamegraph_svg,
    render_profile_report_markdown,
    symbolize_folded_addr_stacks,
    synthesize_guest_kallsyms,
)
from .qemu_driver import (
    EVAL_CASE_PREFIX,
    HOST_META_PREFIX,
    LiveProfileAddresses,
    QemuBootResult,
    QemuRunError,
    build_batch_overlay_cpio_gz,
    extract_guest_folded_profile,
    format_batch_manifest,
    format_guest_runner_args,
    parse_serial_records,
    run_qemu_with_pinning,
)
from .report import (
    render_calibrated_stats_csv,
    render_csv_report,
    render_markdown_report,
    schedule_rounds,
    write_records_jsonl,
    write_vm_runs_jsonl,
)
from .schema import CaseRecord, CaseSpec, SandboxStats, VmRunRecord, load_cases_toml


EVAL_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = EVAL_DIR.parent.parent
BUILD_DIR = EVAL_DIR / ".build"
TMP_ROOT = BUILD_DIR / "tmp"


def _select_cases(
    all_cases: dict[str, CaseSpec],
    groups: list[str] | None,
    case_ids: list[str] | None,
) -> dict[str, CaseSpec]:
    unknown_cases = set(case_ids or ()) - all_cases.keys()
    if unknown_cases:
        raise ValueError(f"unknown cases: {sorted(unknown_cases)}")
    unknown_groups = set(groups or ()) - {spec.group for spec in all_cases.values()}
    if unknown_groups:
        raise ValueError(f"unknown groups: {sorted(unknown_groups)}")
    selected: dict[str, CaseSpec] = {}
    for cid, spec in all_cases.items():
        if case_ids and cid not in case_ids:
            continue
        if groups and spec.group not in groups:
            continue
        selected[cid] = spec
    if not selected:
        raise ValueError("no matching cases selected")
    return selected


def _build_host_initrd(
    base_initrd: Path,
    payload_path: Path,
    batch_text: str,
    out_path: Path,
) -> None:
    overlay = build_batch_overlay_cpio_gz(batch_text, payload_path.read_bytes())
    out_path.write_bytes(base_initrd.read_bytes() + overlay)


def _linux_mitigation_cmdline(profile: str) -> str:
    if profile == "perf-pti":
        return "pti=on"
    return "mitigations=off"


def _verify_batch_completeness(
    records: list[CaseRecord],
    *,
    round_idx: int,
    target: str,
    runnable_specs: dict[str, CaseSpec],
) -> None:
    seen: dict[str, int] = {}
    for rec in records:
        if rec.case_id not in runnable_specs:
            raise RuntimeError(
                f"{target} R{round_idx}: unexpected case_id {rec.case_id!r} in VM output"
            )
        seen[rec.case_id] = seen.get(rec.case_id, 0) + 1
    missing = [cid for cid in runnable_specs if cid not in seen]
    dups = [cid for cid, cnt in seen.items() if cnt != 1]
    if missing or dups:
        raise RuntimeError(
            f"{target} R{round_idx}: incomplete/duplicate records (missing={missing}, dups={dups})"
        )


def _make_vm_run_record(
    *,
    round_idx: int,
    target: str,
    case_ids: list[str],
    kernel_path: Path,
    initrd_path: Path,
    cmdline: str,
    boot: QemuBootResult,
) -> VmRunRecord:
    return VmRunRecord(
        round_idx=round_idx,
        target=target,
        case_ids=case_ids,
        cmd=boot.cmd,
        kernel_path=str(kernel_path),
        initrd_path=str(initrd_path),
        cmdline=cmdline,
        vcpu_tids=boot.vcpu_tids,
        pinned_vcpu_map=boot.pinned_vcpu_map,
        pinned_io_cpu=boot.pinned_io_cpu,
        qemu_rc=boot.qemu_rc,
        serial_log_path=boot.serial_log_path,
        stderr_log_path=boot.stderr_log_path,
    )


class BatchExecutionError(RuntimeError):
    """Preserves completed CaseRecords and VmRunRecords across any VM/parser/gate abort."""

    def __init__(
        self,
        message: str,
        *,
        records: list[CaseRecord],
        vm_runs: list[VmRunRecord],
    ) -> None:
        super().__init__(message)
        self.records = records
        self.vm_runs = vm_runs


def _resolve_profile_paths(args: argparse.Namespace) -> dict[str, Path]:
    profile = getattr(args, "linux_profile", "perf-base")
    prof_dir = BUILD_DIR / f"linux-{profile}"
    default_bz = str(BUILD_DIR / "linux-perf-base" / "arch" / "x86" / "boot" / "bzImage")
    default_cfg = str(BUILD_DIR / "linux-perf-base" / ".config")
    default_initrd = str(BUILD_DIR / "host-eval-initramfs.cpio.gz")
    default_map = str(BUILD_DIR / "linux-perf-base" / "System.map")
    default_ko = str(BUILD_DIR / "endovisor.ko")

    def _pick(raw: str | None, base_default: str, pti_path: Path) -> Path:
        if raw is None or (profile == "perf-pti" and raw == base_default):
            return pti_path if profile == "perf-pti" else Path(base_default)
        return Path(raw)

    return {
        "linux_bzimage": _pick(getattr(args, "linux_bzimage", None), default_bz, prof_dir / "arch" / "x86" / "boot" / "bzImage"),
        "linux_config": _pick(getattr(args, "linux_config", None), default_cfg, prof_dir / ".config"),
        "host_initrd": _pick(getattr(args, "host_initrd", None), default_initrd, BUILD_DIR / "host-eval-initramfs-pti.cpio.gz"),
        "system_map": _pick(getattr(args, "system_map", None), default_map, prof_dir / "System.map"),
        "ko": _pick(getattr(args, "ko", None), default_ko, BUILD_DIR / "endovisor-pti.ko"),
    }


def _run_target_batch(
    *,
    target: str,
    round_idx: int,
    specs: dict[str, CaseSpec],
    linux_bzimage: Path,
    linux_profile: str = "perf-base",
    aster_bzimage: Path,
    host_base_initrd: Path,
    payload_cpio: Path,
    grant_mb: int,
    vcpus: int,
    timeout_sec: int,
    log_dir: Path,
    audit_mode: bool = False,
) -> tuple[list[CaseRecord], list[VmRunRecord]]:
    skipped_records: list[CaseRecord] = []
    runnable_specs: dict[str, CaseSpec] = {}
    for cid, spec in specs.items():
        if spec.auto_skip_reason:
            skipped_records.append(
                CaseRecord(
                    round_idx=round_idx,
                    target=target,
                    case_id=cid,
                    rc=0,
                    wall_ns=0,
                    minflt_delta=0,
                    majflt_delta=0,
                    ru_utime_us=0,
                    ru_stime_us=0,
                    cpu_start=spec.cpus[0],
                    cpu_end=spec.cpus[0],
                    migrated=False,
                    thp_fault_alloc_delta=None,
                    stdout="",
                    stderr="",
                    value=None,
                    unit=spec.unit,
                    valid=True,
                    skipped=True,
                    skip_reason=spec.auto_skip_reason,
                    thp_obs_ok=True,
                    audit_mode=audit_mode,
                )
            )
        else:
            runnable_specs[cid] = spec

    if not runnable_specs:
        return skipped_records, []

    def _validate_record_strict(
        rec: CaseRecord,
        *,
        noop_stats: SandboxStats | None,
        extra_log: str = "",
    ) -> None:
        spec = runnable_specs[rec.case_id]
        ok, reasons = validate_case_record(
            spec,
            rec,
            kernel_log=extra_log,
            noop_stats=None if rec.case_id == "selfcheck.noop" else noop_stats,
        )
        if rec.sandbox_stats is not None:
            if rec.sandbox_stats.vcpus != vcpus:
                reasons.append(f"vCPU count mismatch: requested {vcpus}, got {rec.sandbox_stats.vcpus}")
            if rec.sandbox_stats.grant_mb != grant_mb:
                reasons.append(f"grant mismatch: requested {grant_mb} MiB, got {rec.sandbox_stats.grant_mb} MiB")
        rec.valid = ok and not reasons
        rec.invalid_reasons = reasons

    vm_runs: list[VmRunRecord] = []
    if target == "A":
        all_records: list[CaseRecord] = []
        for spec in runnable_specs.values():
            runner_flags = " ".join(format_guest_runner_args(spec)[1:])
            cmdline = f"console=ttyS0 log_level=error -- --poweroff {runner_flags}"
            try:
                boot = run_qemu_with_pinning(
                    kernel_path=aster_bzimage,
                    initrd_path=payload_cpio,
                    cmdline=cmdline,
                    vcpus=vcpus,
                    mem_mb=2048,
                    timeout_sec=timeout_sec,
                    isa_debug_exit=True,
                    expected_qemu_rcs=(33,),
                    temp_root=TMP_ROOT,
                    log_dir=log_dir,
                    log_prefix=f"r{round_idx}_{target}_{spec.case_id}",
                )
            except QemuRunError as exc:
                vm_runs.append(
                    _make_vm_run_record(
                        round_idx=round_idx,
                        target=target,
                        case_ids=[spec.case_id],
                        kernel_path=aster_bzimage,
                        initrd_path=payload_cpio,
                        cmdline=cmdline,
                        boot=exc.partial_result,
                    )
                )
                try:
                    partial_recs = parse_serial_records(
                        exc.partial_result.serial_log,
                        round_idx=round_idx,
                        target=target,
                        specs={spec.case_id: spec},
                        require_complete=False,
                        audit_mode=audit_mode,
                    )
                except Exception:
                    partial_recs = []
                for pr in partial_recs:
                    _validate_record_strict(pr, noop_stats=None, extra_log=exc.partial_result.serial_log)
                    if pr.valid:
                        pr.valid = False
                        pr.invalid_reasons.append(str(exc))
                    all_records.append(pr)
                raise BatchExecutionError(
                    f"{target} R{round_idx} {spec.case_id}: {exc}",
                    records=skipped_records + all_records,
                    vm_runs=vm_runs,
                ) from exc

            vm_runs.append(
                _make_vm_run_record(
                    round_idx=round_idx,
                    target=target,
                    case_ids=[spec.case_id],
                    kernel_path=aster_bzimage,
                    initrd_path=payload_cpio,
                    cmdline=cmdline,
                    boot=boot,
                )
            )
            try:
                recs = parse_serial_records(
                    boot.serial_log,
                    round_idx=round_idx,
                    target=target,
                    specs={spec.case_id: spec},
                    require_complete=True,
                    audit_mode=audit_mode,
                )
                _verify_batch_completeness(
                    recs, round_idx=round_idx, target=target, runnable_specs={spec.case_id: spec}
                )
            except Exception as exc:
                raise BatchExecutionError(
                    f"{target} R{round_idx} {spec.case_id}: {exc}",
                    records=skipped_records + all_records,
                    vm_runs=vm_runs,
                ) from exc

            for rec in recs:
                _validate_record_strict(rec, noop_stats=None, extra_log=boot.serial_log)
                all_records.append(rec)
                if not rec.valid:
                    raise BatchExecutionError(
                        f"{target} R{round_idx} {spec.case_id} gate failed: " + "; ".join(rec.invalid_reasons),
                        records=skipped_records + all_records,
                        vm_runs=vm_runs,
                    )
        return skipped_records + all_records, vm_runs

    if target == "L":
        eval_role = "L"
        pt_mode = "direct"
    elif target == "K":
        eval_role = "K"
        pt_mode = "direct"
    elif target == "K_vma":
        eval_role = "K"
        pt_mode = "vma"
    else:
        raise ValueError(f"unsupported target: {target!r}")

    batch_text = format_batch_manifest(runnable_specs.values())
    stream_lines: list[str] = []
    stream_noop: SandboxStats | None = None
    expects_host_meta = target.startswith("K")

    def _on_serial_line(line: str) -> str | None:
        nonlocal stream_noop
        stream_lines.append(line)
        s = line.strip()
        # Trigger per-record validation immediately once a case's final frame arrives.
        ready_prefix = HOST_META_PREFIX if expects_host_meta else EVAL_CASE_PREFIX
        if s.startswith(ready_prefix):
            try:
                partial = parse_serial_records(
                    "".join(stream_lines),
                    round_idx=round_idx,
                    target=target,
                    specs=runnable_specs,
                    require_complete=False,
                    audit_mode=audit_mode,
                )
            except Exception as exc:
                return f"streaming parse failure in {target} R{round_idx}: {exc}"
            if partial:
                last = partial[-1]
                if last.case_id == "selfcheck.noop" and last.sandbox_stats is not None:
                    stream_noop = last.sandbox_stats
                _validate_record_strict(last, noop_stats=stream_noop)
                if not last.valid:
                    return (
                        f"streaming invariant failure in {target} R{round_idx} {last.case_id}: "
                        + "; ".join(last.invalid_reasons)
                    )
        elif check_kernel_log_clean(line):
            return f"kernel error detected on {target} R{round_idx}: {s!r}"
        return None

    TMP_ROOT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f"eval-{target}-", dir=str(TMP_ROOT)) as tmpdir:
        initrd = Path(tmpdir) / "host-initrd.cpio.gz"
        _build_host_initrd(host_base_initrd, payload_cpio, batch_text, initrd)
        mit_arg = _linux_mitigation_cmdline(linux_profile)
        audit_arg = "1" if audit_mode else "0"
        cmdline = (
            f"console=ttyS0 panic=-1 transparent_hugepage=never {mit_arg} "
            f"eval_role={eval_role} eval_pt_mode={pt_mode} "
            f"eval_vcpus={vcpus} eval_grant_mb={grant_mb} eval_audit={audit_arg}"
        )
        try:
            boot = run_qemu_with_pinning(
                kernel_path=linux_bzimage,
                initrd_path=initrd,
                cmdline=cmdline,
                vcpus=vcpus,
                mem_mb=2048,
                timeout_sec=max(timeout_sec, len(runnable_specs) * 30),
                isa_debug_exit=False,
                expected_qemu_rcs=(0,),
                temp_root=TMP_ROOT,
                log_dir=log_dir,
                log_prefix=f"r{round_idx}_{target}",
                on_serial_line=_on_serial_line,
            )
        except QemuRunError as exc:
            vm_runs.append(
                _make_vm_run_record(
                    round_idx=round_idx,
                    target=target,
                    case_ids=list(runnable_specs.keys()),
                    kernel_path=linux_bzimage,
                    initrd_path=host_base_initrd,
                    cmdline=cmdline,
                    boot=exc.partial_result,
                )
            )
            try:
                partial_recs = parse_serial_records(
                    exc.partial_result.serial_log,
                    round_idx=round_idx,
                    target=target,
                    specs=runnable_specs,
                    require_complete=False,
                    audit_mode=audit_mode,
                )
            except Exception:
                partial_recs = []
            noop_st: SandboxStats | None = None
            for pr in partial_recs:
                if pr.case_id == "selfcheck.noop" and pr.sandbox_stats is not None:
                    noop_st = pr.sandbox_stats
                _validate_record_strict(pr, noop_stats=noop_st, extra_log=exc.partial_result.serial_log)
            raise BatchExecutionError(
                f"{target} R{round_idx}: {exc}",
                records=skipped_records + partial_recs,
                vm_runs=vm_runs,
            ) from exc

        vm_runs.append(
            _make_vm_run_record(
                round_idx=round_idx,
                target=target,
                case_ids=list(runnable_specs.keys()),
                kernel_path=linux_bzimage,
                initrd_path=host_base_initrd,
                cmdline=cmdline,
                boot=boot,
            )
        )

    if "INIT: done" not in boot.serial_log:
        try:
            partial_recs = parse_serial_records(
                boot.serial_log,
                round_idx=round_idx,
                target=target,
                specs=runnable_specs,
                require_complete=False,
                audit_mode=audit_mode,
            )
        except Exception:
            partial_recs = []
        for pr in partial_recs:
            _validate_record_strict(pr, noop_stats=None, extra_log=boot.serial_log)
        raise BatchExecutionError(
            f"{target} round {round_idx}: missing 'INIT: done' in serial log",
            records=skipped_records + partial_recs,
            vm_runs=vm_runs,
        )

    try:
        recs = parse_serial_records(
            boot.serial_log,
            round_idx=round_idx,
            target=target,
            specs=runnable_specs,
            require_complete=True,
            audit_mode=audit_mode,
        )
        _verify_batch_completeness(
            recs, round_idx=round_idx, target=target, runnable_specs=runnable_specs
        )
    except Exception as exc:
        try:
            partial_recs = parse_serial_records(
                boot.serial_log,
                round_idx=round_idx,
                target=target,
                specs=runnable_specs,
                require_complete=False,
                audit_mode=audit_mode,
            )
        except Exception:
            partial_recs = []
        for pr in partial_recs:
            _validate_record_strict(pr, noop_stats=None, extra_log=boot.serial_log)
        raise BatchExecutionError(
            f"{target} round {round_idx}: {exc}",
            records=skipped_records + partial_recs,
            vm_runs=vm_runs,
        ) from exc

    noop_stats: SandboxStats | None = None
    for rec in recs:
        if rec.case_id == "selfcheck.noop" and rec.sandbox_stats is not None:
            noop_stats = rec.sandbox_stats
            break

    for rec in recs:
        _validate_record_strict(rec, noop_stats=noop_stats, extra_log=boot.serial_log)
    return skipped_records + recs, vm_runs


def _write_diagnostic_outputs(
    *,
    out_dir: Path,
    run_id: str,
    selected: dict[str, CaseSpec],
    records: list[CaseRecord],
    vm_runs: list[VmRunRecord],
    targets: list[str],
    expected_rounds: int,
    aborted_reason: str,
) -> None:
    write_records_jsonl(records, out_dir / "records.jsonl")
    write_vm_runs_jsonl(vm_runs, out_dir / "vm_runs.jsonl")
    md = render_markdown_report(
        selected,
        records,
        targets,
        title=f"Kernelet Eval DIAGNOSTIC ({run_id})",
        expected_rounds=expected_rounds,
        aborted_reason=aborted_reason,
    )
    csv_text = render_csv_report(
        selected, records, targets, expected_rounds=expected_rounds
    )
    (out_dir / "diagnostic_report.md").write_text(md, encoding="utf-8")
    (out_dir / "diagnostic_report.csv").write_text(csv_text, encoding="utf-8")


def cmd_check_config(args: argparse.Namespace) -> int:
    errors = check_kernel_config(Path(args.config), profile=args.profile)
    if errors:
        for err in errors:
            print(f"CONFIG ERROR: {err}", file=sys.stderr)
        return 1
    print(f"OK: {args.config} passed {args.profile} guard")
    return 0


def cmd_write_build_manifest(args: argparse.Namespace) -> int:
    out_path = write_build_inputs_manifest(REPO_ROOT, Path(args.build_dir))
    print(f"Wrote build freshness manifest to {out_path}")
    return 0


def cmd_check_freshness(args: argparse.Namespace) -> int:
    verify_build_freshness(REPO_ROOT, Path(args.build_dir), require_pti=bool(getattr(args, "pti", False)))
    print(f"OK: build artifacts under {args.build_dir} match current sources, patches, and configs")
    return 0


def cmd_component_hash(args: argparse.Namespace) -> int:
    digest = compute_component_input_hash(
        REPO_ROOT,
        Path(args.build_dir),
        args.component,
        payload_mode=getattr(args, "payload_mode", "native"),
    )
    print(digest)
    return 0


def cmd_write_receipt(args: argparse.Namespace) -> int:
    bdir = Path(args.build_dir)
    outputs: dict[str, Path] = {}
    for spec in args.output:
        if "=" not in spec:
            raise ValueError(f"--output must be KEY=RELPATH, got {spec!r}")
        k, rel = spec.split("=", 1)
        outputs[k] = bdir / rel
    path = write_component_receipt(bdir, args.component, args.input_sha, args.toolchain, outputs)
    print(f"Wrote receipt {path}")
    return 0


def cmd_synthesize_build_manifest(args: argparse.Namespace) -> int:
    bdir = Path(args.build_dir)
    try:
        out = synthesize_build_manifest(REPO_ROOT, bdir, require_pti=bool(args.pti))
        print(f"Wrote build freshness manifest to {out}")
        return 0
    except Exception as exc:
        if args.if_complete:
            return 0
        print(f"FRESHNESS ERROR: {exc}", file=sys.stderr)
        return 1


def cmd_run(args: argparse.Namespace) -> int:
    cases_path = Path(args.cases)
    suite = load_cases_toml(cases_path)
    groups = args.group if args.group else None
    case_ids = args.case if args.case else None
    selected = _select_cases(suite.cases, groups, case_ids)

    targets = [t.strip() for t in args.targets.split(",") if t.strip()]
    if not targets or len(set(targets)) != len(targets):
        raise ValueError("targets must be nonempty and unique")
    unknown_targets = set(targets) - {"L", "A", "K", "K_vma"}
    if unknown_targets:
        raise ValueError(f"unsupported targets: {sorted(unknown_targets)}")
    rounds = args.rounds or suite.defaults.rounds
    seed = args.seed or suite.defaults.seed

    resolved = _resolve_profile_paths(args)
    verify_build_freshness(REPO_ROOT, BUILD_DIR, require_pti=(args.linux_profile == "perf-pti"))

    linux_config = resolved["linux_config"]
    linux_bzimage = resolved["linux_bzimage"]
    host_initrd = resolved["host_initrd"]
    endovisor_ko = resolved["ko"]
    cfg_errors = check_kernel_config(linux_config, profile=args.linux_profile)
    if cfg_errors:
        for err in cfg_errors:
            print(f"CONFIG GUARD FAIL: {err}", file=sys.stderr)
        return 1

    payload_cpio = Path(args.payload)
    audit_mode = bool(getattr(args, "audit", False))
    run_id = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S") + f"-{args.tag}"
    out_dir = Path(args.results_dir) / run_id

    generate_and_write_archive(
        run_id=run_id,
        out_dir=out_dir,
        repo_root=REPO_ROOT,
        targets=targets,
        rounds=rounds,
        seed=seed,
        payload_path=payload_cpio,
        host_initrd_path=host_initrd,
        artifacts={
            "linux_bzimage": linux_bzimage,
            "aster_bzimage": Path(args.aster_bzimage),
            "host_base_initrd": host_initrd,
            "payload_cpio": payload_cpio,
            "endovisor_ko": endovisor_ko,
            "run_kernelet": BUILD_DIR / "run-kernelet",
            "kernelet_image": BUILD_DIR / "kernelet-image.elf",
        },
        kernel_configs={args.linux_profile: (linux_config, args.linux_profile)},
        cases_path=cases_path,
        build_dir=BUILD_DIR,
        build_inputs_verified=True,
    )

    all_vm_runs: list[VmRunRecord] = []
    all_records: list[CaseRecord] = []
    sc_records: list[CaseRecord] = []
    only_selfcheck = all(spec.group == "selfcheck" for spec in selected.values())

    def _abort_with_diagnostics(reason: str, records_so_far: list[CaseRecord], selected_map: dict[str, CaseSpec], exp_rounds: int) -> int:
        (out_dir / "error.txt").write_text(reason + "\n", encoding="utf-8")
        _write_diagnostic_outputs(
            out_dir=out_dir,
            run_id=run_id,
            selected=selected_map,
            records=records_so_far,
            vm_runs=all_vm_runs,
            targets=targets,
            expected_rounds=exp_rounds,
            aborted_reason=reason,
        )
        print(f"ABORTED [{run_id}]: {reason}", file=sys.stderr)
        return 1

    try:
        # Step 0 gate: mandatory before any timed rounds (cannot be bypassed).
        if not only_selfcheck:
            sc_specs = _select_cases(suite.cases, ["selfcheck"], None)
            for t in targets:
                recs, runs = _run_target_batch(
                    target=t,
                    round_idx=0,
                    specs=sc_specs,
                    linux_bzimage=linux_bzimage,
                    linux_profile=args.linux_profile,
                    aster_bzimage=Path(args.aster_bzimage),
                    host_base_initrd=host_initrd,
                    payload_cpio=payload_cpio,
                    grant_mb=suite.defaults.grant_mb,
                    vcpus=suite.defaults.vcpus,
                    timeout_sec=suite.defaults.timeout_sec,
                    log_dir=out_dir / "logs",
                    audit_mode=audit_mode,
                )
                sc_records.extend(recs)
                all_vm_runs.extend(runs)
                sc_invalid = [r for r in recs if not r.valid]
                if sc_invalid:
                    for rec in sc_invalid:
                        print(
                            f"STEP 0 SELFCHECK FAIL [{rec.target} {rec.case_id}]: "
                            + "; ".join(rec.invalid_reasons),
                            file=sys.stderr,
                        )
                    return _abort_with_diagnostics(
                        f"Step 0 selfcheck failed on {t}",
                        sc_records,
                        sc_specs,
                        1,
                    )
            write_records_jsonl(sc_records, out_dir / "selfcheck_records.jsonl")

        # Always include selfcheck.noop inside batches for per-boot counter calibration.
        batch_specs = dict(selected)
        if "selfcheck.noop" in suite.cases and "selfcheck.noop" not in batch_specs and not only_selfcheck:
            batch_specs = {"selfcheck.noop": suite.cases["selfcheck.noop"], **batch_specs}

        schedule = schedule_rounds(targets, rounds, seed)
        for round_idx, order in enumerate(schedule, start=1):
            for target in order:
                recs, runs = _run_target_batch(
                    target=target,
                    round_idx=round_idx,
                    specs=batch_specs,
                    linux_bzimage=linux_bzimage,
                    linux_profile=args.linux_profile,
                    aster_bzimage=Path(args.aster_bzimage),
                    host_base_initrd=host_initrd,
                    payload_cpio=payload_cpio,
                    grant_mb=suite.defaults.grant_mb,
                    vcpus=suite.defaults.vcpus,
                    timeout_sec=suite.defaults.timeout_sec,
                    log_dir=out_dir / "logs",
                    audit_mode=audit_mode,
                )
                all_records.extend(recs)
                all_vm_runs.extend(runs)

                invalid_here = [r for r in recs if not r.valid]
                if invalid_here:
                    for rec in invalid_here:
                        print(
                            f"INVALID [{rec.target} R{rec.round_idx} {rec.case_id}]: "
                            + "; ".join(rec.invalid_reasons),
                            file=sys.stderr,
                        )
                    return _abort_with_diagnostics(
                        f"aborted at R{round_idx} {target} due to invalid record",
                        all_records,
                        selected,
                        rounds,
                    )
    except BatchExecutionError as exc:
        all_vm_runs.extend(exc.vm_runs)
        if sc_records and not all_records:
            sc_records.extend(exc.records)
            return _abort_with_diagnostics(str(exc), sc_records, selected, rounds)
        all_records.extend(exc.records)
        return _abort_with_diagnostics(str(exc), all_records, selected, rounds)
    except Exception as exc:
        return _abort_with_diagnostics(str(exc), all_records or sc_records, selected, rounds)

    if not all_records:
        print("ERROR: zero benchmark records produced", file=sys.stderr)
        return 1

    write_records_jsonl(all_records, out_dir / "records.jsonl")
    write_vm_runs_jsonl(all_vm_runs, out_dir / "vm_runs.jsonl")
    md = render_markdown_report(
        selected,
        all_records,
        targets,
        title=f"Kernelet Eval ({run_id})",
        expected_rounds=rounds,
    )
    csv_text = render_csv_report(
        selected, all_records, targets, expected_rounds=rounds
    )
    cal_csv = render_calibrated_stats_csv(selected, all_records)
    (out_dir / "report.md").write_text(md, encoding="utf-8")
    (out_dir / "report.csv").write_text(csv_text, encoding="utf-8")
    (out_dir / "stats_calibrated.csv").write_text(cal_csv, encoding="utf-8")

    print(f"Run complete: {out_dir}")
    print(md)
    return 0


def _parse_section_bases(items: list[str]) -> dict[str, int]:
    bases: dict[str, int] = {}
    for item in items:
        if "=" not in item:
            raise ValueError(f"expected SECTION=HEXADDR, got {item!r}")
        sec, addr = item.split("=", 1)
        bases[sec.strip()] = int(addr.strip(), 16)
    return bases


def cmd_perf_sym(args: argparse.Namespace) -> int:
    sec_bases = _parse_section_bases(args.ko_section)
    text = synthesize_guest_kallsyms(
        vmlinux_system_map=Path(args.system_map),
        vmlinux_live_stext=int(args.live_stext, 16) if args.live_stext else None,
        require_nokaslr=args.require_nokaslr,
        endovisor_ko=Path(args.ko) if args.ko else None,
        endovisor_section_bases=sec_bases,
        kernelet_image=Path(args.kernelet_image) if args.kernelet_image else None,
        kernelet_load_base=int(args.kernelet_base, 16) if args.kernelet_base else None,
        strict_exec_sections=not args.allow_missing_sections,
    )
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(text, encoding="utf-8")
    print(f"Wrote combined guestkallsyms to {out_path}")
    return 0


def cmd_profile(args: argparse.Namespace) -> int:
    perf_bin = shutil.which("perf")
    if not perf_bin:
        print(
            "ERROR: host 'perf' tool is not installed on PATH; cannot run 'perf kvm'",
            file=sys.stderr,
        )
        return 1
    out_kallsyms = Path(args.kallsyms_out)
    sec_bases = _parse_section_bases(args.ko_section)
    text = synthesize_guest_kallsyms(
        vmlinux_system_map=Path(args.system_map),
        vmlinux_live_stext=int(args.live_stext, 16) if args.live_stext else None,
        require_nokaslr=args.require_nokaslr,
        endovisor_ko=Path(args.ko) if args.ko else None,
        endovisor_section_bases=sec_bases,
        kernelet_image=Path(args.kernelet_image) if args.kernelet_image else None,
        kernelet_load_base=int(args.kernelet_base, 16) if args.kernelet_base else None,
        strict_exec_sections=not args.allow_missing_sections,
    )
    out_kallsyms.parent.mkdir(parents=True, exist_ok=True)
    out_kallsyms.write_text(text, encoding="utf-8")
    cmd = [
        perf_bin,
        "kvm",
        f"--guestkallsyms={out_kallsyms}",
        "record",
        "-F",
        str(args.freq),
        "-g",
        "-p",
        str(args.pid),
        "-o",
        str(args.perf_data),
        "--",
        "sleep",
        str(args.duration),
    ]
    return subprocess.call(cmd)


def cmd_profile_case(args: argparse.Namespace) -> int:
    perf_bin = shutil.which("perf")
    if not perf_bin:
        print(
            "ERROR: host 'perf' tool is not installed on PATH; cannot run 'perf kvm'",
            file=sys.stderr,
        )
        return 1

    cases_path = Path(args.cases)
    suite = load_cases_toml(cases_path)
    if args.case not in suite.cases:
        raise ValueError(f"unknown case {args.case!r}")
    spec = suite.cases[args.case]
    if spec.auto_skip_reason:
        raise ValueError(f"cannot profile skipped case {args.case!r}: {spec.auto_skip_reason}")

    resolved = _resolve_profile_paths(args)
    verify_build_freshness(REPO_ROOT, BUILD_DIR, require_pti=(args.linux_profile == "perf-pti"))
    linux_config = resolved["linux_config"]
    linux_bzimage = resolved["linux_bzimage"]
    host_initrd = resolved["host_initrd"]
    system_map = resolved["system_map"]
    ko_path = resolved["ko"]

    cfg_errors = check_kernel_config(linux_config, profile=args.linux_profile)
    if cfg_errors:
        raise RuntimeError("kernel config guard failed: " + "; ".join(cfg_errors))

    target = args.target
    if target not in ("K", "K_vma"):
        raise ValueError("profile-case currently supports K or K_vma")
    pt_mode = "vma" if target == "K_vma" else "direct"

    run_id = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S") + f"-prof-{args.case}"
    out_dir = Path(args.results_dir) / run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    kallsyms_path = out_dir / "guest.kallsyms"
    perf_data_path = out_dir / "perf.data"
    batch_text = format_batch_manifest([spec])
    perf_holder: list[subprocess.Popen[bytes]] = []
    live_addrs_holder: list[LiveProfileAddresses] = []

    def _on_profile_ready(
        _qemu_pid: int,
        vcpu_tids: dict[int, int],
        addrs: LiveProfileAddresses,
    ) -> subprocess.Popen[bytes]:
        live_addrs_holder.append(addrs)
        ks_text = synthesize_guest_kallsyms(
            vmlinux_system_map=system_map,
            vmlinux_live_stext=addrs.vmlinux_stext,
            require_nokaslr=True,
            endovisor_ko=ko_path,
            endovisor_section_bases=addrs.module_sections,
            kernelet_image=Path(args.kernelet_image),
            kernelet_load_base=addrs.kernelet_load_base,
            strict_exec_sections=True,
        )
        kallsyms_path.write_text(ks_text, encoding="utf-8")
        tid_csv = ",".join(str(t) for _, t in sorted(vcpu_tids.items()))
        p = subprocess.Popen(
            [
                perf_bin,
                "kvm",
                f"--guestkallsyms={kallsyms_path}",
                "record",
                "-F",
                str(args.freq),
                "-g",
                "-t",
                tid_csv,
                "-o",
                str(perf_data_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        perf_holder.append(p)
        return p

    TMP_ROOT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="eval-prof-", dir=str(TMP_ROOT)) as tmpdir:
        initrd = Path(tmpdir) / "host-initrd.cpio.gz"
        _build_host_initrd(host_initrd, Path(args.payload), batch_text, initrd)
        mit_arg = _linux_mitigation_cmdline(args.linux_profile)
        cmdline = (
            f"console=ttyS0 panic=-1 nokaslr transparent_hugepage=never {mit_arg} "
            f"eval_role=K eval_pt_mode={pt_mode} eval_profile=1 "
            f"eval_prof_wait=1 eval_prof_hz={args.freq} "
            f"eval_vcpus={suite.defaults.vcpus} eval_grant_mb={suite.defaults.grant_mb}"
        )
        try:
            boot = run_qemu_with_pinning(
                kernel_path=linux_bzimage,
                initrd_path=initrd,
                cmdline=cmdline,
                vcpus=suite.defaults.vcpus,
                mem_mb=2048,
                timeout_sec=max(suite.defaults.timeout_sec, 120),
                isa_debug_exit=False,
                expected_qemu_rcs=(0,),
                temp_root=TMP_ROOT,
                log_dir=out_dir / "logs",
                log_prefix=f"prof_{target}_{args.case}",
                on_profile_addrs=_on_profile_ready,
                send_go_after_prof_ready=True,
            )
        except QemuRunError as exc:
            write_vm_runs_jsonl(
                [
                    _make_vm_run_record(
                        round_idx=0,
                        target=target,
                        case_ids=[args.case],
                        kernel_path=linux_bzimage,
                        initrd_path=host_initrd,
                        cmdline=cmdline,
                        boot=exc.partial_result,
                    )
                ],
                out_dir / "vm_runs.jsonl",
            )
            (out_dir / "error.txt").write_text(str(exc) + "\n", encoding="utf-8")
            raise

    write_vm_runs_jsonl(
        [
            _make_vm_run_record(
                round_idx=0,
                target=target,
                case_ids=[args.case],
                kernel_path=linux_bzimage,
                initrd_path=host_initrd,
                cmdline=cmdline,
                boot=boot,
            )
        ],
        out_dir / "vm_runs.jsonl",
    )

    if not perf_holder or not live_addrs_holder:
        raise RuntimeError("profile-case did not observe synchronized profile address handshake")
    perf_proc = perf_holder[-1]
    perf_out, perf_err = perf_proc.communicate()
    (out_dir / "perf.record.stderr.log").write_bytes(perf_err or b"")
    if perf_proc.returncode not in (0, -2):  # 0 or SIGINT clean stop
        err_tail = (perf_err or b"").decode("utf-8", errors="replace")
        raise RuntimeError(f"perf kvm record failed (rc={perf_proc.returncode}): {err_tail}")
    if "INIT: done" not in boot.serial_log:
        raise RuntimeError("profile-case guest did not reach 'INIT: done'")

    recs = parse_serial_records(
        boot.serial_log, round_idx=0, target=target, specs={args.case: spec}, require_complete=True
    )
    ok, reasons = validate_case_record(spec, recs[0], kernel_log=boot.serial_log)
    if not ok:
        raise RuntimeError(f"profiled case {args.case} failed invariants: " + "; ".join(reasons))

    if not perf_data_path.exists() or perf_data_path.stat().st_size == 0:
        raise RuntimeError(f"perf.data missing or empty: {perf_data_path}")

    script_text = subprocess.check_output(
        [perf_bin, "kvm", f"--guestkallsyms={kallsyms_path}", "script", "-i", str(perf_data_path)],
        text=True,
    )
    (out_dir / "perf.script.txt").write_text(script_text, encoding="utf-8")
    ks_text = kallsyms_path.read_text(encoding="utf-8")
    folded, layer_counts, self_counts = parse_perf_script_stacks(script_text, ks_text)

    guest_folded_lines = extract_guest_folded_profile(boot.serial_log)
    if guest_folded_lines:
        (out_dir / "guest_profile.folded").write_text(
            "\n".join(guest_folded_lines) + "\n", encoding="utf-8"
        )
        g_folded, g_layers, g_self = symbolize_folded_addr_stacks(guest_folded_lines, ks_text)
        (out_dir / "guest_profile_summary.md").write_text(
            render_profile_report_markdown(
                g_layers,
                g_self,
                title=f"Isolated In-Sandbox Callchain Breakdown ({args.case}, {target})",
            ),
            encoding="utf-8",
        )
        (out_dir / "guest_flamegraph.svg").write_text(
            render_flamegraph_svg(g_folded, title=f"{args.case} ({target}, in-sandbox)"),
            encoding="utf-8",
        )
    else:
        g_layers = {}

    if sum(layer_counts.values()) <= 0 and sum(g_layers.values()) <= 0:
        raise RuntimeError(f"profile-case collected 0 samples (both host perf kvm and guest sampler empty)")

    report_md = render_profile_report_markdown(
        layer_counts,
        self_counts,
        title=f"Profile Breakdown ({args.case}, {target})",
    )
    svg = render_flamegraph_svg(folded, title=f"{args.case} ({target})")
    (out_dir / "profile_summary.md").write_text(report_md, encoding="utf-8")
    (out_dir / "flamegraph.svg").write_text(svg, encoding="utf-8")
    print(f"Profile artifacts written to {out_dir}")
    print(report_md)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="kernelet-eval")
    sub = p.add_subparsers(dest="cmd", required=True)

    ck = sub.add_parser("check-config", help="Validate Linux .config against perf guard")
    ck.add_argument("--config", required=True)
    ck.add_argument("--profile", choices=["perf-base", "perf-pti"], default="perf-base")
    ck.set_defaults(func=cmd_check_config)

    wm = sub.add_parser("write-build-manifest", help="Record source & artifact SHA-256 build manifest")
    wm.add_argument("--build-dir", default=str(BUILD_DIR))
    wm.set_defaults(func=cmd_write_build_manifest)

    cf = sub.add_parser("check-freshness", help="Verify built artifacts match current sources/patches/configs")
    cf.add_argument("--build-dir", default=str(BUILD_DIR))
    cf.add_argument("--pti", action="store_true")
    cf.set_defaults(func=cmd_check_freshness)

    ch = sub.add_parser("component-hash", help="Compute input+toolchain SHA-256 for one build component")
    ch.add_argument("--build-dir", default=str(BUILD_DIR))
    ch.add_argument("--component", required=True)
    ch.add_argument("--payload-mode", default="native", choices=["native", "nix", "auto"])
    ch.set_defaults(func=cmd_component_hash)

    wr = sub.add_parser("write-receipt", help="Write per-component build receipt JSON")
    wr.add_argument("--build-dir", default=str(BUILD_DIR))
    wr.add_argument("--component", required=True)
    wr.add_argument("--input-sha", required=True)
    wr.add_argument("--toolchain", required=True)
    wr.add_argument("--output", action="append", default=[])
    wr.set_defaults(func=cmd_write_receipt)

    sm = sub.add_parser("synthesize-build-manifest", help="Synthesize build-inputs.json iff all component receipts are current")
    sm.add_argument("--build-dir", default=str(BUILD_DIR))
    sm.add_argument("--pti", action="store_true")
    sm.add_argument("--if-complete", action="store_true")
    sm.set_defaults(func=cmd_synthesize_build_manifest)

    rn = sub.add_parser("run", help="Run shuffled multi-round evaluation across L/A/K")
    rn.add_argument("--cases", default=str(EVAL_DIR / "configs" / "cases.toml"))
    rn.add_argument("--targets", default="L,A,K,K_vma")
    rn.add_argument("--rounds", type=int, default=0)
    rn.add_argument("--seed", type=int, default=0)
    rn.add_argument("--group", action="append", default=[])
    rn.add_argument("--case", action="append", default=[])
    rn.add_argument("--tag", default="eval")
    rn.add_argument("--audit", action="store_true", help="Enable endovisor audit counters in separate audit run")
    rn.add_argument("--results-dir", default=str(REPO_ROOT / "research" / "evaluation-plan" / "results"))
    rn.add_argument("--linux-bzimage", default=str(BUILD_DIR / "linux-perf-base" / "arch" / "x86" / "boot" / "bzImage"))
    rn.add_argument("--linux-config", default=str(BUILD_DIR / "linux-perf-base" / ".config"))
    rn.add_argument("--linux-profile", choices=["perf-base", "perf-pti"], default="perf-base")
    rn.add_argument("--aster-bzimage", default=str(BUILD_DIR / "asterinas-native.bzImage"))
    rn.add_argument("--host-initrd", default=str(BUILD_DIR / "host-eval-initramfs.cpio.gz"))
    rn.add_argument("--payload", default=str(BUILD_DIR / "eval-payload.cpio"))
    rn.set_defaults(func=cmd_run)

    ps = sub.add_parser("perf-sym", help="Synthesize combined guestkallsyms for perf kvm")
    ps.add_argument("--system-map", required=True)
    ps.add_argument("--live-stext", help="Live guest _stext hex address for KASLR verification/slide")
    ps.add_argument("--require-nokaslr", action="store_true")
    ps.add_argument("--ko")
    ps.add_argument("--ko-section", action="append", default=[], help="SECTION=HEXADDR (e.g. .text=0xffffffffc0000000)")
    ps.add_argument("--allow-missing-sections", action="store_true")
    ps.add_argument("--kernelet-image")
    ps.add_argument("--kernelet-base")
    ps.add_argument("--out", required=True)
    ps.set_defaults(func=cmd_perf_sym)

    pf = sub.add_parser("profile", help="Synthesize guestkallsyms and run host perf kvm record on a live PID")
    pf.add_argument("--system-map", required=True)
    pf.add_argument("--live-stext")
    pf.add_argument("--require-nokaslr", action="store_true")
    pf.add_argument("--ko")
    pf.add_argument("--ko-section", action="append", default=[])
    pf.add_argument("--allow-missing-sections", action="store_true")
    pf.add_argument("--kernelet-image")
    pf.add_argument("--kernelet-base")
    pf.add_argument("--kallsyms-out", default=str(BUILD_DIR / "guest.kallsyms"))
    pf.add_argument("--perf-data", default=str(BUILD_DIR / "perf.data"))
    pf.add_argument("--pid", type=int, required=True)
    pf.add_argument("--freq", type=int, default=999)
    pf.add_argument("--duration", type=int, default=10)
    pf.set_defaults(func=cmd_profile)

    pc = sub.add_parser("profile-case", help="Run an isolated nokaslr profiling round for one case and emit report + flamegraph")
    pc.add_argument("--cases", default=str(EVAL_DIR / "configs" / "cases.toml"))
    pc.add_argument("--case", required=True)
    pc.add_argument("--target", default="K", choices=["K", "K_vma"])
    pc.add_argument("--freq", type=int, default=999)
    pc.add_argument("--results-dir", default=str(REPO_ROOT / "research" / "evaluation-plan" / "results"))
    pc.add_argument("--linux-bzimage", default=str(BUILD_DIR / "linux-perf-base" / "arch" / "x86" / "boot" / "bzImage"))
    pc.add_argument("--linux-config", default=str(BUILD_DIR / "linux-perf-base" / ".config"))
    pc.add_argument("--linux-profile", choices=["perf-base", "perf-pti"], default="perf-base")
    pc.add_argument("--system-map", default=str(BUILD_DIR / "linux-perf-base" / "System.map"))
    pc.add_argument("--ko", default=str(BUILD_DIR / "endovisor.ko"))
    pc.add_argument("--kernelet-image", default=str(BUILD_DIR / "kernelet-image.elf"))
    pc.add_argument("--host-initrd", default=str(BUILD_DIR / "host-eval-initramfs.cpio.gz"))
    pc.add_argument("--payload", default=str(BUILD_DIR / "eval-payload.cpio"))
    pc.set_defaults(func=cmd_profile_case)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
