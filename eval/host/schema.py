"""Data structures and declarative TOML loader for poc/eval."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
import tomllib
from typing import Any


@dataclass(frozen=True)
class TmpFileSpec:
    path: str
    size_mb: int


@dataclass(frozen=True)
class CopyFileSpec:
    src: str
    dst: str


@dataclass(frozen=True)
class InvariantSpec:
    min_minor_faults: int = 0
    max_timing_faults: int | None = None
    timing_stage_index: int | None = None
    min_timing_stage_faults: int | None = None
    forbid_migration: bool = True
    forbid_thp: bool = True
    max_vdso_syscalls: int | None = None
    max_fpu_saves: int | None = None
    max_non_sysret: int | None = None
    require_vm_balance: bool = False


@dataclass(frozen=True)
class CaseSpec:
    case_id: str
    group: str
    suite: str
    binary: str
    args: tuple[str, ...]
    cpus: tuple[int, ...]
    tmpfiles: tuple[TmpFileSpec, ...]
    parser: str
    unit: str
    higher_is_better: bool
    invariants: InvariantSpec
    copy_files: tuple[CopyFileSpec, ...] = ()
    verify_exec: str | None = None
    auto_skip_reason: str | None = None


@dataclass(frozen=True)
class SuiteDefaults:
    grant_mb: int = 512
    vcpus: int = 2
    rounds: int = 5
    seed: int = 20261116
    timeout_sec: int = 120


@dataclass(frozen=True)
class SuiteConfig:
    defaults: SuiteDefaults
    cases: dict[str, CaseSpec]


def _strict_int(val: Any, name: str) -> int:
    if isinstance(val, bool) or not isinstance(val, int):
        raise ValueError(f"{name} must be an integer, got {val!r}")
    return val


@dataclass(frozen=True)
class SandboxStats:
    pt_mode: int
    vcpus: int
    grant_mb: int
    exit_kind: int
    exit_code: int
    exit_msg: str
    fpu_saves: int
    fpu_restores: int
    vm_creates: int
    vm_destroys: int
    vm_flushes: int
    vm_maps: int
    vm_protects: int
    vm_unmaps: int
    exceptions: int
    page_faults: int
    virqs: int
    forced_yields: int
    non_sysret: int | None = None
    bench_vm_apply_cycles: int = 0
    syscalls: int | None = None
    image_load_base: str | None = None
    grant_grains_allocated: int | None = None
    grant_grains_freed: int | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SandboxStats:
        if not isinstance(data, dict):
            raise ValueError("STATS_JSON payload must be a JSON object")
        required = (
            "pt_mode",
            "vcpus",
            "grant_mb",
            "exit_kind",
            "exit_code",
            "fpu_saves",
            "fpu_restores",
            "vm_creates",
            "vm_destroys",
            "vm_flushes",
            "vm_maps",
            "vm_protects",
            "vm_unmaps",
            "exceptions",
            "page_faults",
            "virqs",
            "forced_yields",
        )
        for key in required:
            if key not in data:
                raise ValueError(f"STATS_JSON missing required field {key!r}")
        exit_msg = data.get("exit_msg", "")
        if not isinstance(exit_msg, str):
            raise ValueError(f"exit_msg must be a string, got {exit_msg!r}")
        image_load_base = data.get("image_load_base")
        if image_load_base is not None and not isinstance(image_load_base, str):
            raise ValueError(f"image_load_base must be a string, got {image_load_base!r}")
        return cls(
            pt_mode=_strict_int(data["pt_mode"], "pt_mode"),
            vcpus=_strict_int(data["vcpus"], "vcpus"),
            grant_mb=_strict_int(data["grant_mb"], "grant_mb"),
            exit_kind=_strict_int(data["exit_kind"], "exit_kind"),
            exit_code=_strict_int(data["exit_code"], "exit_code"),
            exit_msg=exit_msg,
            fpu_saves=_strict_int(data["fpu_saves"], "fpu_saves"),
            fpu_restores=_strict_int(data["fpu_restores"], "fpu_restores"),
            vm_creates=_strict_int(data["vm_creates"], "vm_creates"),
            vm_destroys=_strict_int(data["vm_destroys"], "vm_destroys"),
            vm_flushes=_strict_int(data["vm_flushes"], "vm_flushes"),
            vm_maps=_strict_int(data["vm_maps"], "vm_maps"),
            vm_protects=_strict_int(data["vm_protects"], "vm_protects"),
            vm_unmaps=_strict_int(data["vm_unmaps"], "vm_unmaps"),
            exceptions=_strict_int(data["exceptions"], "exceptions"),
            page_faults=_strict_int(data["page_faults"], "page_faults"),
            virqs=_strict_int(data["virqs"], "virqs"),
            forced_yields=_strict_int(data["forced_yields"], "forced_yields"),
            non_sysret=(
                _strict_int(data["non_sysret"], "non_sysret")
                if "non_sysret" in data else None
            ),
            bench_vm_apply_cycles=_strict_int(
                data.get("bench_vm_apply_cycles", 0), "bench_vm_apply_cycles"
            ),
            syscalls=(
                _strict_int(data["syscalls"], "syscalls")
                if "syscalls" in data else None
            ),
            image_load_base=image_load_base,
            grant_grains_allocated=(
                _strict_int(data["grant_grains_allocated"], "grant_grains_allocated")
                if "grant_grains_allocated" in data else None
            ),
            grant_grains_freed=(
                _strict_int(data["grant_grains_freed"], "grant_grains_freed")
                if "grant_grains_freed" in data else None
            ),
        )


@dataclass(frozen=True)
class TimingStage:
    valid: bool
    intervals: int
    minflt: int
    majflt: int


@dataclass(frozen=True)
class HostCaseMeta:
    case_id: str
    host_thp_obs_ok: bool
    host_thp_policy: str | None
    host_thp_fault_alloc_delta: int | None
    grant_accounting_ok: bool
    live_sandboxes: int
    live_grant_grains: int
    live_meta_pages: int
    live_kstack_pages: int
    live_shared_pages: int

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HostCaseMeta:
        if not isinstance(data, dict):
            raise ValueError("HOST_CASE_META payload must be a JSON object")
        for key in (
            "case_id",
            "host_thp_obs_ok",
            "grant_accounting_ok",
            "live_sandboxes",
            "live_grant_grains",
            "live_meta_pages",
            "live_kstack_pages",
            "live_shared_pages",
        ):
            if key not in data:
                raise ValueError(f"HOST_CASE_META missing required field {key!r}")
        thp_delta = data.get("host_thp_fault_alloc_delta")
        if thp_delta is not None:
            thp_delta = _strict_int(thp_delta, "host_thp_fault_alloc_delta")
        pol = data.get("host_thp_policy")
        if pol is not None and not isinstance(pol, str):
            raise ValueError(f"host_thp_policy must be string or null, got {pol!r}")
        return cls(
            case_id=str(data["case_id"]),
            host_thp_obs_ok=bool(data["host_thp_obs_ok"]),
            host_thp_policy=pol,
            host_thp_fault_alloc_delta=thp_delta,
            grant_accounting_ok=bool(data["grant_accounting_ok"]),
            live_sandboxes=_strict_int(data["live_sandboxes"], "live_sandboxes"),
            live_grant_grains=_strict_int(data["live_grant_grains"], "live_grant_grains"),
            live_meta_pages=_strict_int(data["live_meta_pages"], "live_meta_pages"),
            live_kstack_pages=_strict_int(data["live_kstack_pages"], "live_kstack_pages"),
            live_shared_pages=_strict_int(data["live_shared_pages"], "live_shared_pages"),
        )


@dataclass
class CaseRecord:
    round_idx: int
    target: str
    case_id: str
    rc: int
    wall_ns: int
    minflt_delta: int
    majflt_delta: int
    ru_utime_us: int
    ru_stime_us: int
    cpu_start: int
    cpu_end: int
    migrated: bool
    thp_fault_alloc_delta: int | None
    stdout: str
    stderr: str
    value: float | None = None
    unit: str = ""
    valid: bool = False
    invalid_reasons: list[str] = field(default_factory=list)
    sandbox_stats: SandboxStats | None = None
    skipped: bool = False
    skip_reason: str = ""
    cpu_obs_ok: bool = True
    timing_minflt_delta: int | None = None
    timing_majflt_delta: int | None = None
    thp_obs_ok: bool = True
    thp_policy: str | None = None
    timing_stages: list[TimingStage] = field(default_factory=list)
    host_meta: HostCaseMeta | None = None
    audit_mode: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class VmRunRecord:
    round_idx: int
    target: str
    case_ids: list[str]
    cmd: list[str]
    kernel_path: str
    initrd_path: str
    cmdline: str
    vcpu_tids: dict[int, int]
    pinned_vcpu_map: dict[int, int]
    pinned_io_cpu: int
    qemu_rc: int
    serial_log_path: str
    stderr_log_path: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RunManifest:
    run_id: str
    created_utc: str
    git_commit: str
    git_dirty: bool
    poc_git_commit: str
    poc_git_dirty: bool
    targets: list[str]
    rounds: int
    seed: int
    payload_sha256: str
    artifacts_sha256: dict[str, str]
    embedded_artifacts_sha256: dict[str, str]
    kernel_config_checks: dict[str, list[str]]
    host_cpu_model: str
    host_cpu_count: int
    host_governors: list[str]
    host_cpu_topology: list[dict[str, Any]]
    cases_sha256: str = ""
    sources_sha256: dict[str, str] = field(default_factory=dict)
    build_inputs_verified: bool = False
    source_snapshot_file: str = ""
    untracked_files: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_cases_toml(path: Path) -> SuiteConfig:
    """Load and validate declarative benchmark definitions from cases.toml."""
    raw = tomllib.loads(path.read_text(encoding="utf-8"))
    raw_defaults = raw.get("defaults", {})
    defaults = SuiteDefaults(
        grant_mb=int(raw_defaults.get("grant_mb", 512)),
        vcpus=int(raw_defaults.get("vcpus", 2)),
        rounds=int(raw_defaults.get("rounds", 5)),
        seed=int(raw_defaults.get("seed", 20261116)),
        timeout_sec=int(raw_defaults.get("timeout_sec", 120)),
    )

    raw_cases = raw.get("cases", {})
    if not isinstance(raw_cases, dict) or not raw_cases:
        raise ValueError(f"{path}: missing or empty [cases] table")

    cases: dict[str, CaseSpec] = {}
    for case_id, entry in raw_cases.items():
        if not isinstance(entry, dict):
            raise ValueError(f"{path}: case {case_id!r} must be a table")
        tmpfiles = tuple(
            TmpFileSpec(path=str(item["path"]), size_mb=int(item["size_mb"]))
            for item in entry.get("tmpfiles", [])
        )
        copy_files = tuple(
            CopyFileSpec(src=str(item["src"]), dst=str(item["dst"]))
            for item in entry.get("copy_files", [])
        )
        raw_inv = entry.get("invariants", {})
        invariants = InvariantSpec(
            min_minor_faults=int(raw_inv.get("min_minor_faults", 0)),
            max_timing_faults=(
                int(raw_inv["max_timing_faults"])
                if "max_timing_faults" in raw_inv
                else None
            ),
            timing_stage_index=(
                int(raw_inv["timing_stage_index"])
                if "timing_stage_index" in raw_inv
                else None
            ),
            min_timing_stage_faults=(
                int(raw_inv["min_timing_stage_faults"])
                if "min_timing_stage_faults" in raw_inv
                else None
            ),
            forbid_migration=bool(raw_inv.get("forbid_migration", True)),
            forbid_thp=bool(raw_inv.get("forbid_thp", True)),
            max_vdso_syscalls=(
                int(raw_inv["max_vdso_syscalls"])
                if "max_vdso_syscalls" in raw_inv
                else None
            ),
            max_fpu_saves=(
                int(raw_inv["max_fpu_saves"])
                if "max_fpu_saves" in raw_inv
                else None
            ),
            max_non_sysret=(
                int(raw_inv["max_non_sysret"])
                if "max_non_sysret" in raw_inv
                else None
            ),
            require_vm_balance=bool(raw_inv.get("require_vm_balance", False)),
        )
        cpus = tuple(int(c) for c in entry.get("cpus", [0]))
        if not cpus:
            raise ValueError(f"{path}: case {case_id!r} must specify at least one CPU")
        cases[case_id] = CaseSpec(
            case_id=case_id,
            group=str(entry["group"]),
            suite=str(entry["suite"]),
            binary=str(entry["binary"]),
            args=tuple(str(a) for a in entry.get("args", [])),
            cpus=cpus,
            tmpfiles=tmpfiles,
            parser=str(entry["parser"]),
            unit=str(entry["unit"]),
            higher_is_better=bool(entry["higher_is_better"]),
            invariants=invariants,
            copy_files=copy_files,
            verify_exec=str(entry["verify_exec"]) if "verify_exec" in entry else None,
            auto_skip_reason=(
                str(entry["auto_skip_reason"]) if "auto_skip_reason" in entry else None
            ),
        )

    return SuiteConfig(defaults=defaults, cases=cases)
