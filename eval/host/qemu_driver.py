"""QEMU/KVM lifecycle, QMP paused-start physical-core pinning, and serial JSONL capture."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import gzip
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import threading
import time
from typing import Callable, Iterable

from .parsers import parse_case_output
from .schema import CaseRecord, CaseSpec, HostCaseMeta, SandboxStats, TimingStage


EVAL_CASE_PREFIX = "EVAL_CASE_JSON "
STATS_PREFIX = "STATS_JSON "
HOST_META_PREFIX = "HOST_CASE_META "


def discover_distinct_physical_cores(
    needed: int,
    *,
    allowed_cpus: set[int] | None = None,
) -> list[int]:
    """Select `needed` CPUs within allowed affinity belonging to distinct physical cores."""
    if allowed_cpus is None:
        allowed_cpus = set(os.sched_getaffinity(0))

    sys_cpu = Path("/sys/devices/system/cpu")
    seen_groups: set[tuple[int, ...]] = set()
    chosen: list[int] = []

    cpu_dirs = sorted(
        (p for p in sys_cpu.glob("cpu[0-9]*") if p.name[3:].isdigit()),
        key=lambda p: int(p.name[3:]),
    )
    for cpu_dir in cpu_dirs:
        cpu_id = int(cpu_dir.name[3:])
        if cpu_id not in allowed_cpus:
            continue
        online_file = cpu_dir / "online"
        if online_file.exists() and online_file.read_text().strip() == "0":
            continue
        sib_file = cpu_dir / "topology" / "thread_siblings_list"
        if sib_file.exists():
            group = _parse_cpulist(sib_file.read_text().strip())
        else:
            group = (cpu_id,)
        if group in seen_groups:
            continue
        seen_groups.add(group)
        chosen.append(cpu_id)
        if len(chosen) >= needed:
            return chosen

    raise RuntimeError(
        f"need {needed} distinct physical cores within allowed CPUs {sorted(allowed_cpus)}, "
        f"only found {len(chosen)}: {chosen}"
    )


def _parse_cpulist(spec: str) -> tuple[int, ...]:
    cpus: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            cpus.extend(range(int(lo), int(hi) + 1))
        else:
            cpus.append(int(part))
    return tuple(sorted(set(cpus)))


class QmpClient:
    """Minimal synchronous QMP client over a Unix domain socket."""

    def __init__(
        self,
        sock_path: Path,
        timeout_sec: float = 10.0,
        proc: subprocess.Popen[bytes] | None = None,
    ) -> None:
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.settimeout(timeout_sec)
        deadline = time.monotonic() + timeout_sec
        while True:
            if proc is not None and proc.poll() is not None:
                self._sock.close()
                out, err = proc.communicate()
                msg = err.decode("utf-8", errors="replace").strip() or out.decode("utf-8", errors="replace").strip()
                raise RuntimeError(
                    f"QEMU exited before QMP ready (rc={proc.returncode}): {msg}"
                )
            try:
                self._sock.connect(str(sock_path))
                break
            except (FileNotFoundError, ConnectionRefusedError):
                if time.monotonic() >= deadline:
                    self._sock.close()
                    raise
                time.sleep(0.05)
        self._fp = self._sock.makefile("r", encoding="utf-8")
        greeting = self._read_msg()
        if "QMP" not in greeting:
            raise RuntimeError(f"unexpected QMP greeting: {greeting!r}")
        self.command("qmp_capabilities")

    def _read_msg(self) -> dict:
        while True:
            line = self._fp.readline()
            if not line:
                raise RuntimeError("QMP socket closed unexpectedly")
            msg = json.loads(line)
            if "event" in msg:
                continue
            return msg

    def command(self, execute: str, arguments: dict | None = None) -> dict:
        req: dict[str, object] = {"execute": execute}
        if arguments is not None:
            req["arguments"] = arguments
        self._sock.sendall((json.dumps(req) + "\n").encode("utf-8"))
        resp = self._read_msg()
        if "error" in resp:
            raise RuntimeError(f"QMP command {execute} failed: {resp['error']}")
        return resp.get("return", {})

    def close(self) -> None:
        try:
            self._fp.close()
        finally:
            self._sock.close()


def _cpio_newc_file_entry(name: str, data: bytes, mode: int = 0o100644) -> bytes:
    """Encode a single regular file entry in SVR4 newc CPIO format."""
    name_bytes = name.lstrip("/").encode("utf-8") + b"\x00"
    header = (
        f"070701"
        f"{1:08x}"
        f"{mode:08x}"
        f"{0:08x}"
        f"{0:08x}"
        f"{1:08x}"
        f"{0:08x}"
        f"{len(data):08x}"
        f"{0:08x}"
        f"{0:08x}"
        f"{0:08x}"
        f"{0:08x}"
        f"{len(name_bytes):08x}"
        f"{0:08x}"
    ).encode("ascii")
    out = bytearray(header + name_bytes)
    while len(out) % 4 != 0:
        out.append(0)
    out.extend(data)
    while len(out) % 4 != 0:
        out.append(0)
    return bytes(out)


def _cpio_newc_trailer() -> bytes:
    return _cpio_newc_file_entry("TRAILER!!!", b"", mode=0)


def build_batch_overlay_cpio_gz(
    batch_text: str,
    shared_payload: bytes | None = None,
) -> bytes:
    """Create a compressed initramfs overlay containing /etc/eval-batch.txt and optional payload."""
    parts = [
        _cpio_newc_file_entry("etc/eval-batch.txt", batch_text.encode("utf-8"), mode=0o100644)
    ]
    if shared_payload is not None:
        parts.append(
            _cpio_newc_file_entry("payload/eval-payload.cpio", shared_payload, mode=0o100644)
        )
    parts.append(_cpio_newc_trailer())
    return gzip.compress(b"".join(parts), compresslevel=1)


def format_batch_manifest(cases: Iterable[CaseSpec]) -> str:
    """Format cases as tab-delimited lines for /etc/eval-batch.txt."""
    lines: list[str] = []
    for spec in cases:
        cpus_csv = ",".join(str(c) for c in spec.cpus)
        tmp_csv = ",".join(f"{tf.path}:{tf.size_mb}" for tf in spec.tmpfiles)
        copy_csv = ",".join(f"{cf.src}:{cf.dst}" for cf in spec.copy_files)
        verify_exec = spec.verify_exec or ""
        fields = [
            spec.case_id,
            cpus_csv,
            tmp_csv,
            copy_csv,
            verify_exec,
            spec.binary,
            *spec.args,
        ]
        lines.append("\t".join(fields))
    return "\n".join(lines) + "\n"


def format_guest_runner_args(spec: CaseSpec) -> list[str]:
    """Build argv for /bin/eval_guest_runner for a single case."""
    args = [
        "/bin/eval_guest_runner",
        "--case-id",
        spec.case_id,
        "--cpus",
        ",".join(str(c) for c in spec.cpus),
    ]
    for tf in spec.tmpfiles:
        args.extend(["--tmpfile", f"{tf.path}:{tf.size_mb}"])
    for cf in spec.copy_files:
        args.extend(["--copy-file", f"{cf.src}:{cf.dst}"])
    if spec.verify_exec:
        args.extend(["--verify-exec", spec.verify_exec])
    args.append("--")
    args.append(spec.binary)
    args.extend(spec.args)
    return args


@dataclass(frozen=True)
class QemuBootResult:
    qemu_rc: int
    serial_log: str
    stderr_log: str
    cmd: list[str]
    vcpu_tids: dict[int, int]
    pinned_vcpu_map: dict[int, int]
    pinned_io_cpu: int
    serial_log_path: str
    stderr_log_path: str


class QemuRunError(RuntimeError):
    """Error raised when QEMU or streaming validation aborts, carrying partial logs and pin info."""

    def __init__(self, message: str, partial_result: QemuBootResult) -> None:
        super().__init__(message)
        self.partial_result = partial_result


def extract_guest_folded_profile(serial_text: str) -> list[str]:
    """Extract lines between EVAL_PROF_FOLDED_BEGIN and EVAL_PROF_FOLDED_END."""
    lines: list[str] = []
    collecting = False
    for raw in serial_text.splitlines():
        s = raw.strip()
        if s == "EVAL_PROF_FOLDED_BEGIN":
            collecting = True
            continue
        if s == "EVAL_PROF_FOLDED_END":
            collecting = False
            continue
        if collecting and s:
            lines.append(s)
    return lines


@dataclass
class LiveProfileAddresses:
    vmlinux_stext: int | None = None
    module_sections: dict[str, int] | None = None
    kernelet_load_base: int | None = None

    def __post_init__(self) -> None:
        if self.module_sections is None:
            self.module_sections = {}


def parse_live_profile_line(line: str, addrs: LiveProfileAddresses) -> bool:
    """Update LiveProfileAddresses from a guest serial line; returns True if ready."""
    s = line.strip()
    if s.startswith("EVAL_PROF_VMLINUX_STEXT "):
        addrs.vmlinux_stext = int(s.split(None, 1)[1], 16)
    elif s.startswith("EVAL_PROF_MOD_SECTION "):
        kv = s.split(None, 1)[1]
        if "=" in kv:
            sec, addr = kv.split("=", 1)
            assert addrs.module_sections is not None
            addrs.module_sections[sec.strip()] = int(addr.strip(), 16)
    elif s.startswith("EVAL_SANDBOX_LOAD_BASE "):
        addrs.kernelet_load_base = int(s.split(None, 1)[1], 16)
        return True
    return False


def run_qemu_with_pinning(
    *,
    kernel_path: Path,
    initrd_path: Path,
    cmdline: str,
    vcpus: int,
    mem_mb: int = 2048,
    machine: str | None = None,
    timeout_sec: int = 180,
    isa_debug_exit: bool = False,
    expected_qemu_rcs: tuple[int, ...] = (0,),
    temp_root: Path | None = None,
    log_dir: Path | None = None,
    log_prefix: str = "vm",
    on_profile_addrs: Callable[[int, dict[int, int], LiveProfileAddresses], subprocess.Popen[bytes] | None] | None = None,
    send_go_after_prof_ready: bool = False,
    on_serial_line: Callable[[str], str | None] | None = None,
) -> QemuBootResult:
    """Boot QEMU paused (-S), pin vCPU and I/O threads to distinct physical cores via QMP, and stream serial."""
    phys_cores = discover_distinct_physical_cores(vcpus + 1)
    vcpu_cores = phys_cores[:vcpus]
    io_core = phys_cores[vcpus]

    if temp_root is not None:
        temp_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="qmp-", dir=str(temp_root) if temp_root is not None else None
    ) as tmpdir:
        tmp = Path(tmpdir)
        qmp_sock = tmp / "qmp.sock"
        cmd = [
            "qemu-system-x86_64",
            "-enable-kvm",
            "-cpu",
            "host",
            "-smp",
            str(vcpus),
            "-m",
            f"{mem_mb}M",
            "-mem-prealloc",
            "-kernel",
            str(kernel_path),
            "-initrd",
            str(initrd_path),
            "-append",
            cmdline,
            "-display",
            "none",
            "-serial",
            "stdio",
            "-monitor",
            "none",
            "-no-reboot",
            "-nic",
            "none",
            "-S",
            "-qmp",
            f"unix:{qmp_sock},server,nowait",
        ]
        if isa_debug_exit:
            cmd.extend(["-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"])
        if machine is not None:
            cmd.extend(["-machine", machine])

        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE if send_go_after_prof_ready else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid,
        )

        pinned_vcpu_map: dict[int, int] = {}
        vcpu_tids: dict[int, int] = {}
        profiler_proc: subprocess.Popen[bytes] | None = None
        stdout_lines: list[bytes] = []
        stderr_chunks: list[bytes] = []
        err_thr: threading.Thread | None = None
        watchdog_timer: threading.Timer | None = None
        timed_out = threading.Event()
        abort_reason: str | None = None

        def _flush_partial_logs() -> tuple[str, str, str, str]:
            serial_text = b"".join(stdout_lines).decode("utf-8", errors="replace")
            stderr_text = b"".join(stderr_chunks).decode("utf-8", errors="replace")
            s_path = ""
            e_path = ""
            if log_dir is not None:
                log_dir.mkdir(parents=True, exist_ok=True)
                sp = log_dir / f"{log_prefix}.serial.log"
                ep = log_dir / f"{log_prefix}.stderr.log"
                sp.write_text(serial_text, encoding="utf-8")
                ep.write_text(stderr_text, encoding="utf-8")
                s_path = str(sp)
                e_path = str(ep)
            return serial_text, stderr_text, s_path, e_path

        def _make_partial(rc_override: int | None = None) -> QemuBootResult:
            st, et, sp, ep = _flush_partial_logs()
            rc_val = rc_override if rc_override is not None else (
                proc.returncode if proc.returncode is not None else -1
            )
            return QemuBootResult(
                qemu_rc=rc_val,
                serial_log=st,
                stderr_log=et,
                cmd=cmd,
                vcpu_tids=dict(vcpu_tids),
                pinned_vcpu_map=dict(pinned_vcpu_map),
                pinned_io_cpu=io_core,
                serial_log_path=sp,
                stderr_log_path=ep,
            )

        def _on_timeout() -> None:
            timed_out.set()
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

        try:
            qmp = QmpClient(qmp_sock, timeout_sec=15.0, proc=proc)
            try:
                cpus_info = qmp.command("query-cpus-fast")
                cpus_by_index = {int(entry["cpu-index"]): entry for entry in cpus_info}
                if set(cpus_by_index) != set(range(vcpus)):
                    raise RuntimeError(
                        f"expected vCPU indices {list(range(vcpus))}, got {sorted(cpus_by_index)}"
                    )
                for idx, cpu_entry in sorted(cpus_by_index.items()):
                    tid = int(cpu_entry["thread-id"])
                    target_core = vcpu_cores[idx]
                    os.sched_setaffinity(tid, {target_core})
                    if os.sched_getaffinity(tid) != {target_core}:
                        raise RuntimeError(
                            f"failed to pin vCPU {idx} (tid={tid}) to core {target_core}"
                        )
                    vcpu_tids[idx] = tid
                    pinned_vcpu_map[idx] = target_core
                os.sched_setaffinity(proc.pid, {io_core})
                if os.sched_getaffinity(proc.pid) != {io_core}:
                    raise RuntimeError(
                        f"failed to pin QEMU I/O pid={proc.pid} to core {io_core}"
                    )
                qmp.command("cont")
            finally:
                qmp.close()

            assert proc.stdout is not None and proc.stderr is not None

            def _drain_err() -> None:
                while True:
                    chunk = proc.stderr.read(4096)
                    if not chunk:
                        break
                    stderr_chunks.append(chunk)

            err_thr = threading.Thread(target=_drain_err, daemon=True)
            err_thr.start()
            watchdog_timer = threading.Timer(float(timeout_sec), _on_timeout)
            watchdog_timer.daemon = True
            watchdog_timer.start()

            addrs = LiveProfileAddresses()
            started_prof = False
            while True:
                raw_line = proc.stdout.readline()
                if not raw_line:
                    break
                stdout_lines.append(raw_line)
                decoded = raw_line.decode("utf-8", errors="replace")
                if on_profile_addrs is not None:
                    ready = parse_live_profile_line(decoded, addrs)
                    if ready and not started_prof:
                        started_prof = True
                        profiler_proc = on_profile_addrs(proc.pid, vcpu_tids, addrs)
                        if send_go_after_prof_ready and proc.stdin is not None:
                            proc.stdin.write(b"GO\n")
                            proc.stdin.flush()
                if on_serial_line is not None:
                    reason = on_serial_line(decoded)
                    if reason:
                        abort_reason = reason
                        try:
                            os.killpg(proc.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        break

            proc.wait(timeout=10)
            if watchdog_timer is not None:
                watchdog_timer.cancel()
            err_thr.join(timeout=5)
            if timed_out.is_set():
                raise QemuRunError(
                    f"QEMU timed out after {timeout_sec}s",
                    _make_partial(),
                )
            if abort_reason is not None:
                raise QemuRunError(abort_reason, _make_partial())
        except QemuRunError:
            raise
        except BaseException as exc:
            if watchdog_timer is not None:
                watchdog_timer.cancel()
            if profiler_proc is not None and profiler_proc.poll() is None:
                profiler_proc.terminate()
                try:
                    profiler_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    profiler_proc.kill()
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            if proc.poll() is None:
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
            if proc.stdout is not None and not stdout_lines:
                try:
                    stdout_lines.append(proc.stdout.read())
                except Exception:
                    pass
            if err_thr is not None:
                err_thr.join(timeout=2)
            elif proc.stderr is not None and not stderr_chunks:
                try:
                    stderr_chunks.append(proc.stderr.read())
                except Exception:
                    pass
            raise QemuRunError(str(exc), _make_partial()) from exc
        finally:
            if profiler_proc is not None and profiler_proc.poll() is None:
                profiler_proc.send_signal(signal.SIGINT)
                try:
                    profiler_proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    profiler_proc.terminate()
                    profiler_proc.wait(timeout=5)

    serial_text, stderr_text, serial_log_path, stderr_log_path = _flush_partial_logs()
    res = QemuBootResult(
        qemu_rc=proc.returncode,
        serial_log=serial_text,
        stderr_log=stderr_text,
        cmd=cmd,
        vcpu_tids=vcpu_tids,
        pinned_vcpu_map=pinned_vcpu_map,
        pinned_io_cpu=io_core,
        serial_log_path=serial_log_path,
        stderr_log_path=stderr_log_path,
    )
    if proc.returncode not in expected_qemu_rcs:
        raise QemuRunError(
            f"QEMU exited with unexpected code {proc.returncode} "
            f"(expected {expected_qemu_rcs}); tail:\n{serial_text[-2000:]}",
            res,
        )
    return res


def _require_int(payload: dict[str, object], key: str) -> int:
    val = payload[key]
    if isinstance(val, bool) or not isinstance(val, int):
        raise ValueError(f"EVAL_CASE_JSON field {key!r} must be an integer, got {val!r}")
    return val


def _optional_int(payload: dict[str, object], key: str) -> int | None:
    if key not in payload or payload[key] is None:
        return None
    val = payload[key]
    if isinstance(val, bool) or not isinstance(val, int):
        raise ValueError(f"EVAL_CASE_JSON field {key!r} must be int or null, got {val!r}")
    return val


def _decode_b64_field(payload: dict[str, object], key: str) -> str:
    val = payload[key]
    if not isinstance(val, str):
        raise ValueError(f"EVAL_CASE_JSON field {key!r} must be a base64 string")
    try:
        raw = base64.b64decode(val.encode("ascii"), validate=True)
    except Exception as exc:
        raise ValueError(f"EVAL_CASE_JSON invalid base64 in {key!r}: {exc}") from exc
    return raw.decode("utf-8", errors="replace")


_REQUIRED_CASE_KEYS = (
    "case_id",
    "rc",
    "wall_ns",
    "minflt_delta",
    "majflt_delta",
    "ru_utime_us",
    "ru_stime_us",
    "cpu_start",
    "cpu_end",
    "migrated",
    "cpu_obs_ok",
    "thp_fault_alloc_delta",
    "stdout_b64",
    "stderr_b64",
)


def parse_serial_records(
    serial_text: str,
    *,
    round_idx: int,
    target: str,
    specs: dict[str, CaseSpec],
    require_complete: bool = True,
    audit_mode: bool = False,
) -> list[CaseRecord]:
    """Extract and strictly verify EVAL_CASE_JSON, STATS_JSON, and HOST_CASE_META records from serial logs."""
    records: list[CaseRecord] = []
    seen_ids: set[str] = set()
    pending_record: CaseRecord | None = None
    expects_stats = target.startswith("K")

    for raw_line in serial_text.splitlines():
        line = raw_line.strip()
        if line.startswith(EVAL_CASE_PREFIX):
            if expects_stats and pending_record is not None and pending_record.sandbox_stats is None:
                raise ValueError(
                    f"{target} round {round_idx}: missing STATS_JSON after {pending_record.case_id!r}"
                )
            try:
                payload = json.loads(line[len(EVAL_CASE_PREFIX) :])
            except json.JSONDecodeError as exc:
                raise ValueError(f"malformed EVAL_CASE_JSON: {exc}") from exc
            if not isinstance(payload, dict):
                raise ValueError("EVAL_CASE_JSON must be a JSON object")
            for key in _REQUIRED_CASE_KEYS:
                if key not in payload:
                    raise ValueError(f"EVAL_CASE_JSON missing required field {key!r}")

            case_id = payload["case_id"]
            if not isinstance(case_id, str) or not case_id:
                raise ValueError(f"EVAL_CASE_JSON invalid case_id: {case_id!r}")
            if case_id not in specs:
                raise ValueError(f"{target} round {round_idx}: unknown case_id {case_id!r}")
            if case_id in seen_ids:
                raise ValueError(f"{target} round {round_idx}: duplicate result for {case_id!r}")
            seen_ids.add(case_id)

            migrated = payload["migrated"]
            if not isinstance(migrated, bool):
                raise ValueError(f"EVAL_CASE_JSON field 'migrated' must be bool, got {migrated!r}")
            cpu_obs_ok = payload["cpu_obs_ok"]
            if not isinstance(cpu_obs_ok, bool):
                raise ValueError(f"EVAL_CASE_JSON field 'cpu_obs_ok' must be bool, got {cpu_obs_ok!r}")

            thp_obs_ok = payload.get("thp_obs_ok", True)
            if not isinstance(thp_obs_ok, bool):
                raise ValueError(f"EVAL_CASE_JSON field 'thp_obs_ok' must be bool, got {thp_obs_ok!r}")
            thp_policy = payload.get("thp_policy")
            if thp_policy is not None and not isinstance(thp_policy, str):
                raise ValueError(f"EVAL_CASE_JSON field 'thp_policy' must be str or null, got {thp_policy!r}")

            stages: list[TimingStage] = []
            raw_stages = payload.get("timing_stages", [])
            if raw_stages is not None:
                if not isinstance(raw_stages, list):
                    raise ValueError("EVAL_CASE_JSON field 'timing_stages' must be a list")
                for st_obj in raw_stages:
                    if not isinstance(st_obj, dict):
                        raise ValueError("timing_stages element must be a JSON object")
                    stages.append(
                        TimingStage(
                            valid=bool(st_obj["valid"]),
                            intervals=_require_int(st_obj, "intervals"),
                            minflt=_require_int(st_obj, "minflt"),
                            majflt=_require_int(st_obj, "majflt"),
                        )
                    )

            thp_delta = _optional_int(payload, "thp_fault_alloc_delta")
            timing_minflt = _optional_int(payload, "timing_minflt_delta")
            timing_majflt = _optional_int(payload, "timing_majflt_delta")

            rc = _require_int(payload, "rc")
            stdout = _decode_b64_field(payload, "stdout_b64")
            stderr = _decode_b64_field(payload, "stderr_b64")
            spec = specs[case_id]
            parsed_val: float | None = None
            try:
                parsed_val = parse_case_output(spec.parser, stdout, stderr)
            except Exception as exc:
                if rc == 0:
                    raise ValueError(f"{case_id}: {exc}") from exc

            rec = CaseRecord(
                round_idx=round_idx,
                target=target,
                case_id=case_id,
                rc=rc,
                wall_ns=_require_int(payload, "wall_ns"),
                minflt_delta=_require_int(payload, "minflt_delta"),
                majflt_delta=_require_int(payload, "majflt_delta"),
                ru_utime_us=_require_int(payload, "ru_utime_us"),
                ru_stime_us=_require_int(payload, "ru_stime_us"),
                cpu_start=_require_int(payload, "cpu_start"),
                cpu_end=_require_int(payload, "cpu_end"),
                migrated=migrated,
                thp_fault_alloc_delta=thp_delta,
                stdout=stdout,
                stderr=stderr,
                value=parsed_val,
                unit=spec.unit,
                cpu_obs_ok=cpu_obs_ok,
                timing_minflt_delta=timing_minflt,
                timing_majflt_delta=timing_majflt,
                thp_obs_ok=thp_obs_ok,
                thp_policy=thp_policy,
                timing_stages=stages,
                audit_mode=audit_mode,
            )
            records.append(rec)
            pending_record = rec
        elif line.startswith(STATS_PREFIX):
            if not expects_stats:
                raise ValueError(f"{target} round {round_idx}: unexpected STATS_JSON on native target")
            if pending_record is None:
                raise ValueError(f"{target} round {round_idx}: orphan STATS_JSON before EVAL_CASE_JSON")
            if pending_record.sandbox_stats is not None:
                raise ValueError(
                    f"{target} round {round_idx}: duplicate STATS_JSON for {pending_record.case_id!r}"
                )
            try:
                stats_obj = json.loads(line[len(STATS_PREFIX) :])
            except json.JSONDecodeError as exc:
                raise ValueError(f"malformed STATS_JSON: {exc}") from exc
            pending_record.sandbox_stats = SandboxStats.from_dict(stats_obj)
        elif line.startswith(HOST_META_PREFIX):
            if not expects_stats:
                raise ValueError(f"{target} round {round_idx}: unexpected HOST_CASE_META on native target")
            if pending_record is None:
                raise ValueError(f"{target} round {round_idx}: orphan HOST_CASE_META before EVAL_CASE_JSON")
            try:
                meta_obj = json.loads(line[len(HOST_META_PREFIX) :])
            except json.JSONDecodeError as exc:
                raise ValueError(f"malformed HOST_CASE_META: {exc}") from exc
            meta = HostCaseMeta.from_dict(meta_obj)
            if meta.case_id != pending_record.case_id:
                raise ValueError(
                    f"{target} round {round_idx}: HOST_CASE_META case_id {meta.case_id!r} "
                    f"!= pending {pending_record.case_id!r}"
                )
            if pending_record.host_meta is not None:
                raise ValueError(
                    f"{target} round {round_idx}: duplicate HOST_CASE_META for {pending_record.case_id!r}"
                )
            pending_record.host_meta = meta

    if require_complete:
        if expects_stats and pending_record is not None and pending_record.sandbox_stats is None:
            raise ValueError(
                f"{target} round {round_idx}: missing STATS_JSON after {pending_record.case_id!r}"
            )
        missing = [cid for cid in specs if cid not in seen_ids]
        if missing:
            raise ValueError(f"{target} round {round_idx}: missing results for {missing}")

    return records
