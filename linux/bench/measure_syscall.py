from __future__ import annotations

import argparse
from dataclasses import asdict
import gzip
import hashlib
import json
import os
from pathlib import Path
import random
import re
import resource
import statistics
import subprocess
import sys


PROJECT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT / "eval"))
from host.qemu_driver import QemuRunError, run_qemu_with_pinning


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def archive_file(archive: bytes, name: str) -> bytes:
    result = subprocess.run(
        ["cpio", "--extract", "--to-stdout", "--quiet", name],
        input=archive,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    if not result.stdout:
        raise ValueError(f"missing or empty archive member: {name}")
    return result.stdout


def inputs(initrd: Path) -> dict:
    archive = gzip.decompress(initrd.read_bytes())
    native = archive_file(archive, "tests/bench_syscall_fpu")
    guest = archive_file(archive, "guests/guest-syscall.cpio")
    tenant = archive_file(guest, "init")
    if native != tenant:
        raise ValueError("native and tenant benchmark executables differ")
    return {
        "initrd": str(initrd),
        "initrd_sha256": sha256(initrd),
        "benchmark_sha256": hashlib.sha256(native).hexdigest(),
        "image_sha256": hashlib.sha256(archive_file(archive, "kernelet-image.elf")).hexdigest(),
        "module_sha256": hashlib.sha256(archive_file(archive, "modules/endovisor.ko")).hexdigest(),
    }


def host_state() -> dict:
    paths = [Path("/proc/cpuinfo"), Path("/proc/loadavg")]
    paths.extend(Path("/sys/devices/system/cpu/vulnerabilities").glob("*"))
    for policy in Path("/sys/devices/system/cpu/cpufreq").glob("policy*"):
        paths.extend(policy / name for name in (
            "scaling_governor", "scaling_driver", "scaling_min_freq",
            "scaling_max_freq", "scaling_cur_freq", "energy_performance_preference",
        ))
    return {
        "uname": list(os.uname()),
        "affinity": sorted(os.sched_getaffinity(0)),
        "files": {str(path): path.read_text() for path in paths if path.is_file()},
        "qemu_version": subprocess.check_output(
            ["qemu-system-x86_64", "--version"], text=True
        ),
    }


def parse_samples(serial: str) -> list[dict]:
    samples = [json.loads(line.removeprefix("SYSCALL_SAMPLE "))
               for line in serial.splitlines() if line.startswith("SYSCALL_SAMPLE ")]
    if len(samples) != 9 or [s["sample"] for s in samples] != list(range(9)):
        raise ValueError(f"expected exactly nine ordered samples, received {len(samples)}")
    if any(s["valid"] is not True or s["cpu"] != 0 or s["pid"] <= 0
           or s["iterations"] != 1_000_000 or s["elapsed_ns"] <= 0
           or s["tsc_ticks"] <= 0 for s in samples):
        raise ValueError("invalid benchmark sample")
    if "RESULT suite_done 1 bool" not in serial:
        raise ValueError("benchmark suite did not pass")
    if "INIT: result=0" not in serial:
        raise ValueError("host workload or teardown failed")
    if re.search(r"(?:BUG:|WARNING:|Oops:|Kernel panic)", serial):
        raise ValueError("guest kernel fault or warning")
    frequency = re.search(r"tsc: Detected ([0-9.]+) MHz processor", serial)
    if frequency:
        hz = float(frequency[1]) * 1e6
        for sample in samples:
            observed_hz = sample["tsc_ticks"] * 1e9 / sample["elapsed_ns"]
            if abs(observed_hz / hz - 1) > 0.002:
                raise ValueError(f"TSC/monotonic clock disagreement: {observed_hz} vs {hz}")
    return samples


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kernel", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--native", action="append", default=[], metavar="LABEL=INITRD")
    parser.add_argument("--kernelet", action="append", default=[], metavar="LABEL=INITRD")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--temp-root", type=Path, required=True)
    parser.add_argument("--boots", type=int, default=5)
    parser.add_argument("--seed", type=int, default=20261117)
    parser.add_argument("--host-cpus", nargs="+", type=int)
    parser.add_argument("--machine", default="q35,kernel-irqchip=split")
    parser.add_argument("--mitigations", choices=["off", "auto"], default="off")
    parser.add_argument("--suite", choices=["syscall", "smp-syscall-fpu"], default="syscall")
    args = parser.parse_args()
    if args.host_cpus is not None:
        requested = set(args.host_cpus)
        if not requested <= os.sched_getaffinity(0):
            parser.error("--host-cpus includes unavailable CPUs")
        os.sched_setaffinity(0, requested)
    if args.boots <= 0:
        parser.error("--boots must be positive")
    variants = []
    for kind in ("native", "kernelet"):
        for spec in getattr(args, kind):
            label, initrd = spec.split("=", 1)
            if not re.fullmatch(r"[a-zA-Z0-9_-]+", label):
                parser.error("labels must contain only letters, digits, underscores and hyphens")
            variants.append({"label": label, "kind": kind, **inputs(Path(initrd).resolve())})
    if not variants or len({v["label"] for v in variants}) != len(variants):
        parser.error("provide variants with distinct labels")
    if len({v["benchmark_sha256"] for v in variants}) != 1:
        parser.error("all variants must use the identical benchmark executable")
    config = args.config.read_text()
    if args.mitigations == "auto" and "CONFIG_CPU_MITIGATIONS=y\n" not in config:
        parser.error("mitigations=auto requires CONFIG_CPU_MITIGATIONS=y")
    args.output.mkdir(parents=True, exist_ok=True)
    manifest_path = args.output / "manifest.json"
    if manifest_path.exists():
        parser.error("output already contains a manifest; choose a new directory")
    args.temp_root.mkdir(parents=True, exist_ok=True)
    original_memlock = resource.getrlimit(resource.RLIMIT_MEMLOCK)
    resource.setrlimit(resource.RLIMIT_MEMLOCK, (0, original_memlock[1]))
    rng = random.Random(args.seed)
    order = []
    for boot in range(args.boots):
        indices = list(range(len(variants)))
        rng.shuffle(indices)
        order.extend((boot, index) for index in indices)
    manifest = {
        "kernel": str(args.kernel.resolve()), "kernel_sha256": sha256(args.kernel),
        "linux_config": config, "config_sha256": sha256(args.config),
        "variants": variants, "order": order, "seed": args.seed,
        "boots": args.boots, "suite": args.suite, "mitigations": args.mitigations,
        "machine": args.machine,
        "original_memlock": original_memlock, "memlock_soft": 0,
        "host_start": host_state(), "driver_sha256": sha256(Path(__file__)),
        "qemu_driver_sha256": sha256(PROJECT / "eval/host/qemu_driver.py"),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    records = []
    try:
        for boot, index in order:
            variant = variants[index]
            prefix = f"r{boot + 1}-{variant['label']}"
            cmdline = (
                f"console=ttyS0 panic=-1 nokaslr mitigations={args.mitigations} "
                f"kernelet_mode={variant['kind']}-syscall kernelet_pt_mode=direct "
                f"kernelet_vcpus=2 kernelet_grant_mb=256 kernelet_attach=exec "
                f"kernelet_suite={args.suite} kernelet_guest_cmd=kernelet_suite={args.suite}"
            )
            error = None
            try:
                result = run_qemu_with_pinning(
                    kernel_path=args.kernel.resolve(),
                    initrd_path=Path(variant["initrd"]),
                    cmdline=cmdline, vcpus=2, mem_mb=1024, timeout_sec=90,
                    machine=args.machine,
                    temp_root=args.temp_root, log_dir=args.output, log_prefix=prefix,
                )
            except QemuRunError as exc:
                result = exc.partial_result
                error = str(exc)
            record = {key: value for key, value in asdict(result).items()
                      if key not in ("serial_log", "stderr_log")}
            record.update({"round": boot + 1, "label": variant["label"], "valid": False})
            if error is None:
                try:
                    samples = parse_samples(result.serial_log)
                    record.update({
                        "samples": samples,
                        "median_ns": statistics.median(s["elapsed_ns"] / s["iterations"] for s in samples),
                        "median_tsc_ticks": statistics.median(s["tsc_ticks"] / s["iterations"] for s in samples),
                        "valid": True,
                    })
                except ValueError as exc:
                    error = str(exc)
            if error is not None:
                record["error"] = error
            records.append(record)
            with (args.output / "records.jsonl").open("a") as stream:
                stream.write(json.dumps(record) + "\n")
            print(f"{prefix}: {record.get('median_ns', 'invalid')} ns; valid={record['valid']}", flush=True)
            if not record["valid"]:
                raise RuntimeError(record["error"])
    finally:
        (args.output / "host-end.json").write_text(json.dumps(host_state(), indent=2) + "\n")
    report = []
    for variant in variants:
        values = [r["median_ns"] for r in records if r["label"] == variant["label"]]
        report.append({"label": variant["label"], "boots": values,
                       "median_ns": statistics.median(values), "min_ns": min(values), "max_ns": max(values)})
    (args.output / "summary.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
