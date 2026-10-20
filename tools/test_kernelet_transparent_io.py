#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Check ordinary file/mmap/TCP/UDP I/O through copying and zero-copy devices.

Run inside the pinned development container. Only invocation-owned VM disks
are attached. Host/Image counters and offline disk inspection are required.
Elapsed times are functional observations, not a controlled performance study.
"""

import argparse
import gzip
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / "target/kernelet-transparent-io"


def run(command, log, **kwargs):
    with log.open("w") as output:
        subprocess.run(command, check=True, stdout=output, stderr=subprocess.STDOUT, **kwargs)


def fixtures():
    WORK.mkdir(parents=True, exist_ok=True)
    run(["cargo", "run", "--offline", "--manifest-path", str(ROOT / "kernelet/abi/Cargo.toml"),
         "--example", "header", "--", str(WORK / "kernelet-abi.h")], WORK / "header.log", cwd=ROOT)
    for name in ("host", "image"):
        run(["gcc", "-std=gnu11", "-O2", "-static", "-Wall", "-Wextra", "-Werror",
             "-I", str(WORK), str(ROOT / f"test/kernelet-transparent-io/{name}.c"),
             "-o", str(WORK / name)], WORK / f"{name}-compile.log")
    image_root = WORK / "image-root"
    image_root.mkdir(exist_ok=True)
    for name in ("dev", "proc", "tmp"):
        (image_root / name).mkdir(exist_ok=True)
    shutil.copy2(WORK / "image", image_root / "init")
    (image_root / "seed.bin").write_bytes(bytes((i * 13 + 7) & 255 for i in range(256)) * 4096)
    base = WORK / "base.ext2"
    with base.open("wb") as output:
        output.truncate(64 * 1024 * 1024)
    run(["mke2fs", "-q", "-F", "-t", "ext2", "-b", "4096", "-d", str(image_root), str(base)],
        WORK / "mke2fs.log")
    host_root = WORK / "host-root"
    host_root.mkdir(exist_ok=True)
    for name in ("dev", "proc", "tmp"):
        (host_root / name).mkdir(exist_ok=True)
    shutil.copy2(WORK / "host", host_root / "init")
    entries = sorted(str(path.relative_to(host_root)) for path in host_root.rglob("*"))
    with (WORK / "initramfs.cpio").open("wb") as output:
        subprocess.run(["cpio", "--null", "-o", "--format=newc"], cwd=host_root,
                       input=("\0".join(entries) + "\0").encode(), stdout=output, check=True)
    with (WORK / "initramfs.cpio").open("rb") as source:
        with gzip.open(WORK / "initramfs.cpio.gz", "wb") as output:
            shutil.copyfileobj(source, output)
    print("Identical Image roots and ordinary C clients prepared", flush=True)


def build():
    environment = os.environ.copy()
    environment["KERNELET_BENCH_HOST_NETWORK"] = "1"
    environment["KERNELET_SHARED_IO_TEST"] = "1"
    run(["cargo", "osdk", "build", "--release", "--no-default-features", "--kernelet",
         "--kcmd-args=earlycon", "--kcmd-args=console=ttyS0", "--kcmd-args=loglevel=3",
         "--initramfs", str(WORK / "initramfs.cpio.gz"), "-o", str(WORK / "build")],
        WORK / "build.log", cwd=ROOT / "kernel", env=environment)
    print("Paired Host/Image build passed", flush=True)


def qemu():
    for mode in ("copy", "shared"):
        shutil.copy2(WORK / "base.ext2", WORK / f"{mode}.ext2")
    # Use the checkout's supported physical NIC feature set, as make run_kernel does.
    options = (ROOT / "tools/qemu_args.sh").read_text()
    features = re.search(r'^VIRTIO_NET_FEATURES="([^"$]*)"$', options, re.MULTILINE)
    if features is None:
        raise RuntimeError("Cannot read the repository's literal VIRTIO_NET_FEATURES")
    nic = "virtio-net-pci,netdev=transparent-net,disable-legacy=on,disable-modern=off" + features.group(1)
    command = ["qemu-system-x86_64", "-enable-kvm", "-machine", "q35",
               "-bios", "/root/ovmf/release/OVMF.fd", "-cpu", "host", "-smp", "4", "-m", "8G",
               "-no-reboot", "-display", "none", "-serial", "stdio", "-monitor", "none",
               "-boot", "order=d", "-cdrom", str(WORK / "build/asterinas-osdk-bin.iso"),
               "-netdev", "user,id=transparent-net", "-device", nic,
               "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]
    for index, mode in enumerate(("copy", "shared")):
        command += ["-drive", f"file={WORK / (mode + '.ext2')},format=raw,if=none,id=disk{index}",
                    "-device", f"virtio-blk-pci,drive=disk{index},disable-legacy=on"]
    started = time.monotonic()
    result = None
    try:
        with (WORK / "qemu.log").open("w") as output:
            result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, timeout=300)
    finally:
        text = (WORK / "qemu.log").read_text(errors="replace")
        text = re.sub(r"\[image (?:copy|shared) (?:console|log)\] ", "", text)
        report = {"elapsed_seconds": time.monotonic() - started,
                  "qemu_exit": None if result is None else result.returncode,
                  "host_pass": "TRANSPARENT_HOST_PASS" in text,
                  "image_passes": len(re.findall(r"TRANSPARENT_IMAGE_PASS mode=", text)),
                  "file_passes": len(re.findall(r"TRANSPARENT_FILE_PASS mode=", text)),
                  "network_passes": len(re.findall(r"TRANSPARENT_NET_PASS mode=", text)),
                  "paths": re.findall(r"TRANSPARENT_PATHS [^\r\n]+", text),
                  "costs": re.findall(r"TRANSPARENT_COST [^\r\n]+", text),
                  "timings": re.findall(r"TRANSPARENT_(?:FILE|NET)_PASS [^\r\n]+", text),
                  "timing_scope": "Functional observations; not a controlled performance comparison",
                  "disk_write_verified": {}}
        expected = bytearray(bytes((i * 13 + 91) & 255 for i in range(256)) * 4096)
        expected[31:46] = b"shared-file-map"
        for mode in ("copy", "shared"):
            extracted = WORK / f"{mode}-written.bin"
            extracted.unlink(missing_ok=True)
            run(["debugfs", "-R", f"dump /written.bin {extracted}", str(WORK / f"{mode}.ext2")],
                WORK / f"{mode}-inspect.log")
            report["disk_write_verified"][mode] = extracted.is_file() and extracted.read_bytes() == expected
        (WORK / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    if not (report["qemu_exit"] == 33 and report["host_pass"] and report["image_passes"] == 2
            and report["file_passes"] == 2 and report["network_passes"] == 2
            and all(report["disk_write_verified"].values())) or "TRANSPARENT_HOST_FAIL" in text:
        raise RuntimeError(f"Transparent I/O VM test failed; see {WORK / 'qemu.log'}")
    print(json.dumps(report), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("fixtures", "build", "run", "all"), nargs="?", default="all")
    stage = parser.parse_args().stage
    if stage in ("fixtures", "all"):
        fixtures()
    if stage in ("build", "all"):
        build()
    if stage in ("run", "all"):
        qemu()


if __name__ == "__main__":
    main()
