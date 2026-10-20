#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Build and run actual shared-buffer block and two-instance network checks.

Run inside the development container. All images, logs, and QEMU resources
belong to this invocation under target/kernelet-shared-io. No host disk is used.
This is a functional regression test, not an experiment or a copy-count result.
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
WORK = ROOT / "target/kernelet-shared-io"


def run(command, log, **kwargs):
    with log.open("w") as output:
        subprocess.run(command, check=True, stdout=output, stderr=subprocess.STDOUT, **kwargs)


def fixtures():
    WORK.mkdir(parents=True, exist_ok=True)
    source = ROOT / "test/kernelet-shared-io"
    header = WORK / "kernelet-abi.h"
    run(["cargo", "run", "--offline", "--manifest-path", str(ROOT / "kernelet/abi/Cargo.toml"),
         "--example", "header", "--", str(header)], WORK / "header.log", cwd=ROOT)
    for name in ("host", "image"):
        run(["gcc", "-std=gnu11", "-O2", "-static", "-Wall", "-Wextra", "-Werror",
             "-I", str(WORK), str(source / f"{name}.c"), "-o", str(WORK / name)],
            WORK / f"{name}-compile.log")
    image_root = WORK / "image-root"
    image_root.mkdir(exist_ok=True)
    for directory in ("dev", "proc", "tmp"):
        (image_root / directory).mkdir(exist_ok=True)
    shutil.copy2(WORK / "image", image_root / "init")
    disk = WORK / "image-root.ext2"
    with disk.open("wb") as output:
        output.truncate(32 * 1024 * 1024)
    run(["mke2fs", "-q", "-F", "-t", "ext2", "-b", "4096", "-d", str(image_root), str(disk)],
        WORK / "mke2fs.log")
    host_root = WORK / "host-root"
    host_root.mkdir(exist_ok=True)
    for directory in ("dev", "proc", "tmp"):
        (host_root / directory).mkdir(exist_ok=True)
    shutil.copy2(WORK / "host", host_root / "init")
    shutil.copy2(disk, host_root / disk.name)
    entries = sorted(str(path.relative_to(host_root)) for path in host_root.rglob("*"))
    with (WORK / "initramfs.cpio").open("wb") as output:
        subprocess.run(["cpio", "--null", "-o", "--format=newc"], cwd=host_root,
                       input=("\0".join(entries) + "\0").encode(), stdout=output, check=True)
    with (WORK / "initramfs.cpio").open("rb") as source_file:
        with gzip.open(WORK / "initramfs.cpio.gz", "wb") as output:
            shutil.copyfileobj(source_file, output)
    with (WORK / "dma-fixture.img").open("wb") as output:
        output.write(b"KerneletSharedIOv1")
        output.truncate(4 * 1024 * 1024)
    print("Real C clients, ext2 root, initramfs, and dedicated DMA fixture prepared", flush=True)


def build():
    environment = os.environ.copy()
    environment["KERNELET_SHARED_IO_TEST"] = "1"
    run(["cargo", "osdk", "build", "--release", "--no-default-features", "--kernelet",
         "--kcmd-args=earlycon", "--kcmd-args=console=ttyS0",
         "--initramfs", str(WORK / "initramfs.cpio.gz"),
         "-o", str(WORK / "build")], WORK / "build.log", cwd=ROOT / "kernel", env=environment)
    print("Paired Host/Image functional-test build passed", flush=True)


def qemu():
    firmware = Path("/root/ovmf/release/OVMF.fd")
    if not firmware.is_file():
        raise RuntimeError(f"OVMF firmware is missing: {firmware}")
    # Reset the expected write sector even when repeating only the run stage.
    with (WORK / "dma-fixture.img").open("r+b") as disk:
        disk.seek(4096)
        disk.write(bytes(512))
    command = ["qemu-system-x86_64", "-enable-kvm", "-machine", "q35", "-bios", str(firmware),
               "-cpu", "host", "-smp", "4", "-m", "8G", "-no-reboot", "-display", "none",
               "-serial", "stdio", "-monitor", "none", "-boot", "order=d",
               "-cdrom", str(WORK / "build/asterinas-osdk-bin.iso"),
               "-drive", f"file={WORK / 'dma-fixture.img'},format=raw,if=none,id=shared-dma",
               "-device", "virtio-blk-pci,drive=shared-dma,disable-legacy=on",
               "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]
    started = time.monotonic()
    result = None
    try:
        with (WORK / "qemu.log").open("w") as output:
            result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, timeout=150)
    finally:
        log = (WORK / "qemu.log").read_text(errors="replace")
        # A host read can split an image console line. Remove only this
        # fixture's read prefixes before checking the complete image markers.
        log = re.sub(r"\[image \d+ (?:console|log)\] ", "", log)
        with (WORK / "dma-fixture.img").open("rb") as disk:
            disk.seek(4096)
            disk_write_verified = disk.read(512) == bytes([0xa5]) * 512
        report = {"elapsed_seconds": time.monotonic() - started,
                  "qemu_exit": None if result is None else result.returncode,
                  "disk_write_verified": disk_write_verified,
                  "host_pass": "SHARED_IO_HOST_PASS" in log,
                  "image_passes": len(re.findall(r"SHARED_IO_IMAGE_PASS role=", log)),
                  "block_pass": "SHARED_IO_RESULT block ok" in log,
                  "network_passes": len(re.findall(r"SHARED_IO_RESULT network ok", log))}
        (WORK / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    if not (report["qemu_exit"] == 33 and report["disk_write_verified"] and report["host_pass"]
            and report["image_passes"] == 2 and report["block_pass"]
            and report["network_passes"] == 2) or "SHARED_IO_HOST_FAIL" in log:
        raise RuntimeError(f"Functional VM test failed; see {WORK / 'qemu.log'}")
    print(json.dumps(report), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("fixtures", "build", "run", "all"), default="all", nargs="?")
    arguments = parser.parse_args()
    if arguments.stage in ("fixtures", "all"):
        fixtures()
    if arguments.stage in ("build", "all"):
        build()
    if arguments.stage in ("run", "all"):
        qemu()


if __name__ == "__main__":
    main()
