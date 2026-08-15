#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
"""Runs quick negative checks for FrameVM no-build artifact reuse."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
from collections.abc import Callable
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--cargo-osdk", type=Path, default=Path.home() / ".cargo" / "bin" / "cargo-osdk")
    args = parser.parse_args()

    checker = FailureChecker(args.root, args.cargo_osdk)
    checker.run()
    print("framevm failure checks passed")
    return 0


class FailureChecker:
    def __init__(self, root: Path, cargo_osdk: Path) -> None:
        self.root = root.resolve()
        self.cargo_osdk = cargo_osdk
        self.bundle_toml = self.root / "target" / "osdk" / "aster-kernel" / "bundle.toml"
        self.bundle_symbols = self.root / "target" / "osdk" / "aster-kernel" / "framevm.symbols"
        self.framevm_object = self.root / "build" / "framevm" / "framevm.o"

    def run(self) -> None:
        self.require_file(self.cargo_osdk)
        self.require_file(self.bundle_toml)
        self.require_file(self.bundle_symbols)
        self.require_file(self.framevm_object)
        self.expect_no_build_failure(
            "corrupt bundle symbol-table hash",
            ("framevm_symbols_hash mismatch",),
            self.corrupt_bundle_symbol_hash,
        )
        self.expect_no_build_failure(
            "corrupt symbol-table payload",
            ("FrameVM symbol table validation failed", "no reusable FrameVM bundle found"),
            self.corrupt_symbol_payload,
        )
        self.expect_no_build_failure(
            "corrupt framevm object payload",
            ("framevm_o_hash mismatch",),
            self.corrupt_framevm_object,
        )

    def require_file(self, path: Path) -> None:
        if not path.is_file():
            raise RuntimeError(f"required file is missing: {path}")

    def expect_no_build_failure(
        self,
        label: str,
        expected_messages: tuple[str, ...],
        mutate: Callable[[], Callable[[], None]],
    ) -> None:
        restore = mutate()
        try:
            result = subprocess.run(
                [
                    "timeout",
                    "60s",
                    str(self.cargo_osdk),
                    "osdk",
                    "framevm",
                    "run",
                    "--kcmd-args=ostd.log_level=error",
                    "--kcmd-args=console=ttyS0",
                    "--boot-method=grub-rescue-iso",
                    "--grub-boot-protocol=multiboot2",
                    "--qemu-args=-accel kvm",
                    "--framevm-target=x86_64-unknown-none",
                    f"--framevm-object-output={self.framevm_object}",
                    "--framevm-install-path=/framevm/framevm.o",
                    "--no-build",
                ],
                cwd=self.root / "kernel",
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
        finally:
            restore()

        output = result.stdout
        if result.returncode == 0:
            raise RuntimeError(f"{label}: no-build run unexpectedly succeeded")
        if not any(message in output for message in expected_messages):
            expected = "`, `".join(expected_messages)
            raise RuntimeError(f"{label}: expected one of `{expected}` in output:\n{output}")
        qemu_started = "qemu-system-" in output or "BdsDxe:" in output or "OSTD initialized" in output
        if qemu_started:
            raise RuntimeError(f"{label}: failure happened after QEMU launch:\n{output}")

    def corrupt_bundle_symbol_hash(self) -> Callable[[], None]:
        original = self.bundle_toml.read_text(encoding="utf-8")
        corrupted = re.sub(
            r'framevm_symbols_hash = "[0-9a-f]{64}"',
            'framevm_symbols_hash = "0000000000000000000000000000000000000000000000000000000000000000"',
            original,
            count=1,
        )
        if corrupted == original:
            raise RuntimeError("failed to find framevm_symbols_hash in bundle manifest")
        self.bundle_toml.write_text(corrupted, encoding="utf-8")
        return lambda: self.bundle_toml.write_text(original, encoding="utf-8")

    def corrupt_symbol_payload(self) -> Callable[[], None]:
        original, stat = self.backup_file(self.bundle_symbols)
        corrupted = bytearray(original)
        corrupted[-1] ^= 0x01
        self.bundle_symbols.write_bytes(corrupted)
        return lambda: self.restore_file(self.bundle_symbols, original, stat)

    def corrupt_framevm_object(self) -> Callable[[], None]:
        original, stat = self.backup_file(self.framevm_object)
        corrupted = bytearray(original)
        corrupted[-1] ^= 0x01
        self.framevm_object.write_bytes(corrupted)
        return lambda: self.restore_file(self.framevm_object, original, stat)

    @staticmethod
    def backup_file(path: Path) -> tuple[bytes, os.stat_result]:
        return path.read_bytes(), path.stat()

    @staticmethod
    def restore_file(path: Path, content: bytes, stat: os.stat_result) -> None:
        path.write_bytes(content)
        os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns))


if __name__ == "__main__":
    raise SystemExit(main())
