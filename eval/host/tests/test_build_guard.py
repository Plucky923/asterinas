import gzip
from pathlib import Path
import tarfile
import tempfile
import unittest

from host.build_guard import (
    check_kernel_config_text,
    compute_component_input_hash,
    generate_and_write_archive,
    synthesize_build_manifest,
    verify_build_freshness,
    verify_shared_payload,
    write_build_inputs_manifest,
    write_component_receipt,
)
from host.qemu_driver import _cpio_newc_file_entry, _cpio_newc_trailer


VALID_PERF_BASE = """
CONFIG_CC_OPTIMIZE_FOR_PERFORMANCE=y
# CONFIG_CC_OPTIMIZE_FOR_SIZE is not set
# CONFIG_INIT_STACK_ALL_ZERO is not set
# CONFIG_DEBUG_ATOMIC_SLEEP is not set
# CONFIG_SCHEDSTATS is not set
# CONFIG_TRANSPARENT_HUGEPAGE_ALWAYS is not set
# CONFIG_X86_VSYSCALL_EMULATION is not set
CONFIG_ADVISE_SYSCALLS=y
CONFIG_PERF_EVENTS=y
CONFIG_KERNELET=y
CONFIG_VM_EVENT_COUNTERS=y
CONFIG_TMPFS=y
CONFIG_SHMEM=y
CONFIG_CGROUPS=y
CONFIG_MODULES=y
CONFIG_MODULE_UNLOAD=y
CONFIG_KALLSYMS=y
# CONFIG_CPU_MITIGATIONS is not set
# CONFIG_MITIGATION_PAGE_TABLE_ISOLATION is not set
"""


class BuildGuardTests(unittest.TestCase):
    def test_valid_perf_base(self) -> None:
        self.assertEqual(check_kernel_config_text(VALID_PERF_BASE, "perf-base"), [])

    def test_rejects_os_and_debug_atomic_sleep(self) -> None:
        bad = VALID_PERF_BASE.replace(
            "# CONFIG_CC_OPTIMIZE_FOR_SIZE is not set", "CONFIG_CC_OPTIMIZE_FOR_SIZE=y"
        ).replace(
            "# CONFIG_DEBUG_ATOMIC_SLEEP is not set", "CONFIG_DEBUG_ATOMIC_SLEEP=y"
        )
        errs = check_kernel_config_text(bad, "perf-base")
        self.assertTrue(any("CONFIG_CC_OPTIMIZE_FOR_SIZE" in e for e in errs))
        self.assertTrue(any("CONFIG_DEBUG_ATOMIC_SLEEP" in e for e in errs))

    def test_perf_pti_profile(self) -> None:
        errs = check_kernel_config_text(VALID_PERF_BASE, "perf-pti")
        self.assertEqual(len(errs), 2)
        pti_ok = (
            VALID_PERF_BASE
            + "\nCONFIG_CPU_MITIGATIONS=y\nCONFIG_MITIGATION_PAGE_TABLE_ISOLATION=y\n"
        )
        self.assertEqual(check_kernel_config_text(pti_ok, "perf-pti"), [])

    def _make_initrd(
        self,
        path: Path,
        payload_bytes: bytes,
        *,
        include_kernelet: bool = True,
    ) -> None:
        parts = [
            _cpio_newc_file_entry("payload/eval-payload.cpio", payload_bytes, mode=0o100644),
        ]
        if include_kernelet:
            parts.extend(
                [
                    _cpio_newc_file_entry("modules/endovisor.ko", b"ko-bytes", mode=0o100644),
                    _cpio_newc_file_entry("bin/run-kernelet", b"runner-bytes", mode=0o100755),
                    _cpio_newc_file_entry("kernelet-image.elf", b"elf-bytes", mode=0o100755),
                ]
            )
        parts.append(_cpio_newc_trailer())
        path.write_bytes(gzip.compress(b"".join(parts)))

    def test_verify_shared_payload_embedded_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            ext = tdp / "eval-payload.cpio"
            ext.write_bytes(b"identical-cpio")
            initrd_ok = tdp / "initrd-ok.cpio.gz"
            self._make_initrd(initrd_ok, b"identical-cpio", include_kernelet=True)
            h, embedded = verify_shared_payload(
                payload_path=ext,
                host_initrd_path=initrd_ok,
                targets=["L", "A", "K", "K_vma"],
            )
            self.assertEqual(len(h), 64)
            self.assertEqual(embedded["payload/eval-payload.cpio"], h)

            initrd_stale = tdp / "initrd-stale.cpio.gz"
            self._make_initrd(initrd_stale, b"stale-cpio", include_kernelet=True)
            with self.assertRaises(ValueError):
                verify_shared_payload(
                    payload_path=ext,
                    host_initrd_path=initrd_stale,
                    targets=["L", "K"],
                )

            initrd_no_k = tdp / "initrd-no-k.cpio.gz"
            self._make_initrd(initrd_no_k, b"identical-cpio", include_kernelet=False)
            with self.assertRaises(ValueError):
                verify_shared_payload(
                    payload_path=ext,
                    host_initrd_path=initrd_no_k,
                    targets=["K"],
                )

    def test_generate_and_write_archive(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            ext = tdp / "eval-payload.cpio"
            ext.write_bytes(b"payload-data")
            initrd = tdp / "host.cpio.gz"
            self._make_initrd(initrd, b"payload-data", include_kernelet=True)
            cfg = tdp / "perf-base.config"
            cfg.write_text(VALID_PERF_BASE, encoding="utf-8")
            out_dir = tdp / "out"
            cases_file = tdp / "cases.toml"
            cases_file.write_text("[defaults]\n", encoding="utf-8")
            manifest = generate_and_write_archive(
                run_id="r1",
                out_dir=out_dir,
                repo_root=tdp,
                targets=["L", "K"],
                rounds=1,
                seed=42,
                payload_path=ext,
                host_initrd_path=initrd,
                artifacts={"payload": ext},
                kernel_configs={"perf_base": (cfg, "perf-base")},
                cases_path=cases_file,
            )
            self.assertTrue((out_dir / "manifest.json").exists())
            self.assertTrue((out_dir / "perf_base.config").exists())
            self.assertTrue((out_dir / "cases.toml").exists())
            self.assertTrue((out_dir / "source_snapshot.tar.gz").exists())
            self.assertEqual(len(manifest.cases_sha256), 64)
            self.assertEqual(manifest.kernel_config_checks["perf_base"], [])
            self.assertIn("modules/endovisor.ko", manifest.embedded_artifacts_sha256)

    def test_verify_build_freshness_detects_source_change(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            patch = tdp / "prototype" / "linux" / "patches" / "0001-carrier-hooks.patch"
            patch.parent.mkdir(parents=True)
            patch.write_text("v1\n", encoding="utf-8")
            bdir = tdp / "poc" / "eval" / ".build"
            (bdir / "linux-perf-base" / "arch" / "x86" / "boot").mkdir(parents=True)
            for rel in (
                "linux-perf-base/arch/x86/boot/bzImage",
                "linux-perf-base/System.map",
                "linux-perf-base/.config",
                "linux-perf-base/Module.symvers",
                "endovisor.ko",
                "run-kernelet",
                "asterinas-native.bzImage",
                "kernelet-image.elf",
                "eval-payload.cpio",
                "host-eval-initramfs.cpio.gz",
            ):
                p = bdir / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(b"bin")
            write_build_inputs_manifest(tdp, bdir)
            verify_build_freshness(tdp, bdir)
            patch.write_text("v2\n", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                verify_build_freshness(tdp, bdir)

    def test_receipts_prevent_partial_manifest_and_snapshot_includes_poc_kernel(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            (tdp / "reference" / "linux-6.12").mkdir(parents=True)
            (tdp / "reference" / "linux-6.12" / "init.c").write_text("v1\n", encoding="utf-8")
            patch = tdp / "prototype" / "linux" / "patches" / "0001-carrier-hooks.patch"
            patch.parent.mkdir(parents=True)
            patch.write_text("patch-v1\n", encoding="utf-8")
            frag = tdp / "poc" / "eval" / "configs" / "linux-perf-base.fragment"
            frag.parent.mkdir(parents=True)
            frag.write_text("CONFIG_FOO=y\n", encoding="utf-8")
            (tdp / "poc" / "linux" / "endovisor").mkdir(parents=True)
            (tdp / "poc" / "linux" / "endovisor" / "main.c").write_text("c1\n", encoding="utf-8")
            (tdp / "poc" / "linux" / "runner").mkdir(parents=True)
            (tdp / "poc" / "linux" / "runner" / "run-kernelet.c").write_text("r1\n", encoding="utf-8")
            untracked_ostd = tdp / "poc" / "ostd" / "libs" / "ostd-macros" / "src" / "user_event.rs"
            untracked_ostd.parent.mkdir(parents=True)
            untracked_ostd.write_text("// untracked macro file\n", encoding="utf-8")

            bdir = tdp / "poc" / "eval" / ".build"
            for rel in (
                "linux-perf-base/arch/x86/boot/bzImage",
                "linux-perf-base/System.map",
                "linux-perf-base/.config",
                "linux-perf-base/Module.symvers",
                "endovisor.ko",
                "run-kernelet",
                "asterinas-native.bzImage",
                "kernelet-image.elf",
                "eval-payload.cpio",
                "host-eval-initramfs.cpio.gz",
            ):
                p = bdir / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(b"art")

            # Write valid receipts for all components.
            for comp, outs in (
                ("linux_perf_base", {
                    "linux_perf_base_bzimage": bdir / "linux-perf-base/arch/x86/boot/bzImage",
                    "linux_perf_base_system_map": bdir / "linux-perf-base/System.map",
                    "linux_perf_base_config": bdir / "linux-perf-base/.config",
                    "linux_perf_base_symvers": bdir / "linux-perf-base/Module.symvers",
                }),
                ("endovisor", {"endovisor_ko": bdir / "endovisor.ko"}),
                ("run_kernelet", {"run_kernelet": bdir / "run-kernelet"}),
                ("asterinas", {
                    "asterinas_native_bzimage": bdir / "asterinas-native.bzImage",
                    "kernelet_image_elf": bdir / "kernelet-image.elf",
                }),
                ("payload", {
                    "eval_payload_cpio": bdir / "eval-payload.cpio",
                    "host_eval_initramfs": bdir / "host-eval-initramfs.cpio.gz",
                }),
            ):
                sha = compute_component_input_hash(tdp, bdir, comp, payload_mode="native")
                write_component_receipt(bdir, comp, sha, "test-cc", outs)

            synthesize_build_manifest(tdp, bdir)
            verify_build_freshness(tdp, bdir)

            # Mutate reference/linux-6.12 and re-run ONLY payload receipt + synthesize: must fail!
            (tdp / "reference" / "linux-6.12" / "init.c").write_text("v2\n", encoding="utf-8")
            p_sha = compute_component_input_hash(tdp, bdir, "payload", payload_mode="native")
            write_component_receipt(
                bdir,
                "payload",
                p_sha,
                "test-cc",
                {
                    "eval_payload_cpio": bdir / "eval-payload.cpio",
                    "host_eval_initramfs": bdir / "host-eval-initramfs.cpio.gz",
                },
            )
            with self.assertRaises(RuntimeError):
                synthesize_build_manifest(tdp, bdir)
            self.assertFalse((bdir / "build-inputs.json").exists())

            # Source snapshot archive must include untracked poc/ostd files.
            out_dir = tdp / "out"
            initrd = bdir / "host-eval-initramfs.cpio.gz"
            self._make_initrd(initrd, (bdir / "eval-payload.cpio").read_bytes(), include_kernelet=True)
            cfg = bdir / "linux-perf-base/.config"
            cfg.write_text(VALID_PERF_BASE, encoding="utf-8")
            cases_f = tdp / "cases.toml"
            cases_f.write_text("[defaults]\n", encoding="utf-8")
            generate_and_write_archive(
                run_id="r2",
                out_dir=out_dir,
                repo_root=tdp,
                targets=["L", "K"],
                rounds=1,
                seed=1,
                payload_path=bdir / "eval-payload.cpio",
                host_initrd_path=initrd,
                artifacts={"payload": bdir / "eval-payload.cpio"},
                kernel_configs={"perf_base": (cfg, "perf-base")},
                cases_path=cases_f,
            )
            with tarfile.open(out_dir / "source_snapshot.tar.gz", "r:gz") as tf:
                names = set(tf.getnames())
            self.assertIn("poc/ostd/libs/ostd-macros/src/user_event.rs", names)


if __name__ == "__main__":
    unittest.main()
