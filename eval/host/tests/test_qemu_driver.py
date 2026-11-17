import base64
import json
import unittest

from host.qemu_driver import (
    discover_distinct_physical_cores,
    extract_guest_folded_profile,
    format_batch_manifest,
    format_guest_runner_args,
    parse_serial_records,
)
from host.schema import CaseSpec, CopyFileSpec, InvariantSpec, TmpFileSpec


class QemuDriverTests(unittest.TestCase):
    def test_format_batch_and_runner_args(self) -> None:
        spec = CaseSpec(
            case_id="sys.lm.exec",
            group="syscall",
            suite="lmbench",
            binary="/benchmark/bin/lmbench/lat_proc",
            args=("-P", "1", "exec"),
            cpus=(0,),
            tmpfiles=(TmpFileSpec("/tmp/lm_mmap_64m", 64),),
            copy_files=(CopyFileSpec("/benchmark/bin/lmbench/hello", "/tmp/hello"),),
            verify_exec="/tmp/hello",
            parser="lmbench_latency",
            unit="us",
            higher_is_better=False,
            invariants=InvariantSpec(),
        )
        batch = format_batch_manifest([spec])
        self.assertEqual(
            batch.strip(),
            "sys.lm.exec\t0\t/tmp/lm_mmap_64m:64\t/benchmark/bin/lmbench/hello:/tmp/hello\t/tmp/hello\t/benchmark/bin/lmbench/lat_proc\t-P\t1\texec",
        )
        argv = format_guest_runner_args(spec)
        self.assertEqual(
            argv,
            [
                "/bin/eval_guest_runner",
                "--case-id",
                "sys.lm.exec",
                "--cpus",
                "0",
                "--tmpfile",
                "/tmp/lm_mmap_64m:64",
                "--copy-file",
                "/benchmark/bin/lmbench/hello:/tmp/hello",
                "--verify-exec",
                "/tmp/hello",
                "--",
                "/benchmark/bin/lmbench/lat_proc",
                "-P",
                "1",
                "exec",
            ],
        )

    def test_parse_serial_records_pairs_stats(self) -> None:
        spec = CaseSpec(
            case_id="sys.lm.null",
            group="syscall",
            suite="lmbench",
            binary="/benchmark/bin/lmbench/lat_syscall",
            args=("-P", "1", "null"),
            cpus=(0,),
            tmpfiles=(),
            parser="lmbench_latency",
            unit="us/op",
            higher_is_better=False,
            invariants=InvariantSpec(),
        )
        err_b64 = base64.b64encode(b"Simple syscall: 0.2500 microseconds\n").decode("ascii")
        case_json = json.dumps(
            {
                "case_id": "sys.lm.null",
                "rc": 0,
                "wall_ns": 123456,
                "minflt_delta": 12,
                "majflt_delta": 0,
                "ru_utime_us": 100,
                "ru_stime_us": 200,
                "cpu_start": 0,
                "cpu_end": 0,
                "migrated": False,
                "cpu_obs_ok": True,
                "thp_fault_alloc_delta": 0,
                "timing_minflt_delta": 0,
                "timing_majflt_delta": 0,
                "stdout_b64": "",
                "stderr_b64": err_b64,
            }
        )
        stats_json = json.dumps(
            {
                "pt_mode": 0,
                "vcpus": 2,
                "grant_mb": 512,
                "exit_kind": 0,
                "exit_code": 0,
                "exit_msg": "",
                "fpu_saves": 3,
                "fpu_restores": 3,
                "vm_creates": 1,
                "vm_destroys": 1,
                "vm_flushes": 0,
                "vm_maps": 0,
                "vm_protects": 0,
                "vm_unmaps": 0,
                "exceptions": 10,
                "page_faults": 50,
                "virqs": 2,
                "forced_yields": 0,
                "non_sysret": 1,
                "syscalls": 420,
                "grant_grains_allocated": 256,
                "grant_grains_freed": 256,
                "image_load_base": "0xffffc90000100000",
            }
        )
        host_meta = json.dumps(
            {
                "case_id": "sys.lm.null",
                "host_thp_obs_ok": True,
                "host_thp_policy": "always madvise [never]",
                "host_thp_fault_alloc_delta": 0,
                "grant_accounting_ok": True,
                "live_sandboxes": 0,
                "live_grant_grains": 0,
                "live_meta_pages": 0,
                "live_kstack_pages": 0,
                "live_shared_pages": 0,
            }
        )
        serial = f"EVAL_CASE_JSON {case_json}\nSTATS_JSON {stats_json}\nHOST_CASE_META {host_meta}\n"
        recs = parse_serial_records(
            serial, round_idx=1, target="K", specs={"sys.lm.null": spec}
        )
        self.assertEqual(len(recs), 1)
        self.assertAlmostEqual(recs[0].value, 0.25)
        self.assertTrue(recs[0].cpu_obs_ok)
        self.assertEqual(recs[0].timing_minflt_delta, 0)
        self.assertIsNotNone(recs[0].sandbox_stats)
        self.assertEqual(recs[0].sandbox_stats.page_faults, 50)
        self.assertEqual(recs[0].sandbox_stats.non_sysret, 1)
        self.assertEqual(recs[0].sandbox_stats.syscalls, 420)
        self.assertEqual(recs[0].sandbox_stats.grant_grains_allocated, 256)
        self.assertIsNotNone(recs[0].host_meta)
        self.assertEqual(recs[0].host_meta.live_grant_grains, 0)
        self.assertEqual(recs[0].sandbox_stats.image_load_base, "0xffffc90000100000")

        folded_log = "EVAL_PROF_FOLDED_BEGIN\n0x1;0x2 3\n0x1;0x3 1\nEVAL_PROF_FOLDED_END\n"
        self.assertEqual(extract_guest_folded_profile(folded_log), ["0x1;0x2 3", "0x1;0x3 1"])

    def test_discover_distinct_physical_cores_respects_allowed(self) -> None:
        allowed = {1, 2, 3}
        cores = discover_distinct_physical_cores(2, allowed_cpus=allowed)
        self.assertEqual(len(cores), 2)
        self.assertTrue(set(cores).issubset(allowed))
        with self.assertRaises(RuntimeError):
            discover_distinct_physical_cores(9999, allowed_cpus=allowed)


if __name__ == "__main__":
    unittest.main()
