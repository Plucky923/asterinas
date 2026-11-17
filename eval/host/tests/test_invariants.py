import unittest

from host.invariants import validate_case_record
from host.schema import (
    CaseRecord,
    CaseSpec,
    HostCaseMeta,
    InvariantSpec,
    SandboxStats,
    TimingStage,
)


def _make_spec(**inv_kwargs) -> CaseSpec:
    return CaseSpec(
        case_id="mm.wis.pf_anon.p1",
        group="mm",
        suite="will-it-scale",
        binary="/bin/pf",
        args=("-t", "1"),
        cpus=(0,),
        tmpfiles=(),
        parser="will_it_scale_ops",
        unit="ops/s",
        higher_is_better=True,
        invariants=InvariantSpec(**inv_kwargs),
    )


def _make_record(**rec_kwargs) -> CaseRecord:
    defaults = dict(
        round_idx=1,
        target="L",
        case_id="mm.wis.pf_anon.p1",
        rc=0,
        wall_ns=1000,
        minflt_delta=40000,
        majflt_delta=0,
        ru_utime_us=100,
        ru_stime_us=200,
        cpu_start=0,
        cpu_end=0,
        migrated=False,
        thp_fault_alloc_delta=0,
        stdout="average:1000\n",
        stderr="",
        value=1000.0,
        unit="ops/s",
        cpu_obs_ok=True,
        timing_minflt_delta=0,
        timing_majflt_delta=0,
    )
    defaults.update(rec_kwargs)
    return CaseRecord(**defaults)


class InvariantsTests(unittest.TestCase):
    def test_valid_record_passes(self) -> None:
        ok, reasons = validate_case_record(_make_spec(min_minor_faults=32768), _make_record())
        self.assertTrue(ok, reasons)

    def test_thp_violation_fails(self) -> None:
        ok, reasons = validate_case_record(
            _make_spec(forbid_thp=True),
            _make_record(thp_fault_alloc_delta=1),
        )
        self.assertFalse(ok)
        self.assertTrue(any("THP" in r for r in reasons))

    def test_zero_faults_on_linux_fails(self) -> None:
        ok, reasons = validate_case_record(
            _make_spec(min_minor_faults=100),
            _make_record(target="L", minflt_delta=0),
        )
        self.assertFalse(ok)
        self.assertTrue(any("minor faults" in r for r in reasons))

    def test_migration_and_unobservable_procfs_fail(self) -> None:
        ok, reasons = validate_case_record(
            _make_spec(forbid_migration=True),
            _make_record(cpu_end=1, migrated=True),
        )
        self.assertFalse(ok)
        ok_obs, reasons_obs = validate_case_record(
            _make_spec(forbid_migration=True),
            _make_record(cpu_obs_ok=False),
        )
        self.assertFalse(ok_obs)
        self.assertTrue(any("procfs observation" in r for r in reasons_obs))

    def test_timing_window_zero_fault_gate(self) -> None:
        spec = _make_spec(max_timing_faults=0)
        ok_pass, reasons_pass = validate_case_record(
            spec, _make_record(timing_minflt_delta=0, timing_majflt_delta=0)
        )
        self.assertTrue(ok_pass, reasons_pass)

        ok_missing, reasons_missing = validate_case_record(
            spec, _make_record(timing_minflt_delta=None, timing_majflt_delta=None)
        )
        self.assertFalse(ok_missing)
        self.assertTrue(any("missing timing-window" in r for r in reasons_missing))

        ok_nz, reasons_nz = validate_case_record(
            spec, _make_record(timing_minflt_delta=3, timing_majflt_delta=0)
        )
        self.assertFalse(ok_nz)
        self.assertTrue(any("timing-window page faults=3" in r for r in reasons_nz))

    def test_kernelet_stats_checks(self) -> None:
        st = SandboxStats(
            pt_mode=0, vcpus=2, grant_mb=512, exit_kind=0, exit_code=0, exit_msg="ok",
            fpu_saves=5, fpu_restores=5, vm_creates=4, vm_destroys=3, vm_flushes=0,
            vm_maps=0, vm_protects=0, vm_unmaps=0, exceptions=0, page_faults=40000,
            virqs=0, forced_yields=0, non_sysret=2, syscalls=None,
        )
        ok, reasons = validate_case_record(
            _make_spec(min_minor_faults=32768, require_vm_balance=True, max_fpu_saves=0, max_non_sysret=0),
            _make_record(target="K", minflt_delta=0, sandbox_stats=st),
        )
        self.assertFalse(ok)
        self.assertTrue(any("VmSpace leak" in r for r in reasons))
        self.assertTrue(any("minor faults" in r for r in reasons))
        self.assertTrue(any("FPU" in r for r in reasons))
        self.assertTrue(any("non-SYSRET" in r for r in reasons))
        self.assertTrue(any("syscalls counter" in r for r in reasons))

    def test_rejects_missing_thp_missing_k_stats_and_zero_metric(self) -> None:
        ok, reasons = validate_case_record(
            _make_spec(forbid_thp=True),
            _make_record(target="L", thp_fault_alloc_delta=None, value=0.0),
        )
        self.assertFalse(ok)
        self.assertTrue(any("thp_fault_alloc" in r for r in reasons))
        self.assertTrue(any("non-positive" in r for r in reasons))

        ok_k, reasons_k = validate_case_record(
            _make_spec(),
            _make_record(target="K", sandbox_stats=None),
        )
        self.assertFalse(ok_k)
        self.assertTrue(any("STATS_JSON" in r for r in reasons_k))
        self.assertTrue(any("HOST_CASE_META" in r for r in reasons_k))

    def test_host_thp_grant_reclamation_and_timing_stage_gates(self) -> None:
        st_ok = SandboxStats(
            pt_mode=0, vcpus=2, grant_mb=512, exit_kind=0, exit_code=0, exit_msg="",
            fpu_saves=0, fpu_restores=0, vm_creates=1, vm_destroys=1, vm_flushes=0,
            vm_maps=0, vm_protects=0, vm_unmaps=0, exceptions=0, page_faults=40000,
            virqs=0, forced_yields=0, non_sysret=0, syscalls=0,
            grant_grains_allocated=256, grant_grains_freed=256,
        )
        hm_ok = HostCaseMeta(
            case_id="mm.wis.pf_anon.p1",
            host_thp_obs_ok=True,
            host_thp_policy="always madvise [never]",
            host_thp_fault_alloc_delta=0,
            grant_accounting_ok=True,
            live_sandboxes=0,
            live_grant_grains=0,
            live_meta_pages=0,
            live_kstack_pages=0,
            live_shared_pages=0,
        )
        ok, reasons = validate_case_record(
            _make_spec(forbid_thp=True, timing_stage_index=1, min_timing_stage_faults=1024),
            _make_record(
                target="K",
                thp_fault_alloc_delta=None,
                thp_policy=None,
                sandbox_stats=st_ok,
                host_meta=hm_ok,
                timing_stages=[
                    TimingStage(True, 1, 0, 0),
                    TimingStage(True, 5, 2048, 0),
                ],
            ),
        )
        self.assertTrue(ok, reasons)

        # Fail closed when live grant grains remain > 0 or host THP > 0.
        hm_leak = HostCaseMeta(
            case_id="mm.wis.pf_anon.p1",
            host_thp_obs_ok=True,
            host_thp_policy="[always] madvise never",
            host_thp_fault_alloc_delta=2,
            grant_accounting_ok=True,
            live_sandboxes=0,
            live_grant_grains=1,
            live_meta_pages=0,
            live_kstack_pages=0,
            live_shared_pages=0,
        )
        ok_leak, reasons_leak = validate_case_record(
            _make_spec(forbid_thp=True, timing_stage_index=1, min_timing_stage_faults=1024),
            _make_record(
                target="K",
                thp_fault_alloc_delta=None,
                sandbox_stats=st_ok,
                host_meta=hm_leak,
                timing_stages=[
                    TimingStage(True, 1, 0, 0),
                    TimingStage(True, 1, 100, 0),
                ],
            ),
        )
        self.assertFalse(ok_leak)
        self.assertTrue(any("host THP allocation occurred" in r for r in reasons_leak))
        self.assertTrue(any("unreclaimed endovisor resources" in r for r in reasons_leak))
        self.assertTrue(any("insufficient timing stage 1" in r for r in reasons_leak))

    def test_skipped_record_passes(self) -> None:
        ok, reasons = validate_case_record(
            _make_spec(min_minor_faults=100),
            _make_record(rc=-1, value=None, skipped=True, skip_reason="not observable"),
        )
        self.assertTrue(ok, reasons)


if __name__ == "__main__":
    unittest.main()
