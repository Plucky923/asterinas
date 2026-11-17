from pathlib import Path
import unittest

from host.schema import load_cases_toml


CASES_TOML = Path(__file__).resolve().parents[2] / "configs" / "cases.toml"


class SchemaTests(unittest.TestCase):
    def test_load_repo_cases_toml(self) -> None:
        suite = load_cases_toml(CASES_TOML)
        self.assertEqual(suite.defaults.grant_mb, 512)
        self.assertEqual(suite.defaults.vcpus, 2)
        self.assertEqual(suite.defaults.rounds, 5)
        self.assertIn("selfcheck.vdso", suite.cases)
        self.assertIn("selfcheck.noop", suite.cases)
        self.assertIn("sys.lm.null", suite.cases)
        self.assertIn("mm.wis.pf_anon.p1", suite.cases)
        self.assertIn("mm.lm.pf_lat", suite.cases)
        pf_lat = suite.cases["mm.lm.pf_lat"]
        self.assertIsNone(pf_lat.auto_skip_reason)
        self.assertEqual(pf_lat.invariants.timing_stage_index, 1)
        self.assertEqual(pf_lat.invariants.min_timing_stage_faults, 1024)
        self.assertIn("mm.sng.cow", suite.cases)
        self.assertIsNotNone(suite.cases["mm.sng.cow"].auto_skip_reason)
        self.assertIn("mm.stress.fork.p1", suite.cases)
        self.assertIn("mm.stress.fork.p2", suite.cases)
        self.assertIn("mm.stress.vm.p1", suite.cases)
        self.assertEqual(suite.cases["mm.stress.vm.p2"].args[3], "128M")
        self.assertIn("mm.stress.mprotect.p1", suite.cases)
        self.assertIn("mm.stress.mmap_mprotect.p1", suite.cases)
        self.assertEqual(suite.cases["mm.stress.mmap_mprotect.p2"].args[3], "128M")
        self.assertEqual(suite.cases["sys.lm.read"].invariants.max_timing_faults, 0)
        self.assertEqual(suite.cases["sys.lm.write"].invariants.max_timing_faults, 0)
        self.assertEqual(suite.cases["mm.lm.bw_mem.rd"].invariants.max_timing_faults, 0)
        sys_null = suite.cases["sys.lm.null"]
        self.assertEqual(sys_null.invariants.max_fpu_saves, 0)
        self.assertEqual(sys_null.invariants.max_non_sysret, 0)
        exec_case = suite.cases["sys.lm.exec"]
        self.assertEqual(exec_case.verify_exec, "/tmp/hello")
        self.assertEqual(exec_case.copy_files[0].dst, "/tmp/hello")
        pf1 = suite.cases["mm.wis.pf_anon.p1"]
        self.assertEqual(pf1.invariants.min_minor_faults, 32768)
        self.assertTrue(pf1.invariants.forbid_thp)


if __name__ == "__main__":
    unittest.main()
