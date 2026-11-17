"""Tests for report.py, perf_sym.py, and cli.py gate invariants."""

from pathlib import Path
import tempfile
import unittest

from host.cli import _linux_mitigation_cmdline, _verify_batch_completeness, build_parser
from host.perf_sym import (
    GuestSymbol,
    parse_perf_script_stacks,
    parse_readelf_module_symbols,
    parse_readelf_pie_symbols,
    relocate_vmlinux_symbols,
    render_flamegraph_svg,
    render_profile_report_markdown,
    symbolize_folded_addr_stacks,
    synthesize_guest_kallsyms,
)
from host.report import (
    render_calibrated_stats_csv,
    render_calibrated_stats_markdown,
    render_csv_report,
    render_markdown_report,
    schedule_rounds,
)
from host.schema import CaseRecord, CaseSpec, InvariantSpec, SandboxStats


class ReportAndPerfSymTests(unittest.TestCase):
    def test_schedule_rounds_deterministic(self) -> None:
        s1 = schedule_rounds(["L", "A", "K"], 5, 20261116)
        s2 = schedule_rounds(["L", "A", "K"], 5, 20261116)
        self.assertEqual(s1, s2)
        self.assertEqual(len(s1), 5)
        for row in s1:
            self.assertEqual(sorted(row), ["A", "K", "L"])

    def test_cli_forbids_skip_selfcheck(self) -> None:
        parser = build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["run", "--skip-selfcheck"])

    def test_render_markdown_and_csv_fail_closed_on_invalid_or_incomplete(self) -> None:
        spec = CaseSpec(
            case_id="sys.lm.null",
            group="syscall",
            suite="lmbench",
            binary="/bin/lat_syscall",
            args=("-P", "1", "null"),
            cpus=(0,),
            tmpfiles=(),
            parser="lmbench_latency",
            unit="us/op",
            higher_is_better=False,
            invariants=InvariantSpec(),
        )
        recs = [
            CaseRecord(1, "L", "sys.lm.null", 0, 100, 0, 0, 1, 1, 0, 0, False, 0, "", "", 0.10, "us/op", True),
            CaseRecord(1, "A", "sys.lm.null", 0, 100, 0, 0, 1, 1, 0, 0, False, -1, "", "", 0.20, "us/op", True),
            CaseRecord(1, "K", "sys.lm.null", 0, 100, 0, 0, 1, 1, 0, 0, False, -1, "", "", 0.30, "us/op", True),
        ]
        md = render_markdown_report({"sys.lm.null": spec}, recs, ["L", "A", "K"], expected_rounds=1)
        self.assertIn("sys.lm.null", md)
        self.assertIn("3.00x", md)
        self.assertIn("1.50x", md)
        csv_text = render_csv_report({"sys.lm.null": spec}, recs, ["L", "A", "K"], expected_rounds=1)
        self.assertIn("sys.lm.null,syscall,lmbench,K,us/op,False,OK,1,0.300000", csv_text)

        # If round 2 on K is invalid, K must NOT be reported as OK from round 1 alone.
        recs_bad = recs + [
            CaseRecord(2, "L", "sys.lm.null", 0, 100, 0, 0, 1, 1, 0, 0, False, 0, "", "", 0.10, "us/op", True),
            CaseRecord(2, "A", "sys.lm.null", 0, 100, 0, 0, 1, 1, 0, 0, False, -1, "", "", 0.20, "us/op", True),
            CaseRecord(2, "K", "sys.lm.null", 1, 100, 0, 0, 1, 1, 0, 0, False, -1, "", "", None, "us/op", False, ["rc=1"]),
        ]
        md_bad = render_markdown_report({"sys.lm.null": spec}, recs_bad, ["L", "A", "K"], expected_rounds=2)
        self.assertIn("RUN STATUS: INVALID / INCOMPLETE", md_bad)
        self.assertIn("INVALID (R2: rc=1)", md_bad)
        csv_bad = render_csv_report({"sys.lm.null": spec}, recs_bad, ["L", "A", "K"], expected_rounds=2)
        self.assertIn("sys.lm.null,syscall,lmbench,K,us/op,False,INVALID:", csv_bad)
        self.assertNotIn("sys.lm.null,syscall,lmbench,K,us/op,False,OK", csv_bad)

        skipped_rec = CaseRecord(
            1, "L", "sys.lm.null", -1, 0, 0, 0, 0, 0, -1, -1, False, None, "", "", None, "us/op", True, [], None, True, "no timer window fault obs"
        )
        md_skip = render_markdown_report({"sys.lm.null": spec}, [skipped_rec], ["L"])
        self.assertIn("SKIPPED (no timer window fault obs)", md_skip)
        csv_skip = render_csv_report({"sys.lm.null": spec}, [skipped_rec], ["L"])
        self.assertIn("SKIPPED:no timer window fault obs", csv_skip)

    def test_calibrated_counter_analysis(self) -> None:
        noop_spec = CaseSpec("selfcheck.noop", "selfcheck", "selfcheck", "/bin/true", (), (0,), (), "noop_rc", "rc", False, InvariantSpec())
        null_spec = CaseSpec("sys.lm.null", "syscall", "lmbench", "/bin/lat_syscall", (), (0,), (), "lmbench_latency", "us/op", False, InvariantSpec())
        st_noop = SandboxStats(0, 2, 512, 0, 0, "", 1, 1, 1, 1, 2, 0, 0, 0, 3, 10, 1, 0, 0, 0, 50)
        st_null = SandboxStats(0, 2, 512, 0, 0, "", 1, 1, 2, 2, 3, 0, 0, 0, 5, 12, 2, 1, 0, 0, 1050)
        recs = [
            CaseRecord(1, "K", "selfcheck.noop", 0, 100, 10, 0, 1, 1, 0, 0, False, None, "", "", 0.0, "rc", True, [], st_noop),
            CaseRecord(1, "K", "sys.lm.null", 0, 200, 20, 0, 5, 15, 0, 0, False, None, "", "", 0.25, "us/op", True, [], st_null, timing_minflt_delta=0),
        ]
        cal_md = render_calibrated_stats_markdown({"selfcheck.noop": noop_spec, "sys.lm.null": null_spec}, recs)
        self.assertIn("syscalls (cal)", cal_md)
        cal_csv = render_calibrated_stats_csv({"selfcheck.noop": noop_spec, "sys.lm.null": null_spec}, recs)
        # 1050 - 50 = 1000 calibrated syscalls; 12 - 10 = 2 calibrated page faults.
        self.assertIn("sys.lm.null,K,1,20.0,0.0,5.0,15.0,1000.0,2.0,1.0,0.0,1.0,1.0,0.0", cal_csv)

    def test_perf_sym_kaslr_module_sections_and_flamegraph(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            sysmap = Path(td) / "System.map"
            sysmap.write_text("ffffffff81000000 T _stext\nffffffff81001234 t do_syscall_64\n")
            merged = synthesize_guest_kallsyms(
                vmlinux_system_map=sysmap,
                vmlinux_live_stext=0xFFFFFFFF81000000,
                require_nokaslr=True,
            )
            self.assertIn("ffffffff81000000 T _stext", merged)
            self.assertIn("ffffffff81001234 t do_syscall_64", merged)

            with self.assertRaises(ValueError):
                relocate_vmlinux_symbols(
                    [GuestSymbol(0xFFFFFFFF81000000, "T", "_stext")],
                    0xFFFFFFFF91000000,
                    require_nokaslr=True,
                )
            slid = relocate_vmlinux_symbols(
                [GuestSymbol(0xFFFFFFFF81000000, "T", "_stext"), GuestSymbol(0xFFFFFFFF81001000, "t", "foo")],
                0xFFFFFFFF91000000,
                require_nokaslr=False,
            )
            self.assertEqual(slid[1].addr, 0xFFFFFFFF91001000)

        sec_text = (
            "  [ 1] .text             PROGBITS        0000000000000000 000100 001000 00  AX  0   0 16\n"
            "  [ 2] .text.unlikely    PROGBITS        0000000000000000 001100 000200 00  AX  0   0  1\n"
            "  [ 3] .init.text        PROGBITS        0000000000000000 001300 000100 00  AX  0   0 16\n"
        )
        sym_text = (
            "   1: 0000000000000010   64 FUNC    GLOBAL DEFAULT    1 run_sandbox\n"
            "   2: 0000000000000040   32 FUNC    LOCAL  DEFAULT    2 carrier_cold_die\n"
            "   3: 0000000000000020   32 FUNC    LOCAL  DEFAULT    3 init_endovisor\n"
        )
        with self.assertRaises(ValueError):
            # Missing `.text.unlikely` must fail closed under strict_exec_sections.
            parse_readelf_module_symbols(
                sec_text,
                sym_text,
                {".text": 0xFFFFFFFFC0001000},
                strict_exec_sections=True,
            )

        syms = parse_readelf_module_symbols(
            sec_text,
            sym_text,
            {
                ".text": 0xFFFFFFFFC0001000,
                ".text.unlikely": 0xFFFFFFFFC0010000,
                ".init.text": 0xFFFFFFFFC0020000,
            },
        )
        by_name = {s.name: s for s in syms}
        self.assertEqual(by_name["run_sandbox"].addr, 0xFFFFFFFFC0001010)
        self.assertEqual(by_name["carrier_cold_die"].addr, 0xFFFFFFFFC0010040)
        self.assertEqual(by_name["init_endovisor"].addr, 0xFFFFFFFFC0020020)

        pie_syms = parse_readelf_pie_symbols(
            "   4: 0000000000004000  128 FUNC    GLOBAL DEFAULT   10 aster_syscall\n",
            0xFFFF800000100000,
        )
        self.assertEqual(pie_syms[0].addr, 0xFFFF800000104000)

        ks_for_script = (
            "ffffffff81001234 t do_syscall_64\n"
            "ffffffffc0001010 T run_sandbox\t[endovisor]\n"
            "ffff800000104000 T ostd_user_event\t[kernelet]\n"
            "ffff800000108000 T aster_sys_getpid\t[kernelet]\n"
        )
        script_sample = (
            "qemu-system-x86 1234 [000] 10.000: 1000 cycles:\n"
            "    ffff800000108020 [unknown] ([guest.kernel])\n"
            "    ffff800000104010 [unknown] ([guest.kernel])\n"
            "    ffffffffc0001020 [unknown] ([guest.kernel])\n"
            "    ffffffff81001240 do_syscall_64 ([guest.kernel])\n\n"
        )
        folded, layers, self_counts = parse_perf_script_stacks(script_sample, ks_for_script)
        self.assertEqual(layers["aster_core"], 1000)
        self.assertEqual(self_counts[("aster_core", "aster_sys_getpid")], 1000)
        md_prof = render_profile_report_markdown(layers, self_counts)
        self.assertIn("`aster_core` | 1000 | 100.00%", md_prof)
        svg = render_flamegraph_svg(folded, title="Test FG")
        self.assertIn("<svg", svg)
        self.assertIn("aster_sys_getpid", svg)

        self.assertEqual(_linux_mitigation_cmdline("perf-base"), "mitigations=off")
        self.assertEqual(_linux_mitigation_cmdline("perf-pti"), "pti=on")

        spec = CaseSpec(
            case_id="c1",
            group="g",
            suite="s",
            binary="/b",
            args=(),
            cpus=(0,),
            tmpfiles=(),
            parser="noop_rc",
            unit="rc",
            higher_is_better=False,
            invariants=InvariantSpec(),
        )
        with self.assertRaises(RuntimeError):
            _verify_batch_completeness([], round_idx=1, target="L", runnable_specs={"c1": spec})

        # require_nokaslr=True must fail closed if live_stext is None.
        with self.assertRaises(ValueError):
            relocate_vmlinux_symbols(
                [GuestSymbol(0xFFFFFFFF81000000, "T", "_stext")],
                None,
                require_nokaslr=True,
            )

        # Isolated endovisor address callchain symbolization across all 4 layers.
        gf, glayers, gself = symbolize_folded_addr_stacks(
            ["0xffffffff81001240;0xffffffffc0001020;0xffff800000104010;0xffff800000108020 5"],
            ks_for_script,
        )
        self.assertEqual(glayers["aster_core"], 5)
        self.assertEqual(gself[("aster_core", "aster_sys_getpid")], 5)
        self.assertTrue(any("[vmlinux] do_syscall_64;[endovisor] run_sandbox;[vostd] ostd_user_event;[aster_core] aster_sys_getpid" in k for k in gf))


if __name__ == "__main__":
    unittest.main()
