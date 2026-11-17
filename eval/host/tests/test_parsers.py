import unittest

from host.parsers import parse_case_output


class ParserTests(unittest.TestCase):
    def test_lmbench_latency_stderr(self) -> None:
        val = parse_case_output("lmbench_latency", "", "Simple syscall: 0.1423 microseconds\n")
        self.assertAlmostEqual(val, 0.1423)

    def test_lmbench_lat_mmap(self) -> None:
        val = parse_case_output("lmbench_latency", "", "64.0000 1832.5\n")
        self.assertAlmostEqual(val, 1832.5)

    def test_lmbench_bandwidth(self) -> None:
        val = parse_case_output("lmbench_bandwidth", "", "64.000000 19842.15\n")
        self.assertAlmostEqual(val, 19842.15)

    def test_will_it_scale_average(self) -> None:
        sample = (
            "warmup\n"
            "min:100 max:200 total:300\n"
            "average:1458291\n"
        )
        self.assertAlmostEqual(parse_case_output("will_it_scale_ops", sample, ""), 1458291.0)

    def test_vdso_selfcheck(self) -> None:
        out = "VDSO_SELFCHECK iters=100000 clock_gettime_syscalls=0 gettimeofday_syscalls=0\n"
        self.assertEqual(parse_case_output("vdso_selfcheck", out, ""), 0.0)

    def test_stress_ng_metrics_brief(self) -> None:
        err = (
            "stress-ng: info:  [123] stressor       bogo ops real time  usr time  sys time   bogo ops/s     bogo ops/s\n"
            "stress-ng: info:  [123] cow               41250      5.00      1.20      3.75      8250.00      8333.33\n"
        )
        self.assertAlmostEqual(parse_case_output("stress_ng_bogo_ops", "", err), 8250.0)

    def test_invalid_output_raises(self) -> None:
        with self.assertRaises(ValueError):
            parse_case_output("will_it_scale_ops", "no metrics here", "")


if __name__ == "__main__":
    unittest.main()
