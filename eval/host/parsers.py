from __future__ import annotations

import math
import re


_LMBENCH_COLON_RE = re.compile(
    r":\s*([0-9]+(?:\.[0-9]+)?)\s*(?:microseconds|us|usecs)\b",
    re.IGNORECASE,
)
_TWO_FLOAT_RE = re.compile(
    r"^\s*([0-9]+(?:\.[0-9]+)?)\s+([0-9]+(?:\.[0-9]+)?)\s*$"
)
_WIS_AVERAGE_RE = re.compile(r"\baverage\s*:\s*([0-9]+(?:\.[0-9]+)?)", re.IGNORECASE)
_VDSO_RE = re.compile(
    r"VDSO_SELFCHECK\b.*?\bclock_gettime_syscalls=(\d+)\b.*?\bgettimeofday_syscalls=(\d+)\b"
)
_STRESS_NG_ROW_RE = re.compile(
    r"stress-ng:\s*(?:info|metrc):\s*\[\d+\]\s+\S+\s+"
    r"[0-9]+\s+[0-9]+(?:\.[0-9]+)?\s+[0-9]+(?:\.[0-9]+)?\s+[0-9]+(?:\.[0-9]+)?\s+"
    r"([0-9]+(?:\.[0-9]+)?)"
)


def _combined_lines(stdout: str, stderr: str) -> list[str]:
    return (stdout + "\n" + stderr).splitlines()


def parse_lmbench_latency(stdout: str, stderr: str) -> float:
    """Parse LMbench latency output (e.g. 'Simple syscall: 0.1234 microseconds' or '64.00 1234.5')."""
    combined = stdout + "\n" + stderr
    m = _LMBENCH_COLON_RE.search(combined)
    if m:
        return float(m.group(1))

    # Tools like `lat_mmap` print `<size_mb> <latency_us>` on a single line.
    for line in reversed(_combined_lines(stdout, stderr)):
        m2 = _TWO_FLOAT_RE.match(line)
        if m2:
            return float(m2.group(2))

    raise ValueError(f"failed to parse LMbench latency from output: {combined!r}")


def parse_lmbench_bandwidth(stdout: str, stderr: str) -> float:
    """Parse LMbench bandwidth output ('<size_mb> <MB/s>')."""
    for line in reversed(_combined_lines(stdout, stderr)):
        m = _TWO_FLOAT_RE.match(line)
        if m:
            return float(m.group(2))
    raise ValueError(
        f"failed to parse LMbench bandwidth from output: {(stdout + stderr)!r}"
    )


def parse_will_it_scale_ops(stdout: str, stderr: str) -> float:
    """Parse will-it-scale steady-state 'average:<ops/s>' line."""
    combined = stdout + "\n" + stderr
    matches = _WIS_AVERAGE_RE.findall(combined)
    if not matches:
        raise ValueError(f"failed to parse will-it-scale average from output: {combined!r}")
    return float(matches[-1])


def parse_vdso_selfcheck(stdout: str, stderr: str) -> float:
    """Parse vdso_selfcheck output and return total unexpected syscalls."""
    combined = stdout + "\n" + stderr
    m = _VDSO_RE.search(combined)
    if not m:
        raise ValueError(f"failed to parse VDSO_SELFCHECK from output: {combined!r}")
    return float(int(m.group(1)) + int(m.group(2)))


def parse_noop_rc(stdout: str, stderr: str) -> float:
    """Parser for noop baseline command; returns 0.0."""
    _ = (stdout, stderr)
    return 0.0


def parse_stress_ng_bogo_ops(stdout: str, stderr: str) -> float:
    """Parse stress-ng --metrics-brief real-time bogo ops/s."""
    combined = stdout + "\n" + stderr
    matches = _STRESS_NG_ROW_RE.findall(combined)
    if not matches:
        raise ValueError(f"failed to parse stress-ng metrics from output: {combined!r}")
    return float(matches[-1])


PARSERS = {
    "lmbench_latency": parse_lmbench_latency,
    "lmbench_bandwidth": parse_lmbench_bandwidth,
    "will_it_scale_ops": parse_will_it_scale_ops,
    "vdso_selfcheck": parse_vdso_selfcheck,
    "noop_rc": parse_noop_rc,
    "stress_ng_bogo_ops": parse_stress_ng_bogo_ops,
}


def parse_case_output(parser_name: str, stdout: str, stderr: str) -> float:
    """Dispatch to a named parser and validate the parsed numeric value."""
    if parser_name not in PARSERS:
        raise KeyError(f"unknown parser: {parser_name!r}")
    val = PARSERS[parser_name](stdout, stderr)
    if not math.isfinite(val) or val < 0.0:
        raise ValueError(f"parser {parser_name!r} returned invalid value {val!r}")
    return val
