"""Host-side `perf kvm --guestkallsyms=...` symbol table synthesizer, stack attribution, and flamegraph generator."""

from __future__ import annotations

import bisect
from dataclasses import dataclass
import html
from pathlib import Path
import re
import subprocess


@dataclass(frozen=True)
class GuestSymbol:
    addr: int
    sym_type: str
    name: str
    module: str = ""


_KALLSYMS_LINE_RE = re.compile(r"^\s*([0-9a-fA-F]+)\s+([a-zA-Z?])\s+(\S+)(?:\s+\[(\S+)\])?")
_SECTION_RE = re.compile(r"^\s*\[\s*(\d+)\]\s+(\S+)\s+\S+\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+\S+\s+(\S*)")
_SYMTAB_RE = re.compile(
    r"^\s*\d+:\s+([0-9a-fA-F]+)\s+\d+\s+(\S+)\s+(\S+)\s+\S+\s+(\S+)\s+(\S+)"
)
_SCRIPT_HEADER_RE = re.compile(r"^\S+\s+\d+\s+(?:\[\d+\]\s+)?[0-9.]+:\s+(\d+)?\s*[^:]+:")
_SCRIPT_FRAME_RE = re.compile(r"^\s*([0-9a-fA-F]+)\s+(\S+)(?:\s+\(([^)]+)\))?")


def parse_kallsyms_text(text: str) -> list[GuestSymbol]:
    """Parse `/proc/kallsyms` or `System.map` formatted lines."""
    symbols: list[GuestSymbol] = []
    for line in text.splitlines():
        m = _KALLSYMS_LINE_RE.match(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        sym_type = m.group(2)
        name = m.group(3)
        mod = m.group(4) or ""
        symbols.append(GuestSymbol(addr=addr, sym_type=sym_type, name=name, module=mod))
    return symbols


def relocate_vmlinux_symbols(
    symbols: list[GuestSymbol],
    live_stext: int | None,
    *,
    require_nokaslr: bool = False,
) -> list[GuestSymbol]:
    """Verify or relocate vmlinux System.map symbols against live `_stext`."""
    if live_stext is None:
        if require_nokaslr:
            raise ValueError(
                "missing live '_stext' address required for KASLR/nokaslr verification"
            )
        return symbols
    stext_syms = [s for s in symbols if s.name == "_stext" and not s.module]
    if not stext_syms:
        raise ValueError("System.map missing '_stext' symbol required for KASLR verification")
    map_stext = stext_syms[0].addr
    slide = live_stext - map_stext
    if require_nokaslr and slide != 0:
        raise ValueError(
            f"KASLR active despite nokaslr: live _stext=0x{live_stext:x} != System.map 0x{map_stext:x}"
        )
    if slide == 0:
        return symbols
    relocated: list[GuestSymbol] = []
    for s in symbols:
        # Per-CPU offsets live around 0x0..0x100000 and are not KASLR-slid virtual addresses.
        if s.addr >= 0xFFFFFFFF00000000:
            relocated.append(
                GuestSymbol(addr=s.addr + slide, sym_type=s.sym_type, name=s.name, module=s.module)
            )
        else:
            relocated.append(s)
    return relocated


def parse_readelf_sections(readelf_s_text: str) -> dict[str, tuple[str, str]]:
    """Parse `readelf -S -W` output into section index -> (name, flags)."""
    sections: dict[str, tuple[str, str]] = {}
    for line in readelf_s_text.splitlines():
        m = _SECTION_RE.match(line)
        if m:
            sections[m.group(1)] = (m.group(2), m.group(3))
    return sections


def parse_readelf_module_symbols(
    readelf_sec_text: str,
    readelf_sym_text: str,
    section_bases: dict[str, int],
    *,
    module_name: str = "endovisor",
    strict_exec_sections: bool = True,
) -> list[GuestSymbol]:
    """Relocate ET_REL kernel module symbols using per-section live load addresses."""
    sec_by_idx = parse_readelf_sections(readelf_sec_text)
    symbols: list[GuestSymbol] = []
    missing_exec_sections: set[str] = set()
    for line in readelf_sym_text.splitlines():
        m = _SYMTAB_RE.match(line)
        if not m:
            continue
        val = int(m.group(1), 16)
        sym_type_name = m.group(2)
        bind = m.group(3)
        ndx = m.group(4)
        name = m.group(5)
        if sym_type_name != "FUNC" or ndx in ("UND", "ABS", "COM"):
            continue
        sec_info = sec_by_idx.get(ndx)
        if not sec_info:
            continue
        sec_name, sec_flags = sec_info
        if sec_name not in section_bases:
            # `.init.text` and `.exit.text` may be omitted at runtime after module init,
            # while `.text`, `.text.unlikely`, etc. carry live runtime functions.
            if "X" in sec_flags and sec_name not in (".init.text", ".exit.text"):
                missing_exec_sections.add(sec_name)
            continue
        ktype = "T" if bind == "GLOBAL" else "t"
        symbols.append(
            GuestSymbol(
                addr=section_bases[sec_name] + val,
                sym_type=ktype,
                name=name,
                module=module_name,
            )
        )
    if strict_exec_sections and missing_exec_sections:
        raise ValueError(
            f"missing load addresses for executable {module_name} sections with FUNC symbols: "
            + ", ".join(sorted(missing_exec_sections))
        )
    return symbols


def parse_readelf_pie_symbols(
    readelf_sym_text: str,
    load_base: int,
    *,
    module_name: str = "kernelet",
) -> list[GuestSymbol]:
    """Relocate ET_DYN PIE image function symbols by `load_base`."""
    symbols: list[GuestSymbol] = []
    for line in readelf_sym_text.splitlines():
        m = _SYMTAB_RE.match(line)
        if not m:
            continue
        val = int(m.group(1), 16)
        sym_type_name = m.group(2)
        bind = m.group(3)
        ndx = m.group(4)
        name = m.group(5)
        if sym_type_name != "FUNC" or ndx in ("UND", "ABS", "COM"):
            continue
        ktype = "T" if bind == "GLOBAL" else "t"
        symbols.append(
            GuestSymbol(
                addr=load_base + val,
                sym_type=ktype,
                name=name,
                module=module_name,
            )
        )
    return symbols


def _run_readelf(flag: str, binary_path: Path) -> str:
    return subprocess.check_output(
        ["readelf", flag, "-W", str(binary_path)],
        text=True,
    )


def format_kallsyms(symbols: list[GuestSymbol]) -> str:
    """Format symbols as Linux `/proc/kallsyms` lines."""
    ordered = sorted(symbols, key=lambda s: (s.addr, s.name))
    lines: list[str] = []
    for s in ordered:
        if s.module:
            lines.append(f"{s.addr:016x} {s.sym_type} {s.name}\t[{s.module}]")
        else:
            lines.append(f"{s.addr:016x} {s.sym_type} {s.name}")
    return "\n".join(lines) + ("\n" if lines else "")


def synthesize_guest_kallsyms(
    *,
    vmlinux_system_map: Path,
    vmlinux_live_stext: int | None = None,
    require_nokaslr: bool = False,
    endovisor_ko: Path | None = None,
    endovisor_section_bases: dict[str, int] | None = None,
    kernelet_image: Path | None = None,
    kernelet_load_base: int | None = None,
    strict_exec_sections: bool = True,
) -> str:
    """Merge relocated vmlinux System.map, all endovisor.ko sections, and PIE kernelet-image.elf."""
    all_syms: list[GuestSymbol] = relocate_vmlinux_symbols(
        parse_kallsyms_text(vmlinux_system_map.read_text(encoding="utf-8")),
        vmlinux_live_stext,
        require_nokaslr=require_nokaslr,
    )

    if endovisor_ko is not None and endovisor_section_bases:
        all_syms.extend(
            parse_readelf_module_symbols(
                _run_readelf("-S", endovisor_ko),
                _run_readelf("-s", endovisor_ko),
                endovisor_section_bases,
                module_name="endovisor",
                strict_exec_sections=strict_exec_sections,
            )
        )

    if kernelet_image is not None and kernelet_load_base is not None:
        all_syms.extend(
            parse_readelf_pie_symbols(
                _run_readelf("-s", kernelet_image),
                kernelet_load_base,
                module_name="kernelet",
            )
        )

    return format_kallsyms(all_syms)


def classify_symbol_layer(symbol_name: str, module_name: str = "") -> str:
    """Classify a symbol into vmlinux, endovisor, vostd, aster_core, or host/user."""
    mod = module_name.strip("[]")
    if mod == "endovisor":
        return "endovisor"
    if mod == "kernelet" or "ostd" in symbol_name or "aster_" in symbol_name:
        if "ostd" in symbol_name:
            return "vostd"
        return "aster_core"
    if "[guest.kernel]" in mod or mod == "vmlinux" or mod == "":
        return "vmlinux"
    return "other"


def _resolve_symbol(
    addr: int,
    fallback_name: str,
    fallback_mod: str,
    sorted_addrs: list[int],
    sorted_syms: list[GuestSymbol],
) -> tuple[str, str]:
    if addr and sorted_addrs:
        idx = bisect.bisect_right(sorted_addrs, addr) - 1
        if idx >= 0:
            sym = sorted_syms[idx]
            if addr - sym.addr < 0x100000:
                return sym.name, sym.module
    return fallback_name, fallback_mod


def parse_perf_script_stacks(
    script_text: str,
    kallsyms_text: str = "",
) -> tuple[dict[str, int], dict[str, int], dict[tuple[str, str], int]]:
    """Aggregate `perf kvm script` samples into folded stacks, layer totals, and self-symbol counts."""
    syms = [s for s in parse_kallsyms_text(kallsyms_text) if s.addr > 0]
    syms.sort(key=lambda s: s.addr)
    sorted_addrs = [s.addr for s in syms]

    folded: dict[str, int] = {}
    layer_counts: dict[str, int] = {}
    self_counts: dict[tuple[str, str], int] = {}

    cur_frames: list[tuple[str, str]] = []
    cur_weight = 1
    in_sample = False

    def _flush() -> None:
        nonlocal cur_frames, in_sample
        if not in_sample or not cur_frames:
            cur_frames = []
            in_sample = False
            return
        # `perf script` prints leaf first, root last -> reverse for flamegraph folded stacks.
        leaf_name, leaf_layer = cur_frames[0]
        layer_counts[leaf_layer] = layer_counts.get(leaf_layer, 0) + cur_weight
        self_counts[(leaf_layer, leaf_name)] = (
            self_counts.get((leaf_layer, leaf_name), 0) + cur_weight
        )
        stack_key = ";".join(f"[{layer}] {name}" for name, layer in reversed(cur_frames))
        folded[stack_key] = folded.get(stack_key, 0) + cur_weight
        cur_frames = []
        in_sample = False

    for line in script_text.splitlines():
        if not line.strip():
            _flush()
            continue
        hm = _SCRIPT_HEADER_RE.match(line)
        if hm and not line[0].isspace():
            _flush()
            in_sample = True
            cur_weight = int(hm.group(1)) if hm.group(1) else 1
            continue
        if in_sample:
            fm = _SCRIPT_FRAME_RE.match(line)
            if fm:
                addr = int(fm.group(1), 16)
                raw_name = fm.group(2).split("+")[0]
                raw_mod = fm.group(3) or ""
                sym_name, sym_mod = _resolve_symbol(
                    addr, raw_name, raw_mod, sorted_addrs, syms
                )
                layer = classify_symbol_layer(sym_name, sym_mod)
                cur_frames.append((sym_name, layer))
    _flush()
    return folded, layer_counts, self_counts


def symbolize_folded_addr_stacks(
    folded_lines: list[str],
    kallsyms_text: str = "",
) -> tuple[dict[str, int], dict[str, int], dict[tuple[str, str], int]]:
    """Symbolize folded `0xroot;...;0xleaf count` lines from endovisor's isolated sampler."""
    syms = [s for s in parse_kallsyms_text(kallsyms_text) if s.addr > 0]
    syms.sort(key=lambda s: s.addr)
    sorted_addrs = [s.addr for s in syms]

    folded: dict[str, int] = {}
    layer_counts: dict[str, int] = {}
    self_counts: dict[tuple[str, str], int] = {}

    for raw in folded_lines:
        s = raw.strip()
        if not s:
            continue
        parts = s.rsplit(None, 1)
        if len(parts) == 2 and parts[1].isdigit():
            stack_str, weight = parts[0], int(parts[1])
        else:
            stack_str, weight = s, 1
        raw_addrs = [tok.strip() for tok in stack_str.split(";") if tok.strip()]
        if not raw_addrs:
            continue
        named_frames: list[tuple[str, str]] = []
        for tok in raw_addrs:
            try:
                addr = int(tok, 16)
            except ValueError:
                named_frames.append((tok, "other"))
                continue
            sym_name, sym_mod = _resolve_symbol(
                addr, f"0x{addr:x}", "", sorted_addrs, syms
            )
            layer = classify_symbol_layer(sym_name, sym_mod)
            named_frames.append((sym_name, layer))
        leaf_name, leaf_layer = named_frames[-1]
        layer_counts[leaf_layer] = layer_counts.get(leaf_layer, 0) + weight
        self_counts[(leaf_layer, leaf_name)] = (
            self_counts.get((leaf_layer, leaf_name), 0) + weight
        )
        stack_key = ";".join(f"[{layer}] {name}" for name, layer in named_frames)
        folded[stack_key] = folded.get(stack_key, 0) + weight

    return folded, layer_counts, self_counts


def render_profile_report_markdown(
    layer_counts: dict[str, int],
    self_counts: dict[tuple[str, str], int],
    *,
    title: str = "Kernelet Host `perf kvm` Profile Breakdown",
    top_n: int = 30,
) -> str:
    """Render layer-level and per-symbol CPU sample distribution as Markdown."""
    total = sum(layer_counts.values())
    lines = [f"# {title}", "", f"- Total samples: `{total}`", ""]
    lines.extend(["## Breakdown by Layer", "", "| Layer | Samples | Share |", "|---|---:|---:|"])
    for layer in ("vmlinux", "endovisor", "vostd", "aster_core", "other"):
        cnt = layer_counts.get(layer, 0)
        pct = (100.0 * cnt / total) if total > 0 else 0.0
        lines.append(f"| `{layer}` | {cnt} | {pct:.2f}% |")
    lines.extend(["", f"## Top {top_n} Leaf Symbols", "", "| Layer | Symbol | Samples | Share |", "|---|---|---:|---:|"])
    for (layer, name), cnt in sorted(self_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:top_n]:
        pct = (100.0 * cnt / total) if total > 0 else 0.0
        lines.append(f"| `{layer}` | `{name}` | {cnt} | {pct:.2f}% |")
    lines.append("")
    return "\n".join(lines)


def render_flamegraph_svg(folded_stacks: dict[str, int], *, title: str = "Kernelet Flamegraph") -> str:
    """Render a self-contained SVG flamegraph from folded stack counts."""
    total = sum(folded_stacks.values())
    if total <= 0:
        return (
            '<svg xmlns="http://www.w3.org/2000/svg" width="800" height="80">'
            f'<text x="20" y="45" font-family="monospace" font-size="14">{html.escape(title)}: no samples</text>'
            "</svg>\n"
        )

    max_depth = max(len(k.split(";")) for k in folded_stacks)
    width = 1200
    row_h = 18
    top_pad = 36
    bottom_pad = 16
    height = top_pad + (max_depth + 1) * row_h + bottom_pad

    # Build interval spans per depth level by sorting folded stacks alphabetically.
    active: list[tuple[str, int, int]] = []  # (label, start_sample, end_sample)
    rects: list[tuple[int, int, int, str, int]] = []  # (depth, x0, x1, label, samples)
    cursor = 0
    for stack, weight in sorted(folded_stacks.items()):
        frames = stack.split(";")
        common = 0
        while common < len(active) and common < len(frames) and active[common][0] == frames[common]:
            common += 1
        while len(active) > common:
            lbl, s0, s1 = active.pop()
            rects.append((len(active), s0, s1, lbl, s1 - s0))
        for i in range(common):
            lbl, s0, _ = active[i]
            active[i] = (lbl, s0, cursor + weight)
        for i in range(common, len(frames)):
            active.append((frames[i], cursor, cursor + weight))
        cursor += weight
    while active:
        lbl, s0, s1 = active.pop()
        rects.append((len(active), s0, s1, lbl, s1 - s0))

    layer_colors = {
        "[vmlinux]": "#e68a5c",
        "[endovisor]": "#e0b354",
        "[vostd]": "#6baed6",
        "[aster_core]": "#74c476",
        "[other]": "#bdbdbd",
    }

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#fafafa"/>',
        f'<text x="{width // 2}" y="22" text-anchor="middle" font-family="sans-serif" font-size="16" font-weight="bold">{html.escape(title)} ({total} samples)</text>',
    ]
    usable_w = width - 20
    for depth, s0, s1, lbl, samples in rects:
        x = 10.0 + usable_w * (s0 / total)
        w = max(0.5, usable_w * ((s1 - s0) / total))
        y = height - bottom_pad - (depth + 1) * row_h
        color = "#d9d9d9"
        for prefix, c in layer_colors.items():
            if lbl.startswith(prefix):
                color = c
                break
        pct = 100.0 * samples / total
        tip = html.escape(f"{lbl} ({samples} samples, {pct:.2f}%)")
        parts.append(f'<g><title>{tip}</title>')
        parts.append(
            f'<rect x="{x:.2f}" y="{y}" width="{w:.2f}" height="{row_h - 1}" fill="{color}" stroke="#ffffff" stroke-width="0.5"/>'
        )
        if w > 36:
            max_chars = max(3, int((w - 4) / 6.5))
            short = lbl if len(lbl) <= max_chars else lbl[: max_chars - 2] + ".."
            parts.append(
                f'<text x="{x + 3:.2f}" y="{y + row_h - 5}" font-family="monospace" font-size="10" fill="#111111">{html.escape(short)}</text>'
            )
        parts.append("</g>")
    parts.append("</svg>\n")
    return "\n".join(parts)
