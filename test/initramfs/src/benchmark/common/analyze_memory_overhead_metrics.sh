#!/bin/bash

# SPDX-License-Identifier: MPL-2.0

set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  analyze_memory_overhead_metrics.sh --input <metrics_raw.csv> [options]

Input CSV:
  - Produced by extract_bench_memory_metrics.sh (one row per benchmark run).
  - Must contain columns:
      scenario, workset_bytes
  - Must also contain one of:
      system OR stack
  - Preferred metric column: result
  - Legacy compatibility: cycles_op (and optional cycles_page)

Options:
  --output-dir <dir>            Output directory (default: ./memory_overhead_report).
  --fixed-workset-bytes <n>     Fixed workset used by 4-scenario comparison (default: 536870912).
  --guest-system <name>         CSV system name for Linux Guest (default: linux_guest).
  --container-system <name>     CSV system name for Linux Container (default: linux_container).
  --framevm-system <name>       CSV system name for FrameVM (default: framevm).
  --host-system <name>          CSV system name for Host baseline (default: host).
  --nested-l1-system <name>     CSV system name for Linux L1 in nested analysis (default: linux_l1).
  --nested-l2-system <name>     CSV system name for Linux L2 in nested analysis (default: linux_l2).
  -h, --help                    Show this help.

Generated files:
  metrics_agg.csv
  overhead_summary.csv
  sweep_summary.csv
  ept_amp_by_size.csv
  ept_amp_summary.csv
  nested_fixed_summary.csv
  nested_sweep_by_size.csv
  nested_sweep_summary.csv
EOF
}

input_file=""
output_dir="memory_overhead_report"
fixed_workset_bytes=536870912
guest_system="linux_guest"
container_system="linux_container"
framevm_system="framevm"
host_system="host"
nested_l1_system="linux_l1"
nested_l2_system="linux_l2"

while [ $# -gt 0 ]; do
    case "$1" in
        --input)
            input_file="${2:-}"
            shift 2
            ;;
        --output-dir)
            output_dir="${2:-}"
            shift 2
            ;;
        --fixed-workset-bytes)
            fixed_workset_bytes="${2:-}"
            shift 2
            ;;
        --guest-system)
            guest_system="${2:-}"
            shift 2
            ;;
        --container-system)
            container_system="${2:-}"
            shift 2
            ;;
        --framevm-system)
            framevm_system="${2:-}"
            shift 2
            ;;
        --host-system)
            host_system="${2:-}"
            shift 2
            ;;
        --nested-l1-system)
            nested_l1_system="${2:-}"
            shift 2
            ;;
        --nested-l2-system)
            nested_l2_system="${2:-}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Error: unknown argument '$1'" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [ -z "${input_file}" ]; then
    echo "Error: --input is required." >&2
    usage >&2
    exit 1
fi
if [ ! -f "${input_file}" ]; then
    echo "Error: input CSV not found: ${input_file}" >&2
    exit 1
fi
if ! [[ "${fixed_workset_bytes}" =~ ^[0-9]+$ ]]; then
    echo "Error: --fixed-workset-bytes must be an integer." >&2
    exit 1
fi

mkdir -p "${output_dir}"

agg_csv="${output_dir}/metrics_agg.csv"
overhead_csv="${output_dir}/overhead_summary.csv"
sweep_csv="${output_dir}/sweep_summary.csv"
ept_amp_csv="${output_dir}/ept_amp_by_size.csv"
ept_amp_summary_csv="${output_dir}/ept_amp_summary.csv"
nested_fixed_csv="${output_dir}/nested_fixed_summary.csv"
nested_sweep_csv="${output_dir}/nested_sweep_by_size.csv"
nested_sweep_summary_csv="${output_dir}/nested_sweep_summary.csv"

echo "[1/7] Aggregating medians into: ${agg_csv}"
awk -F',' '
function trim(s) {
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", s);
    return s;
}

function isnum(x) {
    return (x ~ /^-?[0-9]+(\.[0-9]+)?$/);
}

function append_value(map, key, value) {
    if (!(key in map) || map[key] == "") {
        map[key] = value;
    } else {
        map[key] = map[key] " " value;
    }
}

function median_from_list(list,    n, a, i, j, tmp) {
    if (list == "") {
        return "";
    }
    n = split(list, a, " ");
    for (i = 2; i <= n; i++) {
        tmp = a[i];
        j = i - 1;
        while (j >= 1 && a[j] > tmp) {
            a[j + 1] = a[j];
            j--;
        }
        a[j + 1] = tmp;
    }
    if (n % 2 == 1) {
        return a[(n + 1) / 2];
    }
    return (a[n / 2] + a[n / 2 + 1]) / 2.0;
}

function normalize_scenario(s) {
    if (s == "bench_memory_page_seq_cold" || s == "page_seq_cold") {
        return "page_seq_cold";
    }
    if (s == "bench_memory_ept_pf") {
        return "page_seq_cold";
    }
    if (s == "bench_memory_page_seq_warm" || s == "page_seq_warm") {
        return "page_seq_warm";
    }
    if (s == "bench_memory_page_rand_warm" || s == "bench_memory_ept_walk" || s == "page_rand_warm") {
        return "page_rand_warm";
    }
    if (s == "bench_memory_word_seq_warm" || s == "word_seq_warm") {
        return "word_seq_warm";
    }
    if (s ~ /^bench_memory_page_rand_warm_.+$/ || s ~ /^page_rand_warm_.+$/) {
        return "page_rand_warm";
    }
    return s;
}

NR == 1 {
    for (i = 1; i <= NF; i++) {
        header = trim($i);
        idx[header] = i;
    }
    if ("system" in idx) {
        system_col = idx["system"];
    } else if ("stack" in idx) {
        system_col = idx["stack"];
    } else {
        print "Error: CSV must contain system or stack column." > "/dev/stderr";
        exit 2;
    }
    if (!("scenario" in idx)) {
        print "Error: CSV missing scenario column." > "/dev/stderr";
        exit 2;
    }
    if (!("workset_bytes" in idx)) {
        print "Error: CSV missing workset_bytes column." > "/dev/stderr";
        exit 2;
    }
    scenario_col = idx["scenario"];
    workset_col = idx["workset_bytes"];
    if ("result" in idx) {
        op_col = idx["result"];
        page_col = idx["result"];
    } else if ("cycles_op" in idx) {
        op_col = idx["cycles_op"];
        page_col = ("cycles_page" in idx) ? idx["cycles_page"] : -1;
    } else {
        print "Error: CSV missing result/cycles_op column." > "/dev/stderr";
        exit 2;
    }
    next;
}

NR > 1 {
    sys = trim($(system_col));
    raw_scenario = trim($(scenario_col));
    scenario = normalize_scenario(raw_scenario);
    workset = trim($(workset_col));
    op = trim($(op_col));
    page = (page_col == -1) ? "" : trim($(page_col));

    if (sys == "" || scenario == "" || !isnum(workset)) {
        next;
    }
    key = sys SUBSEP scenario SUBSEP workset;

    if (isnum(op)) {
        append_value(op_values, key, op);
        op_count[key]++;
    }
    if (isnum(page)) {
        append_value(page_values, key, page);
        page_count[key]++;
    }
}

END {
    print "system,scenario,workset_bytes,samples_cycles_op,samples_cycles_page,median_cycles_op,median_cycles_page";
    for (key in op_values) {
        split(key, parts, SUBSEP);
        sys = parts[1];
        scenario = parts[2];
        workset = parts[3];
        op_median = median_from_list(op_values[key]);
        page_median = median_from_list(page_values[key]);
        op_samples = (key in op_count) ? op_count[key] : 0;
        page_samples = (key in page_count) ? page_count[key] : 0;
        print sys "," scenario "," workset "," op_samples "," page_samples "," op_median "," page_median;
    }
}
' "${input_file}" > "${agg_csv}"

echo "[2/7] Computing fixed-workset overhead proxies into: ${overhead_csv}"
awk -F',' -v fixed_ws="${fixed_workset_bytes}" -v guest="${guest_system}" -v container="${container_system}" -v framevm="${framevm_system}" -v host="${host_system}" '
function isnum(x) {
    return (x ~ /^-?[0-9]+(\.[0-9]+)?$/);
}

NR == 1 {
    for (i = 1; i <= NF; i++) {
        idx[$i] = i;
    }
    system_col = idx["system"];
    scenario_col = idx["scenario"];
    workset_col = idx["workset_bytes"];
    op_col = idx["median_cycles_op"];
    next;
}

NR > 1 {
    sys = $(system_col);
    scenario = $(scenario_col);
    workset = $(workset_col);
    op = $(op_col);
    if (workset != fixed_ws) {
        next;
    }
    if (scenario != "page_seq_cold" && scenario != "page_seq_warm" &&
        scenario != "page_rand_warm" &&
        scenario != "word_seq_warm") {
        next;
    }
    if (!isnum(op)) {
        next;
    }
    value[sys SUBSEP scenario] = op;
    systems[sys] = 1;
}

function getv(s, sc) {
    key = s SUBSEP sc;
    if (key in value) {
        return value[key];
    }
    return "";
}

function calc_pf(s,    cold, warm) {
    cold = getv(s, "page_seq_cold");
    warm = getv(s, "page_seq_warm");
    if (isnum(cold) && isnum(warm)) {
        return cold - warm;
    }
    return "";
}

function calc_tlb(s,    randv, word) {
    randv = getv(s, "page_rand_warm");
    word = getv(s, "word_seq_warm");
    if (isnum(randv) && isnum(word)) {
        return randv - word;
    }
    return "";
}

function emit_row(sys,    seq_cold, seq_warm, rand_warm, word_warm, pf, tlb, host_seq_warm, host_pf, ept_base, ept_pf_amp) {
    seq_cold = getv(sys, "page_seq_cold");
    seq_warm = getv(sys, "page_seq_warm");
    rand_warm = getv(sys, "page_rand_warm");
    word_warm = getv(sys, "word_seq_warm");
    pf = calc_pf(sys);
    tlb = calc_tlb(sys);
    host_seq_warm = getv(host, "page_seq_warm");
    host_pf = calc_pf(host);

    ept_base = "";
    if (isnum(seq_warm) && isnum(host_seq_warm)) {
        ept_base = seq_warm - host_seq_warm;
    }
    ept_pf_amp = "";
    if (isnum(pf) && isnum(host_pf)) {
        ept_pf_amp = pf - host_pf;
    }
    print sys ",result," seq_cold "," seq_warm "," rand_warm "," word_warm "," pf "," tlb "," ept_base "," ept_pf_amp;
}

END {
    print "system,metric,page_seq_cold,page_seq_warm,page_rand_warm,word_seq_warm,pf_proxy,tlb_walk_proxy,ept_base_proxy,ept_pf_amp_proxy";
    emit_row(guest);
    emit_row(container);
    emit_row(framevm);
    emit_row(host);
}
' "${agg_csv}" > "${overhead_csv}"

echo "[3/7] Computing workset-growth metrics into: ${sweep_csv}"
awk -F',' -v guest="${guest_system}" -v container="${container_system}" -v framevm="${framevm_system}" -v host="${host_system}" '
function isnum(x) {
    return (x ~ /^-?[0-9]+(\.[0-9]+)?$/);
}

BEGIN {
    size_count = 11;
    sizes[1] = 65536;
    sizes[2] = 131072;
    sizes[3] = 262144;
    sizes[4] = 524288;
    sizes[5] = 1048576;
    sizes[6] = 2097152;
    sizes[7] = 4194304;
    sizes[8] = 8388608;
    sizes[9] = 16777216;
    sizes[10] = 33554432;
    sizes[11] = 67108864;
    for (i = 1; i <= size_count; i++) {
        allowed[sizes[i]] = 1;
    }
}

NR == 1 {
    for (i = 1; i <= NF; i++) {
        idx[$i] = i;
    }
    system_col = idx["system"];
    scenario_col = idx["scenario"];
    workset_col = idx["workset_bytes"];
    page_col = idx["median_cycles_page"];
    next;
}

NR > 1 {
    sys = $(system_col);
    scenario = $(scenario_col);
    workset = $(workset_col);
    page = $(page_col);
    if (scenario != "page_rand_warm") {
        next;
    }
    if (!(workset in allowed)) {
        next;
    }
    if (!isnum(page)) {
        next;
    }
    y[sys SUBSEP workset] = page;
    systems[sys] = 1;
}

function gety(s, w) {
    key = s SUBSEP w;
    if (key in y) {
        return y[key];
    }
    return "";
}

function calc_growth(s,    a, b) {
    a = gety(s, 65536);
    b = gety(s, 67108864);
    if (isnum(a) && a != 0 && isnum(b)) {
        return b / a;
    }
    return "";
}

function calc_knee(s,    base, threshold, i, val) {
    base = gety(s, 65536);
    if (!isnum(base)) {
        return "";
    }
    threshold = base * 1.5;
    for (i = 1; i <= size_count; i++) {
        val = gety(s, sizes[i]);
        if (isnum(val) && val >= threshold) {
            return sizes[i];
        }
    }
    return "";
}

function calc_auc(s,    i, s1, s2, y1, y2, dx, auc) {
    auc = 0;
    for (i = 1; i < size_count; i++) {
        s1 = sizes[i];
        s2 = sizes[i + 1];
        y1 = gety(s, s1);
        y2 = gety(s, s2);
        if (!(isnum(y1) && isnum(y2))) {
            continue;
        }
        dx = log(s2 / s1) / log(2);
        auc += (y1 + y2) * 0.5 * dx;
    }
    return auc;
}

function emit_row(sys,    v64k, v64m, growth, knee, auc) {
    v64k = gety(sys, 65536);
    v64m = gety(sys, 67108864);
    growth = calc_growth(sys);
    knee = calc_knee(sys);
    auc = calc_auc(sys);
    print sys "," v64k "," v64m "," growth "," knee "," auc;
}

END {
    print "system,result_64k,result_64m,growth_ratio,tlb_knee_size_bytes,auc_tlb_walk_proxy";
    emit_row(guest);
    emit_row(container);
    emit_row(framevm);
    emit_row(host);
}
' "${agg_csv}" > "${sweep_csv}"

echo "[4/7] Computing EPT amplification by workset into: ${ept_amp_csv}"
awk -F',' -v guest="${guest_system}" -v container="${container_system}" -v framevm="${framevm_system}" -v host="${host_system}" '
function isnum(x) {
    return (x ~ /^-?[0-9]+(\.[0-9]+)?$/);
}

function median3(a, b, c,    x, y, z, tmp) {
    x = a; y = b; z = c;
    if (x > y) { tmp = x; x = y; y = tmp; }
    if (y > z) { tmp = y; y = z; z = tmp; }
    if (x > y) { tmp = x; x = y; y = tmp; }
    return y;
}

BEGIN {
    size_count = 11;
    sizes[1] = 65536;
    sizes[2] = 131072;
    sizes[3] = 262144;
    sizes[4] = 524288;
    sizes[5] = 1048576;
    sizes[6] = 2097152;
    sizes[7] = 4194304;
    sizes[8] = 8388608;
    sizes[9] = 16777216;
    sizes[10] = 33554432;
    sizes[11] = 67108864;
    for (i = 1; i <= size_count; i++) {
        allowed[sizes[i]] = 1;
    }
}

NR == 1 {
    for (i = 1; i <= NF; i++) {
        idx[$i] = i;
    }
    system_col = idx["system"];
    scenario_col = idx["scenario"];
    workset_col = idx["workset_bytes"];
    page_col = idx["median_cycles_page"];
    next;
}

NR > 1 {
    sys = $(system_col);
    scenario = $(scenario_col);
    workset = $(workset_col);
    page = $(page_col);

    if (scenario != "page_rand_warm") {
        next;
    }
    if (!(workset in allowed)) {
        next;
    }
    if (!isnum(page)) {
        next;
    }
    y[sys SUBSEP workset] = page;
}

function gety(s, w) {
    key = s SUBSEP w;
    if (key in y) {
        return y[key];
    }
    return "";
}

END {
    print "workset_bytes,linux_guest_result,container_result,framevm_result,host_result,baseline_median,ept_amp";
    for (i = 1; i <= size_count; i++) {
        ws = sizes[i];
        g = gety(guest, ws);
        c = gety(container, ws);
        f = gety(framevm, ws);
        h = gety(host, ws);

        baseline = "";
        amp = "";
        if (isnum(c) && isnum(f) && isnum(h)) {
            baseline = median3(c, f, h);
        }
        if (isnum(g) && isnum(baseline)) {
            amp = g - baseline;
        }
        print ws "," g "," c "," f "," h "," baseline "," amp;
    }
}
' "${agg_csv}" > "${ept_amp_csv}"

echo "[5/7] Summarizing EPT amplification into: ${ept_amp_summary_csv}"
awk -F',' '
function isnum(x) {
    return (x ~ /^-?[0-9]+(\.[0-9]+)?$/);
}

NR == 1 {
    for (i = 1; i <= NF; i++) {
        idx[$i] = i;
    }
    amp_col = idx["ept_amp"];
    ws_col = idx["workset_bytes"];
    next;
}

NR > 1 {
    amp = $(amp_col);
    ws = $(ws_col);
    if (!isnum(amp)) {
        next;
    }
    sum += amp;
    n++;
    if (n == 1 || amp > peak_amp) {
        peak_amp = amp;
        peak_ws = ws;
    }
}

END {
    print "metric,value";
    if (n == 0) {
        print "ept_amp_avg,";
        print "ept_amp_peak,";
        print "ept_amp_peak_workset_bytes,";
    } else {
        print "ept_amp_avg," (sum / n);
        print "ept_amp_peak," peak_amp;
        print "ept_amp_peak_workset_bytes," peak_ws;
    }
}
' "${ept_amp_csv}" > "${ept_amp_summary_csv}"

echo "[6/7] Quantifying nested fixed-workset overhead into: ${nested_fixed_csv}"
awk -F',' -v fixed_ws="${fixed_workset_bytes}" -v l1="${nested_l1_system}" -v l2="${nested_l2_system}" '
function isnum(x) {
    return (x ~ /^-?[0-9]+(\.[0-9]+)?$/);
}

NR == 1 {
    for (i = 1; i <= NF; i++) {
        idx[$i] = i;
    }
    system_col = idx["system"];
    scenario_col = idx["scenario"];
    workset_col = idx["workset_bytes"];
    op_col = idx["median_cycles_op"];
    next;
}

NR > 1 {
    sys = $(system_col);
    scenario = $(scenario_col);
    workset = $(workset_col);
    op = $(op_col);
    if (workset != fixed_ws) {
        next;
    }
    if (scenario != "page_seq_cold" && scenario != "page_seq_warm" &&
        scenario != "page_rand_warm" &&
        scenario != "word_seq_warm") {
        next;
    }
    if (!isnum(op)) {
        next;
    }
    value[sys SUBSEP scenario] = op;
}

function getv(sys, sc) {
    key = sys SUBSEP sc;
    if (key in value) {
        return value[key];
    }
    return "";
}

function emit(metric, l1v, l2v,    delta, ratio) {
    delta = "";
    ratio = "";
    if (isnum(l1v) && isnum(l2v)) {
        delta = l2v - l1v;
    }
    if (isnum(l1v) && l1v != 0 && isnum(l2v)) {
        ratio = l2v / l1v;
    }
    print metric "," l1v "," l2v "," delta "," ratio;
}

END {
    l1_cold = getv(l1, "page_seq_cold");
    l2_cold = getv(l2, "page_seq_cold");
    l1_warm = getv(l1, "page_seq_warm");
    l2_warm = getv(l2, "page_seq_warm");
    l1_rand = getv(l1, "page_rand_warm");
    l2_rand = getv(l2, "page_rand_warm");
    l1_word = getv(l1, "word_seq_warm");
    l2_word = getv(l2, "word_seq_warm");

    l1_pf = "";
    l2_pf = "";
    if (isnum(l1_cold) && isnum(l1_warm)) {
        l1_pf = l1_cold - l1_warm;
    }
    if (isnum(l2_cold) && isnum(l2_warm)) {
        l2_pf = l2_cold - l2_warm;
    }

    l1_tlb = "";
    l2_tlb = "";
    if (isnum(l1_rand) && isnum(l1_word)) {
        l1_tlb = l1_rand - l1_word;
    }
    if (isnum(l2_rand) && isnum(l2_word)) {
        l2_tlb = l2_rand - l2_word;
    }

    print "metric,l1_result,l2_result,delta_l2_minus_l1,ratio_l2_over_l1";
    emit("page_seq_cold", l1_cold, l2_cold);
    emit("page_seq_warm", l1_warm, l2_warm);
    emit("page_rand_warm", l1_rand, l2_rand);
    emit("word_seq_warm", l1_word, l2_word);
    emit("pf_proxy(page_seq_cold-page_seq_warm)", l1_pf, l2_pf);
    emit("tlb_walk_proxy(page_rand_warm-word_seq_warm)", l1_tlb, l2_tlb);
}
' "${agg_csv}" > "${nested_fixed_csv}"

echo "[7/7] Quantifying nested sweep overhead into: ${nested_sweep_csv} and ${nested_sweep_summary_csv}"
awk -F',' -v l1="${nested_l1_system}" -v l2="${nested_l2_system}" '
function isnum(x) {
    return (x ~ /^-?[0-9]+(\.[0-9]+)?$/);
}

BEGIN {
    size_count = 11;
    sizes[1] = 65536;
    sizes[2] = 131072;
    sizes[3] = 262144;
    sizes[4] = 524288;
    sizes[5] = 1048576;
    sizes[6] = 2097152;
    sizes[7] = 4194304;
    sizes[8] = 8388608;
    sizes[9] = 16777216;
    sizes[10] = 33554432;
    sizes[11] = 67108864;
    for (i = 1; i <= size_count; i++) {
        allowed[sizes[i]] = 1;
    }
}

NR == 1 {
    for (i = 1; i <= NF; i++) {
        idx[$i] = i;
    }
    system_col = idx["system"];
    scenario_col = idx["scenario"];
    workset_col = idx["workset_bytes"];
    page_col = idx["median_cycles_page"];
    next;
}

NR > 1 {
    sys = $(system_col);
    scenario = $(scenario_col);
    ws = $(workset_col);
    page = $(page_col);
    if (scenario != "page_rand_warm") {
        next;
    }
    if (!(ws in allowed)) {
        next;
    }
    if (!isnum(page)) {
        next;
    }
    if (sys == l1) {
        l1v[ws] = page;
    } else if (sys == l2) {
        l2v[ws] = page;
    }
}

END {
    print "workset_bytes,l1_result,l2_result,delta_l2_minus_l1,ratio_l2_over_l1";
    for (i = 1; i <= size_count; i++) {
        ws = sizes[i];
        a = (ws in l1v) ? l1v[ws] : "";
        b = (ws in l2v) ? l2v[ws] : "";
        d = "";
        r = "";
        if (isnum(a) && isnum(b)) {
            d = b - a;
        }
        if (isnum(a) && a != 0 && isnum(b)) {
            r = b / a;
        }
        print ws "," a "," b "," d "," r;
    }
}
' "${agg_csv}" > "${nested_sweep_csv}"

awk -F',' '
function isnum(x) {
    return (x ~ /^-?[0-9]+(\.[0-9]+)?$/);
}

function growth(arr,    a, b) {
    a = arr[65536];
    b = arr[67108864];
    if (isnum(a) && a != 0 && isnum(b)) {
        return b / a;
    }
    return "";
}

function knee(arr,    base, threshold, i, ws, v) {
    base = arr[65536];
    if (!isnum(base)) {
        return "";
    }
    threshold = base * 1.5;
    for (i = 1; i <= size_count; i++) {
        ws = sizes[i];
        v = arr[ws];
        if (isnum(v) && v >= threshold) {
            return ws;
        }
    }
    return "";
}

function auc(arr,    i, s1, s2, y1, y2, dx, total) {
    total = 0;
    for (i = 1; i < size_count; i++) {
        s1 = sizes[i];
        s2 = sizes[i + 1];
        y1 = arr[s1];
        y2 = arr[s2];
        if (!(isnum(y1) && isnum(y2))) {
            continue;
        }
        dx = log(s2 / s1) / log(2);
        total += (y1 + y2) * 0.5 * dx;
    }
    return total;
}

function emit(metric, l1v, l2v,    delta, ratio) {
    delta = "";
    ratio = "";
    if (isnum(l1v) && isnum(l2v)) {
        delta = l2v - l1v;
    }
    if (isnum(l1v) && l1v != 0 && isnum(l2v)) {
        ratio = l2v / l1v;
    }
    print metric "," l1v "," l2v "," delta "," ratio;
}

BEGIN {
    size_count = 11;
    sizes[1] = 65536;
    sizes[2] = 131072;
    sizes[3] = 262144;
    sizes[4] = 524288;
    sizes[5] = 1048576;
    sizes[6] = 2097152;
    sizes[7] = 4194304;
    sizes[8] = 8388608;
    sizes[9] = 16777216;
    sizes[10] = 33554432;
    sizes[11] = 67108864;
}

NR == 1 {
    next;
}

NR > 1 {
    ws = $1;
    a = $2;
    b = $3;
    d = $4;
    if (isnum(ws)) {
        if (isnum(a)) {
            l1v[ws] = a;
        }
        if (isnum(b)) {
            l2v[ws] = b;
        }
        if (isnum(d)) {
            delta_v[ws] = d;
            delta_sum += d;
            delta_cnt++;
            if (delta_cnt == 1 || d > delta_peak) {
                delta_peak = d;
                delta_peak_ws = ws;
            }
        }
    }
}

END {
    l1_growth = growth(l1v);
    l2_growth = growth(l2v);
    l1_knee = knee(l1v);
    l2_knee = knee(l2v);
    l1_auc = auc(l1v);
    l2_auc = auc(l2v);

    delta_avg = "";
    if (delta_cnt > 0) {
        delta_avg = delta_sum / delta_cnt;
    }

    print "metric,l1_value,l2_value,delta_l2_minus_l1,ratio_l2_over_l1";
    emit("growth_ratio_64m_over_64k", l1_growth, l2_growth);
    emit("tlb_knee_size_bytes", l1_knee, l2_knee);
    emit("auc_tlb_walk_proxy", l1_auc, l2_auc);
    print "avg_delta_result,,," delta_avg ",";
    print "peak_delta_result,,," delta_peak ",";
    print "peak_delta_workset_bytes,,," delta_peak_ws ",";
}
' "${nested_sweep_csv}" > "${nested_sweep_summary_csv}"

echo "Analysis completed."
echo "  - ${agg_csv}"
echo "  - ${overhead_csv}"
echo "  - ${sweep_csv}"
echo "  - ${ept_amp_csv}"
echo "  - ${ept_amp_summary_csv}"
echo "  - ${nested_fixed_csv}"
echo "  - ${nested_sweep_csv}"
echo "  - ${nested_sweep_summary_csv}"
