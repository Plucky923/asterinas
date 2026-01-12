#!/bin/bash

# SPDX-License-Identifier: MPL-2.0

set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  validate_bench_memory_matrix.sh --input <metrics.csv>

The CSV must contain header columns:
  stack,scenario,result

Validation rules per stack:
  1) page_seq_cold > page_seq_warm
  2) page_rand_warm > word_seq_warm

Preferred metric column is `result`.
Legacy compatibility:
  - if `result` is absent, `cycles_page` is used when complete
  - otherwise falls back to `cycles_op`
EOF
}

input_file=""
while [ $# -gt 0 ]; do
    case "$1" in
        --input)
            input_file="${2:-}"
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

awk -F',' '
function isnum(x) {
    return (x ~ /^-?[0-9]+(\.[0-9]+)?$/)
}

function normalize_scenario(s) {
    if (s == "bench_memory_page_seq_cold" || s == "page_seq_cold") {
        return "page_seq_cold";
    }
    if (s == "bench_memory_ept_pf") {
        return "page_seq_cold";
    }
    if (s == "bench_memory_page_seq_warm") {
        return "page_seq_warm";
    }
    if (s == "bench_memory_page_rand_warm" || s == "bench_memory_ept_walk") {
        return "page_rand_warm";
    }
    if (s == "bench_memory_word_seq_warm") {
        return "word_seq_warm";
    }
    return s;
}

function require_col(colname, idx) {
    if (!(colname in idx)) {
        printf("Error: missing required CSV column: %s\n", colname) > "/dev/stderr";
        exit 2;
    }
}

NR == 1 {
    for (i = 1; i <= NF; i++) {
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", $i);
        idx[$i] = i;
    }
    require_col("stack", idx);
    require_col("scenario", idx);
    has_result = ("result" in idx);
    has_cycles_op = ("cycles_op" in idx);
    has_cycles_page = ("cycles_page" in idx);
    if (!has_result && !has_cycles_op) {
        printf("Error: missing required CSV column: result/cycles_op\n") > "/dev/stderr";
        exit 2;
    }
    next;
}

NR > 1 {
    stack = $(idx["stack"]);
    scenario = normalize_scenario($(idx["scenario"]));
    result = has_result ? $(idx["result"]) : "";
    op = has_cycles_op ? $(idx["cycles_op"]) : "";
    page = has_cycles_page ? $(idx["cycles_page"]) : "";

    if (stack == "" || scenario == "") {
        next;
    }

    stacks[stack] = 1;
    key = stack SUBSEP scenario;
    result_metric[key] = result;
    op_metric[key] = op;
    page_metric[key] = page;
}

END {
    required[1] = "page_seq_cold";
    required[2] = "page_seq_warm";
    required[3] = "page_rand_warm";
    required[4] = "word_seq_warm";

    failures = 0;
    checked = 0;

    for (stack in stacks) {
        checked++;
        stack_fail = 0;
        metric = "result";

        for (i = 1; i <= 4; i++) {
            key = stack SUBSEP required[i];
            if (!isnum(result_metric[key])) {
                metric = "cycles_page";
                break;
            }
        }
        if (metric == "cycles_page") {
            for (i = 1; i <= 4; i++) {
                key = stack SUBSEP required[i];
                if (!isnum(page_metric[key])) {
                    metric = "cycles_op";
                    break;
                }
            }
        }

        for (i = 1; i <= 4; i++) {
            key = stack SUBSEP required[i];
            if (metric == "result") {
                value = result_metric[key];
            } else if (metric == "cycles_page") {
                value = page_metric[key];
            } else {
                value = op_metric[key];
            }
            if (!isnum(value)) {
                printf("[FAIL] stack=%s missing numeric %s for scenario=%s\n", stack, metric, required[i]) > "/dev/stderr";
                stack_fail++;
            }
        }
        if (stack_fail > 0) {
            failures += stack_fail;
            continue;
        }

        if (metric == "result") {
            cold = result_metric[stack SUBSEP "page_seq_cold"];
            warm = result_metric[stack SUBSEP "page_seq_warm"];
            rand_val = result_metric[stack SUBSEP "page_rand_warm"];
            word = result_metric[stack SUBSEP "word_seq_warm"];
        } else if (metric == "cycles_page") {
            cold = page_metric[stack SUBSEP "page_seq_cold"];
            warm = page_metric[stack SUBSEP "page_seq_warm"];
            rand_val = page_metric[stack SUBSEP "page_rand_warm"];
            word = page_metric[stack SUBSEP "word_seq_warm"];
        } else {
            cold = op_metric[stack SUBSEP "page_seq_cold"];
            warm = op_metric[stack SUBSEP "page_seq_warm"];
            rand_val = op_metric[stack SUBSEP "page_rand_warm"];
            word = op_metric[stack SUBSEP "word_seq_warm"];
        }

        if (cold > warm) {
            printf("[PASS] %s: page_seq_cold(%s) > page_seq_warm(%s) [%s]\n", stack, cold, warm, metric);
        } else {
            printf("[FAIL] %s: page_seq_cold(%s) <= page_seq_warm(%s) [%s]\n", stack, cold, warm, metric) > "/dev/stderr";
            stack_fail++;
        }

        if (rand_val > word) {
            printf("[PASS] %s: page_rand_warm(%s) > word_seq_warm(%s) [%s]\n", stack, rand_val, word, metric);
        } else {
            printf("[FAIL] %s: page_rand_warm(%s) <= word_seq_warm(%s) [%s]\n", stack, rand_val, word, metric) > "/dev/stderr";
            stack_fail++;
        }
        failures += stack_fail;
    }

    if (checked == 0) {
        printf("Error: no data rows found in CSV.\n") > "/dev/stderr";
        exit 3;
    }

    if (failures > 0) {
        exit 1;
    }
}
' "${input_file}"
