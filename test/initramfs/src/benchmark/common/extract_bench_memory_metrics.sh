#!/bin/bash

# SPDX-License-Identifier: MPL-2.0

set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  extract_bench_memory_metrics.sh --stack <stack> --scenario <scenario> --input <log> [--timestamp <ts>] [--header]

Example:
  extract_bench_memory_metrics.sh \
    --stack linux_stack \
    --scenario page_rand_warm \
    --input /tmp/l2_page_rand_warm.log \
    --header

Output CSV columns:
  stack,scenario,workset_bytes,runs,result,timestamp,input_file
EOF
}

stack=""
scenario=""
input_file=""
timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
print_header=0

while [ $# -gt 0 ]; do
    case "$1" in
        --stack)
            stack="${2:-}"
            shift 2
            ;;
        --scenario)
            scenario="${2:-}"
            shift 2
            ;;
        --input)
            input_file="${2:-}"
            shift 2
            ;;
        --timestamp)
            timestamp="${2:-}"
            shift 2
            ;;
        --header)
            print_header=1
            shift
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

if [ -z "${stack}" ] || [ -z "${scenario}" ] || [ -z "${input_file}" ]; then
    echo "Error: --stack, --scenario and --input are required." >&2
    usage >&2
    exit 1
fi

if [ ! -f "${input_file}" ]; then
    echo "Error: input log not found: ${input_file}" >&2
    exit 1
fi

sanitized="$(mktemp)"
trap 'rm -f "${sanitized}"' EXIT

tr -d '\r' < "${input_file}" | sed -E 's/\x1b\[[0-9;]*[A-Za-z]//g' > "${sanitized}"

extract_int_field() {
    local key="$1"
    awk -F':' -v key="$key" '
        $1 ~ "^[[:space:]]*" key "[[:space:]]*$" {
            value = $2;
            gsub(/[^0-9]/, "", value);
            if (value != "") {
                last = value;
            }
        }
        END {
            if (last != "") {
                print last;
            }
        }
    ' "${sanitized}"
}

extract_float_field() {
    local key="$1"
    awk -F':' -v key="$key" '
        $1 ~ "^[[:space:]]*" key "[[:space:]]*$" {
            value = $2;
            gsub(/[^0-9.]/, "", value);
            if (value != "") {
                last = value;
            }
        }
        END {
            if (last != "") {
                print last;
            }
        }
    ' "${sanitized}"
}

workset_bytes="$(extract_int_field "Workset")"
runs="$(extract_int_field "Runs")"
result="$(extract_float_field "Result")"

if [ -z "${workset_bytes}" ] || [ -z "${runs}" ] || [ -z "${result}" ]; then
    echo "Error: failed to parse required metrics from ${input_file}" >&2
    exit 1
fi

if [ "${print_header}" -eq 1 ]; then
    echo "stack,scenario,workset_bytes,runs,result,timestamp,input_file"
fi

echo "${stack},${scenario},${workset_bytes},${runs},${result},${timestamp},${input_file}"
