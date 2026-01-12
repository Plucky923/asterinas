#!/bin/bash

# SPDX-License-Identifier: MPL-2.0

set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  build_memory_overhead_binaries.sh [options]

Builds memory benchmark binaries for both:
  1) FrameVM guest benchmarks
  2) initramfs host/Linux benchmarks

Default build config:
  workset_bytes = 536870912 (512 MiB)
  runs          = 5
  seed          = 12345
  do_store      = 0

Note:
  page-seq compare binaries are intentionally baked as write-path tests
  (`bench_memory_page_seq_cold` and `bench_memory_page_seq_warm` use
  MEM_DO_STORE=1). `--do-store` controls the other compare/sweep binaries.

Options:
  --workset-bytes <bytes>   Fixed workset for compare_all targets.
  --runs <n>                MEASURE_RUNS for compare_all targets.
  --seed <n>                MEM_SEED for compare_all targets.
  --do-store <0|1>          MEM_DO_STORE for non-page-seq compare/sweep targets.
  --initramfs-build-dir <dir>
                             BUILD_DIR for initramfs memory app build.
  --skip-framevm            Do not build FrameVM benchmarks.
  --skip-initramfs          Do not build initramfs benchmarks.
  -h, --help                Show this help.

Outputs:
  FrameVM binaries under:
    kernel/comps/framevm/test/
  initramfs binaries under:
    <initramfs-build-dir>/initramfs/test/memory/
EOF
}

workset_bytes=536870912
runs=5
seed=12345
do_store=0
initramfs_build_dir=""
build_framevm=1
build_initramfs=1

while [ $# -gt 0 ]; do
    case "$1" in
        --workset-bytes)
            workset_bytes="${2:-}"
            shift 2
            ;;
        --runs)
            runs="${2:-}"
            shift 2
            ;;
        --seed)
            seed="${2:-}"
            shift 2
            ;;
        --do-store)
            do_store="${2:-}"
            shift 2
            ;;
        --initramfs-build-dir)
            initramfs_build_dir="${2:-}"
            shift 2
            ;;
        --skip-framevm)
            build_framevm=0
            shift
            ;;
        --skip-initramfs)
            build_initramfs=0
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

if ! [[ "${workset_bytes}" =~ ^[0-9]+$ ]]; then
    echo "Error: --workset-bytes must be an integer" >&2
    exit 1
fi
if ! [[ "${runs}" =~ ^[1-9][0-9]*$ ]]; then
    echo "Error: --runs must be >= 1" >&2
    exit 1
fi
if ! [[ "${seed}" =~ ^[0-9]+$ ]]; then
    echo "Error: --seed must be an integer" >&2
    exit 1
fi
if [ "${do_store}" != "0" ] && [ "${do_store}" != "1" ]; then
    echo "Error: --do-store must be 0 or 1" >&2
    exit 1
fi
if [ "${build_framevm}" -eq 0 ] && [ "${build_initramfs}" -eq 0 ]; then
    echo "Error: both targets are disabled" >&2
    exit 1
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../../../../.." && pwd)"

framevm_dir="${repo_root}/kernel/comps/framevm/test"
initramfs_mem_dir="${repo_root}/test/initramfs/src/apps/memory"
if [ -z "${initramfs_build_dir}" ]; then
    initramfs_build_dir="${repo_root}/test/initramfs/build_apps_memory"
fi
initramfs_out_dir="${initramfs_build_dir}/initramfs/test/memory"

scenario_bins=(
    bench_memory_page_seq_cold
    bench_memory_page_seq_warm
    bench_memory_page_rand_warm
    bench_memory_word_seq_warm
)

sweep_bins=(
    bench_memory_page_rand_warm_64k
    bench_memory_page_rand_warm_128k
    bench_memory_page_rand_warm_256k
    bench_memory_page_rand_warm_512k
    bench_memory_page_rand_warm_1m
    bench_memory_page_rand_warm_2m
    bench_memory_page_rand_warm_4m
    bench_memory_page_rand_warm_8m
    bench_memory_page_rand_warm_16m
    bench_memory_page_rand_warm_32m
    bench_memory_page_rand_warm_64m
)

echo "Build config:"
echo "  workset_bytes=${workset_bytes}"
echo "  runs=${runs}"
echo "  seed=${seed}"
echo "  do_store=${do_store}"
echo "  initramfs_build_dir=${initramfs_build_dir}"

if [ "${build_framevm}" -eq 1 ]; then
    echo "[1/2] Building FrameVM memory benchmarks..."
    make -C "${framevm_dir}" \
        compare_all page_rand_warm_sweep \
        MEM_COMPARE_WORKSET_BYTES="${workset_bytes}" \
        MEM_COMPARE_RUNS="${runs}" \
        MEM_COMPARE_SEED="${seed}" \
        MEM_COMPARE_DO_STORE="${do_store}"
fi

if [ "${build_initramfs}" -eq 1 ]; then
    echo "[2/2] Building initramfs memory benchmarks..."
    mkdir -p "${initramfs_build_dir}"
    make -C "${initramfs_mem_dir}" \
        compare_all page_rand_warm_sweep \
        BUILD_DIR="${initramfs_build_dir}" \
        MEM_COMPARE_WORKSET_BYTES="${workset_bytes}" \
        MEM_COMPARE_RUNS="${runs}" \
        MEM_COMPARE_SEED="${seed}" \
        MEM_COMPARE_DO_STORE="${do_store}"
fi

echo "Built scenario binaries:"
for bin in "${scenario_bins[@]}"; do
    framevm_path="${framevm_dir}/${bin}"
    initramfs_path="${initramfs_out_dir}/${bin}"
    if [ "${build_framevm}" -eq 1 ]; then
        if [ -f "${framevm_path}" ]; then
            echo "  [framevm] ${framevm_path}"
        else
            echo "  [framevm][missing] ${framevm_path}" >&2
        fi
    fi
    if [ "${build_initramfs}" -eq 1 ]; then
        if [ -f "${initramfs_path}" ]; then
            echo "  [initramfs] ${initramfs_path}"
        else
            echo "  [initramfs][missing] ${initramfs_path}" >&2
        fi
    fi
done

echo "Built sweep binaries:"
for bin in "${sweep_bins[@]}"; do
    framevm_path="${framevm_dir}/${bin}"
    initramfs_path="${initramfs_out_dir}/${bin}"
    if [ "${build_framevm}" -eq 1 ]; then
        if [ -f "${framevm_path}" ]; then
            echo "  [framevm] ${framevm_path}"
        else
            echo "  [framevm][missing] ${framevm_path}" >&2
        fi
    fi
    if [ "${build_initramfs}" -eq 1 ]; then
        if [ -f "${initramfs_path}" ]; then
            echo "  [initramfs] ${initramfs_path}"
        else
            echo "  [initramfs][missing] ${initramfs_path}" >&2
        fi
    fi
done
