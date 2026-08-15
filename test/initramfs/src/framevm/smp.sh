#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -eu

. /test/framevm/common.sh

framevm_case_start smp

HOST_CPU_COUNT=$(grep -c '^processor' /proc/cpuinfo)
if [ "$HOST_CPU_COUNT" -lt 4 ]; then
    echo "FrameVM SMP test requires at least four Host CPUs"
    framevm_case_fail smp prerequisite
    framevm_finish_host
    exit 1
fi

run_smp_case() {
    vcpu_count="$1"
    framevm_prepare_drive "smp-${vcpu_count}"
    drive="$FRAMEVM_PREPARED_DRIVE"
    log_file="/tmp/framevm-smp-${vcpu_count}.log"
    framevm_register_cleanup_path "$log_file"

    framevm_select_next_sock_device
    FRAMEVM_SOCK_DEVICE_READY=1
    framevm_run_timeout "-k 5 -s TERM 60" "$vcpu_count" "$drive" \
        "init=/bin/framevm-test-runner FRAMEVM_TEST=smp FRAMEVM_VCPUS=${vcpu_count}" \
        >"$log_file" 2>&1 &
    run_pid=$!
    unset FRAMEVM_SOCK_DEVICE_READY
    tail -f "$log_file" &
    tail_pid=$!
    if wait "$run_pid"; then
        run_status=0
    else
        run_status=$?
    fi
    kill "$tail_pid" 2>/dev/null || true
    wait "$tail_pid" 2>/dev/null || true

    if [ "$run_status" -ne 0 ]; then
        echo "FrameVM ${vcpu_count}-vCPU workload failed"
        framevm_dump_log_tail "$log_file"
        return 1
    fi

    cpu=0
    while [ "$cpu" -lt "$vcpu_count" ]; do
        echo "FRAMEVM_SMP_CPU_${cpu}_OK"
        cpu=$((cpu + 1))
    done
    echo "FRAMEVM_SMP_${vcpu_count}_OK"
}

run_smp_case 2
run_smp_case 4

printf '\nFRAMEVM_SMP_OK\n'
framevm_case_pass smp
framevm_finish_host
