#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -eu

. /test/framevm/common.sh

framevm_case_start fairness

CGROUP=/sys/fs/cgroup/framevm-fairness
OBSERVER_CGROUP=/sys/fs/cgroup/framevm-fairness-observer
WAIT_ATTEMPTS=6000

cleanup_fairness_test() {
    framevm_cleanup
    rmdir "$CGROUP" 2>/dev/null || true
    rmdir "$OBSERVER_CGROUP" 2>/dev/null || true
}
trap 'status=$?; \
    if [ "$status" -ne 0 ] && [ "${FRAMEVM_CASE_RESULT_SENT:-0}" -eq 0 ]; then \
        framevm_case_fail fairness host-exit; \
    fi; \
    cleanup_fairness_test; exit "$status"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

wait_for_pattern() {
    log_file="$1"
    pattern="$2"
    attempts=0
    while [ "$attempts" -lt "$WAIT_ATTEMPTS" ]; do
        if grep -q "$pattern" "$log_file" 2>/dev/null; then
            return 0
        fi
        sleep 0.001
        attempts=$((attempts + 1))
    done
    echo "timeout waiting for $pattern in $log_file"
    framevm_dump_log_tail "$log_file"
    return 1
}

read_cpu_usage() {
    while read -r field value; do
        if [ "$field" = usage_usec ]; then
            FRAMEVM_CPU_USAGE="$value"
            return 0
        fi
    done < "$1"
    return 1
}

read_progress_count() {
    FRAMEVM_PROGRESS_COUNT=$(grep -c FRAMEVM_SHARE_PROGRESS "$1" 2>/dev/null || true)
}

run_pair() {
    pair_name="$1"
    first_share="$2"
    second_share="$3"

    framevm_prepare_drive "fairness-${pair_name}-first"
    first_drive="$FRAMEVM_PREPARED_DRIVE"
    framevm_prepare_drive "fairness-${pair_name}-second"
    second_drive="$FRAMEVM_PREPARED_DRIVE"
    first_log="/tmp/framevm-fairness-${pair_name}-first.log"
    second_log="/tmp/framevm-fairness-${pair_name}-second.log"
    first_input="/tmp/framevm-fairness-${pair_name}-first.input"
    second_input="/tmp/framevm-fairness-${pair_name}-second.input"
    framevm_register_cleanup_path "$first_log"
    framevm_register_cleanup_path "$second_log"
    framevm_register_cleanup_path "$first_input"
    framevm_register_cleanup_path "$second_input"
    mkfifo "$first_input" "$second_input"
    exec 3<> "$first_input"
    exec 4<> "$second_input"

    framevm_select_next_sock_device
    first_sock_device="$FRAMEVM_SOCK_DEVICE"
    framevm_select_next_sock_device
    second_sock_device="$FRAMEVM_SOCK_DEVICE"

    FRAMEVM_FAIRNESS_CGROUP_PROCS="$CGROUP/cgroup.procs" \
    FRAMEVM_FAIRNESS_DRIVE="$first_drive" \
    FRAMEVM_FAIRNESS_SHARE="$first_share" \
    FRAMEVM_FAIRNESS_SOCK_DEVICE="$first_sock_device" \
    sh -c '
        echo $$ > "$FRAMEVM_FAIRNESS_CGROUP_PROCS"
        exec timeout -k 5 -s TERM 60 framevmm \
            -smp 1 -m "$FRAMEVM_MEMORY_LIMIT" -share "$FRAMEVM_FAIRNESS_SHARE" \
            -kernel /framevm/framevm.o \
            -append "init=/bin/framevm-test-runner FRAMEVM_TEST=share FRAMEVM_SHARE_PROGRESS_LIMIT=512" \
            -nographic \
            -drive "file=$FRAMEVM_FAIRNESS_DRIVE,id=root,format=raw,readonly=off" \
            -device framev-blk,drive=root,root=on \
            -device "$FRAMEVM_FAIRNESS_SOCK_DEVICE"
    ' <"$first_input" >"$first_log" 2>&1 &
    first_pid=$!
    framevm_register_cleanup_pid "$first_pid"
    wait_for_pattern "$first_log" FRAMEVM_SHARE_READY
    echo "$first_pid" > "$OBSERVER_CGROUP/cgroup.procs"
    echo "[framevm-fairness] $pair_name first VM ready"

    FRAMEVM_FAIRNESS_CGROUP_PROCS="$CGROUP/cgroup.procs" \
    FRAMEVM_FAIRNESS_DRIVE="$second_drive" \
    FRAMEVM_FAIRNESS_SHARE="$second_share" \
    FRAMEVM_FAIRNESS_SOCK_DEVICE="$second_sock_device" \
    sh -c '
        echo $$ > "$FRAMEVM_FAIRNESS_CGROUP_PROCS"
        exec timeout -k 5 -s TERM 60 framevmm \
            -smp 1 -m "$FRAMEVM_MEMORY_LIMIT" -share "$FRAMEVM_FAIRNESS_SHARE" \
            -kernel /framevm/framevm.o \
            -append "init=/bin/framevm-test-runner FRAMEVM_TEST=share FRAMEVM_SHARE_PROGRESS_LIMIT=512" \
            -nographic \
            -drive "file=$FRAMEVM_FAIRNESS_DRIVE,id=root,format=raw,readonly=off" \
            -device framev-blk,drive=root,root=on \
            -device "$FRAMEVM_FAIRNESS_SOCK_DEVICE"
    ' <"$second_input" >"$second_log" 2>&1 &
    second_pid=$!
    framevm_register_cleanup_pid "$second_pid"

    wait_for_pattern "$second_log" FRAMEVM_SHARE_READY
    echo "$second_pid" > "$OBSERVER_CGROUP/cgroup.procs"
    echo "[framevm-fairness] $pair_name second VM ready"
    printf 's\n' >&3
    printf 's\n' >&4
    exec 3>&-
    exec 4>&-
    wait_for_pattern "$first_log" FRAMEVM_SHARE_STARTED
    wait_for_pattern "$second_log" FRAMEVM_SHARE_STARTED

    for cgroup_child in "$CGROUP"/*; do
        if [ -d "$cgroup_child" ]; then
            echo "FrameVM scheduler group appeared in cgroupfs: $cgroup_child"
            return 1
        fi
    done
    read_cpu_usage "$CGROUP/cpu.stat"
    usage_before="$FRAMEVM_CPU_USAGE"
    read_progress_count "$first_log"
    first_progress_before="$FRAMEVM_PROGRESS_COUNT"
    read_progress_count "$second_log"
    second_progress_before="$FRAMEVM_PROGRESS_COUNT"
    echo "[framevm-fairness] $pair_name accounting captured"

    echo "[framevm-fairness] $pair_name workloads running"
    target_usage=$((usage_before + 500000))
    measurement_attempt=0
    while [ "$measurement_attempt" -lt 100000 ]; do
        read_cpu_usage "$CGROUP/cpu.stat"
        usage_after="$FRAMEVM_CPU_USAGE"
        if [ "$usage_after" -ge "$target_usage" ]; then
            break
        fi
        measurement_attempt=$((measurement_attempt + 1))
    done
    if [ "$measurement_attempt" -eq 100000 ]; then
        echo "FrameVM fairness accounting did not advance: before=$usage_before after=$usage_after target=$target_usage"
        return 1
    fi
    read_progress_count "$first_log"
    first_progress_after="$FRAMEVM_PROGRESS_COUNT"
    read_progress_count "$second_log"
    second_progress_after="$FRAMEVM_PROGRESS_COUNT"
    echo "[framevm-fairness] $pair_name measurement window elapsed"
    echo "[framevm-fairness] $pair_name workload measured"
    wait "$first_pid"
    echo "[framevm-fairness] $pair_name first VM stopped"
    wait "$second_pid"
    echo "[framevm-fairness] $pair_name second VM stopped"
    first_progress=$((first_progress_after - first_progress_before))
    second_progress=$((second_progress_after - second_progress_before))
    case "$first_progress:$second_progress" in
        *[!0-9:]*|:*|*:|0:*|*:0)
            echo "invalid FrameVM fairness accounting: $first_progress:$second_progress"
            return 1
            ;;
    esac
    echo "[framevm-fairness] $pair_name progress=$first_progress:$second_progress"

    FRAMEVM_FIRST_PROGRESS="$first_progress"
    FRAMEVM_SECOND_PROGRESS="$second_progress"
}

echo "+cpu +cpuset" > /sys/fs/cgroup/cgroup.subtree_control
mkdir "$OBSERVER_CGROUP"
echo 1 > "$OBSERVER_CGROUP/cpuset.cpus"
mkdir "$CGROUP"
echo 0 > "$CGROUP/cpuset.cpus"
taskset -p 2 $$ >/dev/null

run_pair equal 1024 1024
if [ "$FRAMEVM_FIRST_PROGRESS" -gt "$((FRAMEVM_SECOND_PROGRESS * 3))" ] ||
    [ "$FRAMEVM_SECOND_PROGRESS" -gt "$((FRAMEVM_FIRST_PROGRESS * 3))" ]; then
    echo "equal-share FrameVMs exceeded the broad 1:3 progress bound"
    exit 1
fi
echo "FRAMEVM_FAIRNESS_EQUAL_OK"

run_pair unequal 256 1024
if [ "$FRAMEVM_SECOND_PROGRESS" -lt "$((FRAMEVM_FIRST_PROGRESS * 2))" ] ||
    [ "$FRAMEVM_SECOND_PROGRESS" -gt "$((FRAMEVM_FIRST_PROGRESS * 8))" ]; then
    echo "unequal-share FrameVMs fell outside the broad 2:1..8:1 progress bound"
    exit 1
fi
echo "FRAMEVM_FAIRNESS_UNEQUAL_OK"

printf '\nFRAMEVM_FAIRNESS_OK\n'
framevm_case_pass fairness
framevm_finish_host
