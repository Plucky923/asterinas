#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -eu

. /test/framevm/common.sh

framevm_case_start allocator

allocator_log_a=/tmp/framevm-allocator-a.log
allocator_log_b=/tmp/framevm-allocator-b.log
framevm_register_cleanup_path "$allocator_log_a"
framevm_register_cleanup_path "$allocator_log_b"

framevm_prepare_drive allocator-a
drive_a="$FRAMEVM_PREPARED_DRIVE"
framevm_prepare_drive allocator-b
drive_b="$FRAMEVM_PREPARED_DRIVE"

run_allocator_instance() {
    instance="$1"
    guest_cid="$2"
    drive="$3"
    log_file="$4"

    FRAMEVM_GUEST_CID="$guest_cid" FRAMEVM_NEXT_GUEST_CID="$guest_cid" \
        FRAMEVM_SOCK_DEVICE_READY=0 \
        framevm_run "${FRAMEVM_VCPUS:-1}" "$drive" \
        "init=/bin/framevm-test-runner FRAMEVM_TEST=allocator FRAMEVM_ALLOCATOR_INSTANCE=$instance" \
        >"$log_file" 2>&1
}

run_allocator_instance A 3 "$drive_a" "$allocator_log_a" &
pid_a=$!
framevm_register_cleanup_pid "$pid_a"
run_allocator_instance B 4 "$drive_b" "$allocator_log_b" &
pid_b=$!
framevm_register_cleanup_pid "$pid_b"

status_a=0
status_b=0
wait "$pid_a" || status_a=$?
wait "$pid_b" || status_b=$?

if [ "$status_a" -ne 0 ] || [ "$status_b" -ne 0 ]; then
    echo "[framevm-allocator] one or more allocator instances failed"
    framevm_dump_log_tail "$allocator_log_a"
    framevm_dump_log_tail "$allocator_log_b"
    framevm_case_fail allocator instance
    framevm_finish_host
    exit 1
fi

for pair in \
    "$allocator_log_a:FRAMEVM_ALLOCATOR_INSTANCE=A" \
    "$allocator_log_b:FRAMEVM_ALLOCATOR_INSTANCE=B"; do
    log_file=${pair%%:*}
    marker=${pair#*:}
    if ! grep -qx "$marker" "$log_file"; then
        echo "[framevm-allocator] marker missing: $marker"
        framevm_dump_log_tail "$log_file"
        framevm_case_fail allocator marker
        framevm_finish_host
        exit 1
    fi
done

for log_file in "$allocator_log_a" "$allocator_log_b"; do
    for marker in FRAMEVM_ALLOCATOR_HEAP_OK FRAMEVM_ALLOCATOR_PAGES_OK; do
        if ! grep -qx "$marker" "$log_file"; then
            echo "[framevm-allocator] marker missing: $marker"
            framevm_dump_log_tail "$log_file"
            framevm_case_fail allocator marker
            framevm_finish_host
            exit 1
        fi
    done
    if ! grep -q 'FrameVM terminal status: exited code=0' "$log_file"; then
        echo "[framevm-allocator] terminal status missing"
        framevm_dump_log_tail "$log_file"
        framevm_case_fail allocator terminal-status
        framevm_finish_host
        exit 1
    fi
done

cat "$allocator_log_a" "$allocator_log_b"
printf '\nFRAMEVM_ALLOCATOR_ISOLATION_OK\n'
printf 'FRAMEVM_ALLOCATOR_OK\n'
framevm_case_pass allocator
framevm_finish_host
