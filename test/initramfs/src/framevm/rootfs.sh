#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

. /test/framevm/common.sh

framevm_case_start rootfs

run_write_flush_smoke() {
    framevm_prepare_drive rootfs-write
    drive="$FRAMEVM_PREPARED_DRIVE"
    log_file=/tmp/framevm-rootfs-write.log
    framevm_register_cleanup_path "$log_file"

    framevm_select_next_sock_device
    FRAMEVM_SOCK_DEVICE_READY=1
    framevm_run_timeout "-k 5 -s TERM 60" "${FRAMEVM_VCPUS:-1}" "$drive" \
        "init=/bin/framevm-test-runner FRAMEVM_TEST=rootfs-write" \
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
        echo "[framevm-rootfs] writable drive run failed"
        framevm_dump_log_tail "$log_file"
        return 1
    fi

    if ! grep -q "FrameVM terminal status: exited code=0" "$log_file"; then
        echo "[framevm-rootfs] writable drive run did not exit successfully"
        framevm_dump_log_tail "$log_file"
        return 1
    fi

    if ! grep -q "framevm-rootfs-1111" "$drive"; then
        echo "[framevm-rootfs] synced write was not persisted to the raw ext2 image"
        framevm_dump_log_tail "$log_file"
        return 1
    fi
}

if ! run_write_flush_smoke; then
    printf '\nFRAMEVM_ROOTFS_FAILED\n'
    framevm_case_fail rootfs rootfs-write
    framevm_finish_host
    exit 1
fi

if ! framevm_run_load FRAMEVM_WALL_CLOCK_OK wall-clock; then
    framevm_case_fail rootfs wall-clock
    framevm_finish_host
    exit 1
fi

if framevm_run_load "${FRAMEVM_ROOTFS_MARKER}" rootfs; then
    framevm_case_pass rootfs
    framevm_finish_host
    exit 0
fi

printf '\nFRAMEVM_ROOTFS_FAILED\n'
framevm_case_fail rootfs guest-status
framevm_finish_host
exit 1
