#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

. /test/framevm/common.sh

framevm_case_start nvme-passthrough

FRAMEVM_NVME_PASSTHROUGH_MARKER=FRAMEVM_NVME_PASSTHROUGH_OK
FRAMEVM_NVME_PASSTHROUGH_TIMEOUT=${FRAMEVM_NVME_PASSTHROUGH_TIMEOUT:-180}
FRAMEVM_NVME_READY_TIMEOUT=${FRAMEVM_NVME_READY_TIMEOUT:-60}
framevm_prepare_drive nvme-passthrough
drive="$FRAMEVM_PREPARED_DRIVE"

wait_for_nvme_marker() {
    log_file="$1"
    marker="$2"
    run_pid="$3"
    elapsed=0

    while [ "$elapsed" -lt "$FRAMEVM_NVME_READY_TIMEOUT" ]; do
        if grep -qx "$marker" "$log_file" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "$run_pid" 2>/dev/null; then
            echo "[framevm-nvme] FrameVM exited before ${marker}"
            framevm_dump_log_tail "$log_file"
            return 1
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    echo "[framevm-nvme] timed out waiting for ${marker}"
    framevm_dump_log_tail "$log_file"
    return 1
}

run_nvme_round() {
    round="$1"
    log_file="/tmp/framevm-nvme-passthrough-${round}.log"
    framevm_register_cleanup_path "$log_file"

    framevm_select_next_sock_device
    FRAMEVM_SOCK_DEVICE_READY=1
    framevm_run_timeout "-k 5 -s TERM $FRAMEVM_NVME_PASSTHROUGH_TIMEOUT" \
        "${FRAMEVM_VCPUS:-1}" "$drive" \
        "init=/bin/framevm-test-runner FRAMEVM_TEST=nvme-passthrough" \
        -device vfio-pci,host=0000:00:0b.0 >"$log_file" 2>&1 &
    run_pid=$!
    unset FRAMEVM_SOCK_DEVICE_READY

    if wait "$run_pid"; then
        run_status=0
    else
        run_status=$?
    fi

    if [ "$run_status" -ne 0 ]; then
        echo "[framevm-nvme] assigned NVMe round ${round} failed"
        framevm_dump_log_tail "$log_file"
        return 1
    fi

    cat "$log_file"
    if ! grep -q '^FRAMEVM_NVME_PASSTHROUGH_GUEST_OK$' "$log_file"; then
        echo "[framevm-nvme] round ${round} did not complete NVMe read/write/flush"
        framevm_dump_log_tail "$log_file"
        return 1
    fi
    if ! grep -q 'FrameVM terminal status: exited code=0' "$log_file"; then
        echo "[framevm-nvme] round ${round} did not exit successfully"
        framevm_dump_log_tail "$log_file"
        return 1
    fi
}

run_nvme_forced_stop_round() {
    log_file=/tmp/framevm-nvme-passthrough-forced-stop.log
    framevm_register_cleanup_path "$log_file"

    framevm_select_next_sock_device
    set -- framevmm -smp "${FRAMEVM_VCPUS:-1}" -m "$FRAMEVM_MEMORY_LIMIT" -kernel "$FRAMEVM_ARTIFACT" \
        -append "init=/bin/framevm-test-runner FRAMEVM_TEST=nvme-passthrough-hold" \
        -nographic -drive "file=$drive,id=root,format=raw,readonly=off" \
        -device framev-blk,drive=root,root=on \
        -device "$FRAMEVM_SOCK_DEVICE" \
        -device vfio-pci,host=0000:00:0b.0
    (exec "$@" >"$log_file" 2>&1) &
    run_pid=$!

    if ! wait_for_nvme_marker "$log_file" FRAMEVM_NVME_HOLD_READY "$run_pid"; then
        kill -TERM "$run_pid" 2>/dev/null || true
        wait "$run_pid" 2>/dev/null || true
        return 1
    fi

    owner_name=$(cat "/proc/${run_pid}/comm" 2>/dev/null || true)
    if [ "$owner_name" != framevmm ]; then
        echo "[framevm-nvme] expected framevmm owner pid, got ${owner_name:-missing}"
        return 1
    fi

    # `SIGTERM` requests an orderly stop. `SIGHUP` instead makes framevmm exit
    # without issuing STOP so this round exercises owner-fd loss.
    echo "FRAMEVM_NVME_FORCE_STOP_SIGNAL"
    if ! kill -1 "$run_pid"; then
        echo "[framevm-nvme] failed to kill forced-stop FrameVM"
        return 1
    fi
    if wait "$run_pid"; then
        echo "[framevm-nvme] forced stop returned success"
        framevm_dump_log_tail "$log_file"
        return 1
    fi
    echo "FRAMEVM_NVME_FORCE_STOP_REAPED"
    if ! grep -qx 'FRAMEVM_NVME_PASSTHROUGH_GUEST_OK' "$log_file"; then
        echo "[framevm-nvme] forced-stop guest did not complete NVMe read/write/flush"
        framevm_dump_log_tail "$log_file"
        return 1
    fi
}

run_nvme_local_failure_round() {
    log_file=/tmp/framevm-nvme-passthrough-local-failure.log
    framevm_register_cleanup_path "$log_file"

    if ! framevm_run_timeout "-k 5 -s TERM $FRAMEVM_NVME_PASSTHROUGH_TIMEOUT" \
        "${FRAMEVM_VCPUS:-1}" "$drive" \
        "init=/bin/framevm-test-runner FRAMEVM_TEST=nvme-passthrough-local-failure" \
        -device vfio-pci,host=0000:00:0b.0 >"$log_file" 2>&1; then
        echo "[framevm-nvme] ordinary NVMe failure terminated FrameVM"
        framevm_dump_log_tail "$log_file"
        return 1
    fi

    cat "$log_file"
    if ! grep -qx 'FRAMEVM_NVME_LOCAL_FAILURE_OK' "$log_file"; then
        echo "[framevm-nvme] guest did not observe the ordinary NVMe failure"
        framevm_dump_log_tail "$log_file"
        return 1
    fi
    if ! grep -q 'FrameVM terminal status: exited code=0' "$log_file"; then
        echo "[framevm-nvme] ordinary NVMe failure changed the terminal status"
        framevm_dump_log_tail "$log_file"
        return 1
    fi
}

if ! run_nvme_round first || ! run_nvme_local_failure_round || \
    ! run_nvme_forced_stop_round || \
    ! run_nvme_round reassigned-after-forced-stop; then
    printf '\nFRAMEVM_NVME_PASSTHROUGH_FAILED\n'
    framevm_case_fail nvme-passthrough guest-status
    framevm_finish_host
    exit 1
fi

printf '\n%s\n' "$FRAMEVM_LOAD_MARKER"
printf '\n%s\n' "$FRAMEVM_NVME_PASSTHROUGH_MARKER"
framevm_case_pass nvme-passthrough
framevm_finish_host
