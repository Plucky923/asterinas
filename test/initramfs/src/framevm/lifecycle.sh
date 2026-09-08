#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -eu

. /test/framevm/common.sh

framevm_case_start lifecycle

FRAMEVM_LIFECYCLE_MARKER=FRAMEVM_LIFECYCLE_OK
FRAMEVM_CASE_TIMEOUT=${FRAMEVM_CASE_TIMEOUT:-60}

discard_case_artifacts() {
    if [ "${FRAMEVM_KEEP_ARTIFACTS:-0}" = "1" ]; then
        return 0
    fi

    rm -f "$1" "$2"
}

run_framevmm_test() {
    case_name="$1"
    test_name="$2"
    drive="$3"
    log_file="$4"

    framevm_run_timeout "-k 5 -s TERM $FRAMEVM_CASE_TIMEOUT" \
        "${FRAMEVM_VCPUS:-1}" "$drive" \
        "init=/bin/framevm-test-runner FRAMEVM_TEST=${test_name}" \
        </dev/null >"$log_file" 2>&1
}

wait_for_framevmm_exit() {
    pid="$1"
    timeout_seconds="$2"
    elapsed_seconds=0

    while [ "$elapsed_seconds" -lt "$timeout_seconds" ]; do
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid" 2>/dev/null || true
            return 0
        fi

        sleep 1
        elapsed_seconds=$((elapsed_seconds + 1))
    done

    return 1
}

wait_for_framevmm_ready() {
    log_file="$1"
    pid="$2"
    timeout_seconds="$3"
    elapsed_seconds=0

    while [ "$elapsed_seconds" -lt "$timeout_seconds" ]; do
        if grep -q '^FRAMEVM_LIFECYCLE_READY$' "$log_file" 2>/dev/null; then
            return 0
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "[framevm-lifecycle] framevmm exited before readiness"
            framevm_dump_log_tail "$log_file"
            return 1
        fi
        sleep 1
        elapsed_seconds=$((elapsed_seconds + 1))
    done

    echo "[framevm-lifecycle] timed out waiting for framevmm readiness"
    framevm_dump_log_tail "$log_file"
    return 1
}

run_expect_success() {
    case_name="$1"
    test_selector="$2"
    expected_status="$3"
    log_file="/tmp/framevm-${case_name}.log"
    framevm_prepare_drive "$case_name"
    drive="$FRAMEVM_PREPARED_DRIVE"
    framevm_register_cleanup_path "$log_file"

    echo "[framevm-lifecycle] running ${case_name}"
    if ! run_framevmm_test "$case_name" "$test_selector" "$drive" "$log_file"; then
        echo "[framevm-lifecycle] ${case_name} unexpectedly failed"
        framevm_dump_log_tail "$log_file"
        return 1
    fi

    if ! grep -q "$expected_status" "$log_file"; then
        echo "[framevm-lifecycle] ${case_name} missing ${expected_status}"
        framevm_dump_log_tail "$log_file"
        return 1
    fi

    # Each rootfs image is 720 MiB.  This script runs several independent
    # framevmm instances, so retaining successful case inputs until the final
    # EXIT trap exhausts the outer test kernel before the lifecycle coverage
    # can finish.  The instance has exited and its log has been checked; its
    # artifacts no longer participate in the next case.
    discard_case_artifacts "$drive" "$log_file"
}

run_expect_failure() {
    case_name="$1"
    test_selector="$2"
    expected_exit="$3"
    expected_status="$4"
    log_file="/tmp/framevm-${case_name}.log"
    framevm_prepare_drive "$case_name"
    drive="$FRAMEVM_PREPARED_DRIVE"
    framevm_register_cleanup_path "$log_file"

    echo "[framevm-lifecycle] running ${case_name}"
    set +e
    run_framevmm_test "$case_name" "$test_selector" "$drive" "$log_file"
    exit_status=$?
    set -e

    if [ "$exit_status" -ne "$expected_exit" ]; then
        echo "[framevm-lifecycle] ${case_name} exit ${exit_status}, expected ${expected_exit}"
        framevm_dump_log_tail "$log_file"
        return 1
    fi

    if ! grep -q "$expected_status" "$log_file"; then
        echo "[framevm-lifecycle] ${case_name} missing ${expected_status}"
        framevm_dump_log_tail "$log_file"
        return 1
    fi

    discard_case_artifacts "$drive" "$log_file"
}

run_marker_missing_case() {
    log_file=/tmp/framevm-marker-missing.log
    framevm_prepare_drive marker-missing
    drive="$FRAMEVM_PREPARED_DRIVE"
    framevm_register_cleanup_path "$log_file"

    echo "[framevm-lifecycle] running marker-missing"
    if ! run_framevmm_test marker-missing marker-missing "$drive" "$log_file"; then
        echo "[framevm-lifecycle] marker-missing guest did not exit successfully"
        framevm_dump_log_tail "$log_file"
        return 1
    fi

    if grep -qx "$FRAMEVM_LIFECYCLE_MARKER" "$log_file"; then
        echo "[framevm-lifecycle] marker-missing case emitted success marker"
        framevm_dump_log_tail "$log_file"
        return 1
    fi

    discard_case_artifacts "$drive" "$log_file"
}

run_console_eof_before_terminal_case() {
    log_file=/tmp/framevm-console-eof.log
    framevm_prepare_drive console-eof
    drive="$FRAMEVM_PREPARED_DRIVE"
    framevm_register_cleanup_path "$log_file"

    echo "[framevm-lifecycle] running console-eof-before-terminal"
    framevm_select_next_sock_device
    FRAMEVM_SOCK_DEVICE_READY=1
    framevm_run "${FRAMEVM_VCPUS:-1}" "$drive" \
        "init=/bin/framevm-test-runner FRAMEVM_TEST=lifecycle-hold" \
        </dev/null >"$log_file" 2>&1 &
    pid=$!
    unset FRAMEVM_SOCK_DEVICE_READY
    framevm_register_cleanup_pid "$pid"
    if ! wait_for_framevmm_ready "$log_file" "$pid" 10; then
        return 1
    fi
    echo "[framevm-lifecycle] console-eof framevmm ready"

    if ! kill -0 "$pid" 2>/dev/null; then
        echo "[framevm-lifecycle] framevmm exited after stdin EOF before terminal status"
        framevm_dump_log_tail "$log_file"
        return 1
    fi

    kill -TERM "$pid" 2>/dev/null || true
    echo "[framevm-lifecycle] console-eof TERM sent"
    if ! wait_for_framevmm_exit "$pid" 5; then
        echo "[framevm-lifecycle] framevmm did not exit after host TERM"
        kill -KILL "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        framevm_dump_log_tail "$log_file"
        return 1
    fi

    discard_case_artifacts "$drive" "$log_file"
}

run_host_stop_case() {
    log_file=/tmp/framevm-host-stop.log
    framevm_prepare_drive host-stop
    drive="$FRAMEVM_PREPARED_DRIVE"
    framevm_register_cleanup_path "$log_file"

    echo "[framevm-lifecycle] running host-stop"
    framevm_select_next_sock_device
    FRAMEVM_SOCK_DEVICE_READY=1
    framevm_run "${FRAMEVM_VCPUS:-1}" "$drive" \
        "init=/bin/framevm-test-runner FRAMEVM_TEST=lifecycle-hold" \
        >"$log_file" 2>&1 &
    pid=$!
    unset FRAMEVM_SOCK_DEVICE_READY
    framevm_register_cleanup_pid "$pid"
    if ! wait_for_framevmm_ready "$log_file" "$pid" 10; then
        return 1
    fi
    echo "[framevm-lifecycle] host-stop framevmm ready"

    if ! kill -0 "$pid" 2>/dev/null; then
        echo "[framevm-lifecycle] framevmm exited before host-stop signal"
        framevm_dump_log_tail "$log_file"
        return 1
    fi

    kill -TERM "$pid" 2>/dev/null || true
    echo "[framevm-lifecycle] host-stop TERM sent"
    set +e
    wait_for_framevmm_exit "$pid" 5
    wait_result=$?
    wait "$pid"
    exit_status=$?
    set -e

    if [ "$wait_result" -ne 0 ]; then
        echo "[framevm-lifecycle] host-stop framevmm did not exit after host TERM"
        kill -KILL "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        framevm_dump_log_tail "$log_file"
        return 1
    fi

    if [ "$exit_status" -eq 0 ]; then
        echo "[framevm-lifecycle] host-stop framevmm returned success"
        framevm_dump_log_tail "$log_file"
        return 1
    fi

    discard_case_artifacts "$drive" "$log_file"
}

if ! run_expect_success exit-zero exit-zero "FrameVM terminal status: exited code=0"; then
    printf '\nFRAMEVM_LIFECYCLE_FAILED\n'
    framevm_case_fail lifecycle exit-zero
    framevm_finish_host
    exit 1
fi

if ! run_expect_failure exit-nonzero exit-nonzero 7 "FrameVM terminal status: exited code=7"; then
    printf '\nFRAMEVM_LIFECYCLE_FAILED\n'
    framevm_case_fail lifecycle exit-nonzero
    framevm_finish_host
    exit 1
fi

if ! run_expect_failure restart-requested restart-requested 1 "FrameVM terminal status: exited code=1"; then
    printf '\nFRAMEVM_LIFECYCLE_FAILED\n'
    framevm_case_fail lifecycle restart-requested
    framevm_finish_host
    exit 1
fi

if ! run_marker_missing_case; then
    printf '\nFRAMEVM_LIFECYCLE_FAILED\n'
    framevm_case_fail lifecycle marker-missing
    framevm_finish_host
    exit 1
fi

if ! run_console_eof_before_terminal_case; then
    printf '\nFRAMEVM_LIFECYCLE_FAILED\n'
    framevm_case_fail lifecycle console-eof
    framevm_finish_host
    exit 1
fi

if ! run_host_stop_case; then
    printf '\nFRAMEVM_LIFECYCLE_FAILED\n'
    framevm_case_fail lifecycle host-stop
    framevm_finish_host
    exit 1
fi

printf '\n%s\n' "$FRAMEVM_LIFECYCLE_MARKER"
framevm_case_pass lifecycle
framevm_finish_host
