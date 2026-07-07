#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -eu

. /test/framevm/common.sh

FRAMEVM_LIFECYCLE_MARKER=FRAMEVM_LIFECYCLE_OK
FRAMEVM_CASE_TIMEOUT=${FRAMEVM_CASE_TIMEOUT:-60}

run_framevmctl_input() {
    case_name="$1"
    commands="$2"
    drive="$3"
    log_file="$4"
    input_file="/tmp/framevm-${case_name}.in"
    framevm_register_cleanup_path "$input_file"

    printf '%s\n' "$commands" >"$input_file"
    timeout -s TERM "$FRAMEVM_CASE_TIMEOUT" \
        framevmctl run --vcpus "${FRAMEVM_VCPUS:-1}" --drive "file=$drive" \
        <"$input_file" >"$log_file" 2>&1
}

run_expect_success() {
    case_name="$1"
    commands="$2"
    expected_status="$3"
    log_file="/tmp/framevm-${case_name}.log"
    drive=$(framevm_prepare_drive "$case_name")
    framevm_register_cleanup_path "$log_file"

    echo "[framevm-lifecycle] running ${case_name}"
    if ! run_framevmctl_input "$case_name" "$commands" "$drive" "$log_file"; then
        echo "[framevm-lifecycle] ${case_name} unexpectedly failed"
        framevm_dump_log_tail "$log_file"
        return 1
    fi

    if ! grep -q "$expected_status" "$log_file"; then
        echo "[framevm-lifecycle] ${case_name} missing ${expected_status}"
        framevm_dump_log_tail "$log_file"
        return 1
    fi
}

run_expect_failure() {
    case_name="$1"
    commands="$2"
    expected_exit="$3"
    expected_status="$4"
    log_file="/tmp/framevm-${case_name}.log"
    drive=$(framevm_prepare_drive "$case_name")
    framevm_register_cleanup_path "$log_file"

    echo "[framevm-lifecycle] running ${case_name}"
    set +e
    run_framevmctl_input "$case_name" "$commands" "$drive" "$log_file"
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
}

run_marker_missing_case() {
    log_file=/tmp/framevm-marker-missing.log
    drive=$(framevm_prepare_drive marker-missing)
    framevm_register_cleanup_path "$log_file"

    echo "[framevm-lifecycle] running marker-missing"
    if ! run_framevmctl_input marker-missing "exit" "$drive" "$log_file"; then
        echo "[framevm-lifecycle] marker-missing guest did not exit successfully"
        framevm_dump_log_tail "$log_file"
        return 1
    fi

    if grep -qx "$FRAMEVM_LIFECYCLE_MARKER" "$log_file"; then
        echo "[framevm-lifecycle] marker-missing case emitted success marker"
        framevm_dump_log_tail "$log_file"
        return 1
    fi
}

run_console_eof_before_terminal_case() {
    log_file=/tmp/framevm-console-eof.log
    drive=$(framevm_prepare_drive console-eof)
    framevm_register_cleanup_path "$log_file"

    echo "[framevm-lifecycle] running console-eof-before-terminal"
    framevmctl run --vcpus "${FRAMEVM_VCPUS:-1}" --drive "file=$drive" \
        </dev/null >"$log_file" 2>&1 &
    pid=$!
    framevm_register_cleanup_pid "$pid"
    sleep 2

    if ! kill -0 "$pid" 2>/dev/null; then
        echo "[framevm-lifecycle] framevmctl exited after stdin EOF before terminal status"
        framevm_dump_log_tail "$log_file"
        return 1
    fi

    kill -TERM "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
}

run_host_stop_case() {
    log_file=/tmp/framevm-host-stop.log
    drive=$(framevm_prepare_drive host-stop)
    framevm_register_cleanup_path "$log_file"

    echo "[framevm-lifecycle] running host-stop"
    framevmctl run --vcpus "${FRAMEVM_VCPUS:-1}" --drive "file=$drive" \
        >"$log_file" 2>&1 &
    pid=$!
    framevm_register_cleanup_pid "$pid"
    sleep 2

    if ! kill -0 "$pid" 2>/dev/null; then
        echo "[framevm-lifecycle] framevmctl exited before host-stop signal"
        framevm_dump_log_tail "$log_file"
        return 1
    fi

    kill -TERM "$pid" 2>/dev/null || true
    set +e
    wait "$pid"
    exit_status=$?
    set -e

    if [ "$exit_status" -eq 0 ]; then
        echo "[framevm-lifecycle] host-stop framevmctl returned success"
        framevm_dump_log_tail "$log_file"
        return 1
    fi
}

if ! run_expect_success exit-zero "exit" "FrameVM terminal status: exited-success code=0"; then
    printf '\nFRAMEVM_LIFECYCLE_FAILED\n'
    framevm_finish_host
    exit 1
fi

if ! run_expect_failure exit-nonzero "exit 7" 7 "FrameVM terminal status: exited-failure code=7"; then
    printf '\nFRAMEVM_LIFECYCLE_FAILED\n'
    framevm_finish_host
    exit 1
fi

if ! run_expect_failure restart-requested "/bin/framevm_reboot restart" 1 "FrameVM terminal status: restart-requested"; then
    printf '\nFRAMEVM_LIFECYCLE_FAILED\n'
    framevm_finish_host
    exit 1
fi

if ! run_marker_missing_case; then
    printf '\nFRAMEVM_LIFECYCLE_FAILED\n'
    framevm_finish_host
    exit 1
fi

if ! run_console_eof_before_terminal_case; then
    printf '\nFRAMEVM_LIFECYCLE_FAILED\n'
    framevm_finish_host
    exit 1
fi

if ! run_host_stop_case; then
    printf '\nFRAMEVM_LIFECYCLE_FAILED\n'
    framevm_finish_host
    exit 1
fi

printf '\n%s\n' "$FRAMEVM_LIFECYCLE_MARKER"
framevm_finish_host
