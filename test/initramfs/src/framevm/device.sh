#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -eu

. /test/framevm/common.sh

framevm_case_start device

HOST_BIN=/test/network/vsock/framev_vsock_echo
GUEST_BIN=/bin/framev_vsock_echo
HOST_CID=2
HOST_PORT=1234
GUEST_PORT=4321
SMALL_PAYLOAD=4096
LARGE_PAYLOAD=131072
VCPUS="${FRAMEV_VSOCK_VCPUS:-2}"

wait_for_log() {
    log_file="$1"
    pattern="$2"
    timeout="$3"

    i=0
    while [ "$i" -lt "$timeout" ]; do
        if grep -q "$pattern" "$log_file" 2>/dev/null; then
            return 0
        fi
        if grep -qx "FRAMEV_VSOCK_FAILED" "$log_file" 2>/dev/null; then
            framevm_dump_log_tail "$log_file"
            return 1
        fi
        if [ $((i % 10)) -eq 0 ]; then
            echo "[framev-vsock] waiting for ${pattern} in ${log_file} (${i}s)"
        fi
        i=$((i + 1))
        sleep 1
    done

    echo "timeout waiting for ${pattern} in ${log_file}"
    framevm_dump_log_tail "$log_file"
    return 1
}

wait_for_log_or_framevmm_exit() {
    log_file="$1"
    pattern="$2"
    pid="$3"
    timeout="$4"

    i=0
    while [ "$i" -lt "$timeout" ]; do
        if grep -q "$pattern" "$log_file" 2>/dev/null; then
            return 0
        fi
        if grep -qx "FRAMEV_VSOCK_FAILED" "$log_file" 2>/dev/null; then
            framevm_dump_log_tail "$log_file"
            return 1
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            if wait "$pid"; then
                return 0
            fi
            framevm_dump_log_tail "$log_file"
            return 1
        fi
        if [ $((i % 10)) -eq 0 ]; then
            echo "[framev-vsock] waiting for ${pattern} or framevmm exit (${i}s)"
        fi
        i=$((i + 1))
        sleep 1
    done

    echo "timeout waiting for ${pattern} or framevmm exit"
    framevm_dump_log_tail "$log_file"
    return 1
}

stop_framevmm() {
    pid="$1"
    i=0
    while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 30 ]; do
        sleep 1
        i=$((i + 1))
    done
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    sleep 1
}

dump_log() {
    log_file="$1"
    framevm_dump_log_tail "$log_file"
}

run_framevm_command() {
    log_file="$1"
    framevm_register_cleanup_path "$log_file"
    framevm_prepare_drive device
    drive="$FRAMEVM_PREPARED_DRIVE"
    framevm_select_next_sock_device

    (
        : >"$log_file"
        FRAMEVM_SOCK_DEVICE_READY=1
        export FRAMEVM_SOCK_DEVICE_READY
        framevm_run "$VCPUS" "$drive" \
            "init=/bin/framevm-test-runner FRAMEVM_TEST=device" \
            >"$log_file" 2>&1 &
        framevm_pid=$!

        tail -f "$log_file" &
        tail_pid=$!

        trap 'kill "$framevm_pid" "$tail_pid" 2>/dev/null || true' INT TERM EXIT
        wait "$framevm_pid"
        status=$?
        kill "$tail_pid" 2>/dev/null || true
        wait "$tail_pid" 2>/dev/null || true
        trap - INT TERM EXIT
        exit "$status"
    ) &
    FRAMEVMM_PID=$!
    framevm_register_cleanup_pid "$FRAMEVMM_PID"
}

echo "[framev-vsock] guest-to-host phase"
framevm_register_cleanup_path /tmp/framev_vsock_host_server.log
"$HOST_BIN" server any "$HOST_PORT" 2 >/tmp/framev_vsock_host_server.log 2>&1 &
host_server_pid=$!
framevm_register_cleanup_pid "$host_server_pid"
echo "[framev-vsock] host server pid=${host_server_pid}"
tail -f /tmp/framev_vsock_host_server.log &
host_server_tail_pid=$!
framevm_register_cleanup_pid "$host_server_tail_pid"

run_framevm_command /tmp/framev_vsock_guest.log
guest_pid="$FRAMEVMM_PID"
echo "[framev-vsock] guest framevmm pid=${guest_pid}"
if ! wait_for_log /tmp/framev_vsock_guest.log FRAMEV_VSOCK_GUEST_CLIENT_DONE 180; then
    dump_log /tmp/framev_vsock_host_server.log
    kill "$host_server_tail_pid" 2>/dev/null || true
    wait "$host_server_tail_pid" 2>/dev/null || true
    kill "$host_server_pid" 2>/dev/null || true
    stop_framevmm "$guest_pid"
    printf '\nFRAMEVM_DEVICE_FAILED\n'
    framevm_case_fail device guest-to-host
    framevm_finish_host
    exit 1
fi
wait "$host_server_pid"
kill "$host_server_tail_pid" 2>/dev/null || true
wait "$host_server_tail_pid" 2>/dev/null || true
dump_log /tmp/framev_vsock_host_server.log

echo "[framev-vsock] host-to-guest phase"
if ! wait_for_log /tmp/framev_vsock_guest.log "server listening.*" 180; then
    stop_framevmm "$guest_pid"
    printf '\nFRAMEVM_DEVICE_FAILED\n'
    framevm_case_fail device host-to-guest
    framevm_finish_host
    exit 1
fi

"$HOST_BIN" client "$FRAMEVM_GUEST_CID" "$GUEST_PORT" "$SMALL_PAYLOAD" shutdown
"$HOST_BIN" client "$FRAMEVM_GUEST_CID" "$GUEST_PORT" "$LARGE_PAYLOAD" shutdown
if ! wait_for_log_or_framevmm_exit \
    /tmp/framev_vsock_guest.log FRAMEV_VSOCK_GUEST_SERVER_DONE "$guest_pid" 180; then
    framevm_case_fail device guest-server
    framevm_finish_host
    exit 1
fi
stop_framevmm "$guest_pid"

echo "FrameV Sock test passed."
printf '\n%s\n' "${FRAMEVM_DEVICE_MARKER}"
framevm_case_pass device
framevm_finish_host
