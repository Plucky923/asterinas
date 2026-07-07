#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -eu

. /test/framevm/common.sh

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

wait_for_log_or_framevmctl_exit() {
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
            echo "[framev-vsock] waiting for ${pattern} or framevmctl exit (${i}s)"
        fi
        i=$((i + 1))
        sleep 1
    done

    echo "timeout waiting for ${pattern} or framevmctl exit"
    framevm_dump_log_tail "$log_file"
    return 1
}

stop_framevmctl() {
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

framevm_guest_cid_from_log() {
    log_file="$1"
    cid=$(sed -n 's/^FRAMEVM_GUEST_CID=//p' "$log_file" | tail -n 1)
    if [ -z "$cid" ]; then
        echo "failed to resolve FRAMEVM_GUEST_CID from ${log_file}"
        framevm_dump_log_tail "$log_file"
        return 1
    fi
    printf '%s\n' "$cid"
}

run_framevm_command() {
    log_file="$1"
    framevm_register_cleanup_path "$log_file"
    drive=$(framevm_prepare_drive device)

    (
        : >"$log_file"
        framevmctl run --vcpus "$VCPUS" --drive "file=$drive" \
            --append "init=/bin/framevm-test-runner FRAMEVM_TEST=device" \
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
    FRAMEVMCTL_PID=$!
    framevm_register_cleanup_pid "$FRAMEVMCTL_PID"
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
guest_pid="$FRAMEVMCTL_PID"
echo "[framev-vsock] guest framevmctl pid=${guest_pid}"
if ! wait_for_log /tmp/framev_vsock_guest.log FRAMEV_VSOCK_GUEST_CLIENT_DONE 180; then
    dump_log /tmp/framev_vsock_host_server.log
    kill "$host_server_tail_pid" 2>/dev/null || true
    wait "$host_server_tail_pid" 2>/dev/null || true
    kill "$host_server_pid" 2>/dev/null || true
    stop_framevmctl "$guest_pid"
    printf '\nFRAMEVM_DEVICE_FAILED\n'
    framevm_finish_host
    exit 1
fi
wait "$host_server_pid"
kill "$host_server_tail_pid" 2>/dev/null || true
wait "$host_server_tail_pid" 2>/dev/null || true
dump_log /tmp/framev_vsock_host_server.log

echo "[framev-vsock] host-to-guest phase"
if ! wait_for_log /tmp/framev_vsock_guest.log "server listening.*" 180; then
    stop_framevmctl "$guest_pid"
    printf '\nFRAMEVM_DEVICE_FAILED\n'
    framevm_finish_host
    exit 1
fi

GUEST_CID=$(framevm_guest_cid_from_log /tmp/framev_vsock_guest.log)
"$HOST_BIN" client "$GUEST_CID" "$GUEST_PORT" "$SMALL_PAYLOAD" shutdown
"$HOST_BIN" client "$GUEST_CID" "$GUEST_PORT" "$LARGE_PAYLOAD" shutdown
wait_for_log_or_framevmctl_exit /tmp/framev_vsock_guest.log FRAMEV_VSOCK_GUEST_SERVER_DONE "$guest_pid" 180
stop_framevmctl "$guest_pid"

echo "FrameV Sock test passed."
printf '\n%s\n' "${FRAMEVM_DEVICE_MARKER}"
framevm_finish_host
