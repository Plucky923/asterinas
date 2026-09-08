#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -eu

FRAMEVM_LOAD_MARKER=FRAMEVM_LOAD_OK
FRAMEVM_BOOT_MARKER=FRAMEVM_BOOT_OK
FRAMEVM_REGRESSION_MARKER=FRAMEVM_REGRESSION_OK
FRAMEVM_DEVICE_MARKER=FRAMEVM_DEVICE_OK
FRAMEVM_ROOTFS_MARKER=FRAMEVM_ROOTFS_OK
FRAMEVM_ROOTFS_IMAGE=/framevm/rootfs.ext2.gz
FRAMEVM_ROOTFS_SIZE_FILE=/framevm/rootfs.ext2.size
FRAMEVM_ARTIFACT=/framevm/framevm.o
FRAMEVM_GUEST_CID=${FRAMEVM_GUEST_CID:-3}
FRAMEVM_NEXT_GUEST_CID=${FRAMEVM_NEXT_GUEST_CID:-$FRAMEVM_GUEST_CID}
FRAMEVM_MEMORY_LIMIT=${FRAMEVM_MEMORY_LIMIT:-8G}
export FRAMEVM_MEMORY_LIMIT
FRAMEVM_CASE_RUN=${FRAMEVM_CASE_RUN:-1}
export FRAMEVM_CASE_RUN
FRAMEVM_SOCK_DEVICE=framev-sock,guest-cid=${FRAMEVM_GUEST_CID},guest-connect-host-ports=1234:65530,host-connect-guest-ports=4321:65531
# Set FRAMEVM_KEEP_ARTIFACTS=1 to retain temporary drives and logs after a
# failed or interactive run.
FRAMEVM_CLEANUP_PATHS=
FRAMEVM_CLEANUP_PIDS=
FRAMEVM_CASE_NAME=
FRAMEVM_CASE_RESULT_SENT=0

# A stopped non-co-designed service can retain opaque allocator metadata. Its
# FrameVM identity and Sock CID therefore remain reserved until a future
# service-side teardown protocol releases them. Every invocation in one Host
# test must receive a fresh CID instead of treating a stopped VM as reusable.
framevm_select_next_sock_device() {
    guest_cid="$FRAMEVM_NEXT_GUEST_CID"
    case "$guest_cid" in
        ''|*[!0-9]*)
            echo "FrameVM guest CID must be a decimal integer" >&2
            return 1
            ;;
    esac
    if [ "$guest_cid" -lt 3 ] || [ "$guest_cid" -gt 4294967294 ]; then
        echo "FrameVM guest CID is outside the usable range" >&2
        return 1
    fi

    FRAMEVM_GUEST_CID="$guest_cid"
    FRAMEVM_SOCK_DEVICE=framev-sock,guest-cid=${FRAMEVM_GUEST_CID},guest-connect-host-ports=1234:65530,host-connect-guest-ports=4321:65531
    FRAMEVM_NEXT_GUEST_CID=$((guest_cid + 1))
    export FRAMEVM_GUEST_CID FRAMEVM_NEXT_GUEST_CID FRAMEVM_SOCK_DEVICE
}

framevm_register_cleanup_path() {
    FRAMEVM_CLEANUP_PATHS="${FRAMEVM_CLEANUP_PATHS}${FRAMEVM_CLEANUP_PATHS:+
}$1"
}

framevm_register_cleanup_pid() {
    FRAMEVM_CLEANUP_PIDS="${FRAMEVM_CLEANUP_PIDS}${FRAMEVM_CLEANUP_PIDS:+
}$1"
}

framevm_cleanup_pids() {
    printf '%s\n' "$FRAMEVM_CLEANUP_PIDS" | while IFS= read -r pid; do
        if [ -n "$pid" ]; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
}

framevm_cleanup_paths() {
    if [ "${FRAMEVM_KEEP_ARTIFACTS:-0}" = "1" ]; then
        return 0
    fi

    printf '%s\n' "$FRAMEVM_CLEANUP_PATHS" | while IFS= read -r path; do
        if [ -n "$path" ]; then
            rm -rf "$path"
        fi
    done
}

framevm_cleanup() {
    framevm_cleanup_pids
    framevm_cleanup_paths
}

framevm_install_cleanup_trap() {
    trap 'exit 130' INT
    trap 'exit 143' TERM
    trap 'status=$?; \
        if [ "$status" -ne 0 ] && [ -n "${FRAMEVM_CASE_NAME:-}" ] && \
            [ "${FRAMEVM_CASE_RESULT_SENT:-0}" -eq 0 ]; then \
            framevm_case_fail "$FRAMEVM_CASE_NAME" host-exit; \
        fi; \
        framevm_cleanup; exit "$status"' EXIT
}

framevm_dump_log_tail() {
    log_file="$1"
    lines="${FRAMEVM_FAILURE_LOG_LINES:-80}"
    echo "[framevm] last ${lines} lines from ${log_file}:"
    tail -n "$lines" "$log_file" 2>/dev/null || true
}

framevm_case_start() {
    case_name="$1"
    FRAMEVM_CASE_NAME="$case_name"
    FRAMEVM_CASE_RESULT_SENT=0
    printf 'FRAMEVM_CASE_START case=%s run=%s\n' "$case_name" "$FRAMEVM_CASE_RUN"
}

framevm_case_pass() {
    case_name="$1"
    FRAMEVM_CASE_RESULT_SENT=1
    printf 'FRAMEVM_CASE_RESULT case=%s result=pass\n' "$case_name"
}

framevm_case_fail() {
    case_name="$1"
    failure_kind="$2"
    FRAMEVM_CASE_RESULT_SENT=1
    printf 'FRAMEVM_CASE_RESULT case=%s result=fail class=%s\n' \
        "$case_name" "$failure_kind"
}

framevm_finish_host() {
    if [ "${FRAMEVM_KEEP_HOST:-0}" != "1" ]; then
        poweroff -f
    fi
}

framevm_prepare_drive() {
    case_name="$1"
    drive="/tmp/framevm-${case_name}-rootfs.ext2"
    rm -f "$drive"
    if ! gzip -dc "$FRAMEVM_ROOTFS_IMAGE" > "$drive"; then
        rm -f "$drive"
        return 1
    fi
    if [ "$(wc -c < "$drive")" != "$(cat "$FRAMEVM_ROOTFS_SIZE_FILE")" ]; then
        echo "FrameVM root image size mismatch" >&2
        rm -f "$drive"
        return 1
    fi
    framevm_register_cleanup_path "$drive"
    FRAMEVM_PREPARED_DRIVE="$drive"
}

framevm_run_load() {
    marker="$1"
    case_name="${2:-load}"
    framevm_prepare_drive "$case_name"
    drive="$FRAMEVM_PREPARED_DRIVE"
    if ! framevm_run_with_drive_arg "file=$drive" "$case_name"; then
        printf '\nFRAMEVM_LOAD_FAILED\n'
        return 1
    fi

    printf '\n%s\n' "${marker}"
    return 0
}

framevm_run_with_drive_arg() {
    drive_arg="$1"
    test_name="$2"
    extra_init_args="${3:-}"
    drive=${drive_arg#file=}
    if [ "$test_name" = "load" ]; then
        init_command="init=/bin/framevm-load-exit"
    else
        init_command="init=/bin/framevm-test-runner FRAMEVM_TEST=${test_name} ${extra_init_args}"
    fi
    framevm_run "${FRAMEVM_VCPUS:-1}" "$drive" \
        "$init_command"
}

framevm_run() {
    vcpu_count="$1"
    drive="$2"
    append="$3"
    shift 3
    if [ "${FRAMEVM_SOCK_DEVICE_READY:-0}" != "1" ]; then
        framevm_select_next_sock_device
    fi
    set -- framevmm -smp "$vcpu_count" -m "$FRAMEVM_MEMORY_LIMIT" -kernel "$FRAMEVM_ARTIFACT" \
        -append "$append" -nographic \
        -drive "file=$drive,id=root,format=raw,readonly=off" \
        -device framev-blk,drive=root,root=on \
        -device "$FRAMEVM_SOCK_DEVICE" "$@"
    if [ -n "${FRAMEVM_RUN_TIMEOUT_ARGS:-}" ]; then
        timeout $FRAMEVM_RUN_TIMEOUT_ARGS "$@"
    else
        "$@"
    fi
}

framevm_run_timeout() {
    timeout_args="$1"
    shift
    if [ "${FRAMEVM_RUN_TIMEOUT_ARGS+x}" = x ]; then
        previous_timeout_args="$FRAMEVM_RUN_TIMEOUT_ARGS"
        restore_timeout_args=1
    else
        restore_timeout_args=0
    fi

    FRAMEVM_RUN_TIMEOUT_ARGS="$timeout_args"
    if framevm_run "$@"; then
        run_status=0
    else
        run_status=$?
    fi

    if [ "$restore_timeout_args" -eq 1 ]; then
        FRAMEVM_RUN_TIMEOUT_ARGS="$previous_timeout_args"
    else
        unset FRAMEVM_RUN_TIMEOUT_ARGS
    fi
    return "$run_status"
}

framevm_run_with_network_peer() {
    vcpu_count="$1"
    drive="$2"
    append="$3"
    if [ "${FRAMEVM_SOCK_DEVICE_READY:-0}" != "1" ]; then
        framevm_select_next_sock_device
    fi
    set -- framev-net-peer -- framevmm -smp "$vcpu_count" -m "$FRAMEVM_MEMORY_LIMIT" \
        -kernel "$FRAMEVM_ARTIFACT" -append "$append" -nographic \
        -drive "file=$drive,id=root,format=raw,readonly=off" \
        -device framev-blk,drive=root,root=on \
        -device "$FRAMEVM_SOCK_DEVICE"
    if [ -n "${FRAMEVM_RUN_TIMEOUT_ARGS:-}" ]; then
        timeout $FRAMEVM_RUN_TIMEOUT_ARGS "$@"
    else
        "$@"
    fi
}

framevm_install_cleanup_trap
