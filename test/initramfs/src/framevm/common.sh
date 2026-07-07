#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -eu

FRAMEVM_LOAD_MARKER=FRAMEVM_LOAD_OK
FRAMEVM_BOOT_MARKER=FRAMEVM_BOOT_OK
FRAMEVM_REGRESSION_MARKER=FRAMEVM_REGRESSION_OK
FRAMEVM_DEVICE_MARKER=FRAMEVM_DEVICE_OK
FRAMEVM_ROOTFS_MARKER=FRAMEVM_ROOTFS_OK
FRAMEVM_ROOTFS_IMAGE=/framevm/rootfs.ext2
# Set FRAMEVM_KEEP_ARTIFACTS=1 to retain temporary drives and logs after a
# failed or interactive run.
FRAMEVM_CLEANUP_PATHS=
FRAMEVM_CLEANUP_PIDS=

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
    trap 'status=$?; framevm_cleanup; exit "$status"' EXIT
}

framevm_dump_log_tail() {
    log_file="$1"
    lines="${FRAMEVM_FAILURE_LOG_LINES:-80}"
    echo "[framevm] last ${lines} lines from ${log_file}:"
    tail -n "$lines" "$log_file" 2>/dev/null || true
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
    cp "$FRAMEVM_ROOTFS_IMAGE" "$drive"
    framevm_register_cleanup_path "$drive"
    printf '%s\n' "$drive"
}

framevm_run_load() {
    marker="$1"
    case_name="${2:-load}"
    drive=$(framevm_prepare_drive "$case_name")
    if ! framevm_run_with_drive_arg "file=$drive"; then
        printf '\nFRAMEVM_LOAD_FAILED\n'
        return 1
    fi

    printf '\n%s\n' "${marker}"
    return 0
}

framevm_run_with_drive_arg() {
    drive_arg="$1"
    printf 'exit\n' | framevmctl run --vcpus "${FRAMEVM_VCPUS:-1}" \
        --drive "$drive_arg"
}

framevm_install_cleanup_trap
