#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

. /test/framevm/common.sh

run_write_flush_smoke() {
    drive=$(framevm_prepare_drive rootfs-write)
    log_file=/tmp/framevm-rootfs-write.log
    framevm_register_cleanup_path "$log_file"

    if ! printf 'printf "framevm-rootfs-1111\\n" > /tmp/framevm-persist\nsync\nexit\n' \
        | framevmctl run --vcpus "${FRAMEVM_VCPUS:-1}" --drive "file=$drive" \
        >"$log_file" 2>&1; then
        echo "[framevm-rootfs] writable drive run failed"
        framevm_dump_log_tail "$log_file"
        return 1
    fi

    if ! grep -q "FrameVM terminal status: exited-success" "$log_file"; then
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
    framevm_finish_host
    exit 1
fi

if framevm_run_load "${FRAMEVM_ROOTFS_MARKER}" rootfs; then
    framevm_finish_host
    exit 0
fi

printf '\nFRAMEVM_ROOTFS_FAILED\n'
framevm_finish_host
exit 1
