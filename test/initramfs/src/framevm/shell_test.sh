#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -eu

. /test/framevm/common.sh

FRAMEVM_SHELL_MARKER=FRAMEVM_SHELL_OK

drive=$(framevm_prepare_drive shell)
log_file=/tmp/framevm-shell.log
framevm_register_cleanup_path "$log_file"

if ! framevmctl run --vcpus "${FRAMEVM_VCPUS:-1}" --drive "file=$drive" \
    --append "init=/bin/framevm-test-runner FRAMEVM_TEST=shell" \
    >"$log_file" 2>&1; then
    echo "[framevm-shell] shell parity run failed"
    framevm_dump_log_tail "$log_file"
    printf '\nFRAMEVM_SHELL_FAILED\n'
    framevm_finish_host
    exit 1
fi

if ! grep -q "FrameVM terminal status: exited-success" "$log_file"; then
    echo "[framevm-shell] shell parity run did not exit successfully"
    framevm_dump_log_tail "$log_file"
    printf '\nFRAMEVM_SHELL_FAILED\n'
    framevm_finish_host
    exit 1
fi

if grep -q "can't access tty; job control turned off" "$log_file"; then
    echo "[framevm-shell] BusyBox reported missing TTY"
    framevm_dump_log_tail "$log_file"
    printf '\nFRAMEVM_SHELL_FAILED\n'
    framevm_finish_host
    exit 1
fi

printf '\n%s\n' "$FRAMEVM_SHELL_MARKER"
framevm_finish_host
