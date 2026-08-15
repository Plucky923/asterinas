#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -eu

. /test/framevm/common.sh

framevm_case_start shell

FRAMEVM_SHELL_MARKER=FRAMEVM_SHELL_OK

framevm_prepare_drive shell
drive="$FRAMEVM_PREPARED_DRIVE"
log_file=/tmp/framevm-shell.log
framevm_register_cleanup_path "$log_file"

if ! framevm_run "${FRAMEVM_VCPUS:-1}" "$drive" \
    "init=/bin/framevm-test-runner FRAMEVM_TEST=shell" \
    >"$log_file" 2>&1; then
    echo "[framevm-shell] shell parity run failed"
    framevm_dump_log_tail "$log_file"
    printf '\nFRAMEVM_SHELL_FAILED\n'
    framevm_case_fail shell guest-status
    framevm_finish_host
    exit 1
fi

if ! grep -q "FrameVM terminal status: exited code=0" "$log_file"; then
    echo "[framevm-shell] shell parity run did not exit successfully"
    framevm_dump_log_tail "$log_file"
    printf '\nFRAMEVM_SHELL_FAILED\n'
    framevm_case_fail shell terminal-status
    framevm_finish_host
    exit 1
fi

if grep -q "can't access tty; job control turned off" "$log_file"; then
    echo "[framevm-shell] BusyBox reported missing TTY"
    framevm_dump_log_tail "$log_file"
    printf '\nFRAMEVM_SHELL_FAILED\n'
    framevm_case_fail shell tty
    framevm_finish_host
    exit 1
fi

printf '\n%s\n' "$FRAMEVM_SHELL_MARKER"
framevm_case_pass shell
framevm_finish_host
