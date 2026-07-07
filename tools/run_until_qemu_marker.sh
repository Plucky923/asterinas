#!/bin/sh
# SPDX-License-Identifier: MPL-2.0

set -eu

if [ "$#" -lt 4 ] || [ "$3" != "--" ]; then
    echo "Usage: $0 MARKER TIMEOUT_SECS -- COMMAND [ARG...]" >&2
    exit 2
fi

marker=$1
timeout_secs=$2
shift 3

rm -f qemu.log kernel/qemu.log

setsid "$@" &
cmd_pid=$!
elapsed=0

terminate_cmd() {
    kill -TERM "-$cmd_pid" 2>/dev/null || true
    kill -TERM "$cmd_pid" 2>/dev/null || true
    sleep 2
    if kill -0 "$cmd_pid" 2>/dev/null; then
        kill -KILL "-$cmd_pid" 2>/dev/null || true
        kill -KILL "$cmd_pid" 2>/dev/null || true
    fi
    wait "$cmd_pid" 2>/dev/null || true
}

while [ "$elapsed" -lt "$timeout_secs" ]; do
    for log_file in qemu.log kernel/qemu.log; do
        if [ -f "$log_file" ] && grep -F -q "$marker" "$log_file"; then
            terminate_cmd
            exit 0
        fi
    done

    if ! kill -0 "$cmd_pid" 2>/dev/null; then
        wait "$cmd_pid"
        exit $?
    fi

    sleep 1
    elapsed=$((elapsed + 1))
done

terminate_cmd
echo "Timed out waiting for qemu.log marker: $marker" >&2
exit 124
