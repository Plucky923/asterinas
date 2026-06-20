#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -eu

status_file="/proc/framevm"

/bin/mount -t proc none /proc 2>/dev/null || true
/bin/mount -t sysfs none /sys 2>/dev/null || true

echo "[framevm-busybox-smoke] starting"

if ! echo "busybox_smoke" > "${status_file}"; then
    cat "${status_file}" || true
    echo "FrameVM BusyBox smoke test failed."
    poweroff -f
    exit 1
fi

status="$(cat "${status_file}" | tr -d '\r')"
printf '%s\n' "${status}"

if printf '%s\n' "${status}" | grep -q "busybox_smoke: passed=1" \
    && printf '%s\n' "${status}" | grep -q "found_cwd_tmp=1" \
    && printf '%s\n' "${status}" | grep -q "found_cwd_file=1" \
    && printf '%s\n' "${status}" | grep -q "found_vfs_marker=1" \
    && printf '%s\n' "${status}" | grep -q "exited_to_host=1" \
    && printf '%s\n' "${status}" | grep -q "found_vsock_probe=1" \
    && printf '%s\n' "${status}" | grep -q "^state: completed$" \
    && printf '%s\n' "${status}" | grep -q "^vm_count: 0$"; then
    echo "FrameVM BusyBox smoke test passed."
    poweroff -f
    exit 0
fi

echo "FrameVM BusyBox smoke test failed."
poweroff -f
exit 1
