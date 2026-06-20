#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -eu

status_file="/proc/framevm"

/bin/mount -t proc none /proc 2>/dev/null || true
/bin/mount -t sysfs none /sys 2>/dev/null || true

read_status() {
    cat "${status_file}" | tr -d '\r'
}

require_status() {
    pattern="$1"
    message="$2"

    if printf '%s\n' "${status}" | grep -q "${pattern}"; then
        return
    fi

    echo "FrameVM foreground smoke test failed: ${message}."
    poweroff -f
    exit 1
}

echo "[framevm-foreground-smoke] starting"
printf '%s\n' \
    "input=pwd" \
    "cd /tmp" \
    "pwd" \
    "printf 'framevm-cwd-ok\\n' > cwd-file" \
    "cat cwd-file" \
    "rm cwd-file" \
    "test ! -e cwd-file" \
    "cd /" \
    "ls -l /linktmp" \
    "ls /" \
    "exit" > "${status_file}"

if ! echo 1 > "${status_file}"; then
    cat "${status_file}" || true
    echo "FrameVM foreground smoke test failed."
    poweroff -f
    exit 1
fi

status="$(read_status)"
printf '%s\n' "${status}"

require_status "^state: completed$" "FrameVM did not complete"
require_status "^vm_count: 0$" "FrameVM did not return to host"
require_status "output:" "missing captured FrameVM console output"
require_status "~ # ls /" "missing BusyBox shell command echo"
require_status "^/tmp$" "FrameVM chdir/getcwd did not update cwd"
require_status "framevm-cwd-ok" "FrameVM relative file I/O failed"
require_status "linktmp.*->.*/tmp" "FrameVM symlink metadata/readlink path failed"
require_status "~ # exit" "missing BusyBox shell exit"
require_status "bin" "missing /bin in FrameVM rootfs"
require_status "etc" "missing /etc in FrameVM rootfs"
require_status "proc" "missing /proc in FrameVM rootfs"
require_status "tmp" "missing /tmp in FrameVM rootfs"

echo "FrameVM foreground smoke test passed."
poweroff -f
exit 0
