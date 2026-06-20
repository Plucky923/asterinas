#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

# Interactive init used by `make framevm`.
#
# The generic `/init` wrapper runs commands through `script(1)` and powers off
# after they return, which is useful for tests but not for a hand-driven FrameVM
# session. This script is installed as the kernel init process directly.

/bin/mount -t sysfs none /sys 2>/dev/null || true
/bin/mount -t proc none /proc 2>/dev/null || true
/bin/mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null || true
/bin/mount -t configfs none /sys/kernel/config 2>/dev/null || true
/bin/mount -t ext2 /dev/vda /ext2 2>/dev/null || true
/bin/mount -t exfat /dev/vdb /exfat 2>/dev/null || true

echo "[framevm] Asterinas shell is ready"
echo "[framevm] start FrameVM with: echo 1 > /proc/framevm"

while true; do
    script /dev/null -q -c "/bin/sh -i"
    echo "[framevm] Asterinas shell exited; restarting"
    /bin/sleep 1
done
