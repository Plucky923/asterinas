#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

# Interactive init used by `make run_framevm` without `AUTO_TEST`.
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

demo_rootfs=/tmp/framevm-rootfs.ext2
if ! gzip -dc /framevm/rootfs.ext2.gz > "$demo_rootfs"; then
    echo "[framevm] failed to prepare $demo_rootfs" >&2
    poweroff -f
fi
if [ "$(wc -c < "$demo_rootfs")" != "$(cat /framevm/rootfs.ext2.size)" ]; then
    echo "[framevm] prepared rootfs size mismatch" >&2
    poweroff -f
fi

echo "FrameVM"
echo "[framevm] Asterinas host shell is ready"
echo "[framevm] writable FrameVM rootfs: $demo_rootfs"

framev-net-peer --shell
echo "[framevm] Asterinas host shell exited; powering off"
poweroff -f
