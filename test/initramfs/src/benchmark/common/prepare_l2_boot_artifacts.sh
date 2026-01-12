#!/bin/bash

# SPDX-License-Identifier: MPL-2.0

set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  prepare_l2_boot_artifacts.sh --ext2 <ext2.img> --kernel <vmlinuz|bzImage> --initrd <initramfs.cpio.gz> [--l2-dir /l2]

Example:
  prepare_l2_boot_artifacts.sh \
    --ext2 test/initramfs/build/ext2.img \
    --kernel /opt/linux_binary_cache/vmlinuz \
    --initrd test/initramfs/build/initramfs.cpio.gz \
    --l2-dir /l2

This writes the L2 kernel and initrd into ext2 image, so L1 can boot L2 via:
  /ext2/l2/bzImage
  /ext2/l2/initramfs.cpio.gz
EOF
}

ext2_img=""
kernel_img=""
initrd_img=""
l2_dir="/l2"

while [ $# -gt 0 ]; do
    case "$1" in
        --ext2)
            ext2_img="${2:-}"
            shift 2
            ;;
        --kernel)
            kernel_img="${2:-}"
            shift 2
            ;;
        --initrd)
            initrd_img="${2:-}"
            shift 2
            ;;
        --l2-dir)
            l2_dir="${2:-}"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Error: unknown argument '$1'" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [ -z "${ext2_img}" ] || [ -z "${kernel_img}" ] || [ -z "${initrd_img}" ]; then
    echo "Error: --ext2, --kernel and --initrd are required." >&2
    usage >&2
    exit 1
fi

if ! command -v debugfs >/dev/null 2>&1; then
    echo "Error: debugfs not found. Please install e2fsprogs." >&2
    exit 1
fi

if [ ! -f "${ext2_img}" ]; then
    echo "Error: ext2 image not found: ${ext2_img}" >&2
    exit 1
fi
if [ ! -f "${kernel_img}" ]; then
    echo "Error: kernel image not found: ${kernel_img}" >&2
    exit 1
fi
if [ ! -f "${initrd_img}" ]; then
    echo "Error: initrd image not found: ${initrd_img}" >&2
    exit 1
fi

if command -v stat >/dev/null 2>&1; then
    initrd_size_bytes="$(stat -c '%s' "${initrd_img}")"
    initrd_size_mib="$((initrd_size_bytes / 1024 / 1024))"
    echo "Initrd size: ${initrd_size_mib} MiB (${initrd_size_bytes} bytes)"

    # In nested runs, oversized initrd often fails in L2 with:
    # "rootfs image is not initramfs ... unknown-block(0,0)".
    # Default guardrail: fail early unless user explicitly allows large images.
    max_initrd_mib="${MAX_L2_INITRD_MIB:-256}"
    if [ "${initrd_size_mib}" -gt "${max_initrd_mib}" ] && [ "${ALLOW_LARGE_L2_INITRD:-0}" != "1" ]; then
        echo "Error: initrd is too large for typical L2 memory setup (${initrd_size_mib} MiB > ${max_initrd_mib} MiB)." >&2
        echo "Build a slim L2 initramfs (without nested qemu payload), or set ALLOW_LARGE_L2_INITRD=1 to bypass." >&2
        exit 1
    fi
fi

if command -v gzip >/dev/null 2>&1; then
    if [[ "${initrd_img}" == *.gz ]]; then
        if gzip -t "${initrd_img}" >/dev/null 2>&1; then
            echo "Initrd gzip integrity: OK"
        else
            echo "Error: initrd gzip integrity check failed: ${initrd_img}" >&2
            exit 1
        fi
    fi
fi

run_debugfs() {
    local cmd="$1"
    debugfs -w -R "$cmd" "${ext2_img}" >/dev/null 2>&1
}

echo "[1/4] Ensuring directory exists: ${l2_dir}"
run_debugfs "mkdir ${l2_dir}" || true

echo "[2/4] Removing stale files (if any)"
run_debugfs "rm ${l2_dir}/bzImage" || true
run_debugfs "rm ${l2_dir}/initramfs.cpio.gz" || true

echo "[3/4] Writing L2 kernel/initrd"
debugfs -w -R "write ${kernel_img} ${l2_dir}/bzImage" "${ext2_img}" >/dev/null
debugfs -w -R "write ${initrd_img} ${l2_dir}/initramfs.cpio.gz" "${ext2_img}" >/dev/null

echo "[4/4] Listing target directory"
debugfs -R "ls -l ${l2_dir}" "${ext2_img}" | sed 's/^/  /'

echo "Prepared L2 boot artifacts in ext2 image:"
echo "  ${l2_dir}/bzImage"
echo "  ${l2_dir}/initramfs.cpio.gz"
