#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -eu

usage() {
    cat <<'EOF'
Usage:
  nested_l2_qemu.sh <l2_kernel> <l2_initrd> [extra qemu args...]

Environment variables:
  L2_SMP      vCPU count for L2 (default: 2)
  L2_MEM      guest memory for L2 (default: 2G)
  L2_CPU      CPU model for L2 (default: host)
  L2_APPEND   kernel cmdline for L2

Example:
  nested_l2_qemu.sh /ext2/l2/bzImage /ext2/l2/initramfs.cpio.gz \
    -drive if=none,format=raw,id=d0,file=/ext2/l2/ext2.img \
    -device virtio-blk-pci,drive=d0
EOF
}

if [ $# -lt 2 ]; then
    usage >&2
    exit 1
fi

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "Error: qemu-system-x86_64 not found in this guest." >&2
    echo "Rebuild initramfs with ENABLE_NESTED_QEMU=true." >&2
    exit 1
fi

if [ ! -e /dev/kvm ]; then
    echo "Error: /dev/kvm is missing in L1 guest." >&2
    echo "Ensure L1 was started with nested virtualization enabled (e.g. -cpu host,+vmx)." >&2
    exit 1
fi

if ! grep -Eq 'vmx|svm' /proc/cpuinfo; then
    echo "Warning: vmx/svm flag is not visible in /proc/cpuinfo." >&2
    echo "Nested KVM may fail." >&2
fi

L2_KERNEL="$1"
L2_INITRD="$2"
shift 2

if [ ! -f "${L2_KERNEL}" ]; then
    echo "Error: L2 kernel not found: ${L2_KERNEL}" >&2
    exit 1
fi

if [ ! -f "${L2_INITRD}" ]; then
    echo "Error: L2 initrd not found: ${L2_INITRD}" >&2
    exit 1
fi

L2_SMP="${L2_SMP:-2}"
L2_MEM="${L2_MEM:-2G}"
L2_CPU="${L2_CPU:-host}"
L2_APPEND="${L2_APPEND:-console=ttyS0 rdinit=/bin/sh mitigations=off hugepages=0 transparent_hugepage=never}"

exec qemu-system-x86_64 \
    --no-reboot \
    -accel kvm \
    -machine q35,kernel-irqchip=split \
    -cpu "${L2_CPU}" \
    -smp "${L2_SMP}" \
    -m "${L2_MEM}" \
    -nographic \
    -serial mon:stdio \
    -kernel "${L2_KERNEL}" \
    -initrd "${L2_INITRD}" \
    -append "${L2_APPEND}" \
    "$@"
