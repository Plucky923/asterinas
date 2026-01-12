#!/bin/bash

# SPDX-License-Identifier: MPL-2.0

set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  check_nested_linux_stack.sh [--check-artifacts]

Options:
  --check-artifacts   Also verify required build artifacts exist.
  -h, --help          Show this help message.

This script performs host-side preflight checks for the Linux nested stack:
  L0 Linux Host -> L1 Linux(QEMU/KVM) -> L2 Linux(QEMU/KVM nested)
EOF
}

check_artifacts=0
for arg in "$@"; do
    case "$arg" in
        --check-artifacts)
            check_artifacts=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Error: unknown argument '$arg'" >&2
            usage >&2
            exit 1
            ;;
    esac
done

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../../../../.." && pwd)"

fail_count=0

pass() {
    echo "[PASS] $*"
}

fail() {
    echo "[FAIL] $*" >&2
    fail_count=$((fail_count + 1))
}

check_cmd() {
    local cmd="$1"
    if command -v "$cmd" >/dev/null 2>&1; then
        pass "command found: ${cmd}"
    else
        fail "missing command: ${cmd}"
    fi
}

check_file() {
    local path="$1"
    if [ -f "$path" ]; then
        pass "file exists: ${path}"
    else
        fail "missing file: ${path}"
    fi
}

echo "=== Host Preflight: Linux Nested Stack ==="
echo "Repository root: ${repo_root}"

for cmd in qemu-system-x86_64 nix-build mke2fs debugfs awk grep sed; do
    check_cmd "$cmd"
done

if [ -e /dev/kvm ]; then
    if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
        pass "/dev/kvm is readable and writable"
    else
        fail "/dev/kvm exists but current user lacks rw permission"
    fi
else
    fail "/dev/kvm does not exist"
fi

if grep -Eq '(vmx|svm)' /proc/cpuinfo; then
    pass "CPU virtualization flag detected (vmx/svm)"
else
    fail "CPU virtualization flag not found in /proc/cpuinfo"
fi

if [ "$check_artifacts" -eq 1 ]; then
    echo "=== Artifact Checks ==="
    check_file "${repo_root}/test/initramfs/build/initramfs.cpio.gz"
    check_file "${repo_root}/test/initramfs/build/initramfs.l1.cpio.gz"
    check_file "${repo_root}/test/initramfs/build/initramfs.l2.cpio.gz"
    check_file "${repo_root}/test/initramfs/build/ext2.img"
    check_file "/opt/linux_binary_cache/vmlinuz"
    check_file "${repo_root}/test/initramfs/src/apps/scripts/nested_l2_qemu.sh"
fi

if [ "$fail_count" -ne 0 ]; then
    echo "Preflight failed with ${fail_count} issue(s)." >&2
    exit 1
fi

echo "Preflight checks passed."
