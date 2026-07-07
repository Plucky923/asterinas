#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -eu

FRAMEVM_KEEP_HOST=1
export FRAMEVM_KEEP_HOST

run_child() {
    case_name="$1"
    script="$2"

    if "$script"; then
        return 0
    fi

    printf '\nFRAMEVM_ALL_FAILED case=%s\n' "$case_name"
    poweroff -f
    exit 1
}

run_child boot /test/framevm/boot.sh
run_child regression /test/framevm/regression.sh
run_child device /test/framevm/device.sh
run_child rootfs /test/framevm/rootfs.sh

poweroff -f
