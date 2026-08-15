#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -eu

. /test/framevm/common.sh

framevm_case_start all

FRAMEVM_KEEP_HOST=1
export FRAMEVM_KEEP_HOST
FRAMEVM_ALL_CHILD_CID=3

run_child() {
    case_name="$1"
    script="$2"

    child_cid="$FRAMEVM_ALL_CHILD_CID"
    FRAMEVM_ALL_CHILD_CID=$((FRAMEVM_ALL_CHILD_CID + 100))
    if FRAMEVM_GUEST_CID="$child_cid" FRAMEVM_NEXT_GUEST_CID="$child_cid" "$script"; then
        return 0
    fi

    printf '\nFRAMEVM_ALL_FAILED case=%s\n' "$case_name"
    framevm_case_fail all "child-${case_name}"
    poweroff -f
    exit 1
}

run_child boot /test/framevm/boot.sh
run_child regression /test/framevm/regression.sh
run_child device /test/framevm/device.sh
run_child rootfs /test/framevm/rootfs.sh
run_child lifecycle /test/framevm/lifecycle.sh
run_child net /test/framevm/net.sh
run_child placement /test/framevm/placement.sh
run_child fairness /test/framevm/fairness.sh
run_child shell /test/framevm/shell_test.sh

framevm_case_pass all
poweroff -f
