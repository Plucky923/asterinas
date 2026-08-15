#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -eu

. /test/framevm/common.sh

framevm_case_start memory

memory_log=/tmp/framevm-memory.log
framevm_register_cleanup_path "$memory_log"
framevm_prepare_drive memory
memory_drive="$FRAMEVM_PREPARED_DRIVE"

if ! framevm_run "${FRAMEVM_VCPUS:-1}" "$memory_drive" \
    "init=/bin/framevm-test-runner FRAMEVM_TEST=memory" \
    >"$memory_log" 2>&1; then
    echo "[framevm-memory] local allocation run failed"
    framevm_dump_log_tail "$memory_log"
    framevm_case_fail memory local-run
    framevm_finish_host
    exit 1
fi

if ! grep -q 'FrameVM terminal status: exited code=0' "$memory_log"; then
    echo "[framevm-memory] local allocation run did not exit successfully"
    framevm_dump_log_tail "$memory_log"
    framevm_case_fail memory terminal-status
    framevm_finish_host
    exit 1
fi

# The FrameV console is not the test-result transport. `framevmm` returning
# successfully with an `exited code=0` terminal status proves that the inner
# test function allocated and released its bounded buffer; publish the host
# observable marker only after that authoritative result.
printf '\nFRAMEVM_MEMORY_BOUNDED_ALLOC_OK\n'

# Exact OOM admission and rollback are covered by FrameVisor kernel tests. A
# userspace fault per page makes pressure tests unsuitable for this bounded
# runtime case. This second start proves that a limited domain's allocation
# and teardown do not poison the Host control path.
FRAMEVM_MEMORY_LIMIT=${FRAMEVM_MEMORY_SIBLING_LIMIT:-8G}
# The first instance remains quarantined while its non-co-designed service
# allocator owns opaque metadata. FrameV Sock CIDs are Host-global, so the
# independent sibling must use a different identity rather than colliding with
# that retained instance.
FRAMEVM_GUEST_CID=${FRAMEVM_MEMORY_SIBLING_CID:-4}
FRAMEVM_NEXT_GUEST_CID=$FRAMEVM_GUEST_CID
export FRAMEVM_MEMORY_LIMIT FRAMEVM_GUEST_CID FRAMEVM_NEXT_GUEST_CID
if ! framevm_run_load FRAMEVM_MEMORY_SIBLING_BOOT_OK boot; then
    framevm_case_fail memory sibling-boot
    framevm_finish_host
    exit 1
fi

printf '\nFRAMEVM_MEMORY_OK\n'
framevm_case_pass memory
framevm_finish_host
