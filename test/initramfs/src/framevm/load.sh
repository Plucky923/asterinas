#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

. /test/framevm/common.sh

framevm_case_start load

if framevm_run_load "${FRAMEVM_LOAD_MARKER}" load; then
    framevm_case_pass load
    framevm_finish_host
    exit 0
fi

framevm_case_fail load guest-status
framevm_finish_host
exit 1
