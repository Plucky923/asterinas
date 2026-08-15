#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

. /test/framevm/common.sh

framevm_case_start boot

if framevm_run_load "${FRAMEVM_BOOT_MARKER}" boot; then
    framevm_case_pass boot
    framevm_finish_host
    exit 0
fi

framevm_case_fail boot guest-status
framevm_finish_host
exit 1
