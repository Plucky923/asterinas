#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

. /test/framevm/common.sh

framevm_case_start regression

if framevm_run_load "${FRAMEVM_REGRESSION_MARKER}" regression; then
    framevm_case_pass regression
    framevm_finish_host
    exit 0
fi

printf '\nFRAMEVM_REGRESSION_FAILED\n'
framevm_case_fail regression guest-status
framevm_finish_host
exit 1
