#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

. /test/framevm/common.sh

if framevm_run_load "${FRAMEVM_REGRESSION_MARKER}" regression; then
    framevm_finish_host
    exit 0
fi

printf '\nFRAMEVM_REGRESSION_FAILED\n'
framevm_finish_host
exit 1
