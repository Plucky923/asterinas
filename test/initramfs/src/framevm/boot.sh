#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

. /test/framevm/common.sh

if framevm_run_load "${FRAMEVM_BOOT_MARKER}" boot; then
    framevm_finish_host
    exit 0
fi

framevm_finish_host
exit 1
