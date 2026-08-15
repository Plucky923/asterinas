#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -eu

. /test/framevm/common.sh

FRAMEV_NET_MARKER=FRAMEV_NET_OK
framevm_case_start net
framevm_prepare_drive net
drive="$FRAMEVM_PREPARED_DRIVE"
log_file=/tmp/framev-net.log
framevm_register_cleanup_path "$log_file"

if ! framevm_run_with_network_peer "${FRAMEVM_VCPUS:-1}" "$drive" \
    "init=/bin/framevm-test-runner FRAMEVM_TEST=net" \
    >"$log_file" 2>&1; then
    echo "FrameV-net HTTP fixture failed"
    framevm_dump_log_tail "$log_file"
    framevm_case_fail net network
    framevm_finish_host
    exit 1
fi

for marker in FRAMEV_NET_HTTP_OK FRAMEV_NET_HTTP_SERVED FRAMEV_NET_PEER_OK; do
    if ! grep -q "$marker" "$log_file"; then
        echo "FrameV-net fixture is missing $marker"
        framevm_dump_log_tail "$log_file"
        framevm_case_fail net missing-marker
        framevm_finish_host
        exit 1
    fi
done

cat "$log_file"
printf '\n%s\n' "$FRAMEV_NET_MARKER"
framevm_case_pass net
framevm_finish_host
