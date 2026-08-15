#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -eu

. /test/framevm/common.sh

framevm_case_start application

framevm_prepare_drive application
drive="$FRAMEVM_PREPARED_DRIVE"
nginx_log=/tmp/framevm-application-nginx.log
framevm_register_cleanup_path "$nginx_log"
sqlite_timeout=${FRAMEVM_SQLITE_TIMEOUT:-600}
sqlite_size=${FRAMEVM_SQLITE_SIZE:-25}
case "$sqlite_timeout" in
    ''|*[!0-9]*)
        echo "FRAMEVM_APPLICATION_FAILED stage=sqlite-timeout-value"
        framevm_case_fail application configuration
        framevm_finish_host
        exit 1
        ;;
esac
if [ "$sqlite_timeout" -lt 600 ]; then
    echo "FRAMEVM_APPLICATION_FAILED stage=sqlite-timeout-minimum"
    framevm_case_fail application configuration
    framevm_finish_host
    exit 1
fi

case "$sqlite_size" in
    ''|*[!0-9]*)
        echo "FRAMEVM_APPLICATION_FAILED stage=sqlite-size-value"
        framevm_case_fail application configuration
        framevm_finish_host
        exit 1
        ;;
esac
if [ "$sqlite_size" -lt 1 ] || [ "$sqlite_size" -gt 100 ]; then
    echo "FRAMEVM_APPLICATION_FAILED stage=sqlite-size-range"
    framevm_case_fail application configuration
    framevm_finish_host
    exit 1
fi

echo "FRAMEVM_APPLICATION_STAGE stage=sqlite-workload state=start"
FRAMEVM_RUN_TIMEOUT_ARGS="-k 5 -s TERM $sqlite_timeout"
if ! framevm_run_with_drive_arg \
    "file=$drive" application-sqlite-run \
    "FRAMEVM_SQLITE_TIMEOUT=$sqlite_timeout FRAMEVM_SQLITE_SIZE=$sqlite_size"; then
    echo "FRAMEVM_APPLICATION_FAILED stage=sqlite-workload"
    framevm_case_fail application sqlite-workload
    framevm_finish_host
    exit 1
fi
echo "FRAMEVM_APPLICATION_STAGE stage=sqlite-workload state=done"

echo "FRAMEVM_APPLICATION_STAGE stage=sqlite-integrity state=start"
FRAMEVM_RUN_TIMEOUT_ARGS="-k 5 -s TERM 180"
if ! framevm_run_with_drive_arg \
    "file=$drive" application-sqlite-check; then
    echo "FRAMEVM_APPLICATION_FAILED stage=sqlite-restart-integrity"
    framevm_case_fail application sqlite-integrity
    framevm_finish_host
    exit 1
fi
echo "FRAMEVM_APPLICATION_STAGE stage=sqlite-integrity state=done"
printf '\nFRAMEVM_SQLITE_OK\n'

FRAMEV_NET_PEER_MODE=application
FRAMEVM_RUN_TIMEOUT_ARGS="-k 5 -s TERM 240"
export FRAMEV_NET_PEER_MODE FRAMEVM_RUN_TIMEOUT_ARGS
echo "FRAMEVM_APPLICATION_STAGE stage=nginx-http state=start"
if ! framevm_run_with_network_peer "${FRAMEVM_VCPUS:-1}" "$drive" \
    "init=/bin/framevm-test-runner FRAMEVM_TEST=application-nginx" \
    >"$nginx_log" 2>&1; then
    echo "FRAMEVM_APPLICATION_FAILED stage=nginx-http"
    framevm_case_fail application nginx-http
    framevm_dump_log_tail "$nginx_log"
    framevm_finish_host
    exit 1
fi
for marker in FRAMEVM_NGINX_HTTP_OK FRAMEVM_NGINX_GUEST_OK FRAMEVM_NGINX_PEER_OK; do
    if ! grep -qx "$marker" "$nginx_log"; then
        echo "FRAMEVM_APPLICATION_FAILED stage=nginx-marker marker=$marker"
        framevm_case_fail application nginx-marker
        framevm_dump_log_tail "$nginx_log"
        framevm_finish_host
        exit 1
    fi
done
echo "FRAMEVM_APPLICATION_STAGE stage=nginx-http state=done"
cat "$nginx_log"
printf '\nFRAMEVM_NGINX_OK\n'
printf 'FRAMEVM_APPLICATION_OK\n'
framevm_case_pass application
framevm_finish_host
