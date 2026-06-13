#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -eu

vcpu_count="${1:-1}"
wait_loops="${2:-60}"
status_file="/proc/framevm"

echo "[framevm] starting ${vcpu_count} vCPU(s)"
echo "${vcpu_count}" > "${status_file}"

i=0
while [ "${i}" -lt "${wait_loops}" ]; do
    status="$(cat "${status_file}")"
    state="$(printf '%s\n' "${status}" | sed -n 's/^state: //p')"

    case "${state}" in
    running | completed)
        sleep 1
        status="$(cat "${status_file}")"
        vm_count="$(printf '%s\n' "${status}" | sed -n 's/^vm_count: //p')"
        printf '%s\n' "${status}"
        if [ "${vm_count:-0}" -lt 1 ]; then
            echo "[framevm] no running FrameVM instance was registered"
            exit 1
        fi
        echo "[framevm] started"
        exit 0
        ;;
    failed)
        printf '%s\n' "${status}"
        echo "[framevm] failed"
        exit 1
        ;;
    esac

    i=$((i + 1))
    sleep 1
done

cat "${status_file}"
echo "[framevm] timed out waiting for FrameVM to start"
exit 1
