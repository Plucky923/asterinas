#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -eu

vcpu_count="${1:-1}"
wait_loops="${2:-60}"
task_group_share="${3:-1024}"
status_file="/proc/framevm"

echo "[framevm] starting ${vcpu_count} vCPU(s)"
echo "share=${task_group_share}" > "${status_file}"
echo "background ${vcpu_count}" > "${status_file}"

read_status() {
    cat "${status_file}" | tr -d '\r'
}

verify_completed_status() {
    status="$1"
    printf '%s\n' "${status}"
    if ! printf '%s\n' "${status}" | grep -q "task_group: .*share=${task_group_share}"; then
        echo "[framevm] task group share was not applied"
        exit 1
    fi
    echo "[framevm] completed"
    exit 0
}

i=0
while [ "${i}" -lt "${wait_loops}" ]; do
    status="$(read_status)"
    state="$(printf '%s\n' "${status}" | sed -n 's/^state: //p')"

    case "${state}" in
    running)
        sleep 1
        status="$(read_status)"
        state="$(printf '%s\n' "${status}" | sed -n 's/^state: //p')"
        if [ "${state}" = "completed" ]; then
            verify_completed_status "${status}"
        fi
        vm_count="$(printf '%s\n' "${status}" | sed -n 's/^vm_count: //p')"
        printf '%s\n' "${status}"
        if [ "${vm_count:-0}" -lt 1 ]; then
            echo "[framevm] no running FrameVM instance was registered"
            exit 1
        fi
        echo "[framevm] started; the console is now owned by FrameVM"
        while :; do
            sleep 3600
        done
        ;;
    completed)
        verify_completed_status "${status}"
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

read_status
echo "[framevm] timed out waiting for FrameVM to start"
exit 1
