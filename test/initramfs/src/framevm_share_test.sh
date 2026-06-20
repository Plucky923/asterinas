#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -eu

group0_share="${1:-1024}"
group1_share="${2:-4096}"
duration_ms="${3:-3000}"
status_file="/proc/framevm"

/bin/mount -t proc none /proc 2>/dev/null || true
/bin/mount -t sysfs none /sys 2>/dev/null || true

echo "[framevm-share-test] starting group0_share=${group0_share} group1_share=${group1_share} duration_ms=${duration_ms}"

if ! echo "share_test ${group0_share} ${group1_share} ${duration_ms}" > "${status_file}"; then
    cat "${status_file}" || true
    echo "FrameVM share test failed."
    poweroff -f
    exit 1
fi

status="$(cat "${status_file}" | tr -d '\r')"
printf '%s\n' "${status}"

if printf '%s\n' "${status}" | grep -q "share_test: passed=1" \
    && printf '%s\n' "${status}" | grep -q "^state: completed$" \
    && printf '%s\n' "${status}" | grep -q "^vm_count: 0$" \
    && printf '%s\n' "${status}" | grep -q "dynamic_share_update=1" \
    && printf '%s\n' "${status}" | grep -q "host_scheduler_path_exercised=1" \
    && printf '%s\n' "${status}" | grep -q "host_weight_matches_share=1" \
    && printf '%s\n' "${status}" | grep -q "group0_share=${group0_share}" \
    && printf '%s\n' "${status}" | grep -q "group1_share=${group1_share}" \
    && printf '%s\n' "${status}" | grep -q "group0_host_weight=" \
    && printf '%s\n' "${status}" | grep -q "group1_host_weight=" \
    && printf '%s\n' "${status}" | grep -q "group0_actual_host_weight=" \
    && printf '%s\n' "${status}" | grep -q "group1_actual_host_weight=" \
    && printf '%s\n' "${status}" | grep -q "group0_parent_pick_count=" \
    && printf '%s\n' "${status}" | grep -q "group1_parent_pick_count=" \
    && printf '%s\n' "${status}" | grep -q "group0_parent_pick_with_peer_count=" \
    && printf '%s\n' "${status}" | grep -q "group1_parent_pick_with_peer_count=" \
    && printf '%s\n' "${status}" | grep -q "group0_schedule_in_bound_count=" \
    && printf '%s\n' "${status}" | grep -q "group1_schedule_in_bound_count=" \
    && printf '%s\n' "${status}" | grep -q "group0_schedule_in_unbound_count=0 " \
    && printf '%s\n' "${status}" | grep -q "group1_schedule_in_unbound_count=0 " \
    && printf '%s\n' "${status}" | grep -q "share_update_count=" \
    && printf '%s\n' "${status}" | grep -q "group0_runtime_cycles=" \
    && printf '%s\n' "${status}" | grep -q "group1_runtime_cycles=" \
    && printf '%s\n' "${status}" | grep -q "group0_loops=" \
    && printf '%s\n' "${status}" | grep -q "group1_loops=" \
    && printf '%s\n' "${status}" | grep -q "expected_group1_per_mille=" \
    && printf '%s\n' "${status}" | grep -q "actual_runtime_group1_per_mille=" \
    && printf '%s\n' "${status}" | grep -q "actual_loop_group1_per_mille=" \
    && printf '%s\n' "${status}" | grep -q "tolerance_per_mille="; then
    echo "FrameVM share test passed."
    poweroff -f
    exit 0
fi

echo "FrameVM share test failed."
poweroff -f
exit 1
