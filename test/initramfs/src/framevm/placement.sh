#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -eu

. /test/framevm/common.sh

framevm_case_start placement

CGROUP=/sys/fs/cgroup/framevm-placement
OBSERVER_CGROUP=/sys/fs/cgroup/framevm-placement-observer
LOG=/tmp/framevm-placement.log
CONTROL=/tmp/framevm-placement.control
WAIT_ATTEMPTS=6000

wait_for_pattern() {
    pattern="$1"
    attempts=0
    while [ "$attempts" -lt "$WAIT_ATTEMPTS" ]; do
        if grep -q "$pattern" "$LOG" 2>/dev/null; then
            return 0
        fi
        sleep 0.01
        attempts=$((attempts + 1))
    done
    echo "timeout waiting for $pattern"
    framevm_dump_log_tail "$LOG"
    return 1
}

wait_for_process_exit() {
    pid="$1"
    elapsed=0
    while [ "$elapsed" -lt 5 ]; do
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid" 2>/dev/null || true
            return 0
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    return 1
}

cleanup_placement_test() {
    status=$?
    if [ -n "${FRAMEVMM_PID:-}" ]; then
        kill -TERM "$FRAMEVMM_PID" 2>/dev/null || true
        if ! wait_for_process_exit "$FRAMEVMM_PID"; then
            kill -KILL "$FRAMEVMM_PID" 2>/dev/null || true
        fi
        wait "$FRAMEVMM_PID" 2>/dev/null || true
    fi
    exec 3>&-
    rm -f "$CONTROL"
    rmdir "$CGROUP" 2>/dev/null || true
    rmdir "$OBSERVER_CGROUP" 2>/dev/null || true
    if [ "$status" -ne 0 ] && [ "${FRAMEVM_CASE_RESULT_SENT:-0}" -eq 0 ]; then
        framevm_case_fail placement host-exit
    fi
    return "$status"
}
trap 'exit 130' INT
trap 'exit 143' TERM
trap cleanup_placement_test EXIT

echo '+cpuset +cpu' > /sys/fs/cgroup/cgroup.subtree_control
mkdir "$CGROUP"
echo 0-1 > "$CGROUP/cpuset.cpus"
mkdir "$OBSERVER_CGROUP"
echo 2 > "$OBSERVER_CGROUP/cpuset.cpus"

# Keep the test controller off the CPU reserved for the FrameVM group. The
# process starts with the init task's affinity, which may otherwise remain
# narrower than the root cgroup's effective cpuset.
taskset -p 4 $$ >/dev/null

framevm_prepare_drive placement
drive="$FRAMEVM_PREPARED_DRIVE"
framevm_register_cleanup_path "$LOG"
mkfifo "$CONTROL"
exec 3<> "$CONTROL"
framevm_select_next_sock_device
FRAMEVM_PLACEMENT_CGROUP_PROCS="$CGROUP/cgroup.procs" \
FRAMEVM_PLACEMENT_DRIVE="$drive" \
FRAMEVM_PLACEMENT_SOCK_DEVICE="$FRAMEVM_SOCK_DEVICE" \
sh -c '
    echo $$ > "$FRAMEVM_PLACEMENT_CGROUP_PROCS"
    exec timeout -k 5 180 framevmm -smp 2 -m "$FRAMEVM_MEMORY_LIMIT" -kernel /framevm/framevm.o \
        -append "init=/bin/framevm-test-runner FRAMEVM_TEST=cpuset-resume" \
        -nographic \
        -drive "file=$FRAMEVM_PLACEMENT_DRIVE,id=root,format=raw,readonly=off" \
        -device framev-blk,drive=root,root=on \
        -device "$FRAMEVM_PLACEMENT_SOCK_DEVICE"
' <"$CONTROL" >"$LOG" 2>&1 &
FRAMEVMM_PID=$!

wait_for_pattern FRAMEVM_CPUSET_IDLE_READY

# The hidden FrameVM group keeps the creator's cgroup as its immutable parent.
# Wait for the launcher process tree to settle before moving it to the sibling
# cgroup that remains runnable while the captured parent has no CPU.
while :; do
    observer_pids=$(cat "$CGROUP/cgroup.procs")
    [ -n "$observer_pids" ] || break
    for observer_pid in $observer_pids; do
        echo "$observer_pid" > "$OBSERVER_CGROUP/cgroup.procs"
    done
done
echo "[framevm-placement] FrameVM control processes moved to CPU2"

for cgroup_child in "$CGROUP"/*; do
    if [ -d "$cgroup_child" ]; then
        echo "FrameVM scheduler group appeared in cgroupfs: $cgroup_child"
        exit 1
    fi
done
echo "[framevm-placement] hidden scheduler group is absent from cgroupfs"
remaining_pids=$(cat "$CGROUP/cgroup.procs")
if [ -n "$remaining_pids" ]; then
    echo "FrameVM launcher process remained in the captured cgroup"
    echo "$remaining_pids"
    exit 1
fi
echo "[framevm-placement] captured cgroup has no visible processes"
usage_before=$(sed -n 's/^usage_usec //p' "$CGROUP/cpu.stat")

echo "[framevm-placement] clearing the idle captured cpuset"
printf '\n' > "$CGROUP/cpuset.cpus"
echo "[framevm-placement] idle captured cpuset is empty"

printf 'i\n' >&3
attempts=0
while [ "$attempts" -lt 200 ]; do
    if grep -q FRAMEVM_CPUSET_READY "$LOG"; then
        echo "FrameVM consumed pending idle work while its effective cpuset was empty"
        framevm_dump_log_tail "$LOG"
        exit 1
    fi
    attempts=$((attempts + 1))
done
echo "[framevm-placement] idle work queued while the captured cpuset is empty"

echo "[framevm-placement] restoring the idle captured cpuset"
echo 0-1 > "$CGROUP/cpuset.cpus"
wait_for_pattern FRAMEVM_CPUSET_READY
echo "[framevm-placement] pending idle work made progress after restoration"

printf 'b\n' >&3
wait_for_pattern FRAMEVM_CPUSET_BASELINE
echo "[framevm-placement] busy workload progressed before shrink"

echo "[framevm-placement] shrinking the captured cpuset to CPU0"
printf 's\n' >&3
echo 0 > "$CGROUP/cpuset.cpus"
echo "[framevm-placement] effective cpuset after shrink: $(cat "$CGROUP/cpuset.cpus.effective")"
echo "[framevm-placement] captured cpuset shrink applied"
wait_for_pattern FRAMEVM_CPUSET_SHRUNK
echo "[framevm-placement] busy workload progressed after shrink"

echo "[framevm-placement] expanding the captured cpuset to CPU0-1"
printf 'e\n' >&3
echo 0-1 > "$CGROUP/cpuset.cpus"
wait_for_pattern FRAMEVM_CPUSET_EXPANDED
echo "[framevm-placement] busy workload progressed after expansion"

echo "[framevm-placement] clearing the captured cpuset"
printf 'r\n' >&3
printf '\n' > "$CGROUP/cpuset.cpus"
echo "[framevm-placement] effective cpuset after empty: $(cat "$CGROUP/cpuset.cpus.effective")"
echo "[framevm-placement] captured cpuset is empty"

attempts=0
while [ "$attempts" -lt 200 ]; do
    if grep -q FRAMEVM_CPUSET_RESTORED "$LOG"; then
        echo "FrameVM ran while its effective cpuset was empty"
        framevm_dump_log_tail "$LOG"
        exit 1
    fi
    attempts=$((attempts + 1))
done

echo "[framevm-placement] restoring the captured cpuset"
echo 0-1 > "$CGROUP/cpuset.cpus"
echo "[framevm-placement] captured cpuset restored"
wait_for_pattern FRAMEVM_CPUSET_RESTORED
printf 'f\n' >&3

if ! wait "$FRAMEVMM_PID"; then
    echo "FrameVM failed after cpuset restoration"
    framevm_dump_log_tail "$LOG"
    exit 1
fi
FRAMEVMM_PID=
wait_for_pattern FRAMEVM_CPUSET_DONE
echo "[framevm-placement] busy guest resumed and completed"
usage_after=$(sed -n 's/^usage_usec //p' "$CGROUP/cpu.stat")
if [ "$usage_after" -le "$usage_before" ]; then
    echo "captured cgroup received no FrameVM CPU accounting"
    exit 1
fi
echo "[framevm-placement] captured parent CPU accounting increased"

echo FRAMEVM_PLACEMENT_OK
framevm_case_pass placement
framevm_finish_host
