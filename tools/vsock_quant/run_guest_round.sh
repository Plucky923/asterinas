#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -eu

usage() {
	cat <<'USAGE'
Usage:
  run_guest_round.sh [options]

Options:
  --run-dir <dir>        Guest run dir (default: /ext2/vsock_quant/run)
  --server-bin <path>    Server binary (default: /ext2/vsock_bin/vsock_rtt_seq_server)
  --collector <path>     Collector script (default: /ext2/tools/vsock_quant/collect_kernel_events_tracefs.sh)
  --port <port>          vsock port (default: 20002)
  --payload <bytes>      Payload bytes (default: 4)
  --seconds <sec>        Collection window (default: 240)
  --poweroff             Power off after capture

Example:
  /ext2/tools/vsock_quant/run_guest_round.sh --seconds 240
USAGE
}

RUN_DIR="/ext2/vsock_quant/run"
SERVER_BIN="/ext2/vsock_bin/vsock_rtt_seq_server"
COLLECTOR="/ext2/tools/vsock_quant/collect_kernel_events_tracefs.sh"
PORT="20002"
PAYLOAD="4"
SECONDS_TO_RUN="240"
DO_POWEROFF=0

is_mounted_target() {
	target="$1"
	if [ ! -r /proc/mounts ]; then
		return 1
	fi
	awk -v t="${target}" '$2 == t { found = 1 } END { exit(found ? 0 : 1) }' /proc/mounts
}

ensure_mount() {
	fs_type="$1"
	source="$2"
	target="$3"

	if is_mounted_target "${target}"; then
		return 0
	fi
	mount -t "${fs_type}" "${source}" "${target}"
}

while [ "$#" -gt 0 ]; do
	case "$1" in
	--run-dir)
		RUN_DIR="${2:-}"
		shift 2
		;;
	--server-bin)
		SERVER_BIN="${2:-}"
		shift 2
		;;
	--collector)
		COLLECTOR="${2:-}"
		shift 2
		;;
	--port)
		PORT="${2:-}"
		shift 2
		;;
	--payload)
		PAYLOAD="${2:-}"
		shift 2
		;;
	--seconds)
		SECONDS_TO_RUN="${2:-}"
		shift 2
		;;
	--poweroff)
		DO_POWEROFF=1
		shift
		;;
	-h|--help)
		usage
		exit 0
		;;
	*)
		echo "Unknown arg: $1" >&2
		usage >&2
		exit 1
		;;
	esac
done

mkdir -p /proc /sys /dev /sys/kernel/tracing || true

ensure_mount proc proc /proc || true
ensure_mount sysfs sysfs /sys || true
ensure_mount devtmpfs devtmpfs /dev || true
ensure_mount tracefs tracefs /sys/kernel/tracing || true

mkdir -p /ext2
if ! is_mounted_target /ext2; then
	if ! mount -t ext2 /dev/vda /ext2; then
		mount -t ext2 /dev/sda /ext2
	fi
fi

if [ ! -x "${SERVER_BIN}" ]; then
	echo "ERROR: server not executable: ${SERVER_BIN}" >&2
	exit 1
fi
if [ ! -x "${COLLECTOR}" ]; then
	echo "ERROR: collector not executable: ${COLLECTOR}" >&2
	exit 1
fi

mkdir -p "${RUN_DIR}"
rm -f "${RUN_DIR}"/*

"${SERVER_BIN}" "${PORT}" "${PAYLOAD}" "${RUN_DIR}/server_user.csv" > "${RUN_DIR}/server.log" 2>&1 &
SERVER_PID=$!
echo "SERVER_PID=${SERVER_PID}"

sleep 1
if [ ! -d "/proc/${SERVER_PID}" ]; then
	echo "ERROR: server exited unexpectedly" >&2
	tail -n 80 "${RUN_DIR}/server.log" >&2 || true
	exit 1
fi

tail -n 20 "${RUN_DIR}/server.log" || true

"${COLLECTOR}" --pid "${SERVER_PID}" --side guest --seconds "${SECONDS_TO_RUN}" --out "${RUN_DIR}/guest_kernel.raw" --no-parse > "${RUN_DIR}/guest_collector.log" 2>&1 &
GTRACE_PID=$!
echo "GTRACE_PID=${GTRACE_PID}"

echo "[guest] collector running; now switch to host terminal and run run_host_round.sh"

wait "${GTRACE_PID}" || true

if ! grep -q "syscalls: using" "${RUN_DIR}/guest_collector.log"; then
	echo "ERROR: guest collector log missing syscall mode line" >&2
	tail -n 120 "${RUN_DIR}/guest_collector.log" >&2 || true
	exit 1
fi
if ! grep -q "pid namespace chain:" "${RUN_DIR}/guest_collector.log"; then
	echo "ERROR: guest collector log missing pid namespace diagnostics" >&2
	tail -n 120 "${RUN_DIR}/guest_collector.log" >&2 || true
	exit 1
fi

test -s "${RUN_DIR}/server_user.csv"
test -s "${RUN_DIR}/guest_kernel.raw"

ls -lh "${RUN_DIR}/server_user.csv" "${RUN_DIR}/guest_kernel.raw" "${RUN_DIR}/guest_collector.log"

kill "${SERVER_PID}" 2>/dev/null || true
sync

echo "GUEST_CAPTURE_OK run_dir=${RUN_DIR}"

if [ "${DO_POWEROFF}" -eq 1 ]; then
	poweroff -f
fi
