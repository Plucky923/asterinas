#!/usr/bin/env bash

# SPDX-License-Identifier: MPL-2.0

set -euo pipefail

usage() {
	cat <<'USAGE'
Usage:
  post_analyze_round.sh [options]

Options:
  --run-dir <dir>      Host run dir (default: /tmp/vsock_quant_run)
  --ext2-img <path>    ext2 image path (default: test/initramfs/build/ext2.img)
  --mount-dir <dir>    temp mount dir (default: /mnt/vsock_ext2)

Example:
  tools/vsock_quant/post_analyze_round.sh --run-dir /tmp/vsock_quant_run
USAGE
}

RUN_DIR="/tmp/vsock_quant_run"
EXT2_IMG="test/initramfs/build/ext2.img"
MOUNT_DIR="/mnt/vsock_ext2"

while [ "$#" -gt 0 ]; do
	case "$1" in
	--run-dir)
		RUN_DIR="${2:-}"
		shift 2
		;;
	--ext2-img)
		EXT2_IMG="${2:-}"
		shift 2
		;;
	--mount-dir)
		MOUNT_DIR="${2:-}"
		shift 2
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

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PARSER="${SCRIPT_DIR}/analysis/parse_tracefs_events.py"
ANALYZER="${SCRIPT_DIR}/analysis/analyze_segments.py"

if [ ! -x "${PARSER}" ] || [ ! -x "${ANALYZER}" ]; then
	echo "ERROR: parser/analyzer not executable under ${SCRIPT_DIR}/analysis" >&2
	exit 1
fi

if [ ! -f "${EXT2_IMG}" ]; then
	echo "ERROR: ext2 image not found: ${EXT2_IMG}" >&2
	exit 1
fi

run_as_root() {
	if [ "$(id -u)" -eq 0 ]; then
		"$@"
	else
		sudo "$@"
	fi
}

mkdir -p "${RUN_DIR}"

cleanup() {
	set +e
	if mountpoint -q "${MOUNT_DIR}"; then
		run_as_root umount "${MOUNT_DIR}"
	fi
}
trap cleanup EXIT

run_as_root mkdir -p "${MOUNT_DIR}"
run_as_root mount -o loop "${EXT2_IMG}" "${MOUNT_DIR}"

cp "${MOUNT_DIR}/vsock_quant/run/server_user.csv" "${RUN_DIR}/server_user.csv"
cp "${MOUNT_DIR}/vsock_quant/run/guest_kernel.raw" "${RUN_DIR}/guest_kernel.raw"
cp "${MOUNT_DIR}/vsock_quant/run/guest_collector.log" "${RUN_DIR}/guest_collector.log"

run_as_root umount "${MOUNT_DIR}"

test -s "${RUN_DIR}/client_user.csv"
test -s "${RUN_DIR}/server_user.csv"
test -s "${RUN_DIR}/host_kernel.raw"
test -s "${RUN_DIR}/guest_kernel.raw"

python3 "${PARSER}" --in "${RUN_DIR}/host_kernel.raw" --out "${RUN_DIR}/host_kernel.csv" --side host
python3 "${PARSER}" --in "${RUN_DIR}/guest_kernel.raw" --out "${RUN_DIR}/guest_kernel.csv" --side guest

# Host syscall de-noise by comm selection:
# 1) try comm hint from run_host_round.sh
# 2) fallback to dominant comm by max min(send_cnt, recv_cnt)
cp "${RUN_DIR}/host_kernel.csv" "${RUN_DIR}/host_kernel.raw_parsed.csv"

CLIENT_COMM_HINT=""
if [ -s "${RUN_DIR}/host_selected_comm.txt" ]; then
	CLIENT_COMM_HINT="$(head -n 1 "${RUN_DIR}/host_selected_comm.txt" | tr -d '\r\n')"
elif [ -s "${RUN_DIR}/host_client_comm.txt" ]; then
	CLIENT_COMM_HINT="$(head -n 1 "${RUN_DIR}/host_client_comm.txt" | tr -d '\r\n')"
fi

CHOSEN_COMM=""
if [ -n "${CLIENT_COMM_HINT}" ]; then
	awk -F, -v comm="${CLIENT_COMM_HINT}" 'BEGIN{OFS=","} NR==1{print; next} {ev=$3; c=$8; if (ev=="SYS_ENTER_SEND" || ev=="SYS_EXIT_RECV") { if (c==comm) print } else { print }}' \
		"${RUN_DIR}/host_kernel.raw_parsed.csv" > "${RUN_DIR}/host_kernel.comm_filtered.csv"
	HINT_SEND_CNT=$(grep -c ',SYS_ENTER_SEND,' "${RUN_DIR}/host_kernel.comm_filtered.csv" || true)
	HINT_RECV_CNT=$(grep -c ',SYS_EXIT_RECV,' "${RUN_DIR}/host_kernel.comm_filtered.csv" || true)
	echo "host_comm_hint comm=${CLIENT_COMM_HINT} send=${HINT_SEND_CNT} recv=${HINT_RECV_CNT}"
	if [ "${HINT_SEND_CNT}" -gt 0 ] && [ "${HINT_RECV_CNT}" -gt 0 ]; then
		CHOSEN_COMM="${CLIENT_COMM_HINT}"
		mv "${RUN_DIR}/host_kernel.comm_filtered.csv" "${RUN_DIR}/host_kernel.csv"
	else
		rm -f "${RUN_DIR}/host_kernel.comm_filtered.csv"
	fi
fi

if [ -z "${CHOSEN_COMM}" ]; then
	AUTO_COMM="$(awk -F, 'NR>1 {ev=$3; c=$8; if (ev=="SYS_ENTER_SEND") s[c]++; else if (ev=="SYS_EXIT_RECV") r[c]++} END {best=""; bestv=0; for (c in s) {v=s[c]; if ((c in r) && r[c] < v) v=r[c]; if (v > bestv) {bestv=v; best=c}} if (bestv > 0) print best}' "${RUN_DIR}/host_kernel.raw_parsed.csv")"
	if [ -n "${AUTO_COMM}" ]; then
		awk -F, -v comm="${AUTO_COMM}" 'BEGIN{OFS=","} NR==1{print; next} {ev=$3; c=$8; if (ev=="SYS_ENTER_SEND" || ev=="SYS_EXIT_RECV") { if (c==comm) print } else { print }}' \
			"${RUN_DIR}/host_kernel.raw_parsed.csv" > "${RUN_DIR}/host_kernel.comm_filtered.csv"
		AUTO_SEND_CNT=$(grep -c ',SYS_ENTER_SEND,' "${RUN_DIR}/host_kernel.comm_filtered.csv" || true)
		AUTO_RECV_CNT=$(grep -c ',SYS_EXIT_RECV,' "${RUN_DIR}/host_kernel.comm_filtered.csv" || true)
		echo "host_comm_auto comm=${AUTO_COMM} send=${AUTO_SEND_CNT} recv=${AUTO_RECV_CNT}"
		if [ "${AUTO_SEND_CNT}" -gt 0 ] && [ "${AUTO_RECV_CNT}" -gt 0 ]; then
			CHOSEN_COMM="${AUTO_COMM}"
			mv "${RUN_DIR}/host_kernel.comm_filtered.csv" "${RUN_DIR}/host_kernel.csv"
		else
			rm -f "${RUN_DIR}/host_kernel.comm_filtered.csv"
		fi
	fi
fi

if [ -z "${CHOSEN_COMM}" ]; then
	echo "WARN: host syscall comm de-noise skipped; keep raw parsed host csv"
	cp "${RUN_DIR}/host_kernel.raw_parsed.csv" "${RUN_DIR}/host_kernel.csv"
else
	echo "host_selected_comm=${CHOSEN_COMM}"
fi

wc -l "${RUN_DIR}/client_user.csv" "${RUN_DIR}/server_user.csv" "${RUN_DIR}/host_kernel.csv" "${RUN_DIR}/guest_kernel.csv"
cut -d, -f3 "${RUN_DIR}/host_kernel.csv" | sort | uniq -c
cut -d, -f3 "${RUN_DIR}/guest_kernel.csv" | sort | uniq -c

CLIENT_ROWS=$(( $(wc -l < "${RUN_DIR}/client_user.csv") - 1 ))
SERVER_ROWS=$(( $(wc -l < "${RUN_DIR}/server_user.csv") - 1 ))
echo "user_rows client=${CLIENT_ROWS} server=${SERVER_ROWS}"
if [ "${CLIENT_ROWS}" -ne "${SERVER_ROWS}" ]; then
	echo "WARN: client/server rows mismatch; possible mixed runs" >&2
fi
if [ "${CLIENT_ROWS}" -lt 100 ] || [ "${SERVER_ROWS}" -lt 100 ]; then
	echo "ERROR: need >=100 rows to fit host/guest clock mapping" >&2
	exit 1
fi

HOST_SEND_CNT=$(grep -c ',SYS_ENTER_SEND,' "${RUN_DIR}/host_kernel.csv" || true)
HOST_RECV_CNT=$(grep -c ',SYS_EXIT_RECV,' "${RUN_DIR}/host_kernel.csv" || true)
GUEST_SEND_CNT=$(grep -c ',SYS_ENTER_SEND,' "${RUN_DIR}/guest_kernel.csv" || true)
GUEST_RECV_CNT=$(grep -c ',SYS_EXIT_RECV,' "${RUN_DIR}/guest_kernel.csv" || true)
echo "host_syscall_counts send=${HOST_SEND_CNT} recv=${HOST_RECV_CNT}"
echo "guest_syscall_counts send=${GUEST_SEND_CNT} recv=${GUEST_RECV_CNT}"

if [ "${HOST_SEND_CNT}" -eq 0 ] || [ "${HOST_RECV_CNT}" -eq 0 ]; then
	echo "ERROR: host syscall events missing" >&2
	echo "hint: rerun a fresh round with host command:" >&2
	echo "  tools/vsock_quant/run_host_round.sh --run-dir ${RUN_DIR} --no-syscall-pid-filter" >&2
	tail -n 120 "${RUN_DIR}/host_collector.log" >&2 || true
	exit 1
fi

MIN_EXPECTED=$(( CLIENT_ROWS / 2 ))
if [ "${HOST_SEND_CNT}" -lt "${MIN_EXPECTED}" ] || [ "${HOST_RECV_CNT}" -lt "${MIN_EXPECTED}" ]; then
	echo "ERROR: host syscall events too few (expect >= ${MIN_EXPECTED})" >&2
	exit 1
fi
if [ "${GUEST_SEND_CNT}" -lt "${MIN_EXPECTED}" ] || [ "${GUEST_RECV_CNT}" -lt "${MIN_EXPECTED}" ]; then
	echo "ERROR: guest syscall events too few (expect >= ${MIN_EXPECTED})" >&2
	exit 1
fi

python3 "${ANALYZER}" \
	--client-csv "${RUN_DIR}/client_user.csv" \
	--server-csv "${RUN_DIR}/server_user.csv" \
	--host-kernel-csv "${RUN_DIR}/host_kernel.csv" \
	--guest-kernel-csv "${RUN_DIR}/guest_kernel.csv" \
	--out-dir "${RUN_DIR}/out"

ls -lh "${RUN_DIR}/out"
cat "${RUN_DIR}/out/quality_report.txt"

echo "POST_ANALYZE_OK run_dir=${RUN_DIR}"
