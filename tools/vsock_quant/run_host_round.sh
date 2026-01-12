#!/usr/bin/env bash

# SPDX-License-Identifier: MPL-2.0

set -euo pipefail

usage() {
	cat <<'USAGE'
Usage:
  run_host_round.sh [options]

Options:
  --run-dir <dir>          Host run dir (default: /tmp/vsock_quant_run)
  --client-bin <path>      Client binary path
  --cid <cid>              Guest CID (default: 3)
  --port <port>            vsock port (default: 20002)
  --iters <n>              Iterations (default: 100000)
  --payload <bytes>        Payload bytes (default: 4)
  --start-delay-ms <ms>    Client start delay (default: 3000)
  --seconds <sec>          Collector seconds (default: 120)
  --no-syscall-pid-filter  Disable syscall PID filter for this run (recommended in containerized host env)
  --auto-fallback          Auto retry once with --no-syscall-pid-filter if host SYS events are zero (default: off)
  --no-auto-fallback       Disable auto fallback

Example:
  tools/vsock_quant/run_host_round.sh --run-dir /tmp/vsock_quant_run --no-syscall-pid-filter
USAGE
}

RUN_DIR="/tmp/vsock_quant_run"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
CLIENT_BIN="/tmp/asterinas-apps-build/initramfs/test/vsock/vsock_rtt_seq_client"
CID="3"
PORT="20002"
ITERS="100000"
PAYLOAD="4"
START_DELAY_MS="3000"
SECONDS_TO_RUN="120"
AUTO_FALLBACK=0
FORCE_NO_SYSCALL_PID_FILTER=0

while [ "$#" -gt 0 ]; do
	case "$1" in
	--run-dir)
		RUN_DIR="${2:-}"
		shift 2
		;;
	--client-bin)
		CLIENT_BIN="${2:-}"
		shift 2
		;;
	--cid)
		CID="${2:-}"
		shift 2
		;;
	--port)
		PORT="${2:-}"
		shift 2
		;;
	--iters)
		ITERS="${2:-}"
		shift 2
		;;
	--payload)
		PAYLOAD="${2:-}"
		shift 2
		;;
	--start-delay-ms)
		START_DELAY_MS="${2:-}"
		shift 2
		;;
	--seconds)
		SECONDS_TO_RUN="${2:-}"
		shift 2
		;;
	--no-syscall-pid-filter)
		FORCE_NO_SYSCALL_PID_FILTER=1
		shift
		;;
	--auto-fallback)
		AUTO_FALLBACK=1
		shift
		;;
	--no-auto-fallback)
		AUTO_FALLBACK=0
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

if [ ! -x "${CLIENT_BIN}" ]; then
	echo "ERROR: client binary not executable: ${CLIENT_BIN}" >&2
	exit 1
fi

COLLECTOR="${SCRIPT_DIR}/collect_kernel_events_tracefs.sh"
PARSER="${SCRIPT_DIR}/analysis/parse_tracefs_events.py"
if [ ! -x "${COLLECTOR}" ]; then
	echo "ERROR: collector not executable: ${COLLECTOR}" >&2
	exit 1
fi
if [ ! -x "${PARSER}" ]; then
	echo "ERROR: parser not executable: ${PARSER}" >&2
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
rm -rf "${RUN_DIR:?}"/*
META_FILE="${RUN_DIR}/host_capture_meta.txt"
: > "${META_FILE}"

echo "[host] run_dir=${RUN_DIR}"
echo "[host] client=${CLIENT_BIN} cid=${CID} port=${PORT} iters=${ITERS} payload=${PAYLOAD} start_delay_ms=${START_DELAY_MS} seconds=${SECONDS_TO_RUN}"
if [ "${FORCE_NO_SYSCALL_PID_FILTER}" -eq 1 ]; then
	echo "[host] syscall pid filter disabled by user (--no-syscall-pid-filter)"
fi

collect_once() {
	mode="$1"  # filtered | unfiltered
	echo "[host] attempt mode=${mode}"
	echo "attempt_mode=${mode}" >> "${META_FILE}"

	local extra_args=""
	if [ "${mode}" = "unfiltered" ]; then
		extra_args="--no-syscall-pid-filter"
	fi

	rm -f "${RUN_DIR}/client_user.csv" "${RUN_DIR}/client.log" "${RUN_DIR}/host_kernel.raw" "${RUN_DIR}/host_collector.log" "${RUN_DIR}/host_kernel.csv"

	"${CLIENT_BIN}" "${CID}" "${PORT}" "${ITERS}" "${PAYLOAD}" "${RUN_DIR}/client_user.csv" "${START_DELAY_MS}" > "${RUN_DIR}/client.log" 2>&1 &
	CLIENT_PID=$!
	echo "[host] CLIENT_PID=${CLIENT_PID}"
	echo "CLIENT_PID=${CLIENT_PID}" >> "${META_FILE}"
	CLIENT_COMM="$(cat "/proc/${CLIENT_PID}/comm" 2>/dev/null || true)"
	if [ -z "${CLIENT_COMM}" ]; then
		CLIENT_COMM="$(basename "${CLIENT_BIN}" | cut -c1-15)"
	fi
	echo "${CLIENT_COMM}" > "${RUN_DIR}/host_client_comm.txt"
	echo "[host] CLIENT_COMM=${CLIENT_COMM}"
	echo "CLIENT_COMM=${CLIENT_COMM}" >> "${META_FILE}"

	if [ -n "${extra_args}" ]; then
		run_as_root "${COLLECTOR}" --pid "${CLIENT_PID}" --side host --seconds "${SECONDS_TO_RUN}" --out "${RUN_DIR}/host_kernel.raw" --no-parse --no-syscall-pid-filter > "${RUN_DIR}/host_collector.log" 2>&1 &
	else
		run_as_root "${COLLECTOR}" --pid "${CLIENT_PID}" --side host --seconds "${SECONDS_TO_RUN}" --out "${RUN_DIR}/host_kernel.raw" --no-parse > "${RUN_DIR}/host_collector.log" 2>&1 &
	fi
	HTRACE_PID=$!
	echo "[host] HTRACE_PID=${HTRACE_PID}"

	CLIENT_RC=0
	HTRACE_RC=0
	wait "${CLIENT_PID}" || CLIENT_RC=$?
	wait "${HTRACE_PID}" || HTRACE_RC=$?
	echo "[host] CLIENT_RC=${CLIENT_RC} HTRACE_RC=${HTRACE_RC}"

	if [ "${CLIENT_RC}" -ne 0 ]; then
		echo "ERROR: client failed" >&2
		tail -n 80 "${RUN_DIR}/client.log" >&2 || true
		return 11
	fi
	if [ "${HTRACE_RC}" -ne 0 ]; then
		echo "ERROR: host collector failed" >&2
		tail -n 80 "${RUN_DIR}/host_collector.log" >&2 || true
		return 12
	fi

	if ! grep -q "syscalls: using" "${RUN_DIR}/host_collector.log"; then
		echo "ERROR: host collector log missing syscall mode line" >&2
		tail -n 80 "${RUN_DIR}/host_collector.log" >&2 || true
		return 13
	fi
	if ! grep -q "pid namespace chain:" "${RUN_DIR}/host_collector.log"; then
		echo "ERROR: host collector log missing pid namespace diagnostics" >&2
		tail -n 80 "${RUN_DIR}/host_collector.log" >&2 || true
		return 14
	fi
	grep -E "^(syscalls: using|pid namespace chain:|pid filter:)" "${RUN_DIR}/host_collector.log" || true

	python3 "${PARSER}" --in "${RUN_DIR}/host_kernel.raw" --out "${RUN_DIR}/host_kernel.csv" --side host

	RAW_SEND_CNT=$(grep -c ',SYS_ENTER_SEND,' "${RUN_DIR}/host_kernel.csv" || true)
	RAW_RECV_CNT=$(grep -c ',SYS_EXIT_RECV,' "${RUN_DIR}/host_kernel.csv" || true)
	echo "[host] raw_syscall_counts send=${RAW_SEND_CNT} recv=${RAW_RECV_CNT} before-comm-filter"
	echo "raw_syscall_counts_send=${RAW_SEND_CNT}" >> "${META_FILE}"
	echo "raw_syscall_counts_recv=${RAW_RECV_CNT}" >> "${META_FILE}"

	cp "${RUN_DIR}/host_kernel.csv" "${RUN_DIR}/host_kernel.raw_parsed.csv"

	# Keep TX/RX unchanged; filter syscall events by selected comm.
	# 1) try client comm hint
	# 2) fallback to dominant comm by max min(send_cnt, recv_cnt)
	CHOSEN_COMM=""
	if [ -n "${CLIENT_COMM}" ]; then
		awk -F, -v comm="${CLIENT_COMM}" 'BEGIN{OFS=","} NR==1{print; next} {ev=$3; c=$8; if (ev=="SYS_ENTER_SEND" || ev=="SYS_EXIT_RECV") { if (c==comm) print } else { print }}' \
			"${RUN_DIR}/host_kernel.raw_parsed.csv" > "${RUN_DIR}/host_kernel.comm_filtered.csv"
		HINT_SEND_CNT=$(grep -c ',SYS_ENTER_SEND,' "${RUN_DIR}/host_kernel.comm_filtered.csv" || true)
		HINT_RECV_CNT=$(grep -c ',SYS_EXIT_RECV,' "${RUN_DIR}/host_kernel.comm_filtered.csv" || true)
		echo "[host] hint_comm_counts comm=${CLIENT_COMM} send=${HINT_SEND_CNT} recv=${HINT_RECV_CNT}"
		echo "hint_comm=${CLIENT_COMM}" >> "${META_FILE}"
		echo "hint_comm_send=${HINT_SEND_CNT}" >> "${META_FILE}"
		echo "hint_comm_recv=${HINT_RECV_CNT}" >> "${META_FILE}"
		if [ "${HINT_SEND_CNT}" -gt 0 ] && [ "${HINT_RECV_CNT}" -gt 0 ]; then
			CHOSEN_COMM="${CLIENT_COMM}"
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
			echo "[host] auto_comm_counts comm=${AUTO_COMM} send=${AUTO_SEND_CNT} recv=${AUTO_RECV_CNT}"
			echo "auto_comm=${AUTO_COMM}" >> "${META_FILE}"
			echo "auto_comm_send=${AUTO_SEND_CNT}" >> "${META_FILE}"
			echo "auto_comm_recv=${AUTO_RECV_CNT}" >> "${META_FILE}"
			if [ "${AUTO_SEND_CNT}" -gt 0 ] && [ "${AUTO_RECV_CNT}" -gt 0 ]; then
				CHOSEN_COMM="${AUTO_COMM}"
				mv "${RUN_DIR}/host_kernel.comm_filtered.csv" "${RUN_DIR}/host_kernel.csv"
			else
				rm -f "${RUN_DIR}/host_kernel.comm_filtered.csv"
			fi
		fi
	fi

	if [ -z "${CHOSEN_COMM}" ]; then
		echo "[host] WARN: no valid comm selected; keep unfiltered syscall events"
		cp "${RUN_DIR}/host_kernel.raw_parsed.csv" "${RUN_DIR}/host_kernel.csv"
		echo "selected_syscall_comm=" >> "${META_FILE}"
	else
		echo "[host] selected_syscall_comm=${CHOSEN_COMM}"
		echo "${CHOSEN_COMM}" > "${RUN_DIR}/host_selected_comm.txt"
		echo "selected_syscall_comm=${CHOSEN_COMM}" >> "${META_FILE}"
	fi

	HOST_SEND_CNT=$(grep -c ',SYS_ENTER_SEND,' "${RUN_DIR}/host_kernel.csv" || true)
	HOST_RECV_CNT=$(grep -c ',SYS_EXIT_RECV,' "${RUN_DIR}/host_kernel.csv" || true)
	echo "[host] syscall_counts send=${HOST_SEND_CNT} recv=${HOST_RECV_CNT} mode=${mode} after-comm-filter"
	echo "syscall_counts_send=${HOST_SEND_CNT}" >> "${META_FILE}"
	echo "syscall_counts_recv=${HOST_RECV_CNT}" >> "${META_FILE}"

	if [ "${HOST_SEND_CNT}" -eq 0 ] || [ "${HOST_RECV_CNT}" -eq 0 ]; then
		return 20
	fi

	return 0
}

FIRST_MODE="filtered"
if [ "${FORCE_NO_SYSCALL_PID_FILTER}" -eq 1 ]; then
	FIRST_MODE="unfiltered"
fi

if collect_once "${FIRST_MODE}"; then
	echo "HOST_CAPTURE_OK mode=${FIRST_MODE} run_dir=${RUN_DIR}"
	exit 0
fi

RC=$?
if [ "${RC}" -ne 20 ]; then
	exit "${RC}"
fi

if [ "${AUTO_FALLBACK}" -ne 1 ]; then
	echo "ERROR: host syscall events are zero in ${FIRST_MODE} mode and auto fallback is disabled" >&2
	echo "hint: restart a fresh round and run:" >&2
	echo "  tools/vsock_quant/run_host_round.sh --run-dir ${RUN_DIR} --no-syscall-pid-filter" >&2
	exit 20
fi

echo "[host] fallback: retry with --no-syscall-pid-filter"
if collect_once "unfiltered"; then
	echo "HOST_CAPTURE_OK mode=unfiltered run_dir=${RUN_DIR}"
	exit 0
fi

RC=$?
if [ "${RC}" -eq 20 ]; then
	echo "ERROR: host syscall events are still zero even without syscall pid filter" >&2
	tail -n 120 "${RUN_DIR}/host_collector.log" >&2 || true
fi
exit "${RC}"
