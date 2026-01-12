#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -eu

usage() {
	cat <<'EOF'
Usage:
  collect_kernel_events_tracefs.sh --pid <pid> --side <host|guest> --seconds <sec> --out <file> [--no-parse] [--no-syscall-pid-filter]

Examples:
  sudo ./collect_kernel_events_tracefs.sh --pid 1234 --side guest --seconds 40 --out /tmp/guest_kernel.csv
  sudo ./collect_kernel_events_tracefs.sh --pid 1234 --side guest --seconds 40 --out /tmp/guest_kernel.raw --no-parse
  sudo ./collect_kernel_events_tracefs.sh --pid 1234 --side host --seconds 40 --out /tmp/host_kernel.raw --no-parse --no-syscall-pid-filter
EOF
}

PID=""
SIDE=""
SECONDS_TO_RUN=""
OUT=""
NO_PARSE=0
NO_SYSCALL_PID_FILTER=0
TRACE_FILTER_PID=""
PID_NS_CHAIN=""
TRACE_CLOCK_PREV=""
TRACE_CLOCK_SET=""

while [ "$#" -gt 0 ]; do
	case "$1" in
	--pid)
		PID="${2:-}"
		shift 2
		;;
	--side)
		SIDE="${2:-}"
		shift 2
		;;
	--seconds)
		SECONDS_TO_RUN="${2:-}"
		shift 2
		;;
	--out)
		OUT="${2:-}"
		shift 2
		;;
	--no-parse)
		NO_PARSE=1
		shift
		;;
	--no-syscall-pid-filter)
		NO_SYSCALL_PID_FILTER=1
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "Unknown arg: $1" >&2
		usage
		exit 1
		;;
	esac
done

if [ -z "${PID}" ] || [ -z "${SIDE}" ] || [ -z "${SECONDS_TO_RUN}" ] || [ -z "${OUT}" ]; then
	usage
	exit 1
fi

if [ "${SIDE}" != "host" ] && [ "${SIDE}" != "guest" ]; then
	echo "--side must be host or guest" >&2
	exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
	echo "ERROR: must run as root" >&2
	exit 1
fi

TRACE_ROOT=""
if [ -d /sys/kernel/tracing ]; then
	TRACE_ROOT=/sys/kernel/tracing
elif [ -d /sys/kernel/debug/tracing ]; then
	TRACE_ROOT=/sys/kernel/debug/tracing
else
	echo "ERROR: tracefs not found" >&2
	exit 1
fi

if [ ! -r /proc/kallsyms ]; then
	echo "ERROR: /proc/kallsyms unreadable" >&2
	exit 1
fi

if [ ! -r "/proc/${PID}/status" ]; then
	echo "ERROR: pid ${PID} not found or /proc/${PID}/status unreadable" >&2
	exit 1
fi

current_trace_clock() {
	clock_file="$1"
	# trace_clock format example:
	# "local global [mono] mono_raw boot"
	awk '{for (i = 1; i <= NF; i++) if ($i ~ /^\[/) {gsub(/\[|\]/, "", $i); print $i; exit}}' "${clock_file}"
}

try_set_trace_clock() {
	clock_file="$1"
	if [ ! -w "${clock_file}" ]; then
		return 0
	fi

	TRACE_CLOCK_PREV="$(current_trace_clock "${clock_file}")"
	if [ -z "${TRACE_CLOCK_PREV}" ]; then
		return 0
	fi

	if grep -qw "mono_raw" "${clock_file}"; then
		echo mono_raw > "${clock_file}" 2>/dev/null || true
		TRACE_CLOCK_SET="$(current_trace_clock "${clock_file}")"
		return 0
	fi

	# Fallback to mono if mono_raw is unavailable.
	if grep -qw "mono" "${clock_file}"; then
		echo mono > "${clock_file}" 2>/dev/null || true
		TRACE_CLOCK_SET="$(current_trace_clock "${clock_file}")"
		return 0
	fi

	TRACE_CLOCK_SET="${TRACE_CLOCK_PREV}"
	return 0
}

resolve_trace_filter_pid() {
	in_pid="$1"
	status_file="/proc/${in_pid}/status"

	# NSpid line format: "NSpid:\t<outermost> ... <innermost>"
	ns_line="$(awk '/^NSpid:[[:space:]]*/ {for (i = 2; i <= NF; i++) printf("%s%s", $i, (i < NF ? " " : "")); exit}' "${status_file}")"
	if [ -z "${ns_line}" ]; then
		TRACE_FILTER_PID="${in_pid}"
		PID_NS_CHAIN=""
		return 0
	fi

	PID_NS_CHAIN="${ns_line}"
	set -- ${ns_line}
	if [ -n "${1:-}" ]; then
		TRACE_FILTER_PID="${1}"
	else
		TRACE_FILTER_PID="${in_pid}"
	fi
}

resolve_trace_filter_pid "${PID}"

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PARSER="${SCRIPT_DIR}/analysis/parse_tracefs_events.py"
if [ "${NO_PARSE}" -eq 0 ]; then
	if [ ! -x "${PARSER}" ]; then
		echo "ERROR: parser not executable: ${PARSER}" >&2
		exit 1
	fi
	if ! command -v python3 >/dev/null 2>&1; then
		echo "ERROR: python3 not found; use --no-parse to write raw trace" >&2
		exit 1
	fi
fi

find_sym() {
	pattern="$1"
	# /proc/kallsyms may end with "[module]"; match on the symbol field (3rd col).
	awk -v sym="${pattern}" '$3 == sym { print $3; exit }' /proc/kallsyms
}

find_sym_prefix() {
	prefix="$1"
	awk -v pfx="${prefix}" '$3 ~ ("^" pfx) { print $3; exit }' /proc/kallsyms
}

find_first_sym() {
	for name in "$@"; do
		sym="$(find_sym "${name}")"
		if [ -n "${sym}" ]; then
			echo "${sym}"
			return 0
		fi
	done
	return 1
}

set_event_filter() {
	filter_path="$1"
	expr="$2"
	if [ -e "${filter_path}" ]; then
		if [ -z "${expr}" ]; then
			echo > "${filter_path}" 2>/dev/null || true
		else
			echo "${expr}" > "${filter_path}"
		fi
	else
		echo "WARN: filter path missing: ${filter_path}" >&2
	fi
}

clear_event_filter() {
	filter_path="$1"
	if [ -e "${filter_path}" ]; then
		echo > "${filter_path}" 2>/dev/null || true
	fi
}

TX_SYM="$(find_sym virtio_transport_send_pkt_info)"
if [ -z "${TX_SYM}" ]; then
	TX_SYM="$(find_sym vhost_transport_send_pkt)"
fi
if [ -z "${TX_SYM}" ]; then
	TX_SYM="$(find_sym vhost_transport_do_send_pkt)"
fi
if [ -z "${TX_SYM}" ]; then
	TX_SYM="$(find_sym_prefix virtio_transport_send_pkt_info)"
fi
if [ -z "${TX_SYM}" ]; then
	TX_SYM="$(find_sym_prefix vhost_transport_send_pkt)"
fi
if [ -z "${TX_SYM}" ]; then
	TX_SYM="$(find_sym_prefix vhost_transport_do_send_pkt)"
fi

RX_SYM="$(find_sym virtio_transport_recv_pkt)"
if [ -z "${RX_SYM}" ]; then
	RX_SYM="$(find_sym vhost_transport_recv_pkt)"
fi
if [ -z "${RX_SYM}" ]; then
	RX_SYM="$(find_sym vhost_transport_do_recv_pkt)"
fi
if [ -z "${RX_SYM}" ]; then
	RX_SYM="$(find_sym_prefix virtio_transport_recv_pkt)"
fi
if [ -z "${RX_SYM}" ]; then
	RX_SYM="$(find_sym_prefix vhost_transport_recv_pkt)"
fi
if [ -z "${RX_SYM}" ]; then
	RX_SYM="$(find_sym_prefix vhost_transport_do_recv_pkt)"
fi

if [ -z "${TX_SYM}" ] || [ -z "${RX_SYM}" ]; then
	echo "ERROR: cannot find TX/RX probe symbols (TX='${TX_SYM}' RX='${RX_SYM}')" >&2
	echo "hint: run 'sudo tools/vsock_quant/probe_map.sh' and ensure vsock/vhost modules are loaded" >&2
	exit 1
fi

USE_SYSCALL_TRACEPOINTS=0
SYSCALL_SENDTO_SYM="$(find_first_sym __x64_sys_sendto __sys_sendto __se_sys_sendto || true)"
SYSCALL_SENDMSG_SYM="$(find_first_sym __x64_sys_sendmsg __sys_sendmsg __se_sys_sendmsg || true)"
SYSCALL_RECVFROM_SYM="$(find_first_sym __x64_sys_recvfrom __sys_recvfrom __se_sys_recvfrom || true)"
SYSCALL_RECVMSG_SYM="$(find_first_sym __x64_sys_recvmsg __sys_recvmsg __se_sys_recvmsg || true)"

HAS_KP_SEND=0
HAS_KP_RECV=0
if [ -n "${SYSCALL_SENDTO_SYM}" ] || [ -n "${SYSCALL_SENDMSG_SYM}" ]; then
	HAS_KP_SEND=1
fi
if [ -n "${SYSCALL_RECVFROM_SYM}" ] || [ -n "${SYSCALL_RECVMSG_SYM}" ]; then
	HAS_KP_RECV=1
fi

TP_SENDTO=0
TP_SENDMSG=0
TP_RECVFROM=0
TP_RECVMSG=0
if [ -e "${TRACE_ROOT}/events/syscalls/sys_enter_sendto/enable" ]; then
	TP_SENDTO=1
fi
if [ -e "${TRACE_ROOT}/events/syscalls/sys_enter_sendmsg/enable" ]; then
	TP_SENDMSG=1
fi
if [ -e "${TRACE_ROOT}/events/syscalls/sys_exit_recvfrom/enable" ]; then
	TP_RECVFROM=1
fi
if [ -e "${TRACE_ROOT}/events/syscalls/sys_exit_recvmsg/enable" ]; then
	TP_RECVMSG=1
fi

HAS_TP_SEND=0
HAS_TP_RECV=0
if [ "${TP_SENDTO}" -eq 1 ] || [ "${TP_SENDMSG}" -eq 1 ]; then
	HAS_TP_SEND=1
fi
if [ "${TP_RECVFROM}" -eq 1 ] || [ "${TP_RECVMSG}" -eq 1 ]; then
	HAS_TP_RECV=1
fi

if [ "${HAS_KP_SEND}" -eq 1 ] && [ "${HAS_KP_RECV}" -eq 1 ]; then
	USE_SYSCALL_TRACEPOINTS=0
elif [ "${HAS_TP_SEND}" -eq 1 ] && [ "${HAS_TP_RECV}" -eq 1 ]; then
	USE_SYSCALL_TRACEPOINTS=1
else
	echo "ERROR: cannot find usable syscall probes for send/recv" >&2
	echo "  kprobe sendto='${SYSCALL_SENDTO_SYM}' sendmsg='${SYSCALL_SENDMSG_SYM}' recvfrom='${SYSCALL_RECVFROM_SYM}' recvmsg='${SYSCALL_RECVMSG_SYM}'" >&2
	echo "  tracepoints sendto=${TP_SENDTO} sendmsg=${TP_SENDMSG} recvfrom=${TP_RECVFROM} recvmsg=${TP_RECVMSG}" >&2
	exit 1
fi

EV_TX="vsq_${SIDE}_tx"
EV_RX="vsq_${SIDE}_rx"
EV_SYS_SENDTO="vsq_${SIDE}_sys_sendto"
EV_SYS_SENDMSG="vsq_${SIDE}_sys_sendmsg"
EV_SYS_RECVFROM_RET="vsq_${SIDE}_sys_recvfrom_ret"
EV_SYS_RECVMSG_RET="vsq_${SIDE}_sys_recvmsg_ret"
EV_FILTER_EXPR="common_pid == ${TRACE_FILTER_PID}"
if [ "${NO_SYSCALL_PID_FILTER}" -eq 1 ]; then
	EV_FILTER_EXPR=""
fi
RAW_OUT="$(mktemp /tmp/vsq_trace_raw.XXXXXX 2>/dev/null || true)"
if [ -z "${RAW_OUT}" ]; then
	RAW_OUT="/tmp/vsq_trace_raw.$$.$(date +%s)"
	: > "${RAW_OUT}"
fi

cleanup() {
	set +e
	echo 0 > "${TRACE_ROOT}/tracing_on"
	if [ "${USE_SYSCALL_TRACEPOINTS}" -eq 1 ]; then
		echo 0 > "${TRACE_ROOT}/events/syscalls/sys_enter_sendto/enable" 2>/dev/null
		echo 0 > "${TRACE_ROOT}/events/syscalls/sys_enter_sendmsg/enable" 2>/dev/null
		echo 0 > "${TRACE_ROOT}/events/syscalls/sys_exit_recvfrom/enable" 2>/dev/null
		echo 0 > "${TRACE_ROOT}/events/syscalls/sys_exit_recvmsg/enable" 2>/dev/null
		clear_event_filter "${TRACE_ROOT}/events/syscalls/sys_enter_sendto/filter"
		clear_event_filter "${TRACE_ROOT}/events/syscalls/sys_enter_sendmsg/filter"
		clear_event_filter "${TRACE_ROOT}/events/syscalls/sys_exit_recvfrom/filter"
		clear_event_filter "${TRACE_ROOT}/events/syscalls/sys_exit_recvmsg/filter"
	else
		echo 0 > "${TRACE_ROOT}/events/kprobes/${EV_SYS_SENDTO}/enable" 2>/dev/null
		echo 0 > "${TRACE_ROOT}/events/kprobes/${EV_SYS_SENDMSG}/enable" 2>/dev/null
		echo 0 > "${TRACE_ROOT}/events/kprobes/${EV_SYS_RECVFROM_RET}/enable" 2>/dev/null
		echo 0 > "${TRACE_ROOT}/events/kprobes/${EV_SYS_RECVMSG_RET}/enable" 2>/dev/null
		clear_event_filter "${TRACE_ROOT}/events/kprobes/${EV_SYS_SENDTO}/filter"
		clear_event_filter "${TRACE_ROOT}/events/kprobes/${EV_SYS_SENDMSG}/filter"
		clear_event_filter "${TRACE_ROOT}/events/kprobes/${EV_SYS_RECVFROM_RET}/filter"
		clear_event_filter "${TRACE_ROOT}/events/kprobes/${EV_SYS_RECVMSG_RET}/filter"
	fi
	echo 0 > "${TRACE_ROOT}/events/kprobes/${EV_TX}/enable" 2>/dev/null
	echo 0 > "${TRACE_ROOT}/events/kprobes/${EV_RX}/enable" 2>/dev/null
	echo "-:${EV_TX}" >> "${TRACE_ROOT}/kprobe_events" 2>/dev/null
	echo "-:${EV_RX}" >> "${TRACE_ROOT}/kprobe_events" 2>/dev/null
	echo "-:${EV_SYS_SENDTO}" >> "${TRACE_ROOT}/kprobe_events" 2>/dev/null
	echo "-:${EV_SYS_SENDMSG}" >> "${TRACE_ROOT}/kprobe_events" 2>/dev/null
	echo "-:${EV_SYS_RECVFROM_RET}" >> "${TRACE_ROOT}/kprobe_events" 2>/dev/null
	echo "-:${EV_SYS_RECVMSG_RET}" >> "${TRACE_ROOT}/kprobe_events" 2>/dev/null
	if [ -n "${TRACE_CLOCK_PREV}" ] && [ -w "${TRACE_ROOT}/trace_clock" ]; then
		echo "${TRACE_CLOCK_PREV}" > "${TRACE_ROOT}/trace_clock" 2>/dev/null || true
	fi
	rm -f "${RAW_OUT}"
}
trap cleanup EXIT INT TERM

if [ -e "${TRACE_ROOT}/trace_clock" ]; then
	try_set_trace_clock "${TRACE_ROOT}/trace_clock"
fi

echo "collector trace_root=${TRACE_ROOT} pid=${PID} side=${SIDE}" >&2
echo "symbols: TX=${TX_SYM} RX=${RX_SYM}" >&2
if [ "${USE_SYSCALL_TRACEPOINTS}" -eq 1 ]; then
	echo "syscalls: using tracepoints (fallback) sendto=${TP_SENDTO} sendmsg=${TP_SENDMSG} recvfrom=${TP_RECVFROM} recvmsg=${TP_RECVMSG}" >&2
else
	echo "syscalls: using kprobe (preferred) sendto='${SYSCALL_SENDTO_SYM}' sendmsg='${SYSCALL_SENDMSG_SYM}' recvfrom='${SYSCALL_RECVFROM_SYM}' recvmsg='${SYSCALL_RECVMSG_SYM}'" >&2
fi
if [ -n "${TRACE_CLOCK_SET}" ]; then
	echo "trace_clock: prev=${TRACE_CLOCK_PREV} active=${TRACE_CLOCK_SET}" >&2
else
	echo "trace_clock: unchanged/unknown" >&2
fi
if [ -n "${PID_NS_CHAIN}" ]; then
	echo "pid namespace chain: ${PID_NS_CHAIN}" >&2
else
	echo "pid namespace chain: unavailable" >&2
fi
if [ "${NO_SYSCALL_PID_FILTER}" -eq 1 ]; then
	echo "pid filter: disabled for syscall events (--no-syscall-pid-filter)" >&2
else
	echo "pid filter: apply to syscall events only (common_pid == ${TRACE_FILTER_PID}, user_pid=${PID})" >&2
fi

echo 0 > "${TRACE_ROOT}/tracing_on"
echo > "${TRACE_ROOT}/trace"

# Remove stale events from previous interrupted runs.
echo "-:${EV_TX}" >> "${TRACE_ROOT}/kprobe_events" 2>/dev/null || true
echo "-:${EV_RX}" >> "${TRACE_ROOT}/kprobe_events" 2>/dev/null || true
echo "-:${EV_SYS_SENDTO}" >> "${TRACE_ROOT}/kprobe_events" 2>/dev/null || true
echo "-:${EV_SYS_SENDMSG}" >> "${TRACE_ROOT}/kprobe_events" 2>/dev/null || true
echo "-:${EV_SYS_RECVFROM_RET}" >> "${TRACE_ROOT}/kprobe_events" 2>/dev/null || true
echo "-:${EV_SYS_RECVMSG_RET}" >> "${TRACE_ROOT}/kprobe_events" 2>/dev/null || true

echo "p:${EV_TX} ${TX_SYM}" >> "${TRACE_ROOT}/kprobe_events"
echo "p:${EV_RX} ${RX_SYM}" >> "${TRACE_ROOT}/kprobe_events"

if [ "${USE_SYSCALL_TRACEPOINTS}" -eq 1 ]; then
	if [ "${TP_SENDTO}" -eq 1 ]; then
		echo 1 > "${TRACE_ROOT}/events/syscalls/sys_enter_sendto/enable"
		set_event_filter "${TRACE_ROOT}/events/syscalls/sys_enter_sendto/filter" "${EV_FILTER_EXPR}"
	fi
	if [ "${TP_SENDMSG}" -eq 1 ]; then
		echo 1 > "${TRACE_ROOT}/events/syscalls/sys_enter_sendmsg/enable"
		set_event_filter "${TRACE_ROOT}/events/syscalls/sys_enter_sendmsg/filter" "${EV_FILTER_EXPR}"
	fi
	if [ "${TP_RECVFROM}" -eq 1 ]; then
		echo 1 > "${TRACE_ROOT}/events/syscalls/sys_exit_recvfrom/enable"
		set_event_filter "${TRACE_ROOT}/events/syscalls/sys_exit_recvfrom/filter" "${EV_FILTER_EXPR}"
	fi
	if [ "${TP_RECVMSG}" -eq 1 ]; then
		echo 1 > "${TRACE_ROOT}/events/syscalls/sys_exit_recvmsg/enable"
		set_event_filter "${TRACE_ROOT}/events/syscalls/sys_exit_recvmsg/filter" "${EV_FILTER_EXPR}"
	fi
else
	if [ -n "${SYSCALL_SENDTO_SYM}" ]; then
		echo "p:${EV_SYS_SENDTO} ${SYSCALL_SENDTO_SYM}" >> "${TRACE_ROOT}/kprobe_events"
		echo 1 > "${TRACE_ROOT}/events/kprobes/${EV_SYS_SENDTO}/enable"
		set_event_filter "${TRACE_ROOT}/events/kprobes/${EV_SYS_SENDTO}/filter" "${EV_FILTER_EXPR}"
	fi
	if [ -n "${SYSCALL_SENDMSG_SYM}" ]; then
		echo "p:${EV_SYS_SENDMSG} ${SYSCALL_SENDMSG_SYM}" >> "${TRACE_ROOT}/kprobe_events"
		echo 1 > "${TRACE_ROOT}/events/kprobes/${EV_SYS_SENDMSG}/enable"
		set_event_filter "${TRACE_ROOT}/events/kprobes/${EV_SYS_SENDMSG}/filter" "${EV_FILTER_EXPR}"
	fi
	if [ -n "${SYSCALL_RECVFROM_SYM}" ]; then
		echo "r:${EV_SYS_RECVFROM_RET} ${SYSCALL_RECVFROM_SYM}" >> "${TRACE_ROOT}/kprobe_events"
		echo 1 > "${TRACE_ROOT}/events/kprobes/${EV_SYS_RECVFROM_RET}/enable"
		set_event_filter "${TRACE_ROOT}/events/kprobes/${EV_SYS_RECVFROM_RET}/filter" "${EV_FILTER_EXPR}"
	fi
	if [ -n "${SYSCALL_RECVMSG_SYM}" ]; then
		echo "r:${EV_SYS_RECVMSG_RET} ${SYSCALL_RECVMSG_SYM}" >> "${TRACE_ROOT}/kprobe_events"
		echo 1 > "${TRACE_ROOT}/events/kprobes/${EV_SYS_RECVMSG_RET}/enable"
		set_event_filter "${TRACE_ROOT}/events/kprobes/${EV_SYS_RECVMSG_RET}/filter" "${EV_FILTER_EXPR}"
	fi
fi
echo 1 > "${TRACE_ROOT}/events/kprobes/${EV_TX}/enable"
echo 1 > "${TRACE_ROOT}/events/kprobes/${EV_RX}/enable"

echo 1 > "${TRACE_ROOT}/tracing_on"

if timeout "${SECONDS_TO_RUN}" sh -c 'exit 0' >/dev/null 2>&1; then
	timeout "${SECONDS_TO_RUN}" cat "${TRACE_ROOT}/trace_pipe" > "${RAW_OUT}" || true
elif timeout -t "${SECONDS_TO_RUN}" sh -c 'exit 0' >/dev/null 2>&1; then
	timeout -t "${SECONDS_TO_RUN}" cat "${TRACE_ROOT}/trace_pipe" > "${RAW_OUT}" || true
else
	echo "ERROR: timeout command not compatible with this script" >&2
	exit 1
fi
echo 0 > "${TRACE_ROOT}/tracing_on"

if [ "${NO_PARSE}" -eq 1 ]; then
	cp "${RAW_OUT}" "${OUT}"
	echo "wrote raw trace ${OUT}" >&2
else
	python3 "${PARSER}" --in "${RAW_OUT}" --out "${OUT}" --side "${SIDE}"
	echo "wrote ${OUT}" >&2
fi
