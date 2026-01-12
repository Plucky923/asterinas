#!/usr/bin/env bash

# SPDX-License-Identifier: MPL-2.0

set -euo pipefail

if [[ ! -r /proc/kallsyms ]]; then
	echo "ERROR: /proc/kallsyms is not readable; run as root." >&2
	exit 1
fi

echo "=== vsock probe map ==="
echo "Kernel: $(uname -r)"
echo

echo "[TX candidates]"
grep -E " virtio_transport_send_pkt| vhost_transport_send_pkt| vhost_transport_do_send_pkt" /proc/kallsyms \
	| awk '{print $3}' | sort -u || true

echo
echo "[RX candidates]"
grep -E " virtio_transport_recv_pkt| vhost_transport_recv_pkt| vhost_transport_do_recv_pkt" /proc/kallsyms \
	| awk '{print $3}' | sort -u || true

echo
echo "[syscalls tracepoints]"
TRACEFS_EVENTS_DIR=""
if [[ -d /sys/kernel/tracing/events ]]; then
	TRACEFS_EVENTS_DIR="/sys/kernel/tracing/events"
elif [[ -d /sys/kernel/debug/tracing/events ]]; then
	TRACEFS_EVENTS_DIR="/sys/kernel/debug/tracing/events"
fi

if [[ -n "${TRACEFS_EVENTS_DIR}" && -d "${TRACEFS_EVENTS_DIR}/syscalls" ]]; then
	ls "${TRACEFS_EVENTS_DIR}/syscalls" \
		| grep -E "^sys_(enter_sendto|enter_sendmsg|exit_recvfrom|exit_recvmsg)$" || true
else
	echo "tracefs not found under /sys/kernel/tracing/events or /sys/kernel/debug/tracing/events" >&2
	echo "hint: sudo mount -t tracefs tracefs /sys/kernel/tracing" >&2
fi

echo
echo "[syscall kprobe symbol candidates]"
grep -E " (__x64_sys_sendto|__sys_sendto|__se_sys_sendto|__x64_sys_sendmsg|__sys_sendmsg|__se_sys_sendmsg|__x64_sys_recvfrom|__sys_recvfrom|__se_sys_recvfrom|__x64_sys_recvmsg|__sys_recvmsg|__se_sys_recvmsg)$" /proc/kallsyms \
	| awk '{print $3}' | sort -u || true
