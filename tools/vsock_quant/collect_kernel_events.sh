#!/usr/bin/env bash

# SPDX-License-Identifier: MPL-2.0

set -euo pipefail

usage() {
	cat <<'EOF'
Usage:
  collect_kernel_events.sh --pid <pid> --side <host|guest> --seconds <sec> --out <file>

Example:
  sudo ./collect_kernel_events.sh --pid 1234 --side host --seconds 30 --out host_kernel.csv
EOF
}

PID=""
SIDE=""
SECONDS_TO_RUN=""
OUT=""

while [[ $# -gt 0 ]]; do
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

if [[ -z "${PID}" || -z "${SIDE}" || -z "${SECONDS_TO_RUN}" || -z "${OUT}" ]]; then
	usage
	exit 1
fi

if [[ "${SIDE}" != "host" && "${SIDE}" != "guest" ]]; then
	echo "--side must be host or guest" >&2
	exit 1
fi

if ! command -v bpftrace >/dev/null 2>&1; then
	echo "ERROR: bpftrace not found" >&2
	exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="${SCRIPT_DIR}/bpf/vsock_segments_template.bt"

if [[ ! -f "${TEMPLATE}" ]]; then
	echo "ERROR: template missing: ${TEMPLATE}" >&2
	exit 1
fi

TMP_BT="$(mktemp /tmp/vsock_segments.XXXXXX.bt)"
trap 'rm -f "${TMP_BT}"' EXIT

sed "s/__TARGET_PID__/${PID}/g; s/__SIDE__/${SIDE}/g" "${TEMPLATE}" >"${TMP_BT}"

echo "collecting kernel events: pid=${PID} side=${SIDE} seconds=${SECONDS_TO_RUN} out=${OUT}" >&2
timeout "${SECONDS_TO_RUN}"s bpftrace "${TMP_BT}" >"${OUT}"

