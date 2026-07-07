#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -e

HOST_CID="${FRAMEV_VSOCK_HOST_CID:-2}"
HOST_PORT="${FRAMEV_VSOCK_HOST_PORT:-1234}"
HOST_CLOSED_PORT="${FRAMEV_VSOCK_HOST_CLOSED_PORT:-65530}"
SMALL_PAYLOAD="${FRAMEV_VSOCK_SMALL_PAYLOAD:-4096}"
LARGE_PAYLOAD="${FRAMEV_VSOCK_LARGE_PAYLOAD:-131072}"

DIR="$(dirname "$0")"

"${DIR}/framev_vsock_echo" client "${HOST_CID}" "${HOST_PORT}" "${SMALL_PAYLOAD}" shutdown
"${DIR}/framev_vsock_echo" client "${HOST_CID}" "${HOST_PORT}" "${LARGE_PAYLOAD}" shutdown
"${DIR}/framev_vsock_echo" negative "${HOST_CID}" "${HOST_CLOSED_PORT}"
