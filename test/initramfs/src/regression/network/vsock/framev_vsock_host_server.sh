#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -e

HOST_PORT="${FRAMEV_VSOCK_HOST_PORT:-1234}"
CONNECTIONS="${FRAMEV_VSOCK_HOST_SERVER_CONNECTIONS:-2}"
BIN="${FRAMEV_VSOCK_HOST_BIN:-./framev_vsock_echo}"

"${BIN}" server any "${HOST_PORT}" "${CONNECTIONS}"
