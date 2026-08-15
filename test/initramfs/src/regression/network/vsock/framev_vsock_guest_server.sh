#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

set -e

GUEST_PORT="${FRAMEV_VSOCK_GUEST_PORT:-4321}"
CONNECTIONS="${FRAMEV_VSOCK_GUEST_SERVER_CONNECTIONS:-2}"

DIR="$(dirname "$0")"

"${DIR}/framev_vsock_echo" server any "${GUEST_PORT}" "${CONNECTIONS}"
