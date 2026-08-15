#!/bin/sh

# SPDX-License-Identifier: MPL-2.0

# To successfully run the vsock test, you should
# 1. Run vsock server binding port 1234 on the host, before running ./vsock_client
# 2. Run vsock client connecting (cid,port)=(3,4321) on the host, after running ./vsock_server

set -e

VSOCK_DIR=/test/network/vsock
cd ${VSOCK_DIR}

echo "Start vsock test......"
case "${FRAMEV_VSOCK_ROLE:-legacy}" in
guest-client)
	sh ./framev_vsock_guest_client.sh
	;;
guest-server)
	sh ./framev_vsock_guest_server.sh
	;;
legacy)
	./vsock_client
	./vsock_server
	;;
*)
	echo "unknown FRAMEV_VSOCK_ROLE: ${FRAMEV_VSOCK_ROLE}" >&2
	exit 1
	;;
esac
echo "Vsock test passed."
