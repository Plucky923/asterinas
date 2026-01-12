#!/bin/bash

# SPDX-License-Identifier: MPL-2.0

set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  tools/framevm/set_guest_payload.sh <guest_binary_name>

Example:
  tools/framevm/set_guest_payload.sh bench_memory_page_seq_cold

This updates the include_bytes target in:
  kernel/comps/framevm/src/main.rs
EOF
}

if [ $# -eq 1 ] && { [ "$1" = "-h" ] || [ "$1" = "--help" ]; }; then
    usage
    exit 0
fi

if [ $# -ne 1 ]; then
    usage >&2
    exit 1
fi

payload="$1"
if [[ ! "$payload" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "Error: invalid payload name '$payload'" >&2
    exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
payload_path="${repo_root}/kernel/comps/framevm/test/${payload}"
main_rs="${repo_root}/kernel/comps/framevm/src/main.rs"

if [ ! -f "${payload_path}" ]; then
    echo "Error: payload binary not found: ${payload_path}" >&2
    exit 1
fi

if [ ! -f "${main_rs}" ]; then
    echo "Error: file not found: ${main_rs}" >&2
    exit 1
fi

if ! grep -q 'include_bytes!("..\/test\/' "${main_rs}"; then
    echo "Error: include_bytes target not found in ${main_rs}" >&2
    exit 1
fi

perl -i -pe 's@include_bytes!\("\.\./test/[^"]+"\)@include_bytes!("../test/'"${payload}"'")@' "${main_rs}"

if ! grep -q "include_bytes!(\"../test/${payload}\")" "${main_rs}"; then
    echo "Error: failed to update include_bytes target in ${main_rs}" >&2
    exit 1
fi

echo "Updated FrameVM guest payload:"
grep -n "include_bytes!(\"../test/" "${main_rs}"
