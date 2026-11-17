#!/usr/bin/env bash
# Build `eval-payload.cpio` via Nix (`poc/eval/nix/default.nix`) and assemble
# `host-eval-initramfs*.cpio.gz`, binding outputs via payload receipt + manifest synthesis.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVAL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$EVAL_DIR/.build}"
GUEST_BIN_DIR="$BUILD_DIR/guest"
mkdir -p "$GUEST_BIN_DIR" "$BUILD_DIR/receipts"

if ! command -v nix-build >/dev/null 2>&1; then
    echo "error: nix-build is not installed; set PAYLOAD_MODE=native or install nix" >&2
    exit 1
fi

GEN_INIT_CPIO="${GEN_INIT_CPIO:-$BUILD_DIR/linux-perf-base/usr/gen_init_cpio}"
if [[ ! -x "$GEN_INIT_CPIO" ]]; then
    echo "error: gen_init_cpio not found at $GEN_INIT_CPIO; run 'make build-kernels' first" >&2
    exit 1
fi

NIX_VER="$(nix-build --version | head -n 1)"
nix-build "$EVAL_DIR/nix/default.nix" --out-link "$BUILD_DIR/nix-eval-payload"
cp -fL "$BUILD_DIR/nix-eval-payload" "$BUILD_DIR/eval-payload.cpio"
chmod 0644 "$BUILD_DIR/eval-payload.cpio"
sha256sum "$BUILD_DIR/eval-payload.cpio" > "$BUILD_DIR/eval-payload.cpio.sha256"

CC="${CC:-gcc}"
CC_VER="$($CC --version | head -n 1)"
$CC -O2 -Wall -Wextra -Werror -static -pthread -o "$GUEST_BIN_DIR/eval_init" "$EVAL_DIR/guest/eval_init.c"

read -r BUSYBOX_VER BUSYBOX_URL BUSYBOX_SHA BUSYBOX_ARC < <(python3 - "$EVAL_DIR/configs/payload-sources.json" <<'PY'
import json, sys
from pathlib import Path
s = json.loads(Path(sys.argv[1]).read_text())["busybox"]
print(s["version"], s["url"], s["sha256"], s["archive"])
PY
)
BUSYBOX_TAR="$BUILD_DIR/sources/$BUSYBOX_ARC"
BUSYBOX_DIR="$BUILD_DIR/sources/busybox-$BUSYBOX_VER"
mkdir -p "$BUILD_DIR/sources"
if [[ ! -f "$BUSYBOX_TAR" ]]; then
    curl -fL --retry 3 -o "$BUSYBOX_TAR" "$BUSYBOX_URL"
fi
printf '%s  %s\n' "$BUSYBOX_SHA" "$BUSYBOX_TAR" | sha256sum --check --status
if [[ ! -x "$GUEST_BIN_DIR/busybox" ]]; then
    rm -rf "$BUSYBOX_DIR"
    tar -xjf "$BUSYBOX_TAR" -C "$BUILD_DIR/sources"
    make -C "$BUSYBOX_DIR" defconfig >/dev/null
    sed -i 's/^# CONFIG_STATIC is not set$/CONFIG_STATIC=y/' "$BUSYBOX_DIR/.config"
    sed -i 's/^CONFIG_TC=y$/# CONFIG_TC is not set/' "$BUSYBOX_DIR/.config"
    make -C "$BUSYBOX_DIR" oldconfig </dev/null >/dev/null
    make -C "$BUSYBOX_DIR" -j"${JOBS:-$(nproc)}" CC="$CC" busybox
    cp "$BUSYBOX_DIR/busybox" "$GUEST_BIN_DIR/busybox"
fi

pack_host_initramfs() {
    local ko_path="$1"
    local list_path="$2"
    local out_gz="$3"
    for req in "$ko_path" "$BUILD_DIR/run-kernelet" "$BUILD_DIR/kernelet-image.elf"; do
        test -s "$req" || { echo "error: missing $req" >&2; exit 1; }
    done
    cat > "$list_path" <<EOF
dir /dev 0755 0 0
nod /dev/console 0600 0 0 c 5 1
dir /proc 0755 0 0
dir /sys 0755 0 0
dir /etc 0755 0 0
dir /bin 0755 0 0
dir /modules 0755 0 0
dir /payload 0755 0 0
dir /mnt 0755 0 0
dir /mnt/payload 0755 0 0
file /init $GUEST_BIN_DIR/eval_init 0755 0 0
file /bin/busybox $GUEST_BIN_DIR/busybox 0755 0 0
file /bin/run-kernelet $BUILD_DIR/run-kernelet 0755 0 0
file /modules/endovisor.ko $ko_path 0644 0 0
file /kernelet-image.elf $BUILD_DIR/kernelet-image.elf 0644 0 0
file /payload/eval-payload.cpio $BUILD_DIR/eval-payload.cpio 0644 0 0
EOF
    "$GEN_INIT_CPIO" "$list_path" | gzip -9 > "$out_gz"
}

pack_host_initramfs "$BUILD_DIR/endovisor.ko" "$BUILD_DIR/host-eval-initramfs.list" "$BUILD_DIR/host-eval-initramfs.cpio.gz"
RECEIPT_OUT_ARGS=(--output "eval_payload_cpio=eval-payload.cpio" --output "host_eval_initramfs=host-eval-initramfs.cpio.gz")
SYNTH_ARGS=(--build-dir "$BUILD_DIR")
if [[ "${BUILD_PTI:-0}" == "1" || -s "$BUILD_DIR/endovisor-pti.ko" ]]; then
    pack_host_initramfs "$BUILD_DIR/endovisor-pti.ko" "$BUILD_DIR/host-eval-initramfs-pti.list" "$BUILD_DIR/host-eval-initramfs-pti.cpio.gz"
    RECEIPT_OUT_ARGS+=(--output "host_eval_initramfs_pti=host-eval-initramfs-pti.cpio.gz")
    SYNTH_ARGS+=(--pti)
fi

PAYLOAD_SHA="$(PYTHONPATH="$EVAL_DIR" python3 -m host.cli component-hash --build-dir "$BUILD_DIR" --component payload --payload-mode nix)"
PYTHONPATH="$EVAL_DIR" python3 -m host.cli write-receipt \
    --build-dir "$BUILD_DIR" \
    --component payload \
    --input-sha "$PAYLOAD_SHA" \
    --toolchain "nix:${NIX_VER};${CC_VER}" \
    "${RECEIPT_OUT_ARGS[@]}"

PYTHONPATH="$EVAL_DIR" python3 -m host.cli synthesize-build-manifest "${SYNTH_ARGS[@]}"
