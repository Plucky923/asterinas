#!/usr/bin/env bash
# Build the immutable shared `eval-payload.cpio` and `host-eval-initramfs*.cpio.gz`
# natively using static gcc, pinned upstream sources in `configs/payload-sources.json`,
# and gen_init_cpio. Writes only the payload receipt and synthesizes `build-inputs.json`
# only when all other component receipts also match current inputs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVAL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$EVAL_DIR/../.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$EVAL_DIR/.build}"
SRC_CACHE="$BUILD_DIR/sources"
DEPS_DIR="$BUILD_DIR/payload-deps"
PAYLOAD_ROOT="$BUILD_DIR/payload-root"
GUEST_BIN_DIR="$BUILD_DIR/guest"
JOBS="${JOBS:-$(nproc)}"
SOURCES_JSON="$EVAL_DIR/configs/payload-sources.json"

GEN_INIT_CPIO="${GEN_INIT_CPIO:-$BUILD_DIR/linux-perf-base/usr/gen_init_cpio}"
if [[ ! -x "$GEN_INIT_CPIO" ]]; then
    echo "error: gen_init_cpio not found at $GEN_INIT_CPIO; run 'make build-kernels' first" >&2
    exit 1
fi

mkdir -p "$SRC_CACHE" "$DEPS_DIR" "$GUEST_BIN_DIR" "$PAYLOAD_ROOT" "$BUILD_DIR/receipts"

source_spec() {
    python3 - "$SOURCES_JSON" "$1" <<'PY'
import json, sys
from pathlib import Path
spec = json.loads(Path(sys.argv[1]).read_text())[sys.argv[2]]
print(spec["version"], spec["url"], spec["sha256"], spec["archive"])
PY
}

fetch_and_verify() {
    local url="$1"
    local out="$2"
    local expected_sha="$3"
    if [[ ! -f "$out" ]]; then
        curl -fL --retry 3 -o "$out.part" "$url"
        mv "$out.part" "$out"
    fi
    local actual_sha
    actual_sha=$(sha256sum "$out" | awk '{print $1}')
    if [[ "$actual_sha" != "$expected_sha" ]]; then
        echo "error: sha256 mismatch for $out (expected $expected_sha, got $actual_sha)" >&2
        rm -f "$out"
        exit 1
    fi
}

CC="${CC:-gcc}"
CC_VER="$($CC --version | head -n 1)"
CFLAGS="-O2 -Wall -Wextra -Werror -static -pthread"

# 1. Always recompile poc/eval guest & host-init C components statically.
$CC $CFLAGS -o "$GUEST_BIN_DIR/eval_guest_runner" "$EVAL_DIR/guest/eval_guest_runner.c"
$CC $CFLAGS -o "$GUEST_BIN_DIR/vdso_selfcheck" "$EVAL_DIR/guest/vdso_selfcheck.c"
$CC $CFLAGS -o "$GUEST_BIN_DIR/eval_init" "$EVAL_DIR/guest/eval_init.c"

# 2. Build real upstream static hwloc + libtirpc via `build_payload_deps.sh`
# (versions/hashes from `configs/payload-sources.json`, invalidated on input+CC+flags).
BUILD_DIR="$BUILD_DIR" JOBS="$JOBS" CC="$CC" bash "$EVAL_DIR/scripts/build_payload_deps.sh"

read -r HWLOC_VER HWLOC_URL HWLOC_SHA HWLOC_ARC < <(source_spec hwloc)
read -r TIRPC_VER TIRPC_URL TIRPC_SHA TIRPC_ARC < <(source_spec libtirpc)
HWLOC_PREFIX="$DEPS_DIR/hwloc-$HWLOC_VER"
TIRPC_PREFIX="$DEPS_DIR/libtirpc-$TIRPC_VER"

# 3. Build static BusyBox from `payload-sources.json`, invalidated on input+CC.
read -r BUSYBOX_VER BUSYBOX_URL BUSYBOX_SHA BUSYBOX_ARC < <(source_spec busybox)
BUSYBOX_TAR="$SRC_CACHE/$BUSYBOX_ARC"
BUSYBOX_DIR="$SRC_CACHE/busybox-$BUSYBOX_VER"
fetch_and_verify "$BUSYBOX_URL" "$BUSYBOX_TAR" "$BUSYBOX_SHA"
BUSYBOX_WANT_SHA="$(printf '%s\n' "$BUSYBOX_SHA" "$CC_VER" "CONFIG_STATIC=y" | sha256sum | awk '{print $1}')"
BUSYBOX_CUR_SHA=""
if [[ -f "$GUEST_BIN_DIR/.busybox.sha256" ]]; then
    BUSYBOX_CUR_SHA="$(cat "$GUEST_BIN_DIR/.busybox.sha256")"
fi
if [[ "$BUSYBOX_CUR_SHA" != "$BUSYBOX_WANT_SHA" || ! -x "$GUEST_BIN_DIR/busybox" ]]; then
    rm -rf "$BUSYBOX_DIR"
    tar -xjf "$BUSYBOX_TAR" -C "$SRC_CACHE"
    make -C "$BUSYBOX_DIR" defconfig >/dev/null
    sed -i 's/^# CONFIG_STATIC is not set$/CONFIG_STATIC=y/' "$BUSYBOX_DIR/.config"
    sed -i 's/^CONFIG_TC=y$/# CONFIG_TC is not set/' "$BUSYBOX_DIR/.config"
    make -C "$BUSYBOX_DIR" oldconfig </dev/null >/dev/null
    make -C "$BUSYBOX_DIR" -j"$JOBS" CC="$CC" busybox
    cp "$BUSYBOX_DIR/busybox" "$GUEST_BIN_DIR/busybox"
    printf '%s\n' "$BUSYBOX_WANT_SHA" > "$GUEST_BIN_DIR/.busybox.sha256"
fi

# 4. Build LMbench 3 subset linked statically against real libtirpc.a.
read -r LMBENCH_REV LMBENCH_URL LMBENCH_SHA LMBENCH_ARC < <(source_spec lmbench)
OS="x86_64-linux-gnu"
LMBENCH_TAR="$SRC_CACHE/$LMBENCH_ARC"
LMBENCH_DIR="$SRC_CACHE/lmbench-$LMBENCH_REV"
LMBENCH_PATCH="$EVAL_DIR/patches/lmbench-timing-rusage.patch"
LMBENCH_OUT="$BUILD_DIR/lmbench-bin"
LMBENCH_TARGETS=(
    lat_syscall lat_pipe lat_select lat_proc lat_mmap
    bw_mmap_rd lat_pagefault lat_sig bw_mem hello
)
fetch_and_verify "$LMBENCH_URL" "$LMBENCH_TAR" "$LMBENCH_SHA"
LMBENCH_PATCH_SHA="$(sha256sum "$LMBENCH_PATCH" | awk '{print $1}')"
TIRPC_LIB_SHA="$(sha256sum "$TIRPC_PREFIX/lib/libtirpc.a" | awk '{print $1}')"
LMBENCH_WANT_SHA="$(printf '%s\n' "$LMBENCH_SHA" "$LMBENCH_PATCH_SHA" "$TIRPC_LIB_SHA" "$CC_VER" | sha256sum | awk '{print $1}')"
CUR_LMBENCH_SHA=""
if [[ -f "$LMBENCH_DIR/.eval-lmbench.sha256" ]]; then
    CUR_LMBENCH_SHA="$(cat "$LMBENCH_DIR/.eval-lmbench.sha256")"
fi
if [[ ! -d "$LMBENCH_DIR" || "$CUR_LMBENCH_SHA" != "$LMBENCH_WANT_SHA" || ! -x "$LMBENCH_OUT/lat_pagefault" ]]; then
    rm -rf "$LMBENCH_DIR" "$LMBENCH_OUT"
    tar -xzf "$LMBENCH_TAR" -C "$SRC_CACHE"
    (cd "$LMBENCH_DIR" && patch -p1 --force --silent < "$LMBENCH_PATCH")
    mkdir -p "$LMBENCH_OUT" "$LMBENCH_DIR/bin/$OS"
    LMBENCH_O="../bin/$OS"
    LMBENCH_CFLAGS="-O2 -std=gnu89 -I$TIRPC_PREFIX/include/tirpc -DRUSAGE -DHAVE_uint=1 -DHAVE_uint64_t=1 -DHAVE_int64_t=1 -DHAVE_DRAND48 -DHAVE_SCHED_SETAFFINITY=1 -Wno-error=format-security -Wno-implicit-function-declaration -Wno-return-type"
    make -C "$LMBENCH_DIR/src" CC="$CC" OS="$OS" O="$LMBENCH_O" \
        CFLAGS="$LMBENCH_CFLAGS" LDFLAGS="-static -L$TIRPC_PREFIX/lib" LDLIBS="-ltirpc -lm" \
        "$LMBENCH_O/lmbench.a" "${LMBENCH_TARGETS[@]/#/$LMBENCH_O/}"
    for t in "${LMBENCH_TARGETS[@]}"; do
        cp "$LMBENCH_DIR/bin/$OS/$t" "$LMBENCH_OUT/$t"
    done
    printf '%s\n' "$LMBENCH_WANT_SHA" > "$LMBENCH_DIR/.eval-lmbench.sha256"
fi

# 5. Build pinned will-it-scale linked statically against real libhwloc.a.
read -r WIS_REV WIS_URL WIS_SHA WIS_ARC < <(source_spec will-it-scale)
WIS_TAR="$SRC_CACHE/$WIS_ARC"
WIS_DIR="$SRC_CACHE/will-it-scale-$WIS_REV"
WIS_OUT="$BUILD_DIR/will-it-scale-bin"
WIS_TESTS=(
    getppid1 open1 dup1 pipe1
    page_fault1 page_fault2 page_fault3
    mmap1 mmap2 brk1 malloc1
)
fetch_and_verify "$WIS_URL" "$WIS_TAR" "$WIS_SHA"
HWLOC_LIB_SHA="$(sha256sum "$HWLOC_PREFIX/lib/libhwloc.a" | awk '{print $1}')"
WIS_WANT_SHA="$(printf '%s\n' "$WIS_SHA" "$HWLOC_LIB_SHA" "$CC_VER" | sha256sum | awk '{print $1}')"
CUR_WIS_SHA=""
if [[ -f "$WIS_OUT/.eval-wis.sha256" ]]; then
    CUR_WIS_SHA="$(cat "$WIS_OUT/.eval-wis.sha256")"
fi
if [[ ! -d "$WIS_DIR" || "$CUR_WIS_SHA" != "$WIS_WANT_SHA" ]]; then
    rm -rf "$WIS_DIR" "$WIS_OUT"
    tar -xzf "$WIS_TAR" -C "$SRC_CACHE"
    mkdir -p "$WIS_OUT"
    for t in "${WIS_TESTS[@]}"; do
        $CC -O2 -Wall -static -pthread -I"$HWLOC_PREFIX/include" -I"$WIS_DIR" \
            "$WIS_DIR/tests/$t.c" "$WIS_DIR/main.c" \
            -L"$HWLOC_PREFIX/lib" -lhwloc -lm \
            -o "$WIS_OUT/${t}_processes"
    done
    printf '%s\n' "$WIS_WANT_SHA" > "$WIS_OUT/.eval-wis.sha256"
fi

# 6. Build static stress-ng from `payload-sources.json`, invalidated on input+CC.
read -r STRESS_VER STRESS_URL STRESS_SHA STRESS_ARC < <(source_spec stress-ng)
STRESS_TAR="$SRC_CACHE/$STRESS_ARC"
STRESS_DIR="$SRC_CACHE/stress-ng-${STRESS_VER#V}"
fetch_and_verify "$STRESS_URL" "$STRESS_TAR" "$STRESS_SHA"
STRESS_WANT_SHA="$(printf '%s\n' "$STRESS_SHA" "$CC_VER" "STATIC=1" | sha256sum | awk '{print $1}')"
CUR_STRESS_SHA=""
if [[ -f "$GUEST_BIN_DIR/.stress-ng.sha256" ]]; then
    CUR_STRESS_SHA="$(cat "$GUEST_BIN_DIR/.stress-ng.sha256")"
fi
if [[ "$CUR_STRESS_SHA" != "$STRESS_WANT_SHA" || ! -x "$GUEST_BIN_DIR/stress-ng" ]]; then
    rm -rf "$STRESS_DIR"
    tar -xzf "$STRESS_TAR" -C "$SRC_CACHE"
    make -C "$STRESS_DIR" -j"$JOBS" STATIC=1 CC="$CC"
    cp "$STRESS_DIR/stress-ng" "$GUEST_BIN_DIR/stress-ng"
    printf '%s\n' "$STRESS_WANT_SHA" > "$GUEST_BIN_DIR/.stress-ng.sha256"
fi

# 7. Assemble single immutable eval-payload.cpio.
rm -rf "$PAYLOAD_ROOT"
mkdir -p "$PAYLOAD_ROOT"/{bin,dev,etc,proc,sys,tmp,benchmark/bin/lmbench,benchmark/bin/will-it-scale}
chmod 1777 "$PAYLOAD_ROOT/tmp"

cp "$GUEST_BIN_DIR/busybox" "$PAYLOAD_ROOT/bin/busybox"
for applet in sh true false echo cat ls mkdir rm cp mv chmod; do
    ln -sf busybox "$PAYLOAD_ROOT/bin/$applet"
done
cp "$GUEST_BIN_DIR/eval_guest_runner" "$PAYLOAD_ROOT/bin/eval_guest_runner"
cp "$GUEST_BIN_DIR/vdso_selfcheck" "$PAYLOAD_ROOT/bin/vdso_selfcheck"
ln -sf /bin/eval_guest_runner "$PAYLOAD_ROOT/init"

cp "$LMBENCH_OUT"/* "$PAYLOAD_ROOT/benchmark/bin/lmbench/"
cp "$WIS_OUT"/* "$PAYLOAD_ROOT/benchmark/bin/will-it-scale/"
cp "$GUEST_BIN_DIR/stress-ng" "$PAYLOAD_ROOT/benchmark/bin/stress-ng"

(cd "$PAYLOAD_ROOT" && find . -print0 | LC_ALL=C sort -z | cpio -o -H newc --null > "$BUILD_DIR/eval-payload.cpio")
sha256sum "$BUILD_DIR/eval-payload.cpio" > "$BUILD_DIR/eval-payload.cpio.sha256"

# 8. Assemble host-eval-initramfs*.cpio.gz (FAIL-CLOSED if any required Kernelet artifact is missing).
RUN_KERNELET="${RUN_KERNELET:-$BUILD_DIR/run-kernelet}"
KERNELET_IMAGE="${KERNELET_IMAGE:-$BUILD_DIR/kernelet-image.elf}"

pack_host_initramfs() {
    local ko_path="$1"
    local list_path="$2"
    local out_gz="$3"
    for req in "$ko_path" "$RUN_KERNELET" "$KERNELET_IMAGE"; do
        if [[ ! -s "$req" ]]; then
            echo "error: required host-initramfs artifact missing or empty: $req (run 'make build-kernels' first)" >&2
            exit 1
        fi
    done
    if [[ ! -x "$RUN_KERNELET" ]]; then
        echo "error: run-kernelet is not executable: $RUN_KERNELET" >&2
        exit 1
    fi
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
file /bin/run-kernelet $RUN_KERNELET 0755 0 0
file /modules/endovisor.ko $ko_path 0644 0 0
file /kernelet-image.elf $KERNELET_IMAGE 0644 0 0
file /payload/eval-payload.cpio $BUILD_DIR/eval-payload.cpio 0644 0 0
EOF
    "$GEN_INIT_CPIO" "$list_path" | gzip -9 > "$out_gz"
    local contents
    contents=$(gzip -dc "$out_gz" | cpio -it 2>/dev/null)
    for expected in "init" "bin/busybox" "bin/run-kernelet" "modules/endovisor.ko" "kernelet-image.elf" "payload/eval-payload.cpio"; do
        if ! grep -qx "$expected" <<<"$contents"; then
            echo "error: $out_gz missing $expected" >&2
            exit 1
        fi
    done
    if grep -qE "poc_endovisor|run-poc" <<<"$contents"; then
        echo "error: $out_gz contains stale poc_endovisor or run-poc" >&2
        exit 1
    fi
}

ENDOVISOR_KO="${ENDOVISOR_KO:-$BUILD_DIR/endovisor.ko}"
pack_host_initramfs "$ENDOVISOR_KO" "$BUILD_DIR/host-eval-initramfs.list" "$BUILD_DIR/host-eval-initramfs.cpio.gz"

RECEIPT_OUT_ARGS=(
    --output "eval_payload_cpio=eval-payload.cpio"
    --output "host_eval_initramfs=host-eval-initramfs.cpio.gz"
)
SYNTH_ARGS=(--build-dir "$BUILD_DIR")
if [[ "${BUILD_PTI:-0}" == "1" || -s "$BUILD_DIR/endovisor-pti.ko" ]]; then
    if [[ -s "$BUILD_DIR/endovisor-pti.ko" ]]; then
        pack_host_initramfs "$BUILD_DIR/endovisor-pti.ko" \
            "$BUILD_DIR/host-eval-initramfs-pti.list" \
            "$BUILD_DIR/host-eval-initramfs-pti.cpio.gz"
        RECEIPT_OUT_ARGS+=(--output "host_eval_initramfs_pti=host-eval-initramfs-pti.cpio.gz")
        SYNTH_ARGS+=(--pti)
    elif [[ "${BUILD_PTI:-0}" == "1" ]]; then
        echo "error: BUILD_PTI=1 requested but $BUILD_DIR/endovisor-pti.ko is missing" >&2
        exit 1
    fi
fi

PAYLOAD_SHA="$(PYTHONPATH="$EVAL_DIR" python3 -m host.cli component-hash --build-dir "$BUILD_DIR" --component payload --payload-mode native)"
PYTHONPATH="$EVAL_DIR" python3 -m host.cli write-receipt \
    --build-dir "$BUILD_DIR" \
    --component payload \
    --input-sha "$PAYLOAD_SHA" \
    --toolchain "native:${CC_VER}" \
    "${RECEIPT_OUT_ARGS[@]}"

# Synthesize build-inputs.json ONLY if ALL other component receipts are also fresh.
PYTHONPATH="$EVAL_DIR" python3 -m host.cli synthesize-build-manifest "${SYNTH_ARGS[@]}"

ls -lh "$BUILD_DIR/eval-payload.cpio" "$BUILD_DIR/host-eval-initramfs.cpio.gz"
