#!/usr/bin/env bash
# Build isolated Linux perf kernels (O=poc/eval/.build/linux-perf-*), endovisor.ko,
# run-kernelet, Native Asterinas bzImage (A), and Kernelet ELF image (K).
# Invalidation binds full sources (including reference/linux-6.12), patches,
# configs, and toolchains to outputs via per-component receipts.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVAL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$EVAL_DIR/../.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$EVAL_DIR/.build}"
JOBS="${JOBS:-$(nproc)}"

LINUX_SRC="$BUILD_DIR/linux-6.12-src"
REF_LINUX="$REPO_ROOT/reference/linux-6.12"
PATCH="$REPO_ROOT/prototype/linux/patches/0001-carrier-hooks.patch"

mkdir -p "$BUILD_DIR" "$BUILD_DIR/receipts"
# Never leave a previous global manifest alive across partial kernel rebuilds.
rm -f "$BUILD_DIR/build-inputs.json"

component_hash() {
    PYTHONPATH="$EVAL_DIR" python3 -m host.cli component-hash --build-dir "$BUILD_DIR" "$@"
}

write_receipt() {
    PYTHONPATH="$EVAL_DIR" python3 -m host.cli write-receipt --build-dir "$BUILD_DIR" "$@"
}

CC_VER="$(gcc --version | head -n 1)"

# 1. Prepare clean patched Linux 6.12 source tree; invalidate on reference source or patch change.
PATCH_SRC_SHA="$(component_hash --component linux_src)"
CUR_PATCH_SRC_SHA=""
if [[ -f "$LINUX_SRC/.carrier-hooks-patch.sha256" ]]; then
    CUR_PATCH_SRC_SHA="$(cat "$LINUX_SRC/.carrier-hooks-patch.sha256")"
fi
if [[ ! -d "$LINUX_SRC" || "$CUR_PATCH_SRC_SHA" != "$PATCH_SRC_SHA" ]]; then
    echo "[build_kernels] Refreshing $LINUX_SRC (sha256=$PATCH_SRC_SHA)..."
    rm -rf "$LINUX_SRC"
    cp -al "$REF_LINUX" "$LINUX_SRC"
    (cd "$LINUX_SRC" && patch -p1 --force --silent < "$PATCH")
    printf '%s\n' "$PATCH_SRC_SHA" > "$LINUX_SRC/.carrier-hooks-patch.sha256"
    rm -f "$BUILD_DIR/linux-perf-base/.eval-build.sha256" \
          "$BUILD_DIR/linux-perf-pti/.eval-build.sha256" \
          "$BUILD_DIR/receipts/linux_perf_base.json" \
          "$BUILD_DIR/receipts/linux_perf_pti.json"
fi

build_linux_profile() {
    local profile="$1"
    local comp="linux_${profile//-/_}"
    local out_dir="$BUILD_DIR/linux-$profile"
    local stamp_file="$out_dir/.eval-build.sha256"
    local frag_args=("$EVAL_DIR/configs/linux-perf-base.fragment")
    if [[ "$profile" != "perf-base" ]]; then
        frag_args+=("$EVAL_DIR/configs/linux-${profile}.fragment")
    fi
    local want_sha
    want_sha="$(component_hash --component "$comp")"
    local cur_sha=""
    if [[ -f "$stamp_file" ]]; then
        cur_sha="$(cat "$stamp_file")"
    fi
    if [[ "$cur_sha" != "$want_sha" || \
          ! -s "$out_dir/arch/x86/boot/bzImage" || \
          ! -s "$out_dir/System.map" || \
          ! -s "$out_dir/.config" || \
          ! -s "$out_dir/Module.symvers" ]]; then
        echo "[build_kernels] Building linux-$profile..."
        mkdir -p "$out_dir"
        make -C "$LINUX_SRC" O="$out_dir" ARCH=x86_64 tinyconfig
        (cd "$LINUX_SRC" && ARCH=x86_64 ./scripts/kconfig/merge_config.sh -m -O "$out_dir" \
            "$out_dir/.config" "${frag_args[@]}")
        make -C "$LINUX_SRC" O="$out_dir" ARCH=x86_64 CC="gcc -std=gnu11" olddefconfig
        PYTHONPATH="$EVAL_DIR" python3 -m host.cli check-config --config "$out_dir/.config" --profile "$profile"
        make -C "$LINUX_SRC" O="$out_dir" ARCH=x86_64 CC="gcc -std=gnu11" -j"$JOBS" bzImage modules modules_prepare
        printf '%s\n' "$want_sha" > "$stamp_file"
    else
        PYTHONPATH="$EVAL_DIR" python3 -m host.cli check-config --config "$out_dir/.config" --profile "$profile"
    fi

    write_receipt \
        --component "$comp" \
        --input-sha "$want_sha" \
        --toolchain "$CC_VER" \
        --output "${comp}_bzimage=linux-${profile}/arch/x86/boot/bzImage" \
        --output "${comp}_system_map=linux-${profile}/System.map" \
        --output "${comp}_config=linux-${profile}/.config" \
        --output "${comp}_symvers=linux-${profile}/Module.symvers"
}

build_endovisor_for_profile() {
    local profile="$1"
    local comp="endovisor"
    local ko_name="endovisor.ko"
    local work_dir="$BUILD_DIR/endovisor"
    local stamp_file="$BUILD_DIR/.endovisor.sha256"
    if [[ "$profile" == "perf-pti" ]]; then
        comp="endovisor_pti"
        ko_name="endovisor-pti.ko"
        work_dir="$BUILD_DIR/endovisor-pti"
        stamp_file="$BUILD_DIR/.endovisor-pti.sha256"
    fi

    local want_sha
    want_sha="$(component_hash --component "$comp")"
    local cur_sha=""
    if [[ -f "$stamp_file" ]]; then
        cur_sha="$(cat "$stamp_file")"
    fi
    if [[ "$cur_sha" != "$want_sha" || ! -s "$BUILD_DIR/$ko_name" ]]; then
        echo "[build_kernels] Building $ko_name (profile=$profile)..."
        rm -rf "$work_dir"
        mkdir -p "$work_dir"
        cp -a "$REPO_ROOT/poc/linux/endovisor/Makefile" \
            "$REPO_ROOT/poc/linux/endovisor/"*.c \
            "$REPO_ROOT/poc/linux/endovisor/"*.S \
            "$REPO_ROOT/poc/linux/endovisor/"*.h \
            "$REPO_ROOT/poc/linux/endovisor/uapi" \
            "$work_dir/"
        make -C "$BUILD_DIR/linux-$profile" ARCH=x86_64 CC="gcc -std=gnu11" -j"$JOBS" M="$work_dir" modules
        cp "$work_dir/endovisor.ko" "$BUILD_DIR/$ko_name"
        printf '%s\n' "$want_sha" > "$stamp_file"
    fi

    write_receipt \
        --component "$comp" \
        --input-sha "$want_sha" \
        --toolchain "$CC_VER" \
        --output "${comp}_ko=${ko_name}"
}

build_linux_profile "perf-base"
build_endovisor_for_profile "perf-base"

if [[ "${BUILD_PTI:-0}" == "1" ]]; then
    build_linux_profile "perf-pti"
    build_endovisor_for_profile "perf-pti"
fi

# 3. Build run-kernelet into $BUILD_DIR/run-kernelet; invalidate on runner/UAPI/toolchain change.
RUNNER_OUT="$BUILD_DIR/runner"
RUNNER_STAMP="$BUILD_DIR/.runner.sha256"
RUNNER_SHA="$(component_hash --component run_kernelet)"
CUR_RUNNER_SHA=""
if [[ -f "$RUNNER_STAMP" ]]; then
    CUR_RUNNER_SHA="$(cat "$RUNNER_STAMP")"
fi
if [[ "$CUR_RUNNER_SHA" != "$RUNNER_SHA" || ! -x "$BUILD_DIR/run-kernelet" ]]; then
    echo "[build_kernels] Building run-kernelet..."
    rm -rf "$RUNNER_OUT"
    mkdir -p "$RUNNER_OUT"
    make -C "$REPO_ROOT/poc/linux/runner" OUT_DIR="$RUNNER_OUT"
    cp "$RUNNER_OUT/run-kernelet" "$BUILD_DIR/run-kernelet"
    printf '%s\n' "$RUNNER_SHA" > "$RUNNER_STAMP"
fi
write_receipt \
    --component run_kernelet \
    --input-sha "$RUNNER_SHA" \
    --toolchain "$CC_VER" \
    --output "run_kernelet=run-kernelet"

# 4. Build both Native Asterinas (A) and Kernelet PIE image (K) from identical poc/kernel source.
export PATH="$HOME/.cargo/bin:$PATH"
export VDSO_LIBRARY_DIR="${VDSO_LIBRARY_DIR:-$HOME/.local/share/asterinas/linux_vdso}"
export OSDK_TARGET_ARCH="x86_64"
export OSTD_TASK_STACK_SIZE_IN_PAGES=8

OSDK_BIN_DIR="$BUILD_DIR/osdk-bin/bin"
OSDK_STAMP="$BUILD_DIR/.cargo-osdk.sha256"
OSDK_INPUT_SHA="$(cd "$EVAL_DIR" && PYTHONPATH="$EVAL_DIR" python3 - <<'PY'
import hashlib, pathlib
from host.build_guard import _walk_source_paths, _cmd_version
repo = pathlib.Path("../..").resolve()
h = hashlib.sha256()
for p in _walk_source_paths((repo / "poc" / "osdk", repo / "poc" / "Cargo.toml", repo / "poc" / "Cargo.lock")):
    h.update(p.relative_to(repo).as_posix().encode())
    h.update(b"\0")
    h.update(p.read_bytes())
    h.update(b"\0")
h.update(_cmd_version(["rustc", "--version"]).encode())
print(h.hexdigest())
PY
)"
CUR_OSDK_SHA=""
if [[ -f "$OSDK_STAMP" ]]; then
    CUR_OSDK_SHA="$(cat "$OSDK_STAMP")"
fi
if [[ "$CUR_OSDK_SHA" != "$OSDK_INPUT_SHA" || ! -x "$OSDK_BIN_DIR/cargo-osdk" ]]; then
    echo "[build_kernels] Building workspace cargo-osdk (OSDK_LOCAL_DEV=1)..."
    OSDK_LOCAL_DEV=1 cargo install cargo-osdk \
        --path "$REPO_ROOT/poc/osdk" \
        --locked \
        --offline \
        --force \
        --root "$BUILD_DIR/osdk-bin" \
        --target-dir "$REPO_ROOT/poc/osdk/target"
    printf '%s\n' "$OSDK_INPUT_SHA" > "$OSDK_STAMP"
fi
export PATH="$OSDK_BIN_DIR:$PATH"

RUST_VER="$(rustc --version 2>/dev/null || echo unknown)"
OSDK_VER="$("$OSDK_BIN_DIR/cargo-osdk" --version 2>/dev/null || echo unknown)"
RUST_STAMP="$BUILD_DIR/.asterinas.sha256"
RUST_SHA="$(component_hash --component asterinas)"
CUR_RUST_SHA=""
if [[ -f "$RUST_STAMP" ]]; then
    CUR_RUST_SHA="$(cat "$RUST_STAMP")"
fi

if [[ "$CUR_RUST_SHA" != "$RUST_SHA" || \
      ! -s "$BUILD_DIR/asterinas-native.bzImage" || \
      ! -s "$BUILD_DIR/kernelet-image.elf" ]]; then
    echo "[build_kernels] Building Asterinas Native (A) and Kernelet ELF (K)..."
    if [[ ! -f "$VDSO_LIBRARY_DIR/vdso_x86_64.so" ]]; then
        echo "error: missing $VDSO_LIBRARY_DIR/vdso_x86_64.so" >&2
        exit 1
    fi

    ASTER_OUT="$BUILD_DIR/asterinas-native-osdk"
    rm -rf "$ASTER_OUT"
    mkdir -p "$ASTER_OUT"
    (
        cd "$REPO_ROOT/poc/kernel"
        cargo osdk build \
            --release \
            --boot-method="vmm-direct" \
            --linux-x86-legacy-boot \
            --grub-boot-protocol="linux" \
            --strip-elf \
            --output="$ASTER_OUT"
    )
    if [[ -f "$ASTER_OUT/asterinas" ]]; then
        cp "$ASTER_OUT/asterinas" "$BUILD_DIR/asterinas-native.bzImage"
    elif [[ -f "$ASTER_OUT/asterinas-osdk-bin" ]]; then
        cp "$ASTER_OUT/asterinas-osdk-bin" "$BUILD_DIR/asterinas-native.bzImage"
    else
        found_img=$(find "$ASTER_OUT" -maxdepth 2 -type f -executable | head -n 1 || true)
        if [[ -z "$found_img" ]]; then
            echo "error: could not locate built native Asterinas image under $ASTER_OUT" >&2
            exit 1
        fi
        cp "$found_img" "$BUILD_DIR/asterinas-native.bzImage"
    fi

    KERNELET_OUT="$BUILD_DIR/asterinas-kernelet-osdk"
    rm -rf "$KERNELET_OUT"
    mkdir -p "$KERNELET_OUT"
    (
        cd "$REPO_ROOT/poc/kernel"
        OSDK_KERNELET_IMAGE_ONLY=1 cargo osdk build \
            --kernelet \
            --release \
            --output="$KERNELET_OUT"
    )
    KLET_ELF=$(cat "$KERNELET_OUT/kernelet-image-path.txt")
    if [[ ! -f "$KLET_ELF" ]]; then
        echo "error: kernelet image missing at $KLET_ELF" >&2
        exit 1
    fi
    cp "$KLET_ELF" "$BUILD_DIR/kernelet-image.elf"
    printf '%s\n' "$RUST_SHA" > "$RUST_STAMP"
fi

write_receipt \
    --component asterinas \
    --input-sha "$RUST_SHA" \
    --toolchain "${RUST_VER}; ${OSDK_VER}" \
    --output "asterinas_native_bzimage=asterinas-native.bzImage" \
    --output "kernelet_image_elf=kernelet-image.elf"

# Synthesize build-inputs.json if an up-to-date payload receipt already matches everything.
PYTHONPATH="$EVAL_DIR" python3 -m host.cli synthesize-build-manifest --build-dir "$BUILD_DIR" --if-complete || true

ls -lh \
    "$BUILD_DIR/linux-perf-base/arch/x86/boot/bzImage" \
    "$BUILD_DIR/endovisor.ko" \
    "$BUILD_DIR/run-kernelet" \
    "$BUILD_DIR/asterinas-native.bzImage" \
    "$BUILD_DIR/kernelet-image.elf"
