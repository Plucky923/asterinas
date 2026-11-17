#!/usr/bin/env bash
# Build real static CPU-topology and RPC libraries for the native payload.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVAL_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-$EVAL_DIR/.build}"
SRC_CACHE="$BUILD_DIR/sources"
DEPS_DIR="$BUILD_DIR/payload-deps"
JOBS="${JOBS:-$(nproc)}"
CC="${CC:-gcc}"
mkdir -p "$SRC_CACHE" "$DEPS_DIR"
BUILD_TMP="$(mktemp -d "$DEPS_DIR/build-tmp.XXXXXX")"
trap 'rm -rf -- "$BUILD_TMP"' EXIT
export TMPDIR="$BUILD_TMP"

source_spec() {
    python3 - "$EVAL_DIR/configs/payload-sources.json" "$1" <<'PY'
import json
import sys
from pathlib import Path

spec = json.loads(Path(sys.argv[1]).read_text())[sys.argv[2]]
print(spec["version"], spec["url"], spec["sha256"])
PY
}

build_dependency() {
    local name="$1"
    local version url digest
    read -r version url digest < <(source_spec "$name")
    local archive="$SRC_CACHE/$name-$version.tar.bz2"
    if [[ ! -f "$archive" ]]; then
        curl -fL --retry 3 -o "$archive.part" "$url"
        mv "$archive.part" "$archive"
    fi
    printf '%s  %s\n' "$digest" "$archive" | sha256sum --check --status

    local prefix="$DEPS_DIR/$name-$version"
    local library="$name"
    if [[ "$name" == "libtirpc" ]]; then
        library="tirpc"
    fi
    local configure_flags=(--disable-shared --enable-static)
    if [[ "$name" == "hwloc" ]]; then
        configure_flags+=(--disable-io --disable-cairo --disable-libxml2 --disable-libudev)
    else
        configure_flags+=(--disable-gssapi)
    fi
    local build_digest
    build_digest="$(printf '%s\n' "$digest" "$CC" "$($CC --version)" "${configure_flags[@]}" | sha256sum)"
    build_digest="${build_digest%% *}"
    if [[ -f "$prefix/.build-sha256" ]] &&
       [[ "$(cat "$prefix/.build-sha256")" == "$build_digest" ]] &&
       [[ -f "$prefix/lib/lib$library.a" ]]; then
        return
    fi
    local source="$SRC_CACHE/$name-$version"
    if [[ ! -d "$source" ]]; then
        tar -xjf "$archive" -C "$SRC_CACHE"
    fi
    local work="$DEPS_DIR/build-$name-$version"
    mkdir -p "$work"
    (
        cd "$work"
        "$source/configure" --prefix="$prefix" --libdir="$prefix/lib" \
            CC="$CC" "${configure_flags[@]}"
        make -j"$JOBS"
        make install
    )
    printf '%s\n' "$build_digest" > "$prefix/.build-sha256"
}

build_dependency hwloc
build_dependency libtirpc
