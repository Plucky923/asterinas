#!/usr/bin/env bash
# Pack guest CPIO archives (guest-syscall.cpio, guest-mm.cpio, guest-safety.cpio)
# and host-initramfs.cpio.gz using Linux's gen_init_cpio.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
OUT_DIR="${OUT_DIR:-$SCRIPT_DIR/build}"
GEN_INIT_CPIO="${GEN_INIT_CPIO:-$REPO_ROOT/prototype/.build/linux-6.12/usr/gen_init_cpio}"

ENDOVISOR_KO="${ENDOVISOR_KO:-$REPO_ROOT/poc/linux/endovisor/endovisor.ko}"
RUN_KERNELET="${RUN_KERNELET:-$REPO_ROOT/poc/linux/runner/run-kernelet}"
KERNELET_IMAGE="${KERNELET_IMAGE:-}"

if [[ ! -x "$GEN_INIT_CPIO" ]]; then
    echo "error: gen_init_cpio not found at $GEN_INIT_CPIO" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"

pack_guest_cpio() {
    local bin="$1"
    local out="$2"
    local list_file="$OUT_DIR/$(basename "$out").list"
    cat > "$list_file" <<EOF
dir /dev 0755 0 0
nod /dev/console 0600 0 0 c 5 1
dir /proc 0755 0 0
dir /tmp 0777 0 0
file /init $bin 0755 0 0
EOF
    "$GEN_INIT_CPIO" "$list_file" > "$out"
    ls -lh "$out"
}

pack_guest_cpio "$OUT_DIR/bench_syscall_fpu" "$OUT_DIR/guest-syscall.cpio"
pack_guest_cpio "$OUT_DIR/bench_mm" "$OUT_DIR/guest-mm.cpio"
pack_guest_cpio "$OUT_DIR/test_mm_safety" "$OUT_DIR/guest-safety.cpio"
pack_guest_cpio "$OUT_DIR/test_event_paths" "$OUT_DIR/guest-events.cpio"

HOST_LIST="$OUT_DIR/host-initramfs.list"
cat > "$HOST_LIST" <<EOF
dir /dev 0755 0 0
nod /dev/console 0600 0 0 c 5 1
dir /proc 0755 0 0
dir /sys 0755 0 0
dir /bin 0755 0 0
dir /modules 0755 0 0
dir /tests 0755 0 0
dir /guests 0755 0 0
file /init $OUT_DIR/host_init 0755 0 0
file /tests/bench_syscall_fpu $OUT_DIR/bench_syscall_fpu 0755 0 0
file /tests/bench_mm $OUT_DIR/bench_mm 0755 0 0
file /tests/test_mm_safety $OUT_DIR/test_mm_safety 0755 0 0
file /tests/test_event_paths $OUT_DIR/test_event_paths 0755 0 0
file /tests/test_endovisor $OUT_DIR/test_endovisor 0755 0 0
file /guests/guest-syscall.cpio $OUT_DIR/guest-syscall.cpio 0644 0 0
file /guests/guest-mm.cpio $OUT_DIR/guest-mm.cpio 0644 0 0
file /guests/guest-safety.cpio $OUT_DIR/guest-safety.cpio 0644 0 0
file /guests/guest-events.cpio $OUT_DIR/guest-events.cpio 0644 0 0
EOF

if [[ -f "$ENDOVISOR_KO" ]]; then
    echo "file /modules/endovisor.ko $ENDOVISOR_KO 0644 0 0" >> "$HOST_LIST"
    local_order="$OUT_DIR/modules.order"
    printf 'endovisor.ko\n' > "$local_order"
    echo "file /modules/order $local_order 0644 0 0" >> "$HOST_LIST"
else
    echo "note: endovisor.ko not found at $ENDOVISOR_KO (omitted from host-initramfs)"
fi

if [[ -x "$RUN_KERNELET" ]]; then
    echo "file /bin/run-kernelet $RUN_KERNELET 0755 0 0" >> "$HOST_LIST"
else
    echo "note: run-kernelet not found at $RUN_KERNELET (omitted from host-initramfs)"
fi

if [[ -n "$KERNELET_IMAGE" && -f "$KERNELET_IMAGE" ]]; then
    echo "file /kernelet-image.elf $KERNELET_IMAGE 0644 0 0" >> "$HOST_LIST"
else
    echo "note: KERNELET_IMAGE not set or missing (omitted from host-initramfs)"
fi

"$GEN_INIT_CPIO" "$HOST_LIST" | gzip -9 > "$OUT_DIR/host-initramfs.cpio.gz"
ls -lh "$OUT_DIR/host-initramfs.cpio.gz"
