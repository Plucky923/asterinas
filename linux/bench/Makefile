CC ?= gcc
CFLAGS := -O2 -Wall -Wextra -static -pthread
OUT_DIR ?= $(CURDIR)/build
export TMPDIR := $(OUT_DIR)/.tmp

BINS := $(OUT_DIR)/bench_syscall_fpu \
        $(OUT_DIR)/bench_mm \
        $(OUT_DIR)/test_mm_safety \
        $(OUT_DIR)/test_event_paths \
        $(OUT_DIR)/test_endovisor \
        $(OUT_DIR)/host_init

CPIO := $(OUT_DIR)/guest-syscall.cpio \
        $(OUT_DIR)/guest-mm.cpio \
        $(OUT_DIR)/guest-safety.cpio \
        $(OUT_DIR)/guest-events.cpio \
        $(OUT_DIR)/host-initramfs.cpio.gz

.PHONY: all bins initramfs clean

all: bins initramfs

bins: $(BINS)

$(OUT_DIR):
	mkdir -p $(OUT_DIR) $(OUT_DIR)/.tmp

$(OUT_DIR)/bench_syscall_fpu: bench_syscall_fpu.c | $(OUT_DIR)
	$(CC) $(CFLAGS) -o $@ $<

$(OUT_DIR)/bench_mm: bench_mm.c | $(OUT_DIR)
	$(CC) $(CFLAGS) -o $@ $<

$(OUT_DIR)/test_mm_safety: test_mm_safety.c | $(OUT_DIR)
	$(CC) $(CFLAGS) -o $@ $<

$(OUT_DIR)/test_event_paths: test_event_paths.c | $(OUT_DIR)
	$(CC) $(CFLAGS) -o $@ $<

$(OUT_DIR)/test_endovisor: test_endovisor.c ../endovisor/uapi/endovisor.h | $(OUT_DIR)
	$(CC) $(CFLAGS) -o $@ $<

$(OUT_DIR)/host_init: host_init.c | $(OUT_DIR)
	$(CC) $(CFLAGS) -o $@ $<

initramfs: $(BINS) pack_initramfs.sh
	OUT_DIR=$(OUT_DIR) bash $(CURDIR)/pack_initramfs.sh

clean:
	rm -rf $(OUT_DIR)
