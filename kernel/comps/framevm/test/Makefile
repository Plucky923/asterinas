# SPDX-License-Identifier: MPL-2.0
#
# Makefile for FrameVM Freestanding Test Programs
# These programs run inside FrameVM Guest without any C runtime dependencies.
#
# Usage:
#   make                        # Build all variants (default)
#   make all_variants           # Same as above
#   make BUF_SIZE=65536         # Build default targets with 64KB buffer
#   make clean                  # Remove all built binaries

CC = gcc
CFLAGS = -static -nostdlib -fno-builtin -O2 -Wall

# Default buffer size (can be overridden via command line)
BUF_SIZE ?= 1024
TOTAL_BYTES ?= 104857600

# RTT test defaults
RTT_ITERATIONS ?= 10000
RTT_PORT ?= 20002

# Buffer size variants: suffix=bytes
# Generates targets like bench_throughput_receiver_64, bench_throughput_sender_1k, etc.
SIZE_64 = 64
SIZE_128 = 128
SIZE_256 = 256
SIZE_512 = 512
SIZE_1k = 1024
SIZE_2k = 2048
SIZE_4k = 4096
SIZE_8k = 8192
SIZE_16k = 16384
SIZE_32k = 32768
SIZE_64k = 65536
SIZE_128k = 131072
SIZE_256k = 262144
SIZE_512k = 524288
SIZE_1m = 1048576

# All size suffixes
SUFFIXES = 64 128 256 512 1k 2k 4k 8k 16k 32k 64k 128k 256k 512k 1m

# Generate target lists
RECEIVER_TARGETS = $(addprefix bench_throughput_receiver_,$(SUFFIXES))
SENDER_TARGETS = $(addprefix bench_throughput_sender_,$(SUFFIXES))
RTT_CLIENT_TARGETS = bench_rtt_client
RTT_SERVER_TARGETS = bench_rtt_server
ALL_TARGETS = $(RECEIVER_TARGETS) $(SENDER_TARGETS) $(RTT_CLIENT_TARGETS) $(RTT_SERVER_TARGETS)

# Default target: build all variants
.PHONY: all all_variants clean info receivers_all senders_all rtt_all

all: all_variants

all_variants: $(ALL_TARGETS)
	@echo "=== Built all variants ==="
	@echo "Receivers: $(RECEIVER_TARGETS)"
	@echo "Senders: $(SENDER_TARGETS)"
	@echo "RTT: $(RTT_CLIENT_TARGETS) $(RTT_SERVER_TARGETS)"

# Pattern rule for receivers
define RECEIVER_RULE
bench_throughput_receiver_$(1): bench_throughput_receiver.c syscalls.h
	$$(CC) $$(CFLAGS) -DBUF_SIZE=$$(SIZE_$(1)) -o $$@ $$<
endef

# Pattern rule for senders
define SENDER_RULE
bench_throughput_sender_$(1): bench_throughput_sender.c syscalls.h
	$$(CC) $$(CFLAGS) -DBUF_SIZE=$$(SIZE_$(1)) -DTOTAL_BYTES=$$(TOTAL_BYTES) -o $$@ $$<
endef

# Generate all rules using foreach and eval
$(foreach suffix,$(SUFFIXES),$(eval $(call RECEIVER_RULE,$(suffix))))
$(foreach suffix,$(SUFFIXES),$(eval $(call SENDER_RULE,$(suffix))))

# Aggregate targets
receivers_all: $(RECEIVER_TARGETS)
	@echo "Built all receiver variants"

senders_all: $(SENDER_TARGETS)
	@echo "Built all sender variants"

# RTT targets
rtt_all: $(RTT_CLIENT_TARGETS) $(RTT_SERVER_TARGETS)
	@echo "Built all RTT variants"

bench_rtt_client: bench_rtt_client.c syscalls.h
	$(CC) $(CFLAGS) -DITERATIONS=$(RTT_ITERATIONS) -DPORT=$(RTT_PORT) -o $@ $<
	@echo "Built: $@ (ITERATIONS=$(RTT_ITERATIONS), PORT=$(RTT_PORT))"

bench_rtt_server: bench_rtt_server.c syscalls.h
	$(CC) $(CFLAGS) -DPORT=$(RTT_PORT) -o $@ $<
	@echo "Built: $@ (PORT=$(RTT_PORT))"

# Legacy default targets (for backward compatibility with BUF_SIZE parameter)
bench_throughput_sender: bench_throughput_sender.c syscalls.h
	$(CC) $(CFLAGS) -DBUF_SIZE=$(BUF_SIZE) -DTOTAL_BYTES=$(TOTAL_BYTES) -o $@ $<
	@echo "Built: $@ (BUF_SIZE=$(BUF_SIZE), TOTAL_BYTES=$(TOTAL_BYTES))"

bench_throughput_receiver: bench_throughput_receiver.c syscalls.h
	$(CC) $(CFLAGS) -DBUF_SIZE=$(BUF_SIZE) -o $@ $<
	@echo "Built: $@ (BUF_SIZE=$(BUF_SIZE))"

clean:
	rm -f bench_throughput_sender bench_throughput_receiver $(ALL_TARGETS)
	@echo "Cleaned all binaries"

info:
	@echo "=== Available Targets ==="
	@echo "Default: make (builds all variants)"
	@echo ""
	@echo "Receiver variants: $(RECEIVER_TARGETS)"
	@echo "Sender variants: $(SENDER_TARGETS)"
	@echo "RTT variants: $(RTT_CLIENT_TARGETS) $(RTT_SERVER_TARGETS)"
	@echo ""
	@echo "=== Built Binaries ==="
	@ls -lh bench_* 2>/dev/null || echo "No binaries built yet"
