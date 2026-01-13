# SPDX-License-Identifier: MPL-2.0
#
# Makefile for FrameVM Freestanding Test Programs
# These programs run inside FrameVM Guest without any C runtime dependencies.
#
# Usage:
#   make                        # Build with default BUF_SIZE=1024
#   make BUF_SIZE=65536         # Build with 64KB buffer
#   make receiver_64k           # Build receiver with 64KB buffer

CC = gcc
CFLAGS = -static -nostdlib -fno-builtin -O2 -Wall

# Default buffer size (can be overridden via command line)
BUF_SIZE ?= 1024
TOTAL_BYTES ?= 104857600

TARGETS = bench_throughput_sender bench_throughput_receiver

.PHONY: all clean info

all: $(TARGETS)

bench_throughput_sender: bench_throughput_sender.c syscalls.h
	$(CC) $(CFLAGS) -DBUF_SIZE=$(BUF_SIZE) -DTOTAL_BYTES=$(TOTAL_BYTES) -o $@ $<
	@echo "Built: $@ (BUF_SIZE=$(BUF_SIZE), TOTAL_BYTES=$(TOTAL_BYTES))"
	@ls -lh $@

bench_throughput_receiver: bench_throughput_receiver.c syscalls.h
	$(CC) $(CFLAGS) -DBUF_SIZE=$(BUF_SIZE) -o $@ $<
	@echo "Built: $@ (BUF_SIZE=$(BUF_SIZE))"
	@ls -lh $@

# Build receiver with specific buffer sizes for benchmark suite
# Buffer sizes: 64B, 128B, 256B, 512B, 1KB, 2KB, 4KB, 8KB, 16KB, 32KB, 64KB, 128KB, 256KB, 512KB, 1MB
receiver_64: bench_throughput_receiver.c syscalls.h
	$(CC) $(CFLAGS) -DBUF_SIZE=64 -o bench_throughput_receiver_64 $<

receiver_128: bench_throughput_receiver.c syscalls.h
	$(CC) $(CFLAGS) -DBUF_SIZE=128 -o bench_throughput_receiver_128 $<

receiver_256: bench_throughput_receiver.c syscalls.h
	$(CC) $(CFLAGS) -DBUF_SIZE=256 -o bench_throughput_receiver_256 $<

receiver_512: bench_throughput_receiver.c syscalls.h
	$(CC) $(CFLAGS) -DBUF_SIZE=512 -o bench_throughput_receiver_512 $<

receiver_1k: bench_throughput_receiver.c syscalls.h
	$(CC) $(CFLAGS) -DBUF_SIZE=1024 -o bench_throughput_receiver_1k $<

receiver_2k: bench_throughput_receiver.c syscalls.h
	$(CC) $(CFLAGS) -DBUF_SIZE=2048 -o bench_throughput_receiver_2k $<

receiver_4k: bench_throughput_receiver.c syscalls.h
	$(CC) $(CFLAGS) -DBUF_SIZE=4096 -o bench_throughput_receiver_4k $<

receiver_8k: bench_throughput_receiver.c syscalls.h
	$(CC) $(CFLAGS) -DBUF_SIZE=8192 -o bench_throughput_receiver_8k $<

receiver_16k: bench_throughput_receiver.c syscalls.h
	$(CC) $(CFLAGS) -DBUF_SIZE=16384 -o bench_throughput_receiver_16k $<

receiver_32k: bench_throughput_receiver.c syscalls.h
	$(CC) $(CFLAGS) -DBUF_SIZE=32768 -o bench_throughput_receiver_32k $<

receiver_64k: bench_throughput_receiver.c syscalls.h
	$(CC) $(CFLAGS) -DBUF_SIZE=65536 -o bench_throughput_receiver_64k $<

receiver_128k: bench_throughput_receiver.c syscalls.h
	$(CC) $(CFLAGS) -DBUF_SIZE=131072 -o bench_throughput_receiver_128k $<

receiver_256k: bench_throughput_receiver.c syscalls.h
	$(CC) $(CFLAGS) -DBUF_SIZE=262144 -o bench_throughput_receiver_256k $<

receiver_512k: bench_throughput_receiver.c syscalls.h
	$(CC) $(CFLAGS) -DBUF_SIZE=524288 -o bench_throughput_receiver_512k $<

receiver_1m: bench_throughput_receiver.c syscalls.h
	$(CC) $(CFLAGS) -DBUF_SIZE=1048576 -o bench_throughput_receiver_1m $<

# Build all receiver variants for benchmark suite
receivers_all: receiver_64 receiver_128 receiver_256 receiver_512 \
               receiver_1k receiver_2k receiver_4k receiver_8k \
               receiver_16k receiver_32k receiver_64k receiver_128k \
               receiver_256k receiver_512k receiver_1m
	@echo "Built all receiver variants"

clean:
	rm -f $(TARGETS) bench_throughput_receiver_*

# Show binary info
info: $(TARGETS)
	@echo "=== Binary Info ==="
	@for f in $(TARGETS); do \
		echo "--- $$f ---"; \
		file $$f; \
		size $$f; \
	done
