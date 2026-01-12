# SPDX-License-Identifier: MPL-2.0
#
# FrameVM Guest Benchmarks and Tests
#
# Memory benchmarks: page-stride and word-level patterns for EPT/TLB analysis.
#
# Experiment targets:
#   page_seq_cold - Page Fault overhead (write-first-touch, no warmup)
#   page_seq_warm  - Baseline comparison (with warmup, no PF)
#   page_rand_warm - TLB miss + EPT walk overhead (random page access)
#   word_seq_warm  - EPT baseline overhead (high TLB hit, sequential words)
# Vsock tests: throughput and RTT latency benchmarks (pairs with host tests).
#
# Usage:
#   make                    # Build all (memory + vsock)
#   make memory_all         # Build memory benchmarks only
#   make vsock_all          # Build all vsock tests
#   make throughput_all     # Build throughput variants only
#   make rtt_all            # Build RTT tests only
#   make info               # Show all targets
#   make clean

# Toolchain
CC = gcc
CFLAGS = -static -nostdlib -fno-builtin -O2 -Wall

# ============================================================================
# Memory Benchmark Configuration
# ============================================================================

MEM_COMPARE_WORKSET_BYTES ?= 536870912
MEM_PAGE_SEQ_COLD_REPEAT ?= 1
MEM_PAGE_SEQ_WARM_REPEAT ?= 200
MEM_PAGE_RAND_WARM_REPEAT ?= 200
MEM_WORD_SEQ_WARM_REPEAT ?= 200
MEM_PAGE_SEQ_COLD_DO_STORE ?= 1
MEM_PAGE_SEQ_WARM_DO_STORE ?= 1
MEM_COMPARE_DO_STORE ?= 0
MEM_COMPARE_SEED ?= 12345
MEM_COMPARE_RUNS ?= 1
MEM_PAGE_SEQ_COLD_RUNS ?= 500
MEM_PAGE_SEQ_COLD_AGG_MIN ?= 1
MEM_PAGE_SEQ_COLD_MULTI_RUNS ?= 1

MEM_PAGE_RAND_REPEAT ?= 200
MEM_PAGE_RAND_DO_STORE ?= 0
MEM_PAGE_RAND_SEED ?= 12345
MEM_PAGE_RAND_RUNS := 10000
MEM_PAGE_RAND_AGG_MIN := 1
FRAMEVM_PAGE_RAND_STORE_WORKSET_BYTES ?= 2097152

PAGE_RAND_WARM_SIZES = 64k 128k 256k 512k 1m 2m 4m 8m 16m 32m 64m
PAGE_RAND_WARM_BYTES_64k = 65536
PAGE_RAND_WARM_BYTES_128k = 131072
PAGE_RAND_WARM_BYTES_256k = 262144
PAGE_RAND_WARM_BYTES_512k = 524288
PAGE_RAND_WARM_BYTES_1m = 1048576
PAGE_RAND_WARM_BYTES_2m = 2097152
PAGE_RAND_WARM_BYTES_4m = 4194304
PAGE_RAND_WARM_BYTES_8m = 8388608
PAGE_RAND_WARM_BYTES_16m = 16777216
PAGE_RAND_WARM_BYTES_32m = 33554432
PAGE_RAND_WARM_BYTES_64m = 67108864

# ============================================================================
# Vsock Test Configuration
# ============================================================================

# Default ports (match host tests)
THROUGHPUT_PORT ?= 20001
RTT_PORT ?= 20002

# Default total bytes for throughput (1GB)
TOTAL_BYTES ?= 1073741824

# Warmup bytes (64MB, not measured)
WARMUP_BYTES ?= 67108864

# CPU frequency (MHz) for guest-side throughput estimation
CPU_MHZ ?= 2600

# RTT iterations
RTT_ITERATIONS ?= 100000

# Buffer size variants for throughput tests
BUF_SIZES = 64 128 256 512 1k 2k 4k 8k 16k 32k 64k 128k 256k 512k 1m
BUF_BYTES_64 = 64
BUF_BYTES_128 = 128
BUF_BYTES_256 = 256
BUF_BYTES_512 = 512
BUF_BYTES_1k = 1024
BUF_BYTES_2k = 2048
BUF_BYTES_4k = 4096
BUF_BYTES_8k = 8192
BUF_BYTES_16k = 16384
BUF_BYTES_32k = 32768
BUF_BYTES_64k = 65536
BUF_BYTES_128k = 131072
BUF_BYTES_256k = 262144
BUF_BYTES_512k = 524288
BUF_BYTES_1m = 1048576

# Multi-process receiver defaults
FORK_PROCESSES ?= 4
FORK_BUF_SIZE ?= $(BUF_BYTES_64k)
FORK_BYTES_PER_CONN ?= $(TOTAL_BYTES)
FORK_WARMUP_BYTES ?= 0

# ============================================================================
# Target Lists
# ============================================================================

# Memory benchmark targets (renamed for clarity)
# Pattern mapping:
#   page_seq_cold: pattern=2, warmup=0, do_store=1 → cold PF path (write-first-touch)
#   page_seq_warm:  pattern=2, warmup=1, do_store=1 → warm baseline for PF delta
#   page_rand_warm: pattern=3, warmup=1 → TLB miss measurement
#   word_seq_warm:  pattern=0, warmup=1 → EPT baseline (high TLB hit)
# Note: page_rand_cold removed - build_page_chain() triggers all PFs before measurement
COMPARE_TARGETS = bench_memory_page_seq_cold \
	bench_memory_page_seq_warm \
	bench_memory_page_rand_warm bench_memory_word_seq_warm
PAGE_RAND_WARM_TARGETS = $(foreach size,$(PAGE_RAND_WARM_SIZES),bench_memory_page_rand_warm_$(size))
PAGE_RAND_STORE_TARGET = bench_memory_page_rand_warm_2m_store

# Vsock throughput targets (with buffer size variants)
SENDER_TARGETS = $(foreach size,$(BUF_SIZES),guest_sender_$(size))
RECEIVER_TARGETS = $(foreach size,$(BUF_SIZES),guest_receiver_$(size))
THROUGHPUT_TARGETS = $(SENDER_TARGETS) $(RECEIVER_TARGETS)

# Vsock RTT targets
RTT_TARGETS = guest_rtt_client guest_rtt_server

# All vsock targets
FORK_BUF_TARGETS = $(foreach size,$(BUF_SIZES),guest_fork_receiver_$(size))
MULTIPROC_TARGETS = guest_fork_receiver $(FORK_BUF_TARGETS)
VSOCK_TARGETS = $(THROUGHPUT_TARGETS) $(RTT_TARGETS) $(MULTIPROC_TARGETS)

# Misc tests
FORK_TARGETS = guest_fork_test

# ============================================================================
# Phony Targets
# ============================================================================

.PHONY: all memory_all vsock_all throughput_all rtt_all fork_all \
	compare_all page_rand_warm_sweep page_rand_warm_store \
	$(COMPARE_TARGETS) $(PAGE_RAND_WARM_TARGETS) \
	$(VSOCK_TARGETS) $(FORK_TARGETS) clean info

all: memory_all vsock_all fork_all

memory_all: $(COMPARE_TARGETS) $(PAGE_RAND_WARM_TARGETS)
	@echo "Built memory benchmarks"

vsock_all: $(VSOCK_TARGETS)
	@echo "Built vsock tests"

throughput_all: $(THROUGHPUT_TARGETS)
	@echo "Built throughput benchmarks"

rtt_all: $(RTT_TARGETS)
	@echo "Built RTT benchmarks"

fork_all: $(FORK_TARGETS)
	@echo "Built fork/clone tests"

compare_all: $(COMPARE_TARGETS) $(PAGE_RAND_WARM_TARGETS) $(PAGE_RAND_STORE_TARGET)
	@echo "Built page/word compare benchmarks + page-rand sweep"

page_rand_warm_sweep: $(PAGE_RAND_WARM_TARGETS)
	@echo "Built page-rand warm sweep targets"

page_rand_warm_store: $(PAGE_RAND_STORE_TARGET)
	@echo "Built page-rand warm store target"

# ============================================================================
# Memory Benchmark Rules
# ============================================================================

define COMPARE_RULE
bench_memory_$(1): bench_memory.c syscalls.h
	$$(CC) $$(CFLAGS) \
		-DWORKSET_BYTES=$$(MEM_COMPARE_WORKSET_BYTES) \
		-DREPEAT=$(4) \
		-DACCESS_PATTERN=$(2) \
		-DWARMUP=$(3) \
		-DMEM_DO_STORE=$$(MEM_COMPARE_DO_STORE) \
		-DMEM_SEED=$$(MEM_COMPARE_SEED) \
		-DMEASURE_RUNS=$$(MEM_COMPARE_RUNS) \
		-o $$@ $$<
	@echo "Built: $$@"
endef

$(eval $(call COMPARE_RULE,word_seq_warm,0,1,$(MEM_WORD_SEQ_WARM_REPEAT)))

bench_memory_page_seq_warm: bench_memory.c syscalls.h
	$(CC) $(CFLAGS) \
		-DWORKSET_BYTES=$(MEM_COMPARE_WORKSET_BYTES) \
		-DREPEAT=$(MEM_PAGE_SEQ_WARM_REPEAT) \
		-DACCESS_PATTERN=2 \
		-DWARMUP=1 \
		-DMEM_DO_STORE=$(MEM_PAGE_SEQ_WARM_DO_STORE) \
		-DMEM_SEED=$(MEM_COMPARE_SEED) \
		-DMEASURE_RUNS=$(MEM_COMPARE_RUNS) \
		-o $@ $<
	@echo "Built: $@"

bench_memory_page_rand_warm: bench_memory.c syscalls.h
	$(CC) $(CFLAGS) \
		-DWORKSET_BYTES=$(MEM_COMPARE_WORKSET_BYTES) \
		-DREPEAT=$(MEM_PAGE_RAND_WARM_REPEAT) \
		-DACCESS_PATTERN=3 \
		-DWARMUP=1 \
		-DMEM_DO_STORE=$(MEM_COMPARE_DO_STORE) \
		-DMEM_SEED=$(MEM_COMPARE_SEED) \
		-DMEASURE_RUNS=$(MEM_PAGE_RAND_RUNS) \
		-DMEASURE_AGGREGATE_MIN=$(MEM_PAGE_RAND_AGG_MIN) \
		-o $@ $<
	@echo "Built: $@"

bench_memory_page_seq_cold: bench_memory.c syscalls.h
	$(CC) $(CFLAGS) \
		-DWORKSET_BYTES=$(MEM_COMPARE_WORKSET_BYTES) \
		-DREPEAT=$(MEM_PAGE_SEQ_COLD_REPEAT) \
		-DACCESS_PATTERN=2 \
		-DWARMUP=0 \
		-DMEM_DO_STORE=$(MEM_PAGE_SEQ_COLD_DO_STORE) \
		-DMEM_SEED=$(MEM_COMPARE_SEED) \
		-DMEASURE_RUNS=$(MEM_PAGE_SEQ_COLD_RUNS) \
		-DMEASURE_AGGREGATE_MIN=$(MEM_PAGE_SEQ_COLD_AGG_MIN) \
		-DCOLD_MULTI_RUNS=$(MEM_PAGE_SEQ_COLD_MULTI_RUNS) \
		-o $@ $<
	@echo "Built: $@"

define PAGE_RAND_WARM_RULE
bench_memory_page_rand_warm_$(1): bench_memory.c syscalls.h
	$$(CC) $$(CFLAGS) \
		-DWORKSET_BYTES=$$(PAGE_RAND_WARM_BYTES_$(1)) \
		-DREPEAT=$$(MEM_PAGE_RAND_REPEAT) \
		-DACCESS_PATTERN=3 \
		-DWARMUP=1 \
		-DMEM_DO_STORE=$$(MEM_PAGE_RAND_DO_STORE) \
		-DMEM_SEED=$$(MEM_PAGE_RAND_SEED) \
		-DMEASURE_RUNS=$$(MEM_PAGE_RAND_RUNS) \
		-DMEASURE_AGGREGATE_MIN=$$(MEM_PAGE_RAND_AGG_MIN) \
		-o $$@ $$<
	@echo "Built: $$@"
endef

$(foreach size,$(PAGE_RAND_WARM_SIZES),$(eval $(call PAGE_RAND_WARM_RULE,$(size))))

bench_memory_page_rand_warm_2m_store: bench_memory.c syscalls.h
	$(CC) $(CFLAGS) \
		-DWORKSET_BYTES=$(FRAMEVM_PAGE_RAND_STORE_WORKSET_BYTES) \
		-DREPEAT=$(MEM_PAGE_RAND_REPEAT) \
		-DACCESS_PATTERN=3 \
		-DWARMUP=1 \
		-DMEM_DO_STORE=1 \
		-DMEM_SEED=$(MEM_PAGE_RAND_SEED) \
		-DMEASURE_RUNS=$(MEM_PAGE_RAND_RUNS) \
		-DMEASURE_AGGREGATE_MIN=$(MEM_PAGE_RAND_AGG_MIN) \
		-o $@ $<
	@echo "Built: $@"

# ============================================================================
# Vsock Throughput Rules (with buffer size variants)
# ============================================================================

define SENDER_RULE
guest_sender_$(1): guest_sender.c syscalls.h
	$$(CC) $$(CFLAGS) \
		-DPORT=$$(THROUGHPUT_PORT) \
		-DBUF_SIZE=$$(BUF_BYTES_$(1)) \
		-DTOTAL_BYTES=$$(TOTAL_BYTES) \
		-DWARMUP_BYTES=$$(WARMUP_BYTES) \
		-DCPU_MHZ=$$(CPU_MHZ) \
		-o $$@ $$<
	@echo "Built: $$@"
endef

$(foreach size,$(BUF_SIZES),$(eval $(call SENDER_RULE,$(size))))

define RECEIVER_RULE
guest_receiver_$(1): guest_receiver.c syscalls.h
	$$(CC) $$(CFLAGS) \
		-DPORT=$$(THROUGHPUT_PORT) \
		-DBUF_SIZE=$$(BUF_BYTES_$(1)) \
		-DWARMUP_BYTES=$$(WARMUP_BYTES) \
		-DCPU_MHZ=$$(CPU_MHZ) \
		-o $$@ $$<
	@echo "Built: $$@"
endef

$(foreach size,$(BUF_SIZES),$(eval $(call RECEIVER_RULE,$(size))))

# ============================================================================
# Vsock RTT Rules
# ============================================================================

guest_rtt_client: guest_rtt_client.c syscalls.h
	$(CC) $(CFLAGS) \
		-DPORT=$(RTT_PORT) \
		-DITERATIONS=$(RTT_ITERATIONS) \
		-o $@ $<
	@echo "Built: $@"

guest_rtt_server: guest_rtt_server.c syscalls.h
	$(CC) $(CFLAGS) \
		-DPORT=$(RTT_PORT) \
		-o $@ $<
	@echo "Built: $@"

# ============================================================================
# Fork/Clone Tests
# ============================================================================

guest_fork_test: guest_fork_test.c syscalls.h
	$(CC) $(CFLAGS) -o $@ $<
	@echo "Built: $@"

# Multi-process FrameVsock receiver
guest_fork_receiver: guest_fork_receiver.c syscalls.h
	$(CC) $(CFLAGS) \
		-DPORT=$(THROUGHPUT_PORT) \
		-DBUF_SIZE=$(FORK_BUF_SIZE) \
		-DMAX_BUF_SIZE=$(BUF_BYTES_1m) \
		-DPROCESSES=$(FORK_PROCESSES) \
		-DBYTES_PER_CONN=$(FORK_BYTES_PER_CONN) \
		-DWARMUP_BYTES=$(FORK_WARMUP_BYTES) \
		-DCPU_MHZ=$(CPU_MHZ) \
		-o $@ $<
	@echo "Built: $@"

# Multi-process FrameVsock receiver (buffer size variants)
define FORK_RECEIVER_RULE
guest_fork_receiver_$(1): guest_fork_receiver.c syscalls.h
	$$(CC) $$(CFLAGS) \
		-DPORT=$$(THROUGHPUT_PORT) \
		-DBUF_SIZE=$$(BUF_BYTES_$(1)) \
		-DMAX_BUF_SIZE=$$(BUF_BYTES_1m) \
		-DPROCESSES=$$(FORK_PROCESSES) \
		-DBYTES_PER_CONN=$$(FORK_BYTES_PER_CONN) \
		-DWARMUP_BYTES=$$(FORK_WARMUP_BYTES) \
		-DCPU_MHZ=$$(CPU_MHZ) \
		-o $$@ $$<
	@echo "Built: $$@"
endef

$(foreach size,$(BUF_SIZES),$(eval $(call FORK_RECEIVER_RULE,$(size))))

# ============================================================================
# Clean and Info
# ============================================================================

clean:
	rm -f $(COMPARE_TARGETS) $(PAGE_RAND_WARM_TARGETS) $(PAGE_RAND_STORE_TARGET) $(VSOCK_TARGETS) $(FORK_TARGETS)
	@echo "Cleaned all binaries"

info:
	@echo "========================================"
	@echo " FrameVM Guest Test Programs"
	@echo "========================================"
	@echo ""
	@echo "=== Memory Benchmarks ==="
	@echo "  bench_memory_page_seq_cold       - Page Fault overhead, cold write-first-touch"
	@echo "  bench_memory_page_seq_warm  - Warm baseline for PF delta (pattern=2, warmup, store)"
	@echo "  bench_memory_page_rand_warm - TLB miss + EPT walk (pattern=3, warmup)"
	@echo "  bench_memory_page_rand_warm_2m_store - TLB miss + EPT walk (2M, load+store)"
	@echo "  bench_memory_word_seq_warm  - EPT baseline, high TLB hit (pattern=0, warmup)"
	@echo "  page_rand_warm_sweep        - TLB miss across sizes: $(PAGE_RAND_WARM_SIZES)"
	@echo ""
	@echo "  Note: page_rand_cold removed - build phase triggers all Page Faults"
	@echo ""
	@echo "=== Vsock Throughput Benchmarks ==="
	@echo "  guest_sender_<size>     - Send to Host (pairs with host_receiver)"
	@echo "  guest_receiver_<size>   - Receive from Host (pairs with host_sender)"
	@echo "  Buffer sizes: $(BUF_SIZES)"
	@echo "  Port: $(THROUGHPUT_PORT), Total bytes: $(TOTAL_BYTES)"
	@echo ""
	@echo "=== Vsock RTT Benchmarks ==="
	@echo "  guest_rtt_client        - Ping Host (pairs with host_rtt_server)"
	@echo "  guest_rtt_server        - Pong to Host (pairs with host_rtt_client)"
	@echo "  Port: $(RTT_PORT), Iterations: $(RTT_ITERATIONS)"
	@echo ""
	@echo "=== Vsock Multi-Process Benchmark ==="
	@echo "  guest_fork_receiver     - Fork-per-connection receiver (pairs with host_multi_sender)"
	@echo "  Processes: $(FORK_PROCESSES), Buffer: $(FORK_BUF_SIZE), Bytes/Conn: $(FORK_BYTES_PER_CONN)"
	@echo ""
	@echo "=== Fork/Clone Tests ==="
	@echo "  guest_fork_test         - clone/fork smoke test (thread semantics)"
	@echo ""
	@echo "=== Build Targets ==="
	@echo "  make all            - Build everything"
	@echo "  make memory_all     - Build memory benchmarks"
	@echo "  make vsock_all      - Build all vsock tests"
	@echo "  make throughput_all - Build throughput variants"
	@echo "  make rtt_all        - Build RTT tests"
	@echo "  make fork_all       - Build fork/clone tests"
	@echo ""
	@echo "=== Custom Build ==="
	@echo "  make TOTAL_BYTES=1073741824      # 1GB throughput test"
	@echo "  make RTT_ITERATIONS=1000000      # 1M RTT iterations"
	@echo ""
	@echo "=== Built Binaries ==="
	@ls -1 $(COMPARE_TARGETS) $(PAGE_RAND_WARM_TARGETS) $(VSOCK_TARGETS) $(FORK_TARGETS) 2>/dev/null || echo "  (none built yet)"
