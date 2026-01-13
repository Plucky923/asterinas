# SPDX-License-Identifier: MPL-2.0
#
# Unified Benchmark Suite Makefile
#
# This Makefile builds all benchmarks with consistent compiler flags
# and provides convenient targets for running benchmarks.
#
# Usage:
#   make              - Build all benchmarks
#   make bench_rtt    - Build RTT benchmark only
#   make clean        - Remove all built files
#   make help         - Show available targets
#
# Copyright (C) 2024 Asterinas Developers.

# Compiler settings
CC ?= gcc
CFLAGS := -O2 -Wall -Wextra -Wpedantic -std=gnu11
CFLAGS += -march=native -mtune=native
CFLAGS += -fno-omit-frame-pointer
LDFLAGS := -lm -lpthread

# Debug build
ifdef DEBUG
CFLAGS += -g -O0 -DDEBUG
endif

# Sanitizers (for development)
ifdef ASAN
CFLAGS += -fsanitize=address -fsanitize=undefined
LDFLAGS += -fsanitize=address -fsanitize=undefined
endif

# Source files
COMMON_HDR := bench_common.h

# Benchmark programs
BENCHMARKS := bench_rtt bench_throughput bench_latency

# Default target
.PHONY: all
all: $(BENCHMARKS)

# Individual benchmark targets
bench_rtt: bench_rtt.c $(COMMON_HDR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

bench_throughput: bench_throughput.c $(COMMON_HDR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

bench_latency: bench_latency.c $(COMMON_HDR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Static builds (for use in minimal environments)
.PHONY: static
static: LDFLAGS += -static
static: $(BENCHMARKS)

# Clean
.PHONY: clean
clean:
	rm -f $(BENCHMARKS)
	rm -f *.o

# Install to a directory
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

.PHONY: install
install: $(BENCHMARKS)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(BENCHMARKS) $(DESTDIR)$(BINDIR)/

# Uninstall
.PHONY: uninstall
uninstall:
	cd $(DESTDIR)$(BINDIR) && rm -f $(BENCHMARKS)

# ============================================================================
# Convenience targets for running benchmarks
# ============================================================================

# RTT benchmark - server mode
.PHONY: run-rtt-server
run-rtt-server: bench_rtt
	./bench_rtt --server --type vsock --port 20000

# RTT benchmark - client mode (requires CID argument)
.PHONY: run-rtt-client
run-rtt-client: bench_rtt
	@if [ -z "$(CID)" ]; then \
		echo "Usage: make run-rtt-client CID=<target_cid>"; \
		echo "Example: make run-rtt-client CID=2"; \
		exit 1; \
	fi
	./bench_rtt --client $(CID) --type vsock --port 20000 --iterations 10000

# Throughput benchmark - receiver mode
.PHONY: run-throughput-receiver
run-throughput-receiver: bench_throughput
	./bench_throughput --receiver --type vsock --port 20001

# Throughput benchmark - sender mode (requires CID argument)
.PHONY: run-throughput-sender
run-throughput-sender: bench_throughput
	@if [ -z "$(CID)" ]; then \
		echo "Usage: make run-throughput-sender CID=<target_cid>"; \
		echo "Example: make run-throughput-sender CID=2"; \
		exit 1; \
	fi
	./bench_throughput --sender $(CID) --type vsock --port 20001 --bytes 1G

# Latency benchmark - all tests
.PHONY: run-latency
run-latency: bench_latency
	./bench_latency --test all --iterations 100000

# Latency benchmark - VMCALL only (must be in VM)
.PHONY: run-latency-vmcall
run-latency-vmcall: bench_latency
	./bench_latency --test vmcall --iterations 100000

# ============================================================================
# TCP/Unix socket variants (for local testing without vsock)
# ============================================================================

.PHONY: run-rtt-tcp-server
run-rtt-tcp-server: bench_rtt
	./bench_rtt --server --type tcp --port 20000

.PHONY: run-rtt-tcp-client
run-rtt-tcp-client: bench_rtt
	./bench_rtt --client 127.0.0.1 --type tcp --port 20000 --iterations 10000

.PHONY: run-throughput-tcp-receiver
run-throughput-tcp-receiver: bench_throughput
	./bench_throughput --receiver --type tcp --port 20001

.PHONY: run-throughput-tcp-sender
run-throughput-tcp-sender: bench_throughput
	./bench_throughput --sender 127.0.0.1 --type tcp --port 20001 --bytes 1G

.PHONY: run-rtt-unix-server
run-rtt-unix-server: bench_rtt
	./bench_rtt --server --type unix --path /tmp/bench_rtt.sock

.PHONY: run-rtt-unix-client
run-rtt-unix-client: bench_rtt
	./bench_rtt --client 0 --type unix --path /tmp/bench_rtt.sock --iterations 10000

# ============================================================================
# FrameVsock variants
# ============================================================================

.PHONY: run-rtt-framevsock-server
run-rtt-framevsock-server: bench_rtt
	./bench_rtt --server --type framevsock --port 20000

.PHONY: run-rtt-framevsock-client
run-rtt-framevsock-client: bench_rtt
	@if [ -z "$(CID)" ]; then \
		echo "Usage: make run-rtt-framevsock-client CID=<target_cid>"; \
		exit 1; \
	fi
	./bench_rtt --client $(CID) --type framevsock --port 20000 --iterations 10000

.PHONY: run-throughput-framevsock-receiver
run-throughput-framevsock-receiver: bench_throughput
	./bench_throughput --receiver --type framevsock --port 20001

.PHONY: run-throughput-framevsock-sender
run-throughput-framevsock-sender: bench_throughput
	@if [ -z "$(CID)" ]; then \
		echo "Usage: make run-throughput-framevsock-sender CID=<target_cid>"; \
		exit 1; \
	fi
	./bench_throughput --sender $(CID) --type framevsock --port 20001 --bytes 1G

# ============================================================================
# JSON/CSV output variants
# ============================================================================

.PHONY: run-latency-json
run-latency-json: bench_latency
	./bench_latency --test all --json

.PHONY: run-latency-csv
run-latency-csv: bench_latency
	./bench_latency --test all --csv

# ============================================================================
# Full benchmark suite
# ============================================================================

.PHONY: run-all-local
run-all-local: $(BENCHMARKS)
	@echo "========================================"
	@echo " Running local benchmarks (no vsock)"
	@echo "========================================"
	@echo ""
	@echo "--- Latency Microbenchmarks ---"
	./bench_latency --test all --iterations 100000
	@echo ""
	@echo "--- RTT over TCP loopback ---"
	@echo "Starting server in background..."
	./bench_rtt --server --type tcp --port 20000 &
	@sleep 1
	./bench_rtt --client 127.0.0.1 --type tcp --port 20000 --iterations 10000
	@pkill -f "bench_rtt --server" || true
	@echo ""
	@echo "--- Throughput over TCP loopback ---"
	@echo "Starting receiver in background..."
	./bench_throughput --receiver --type tcp --port 20001 &
	@sleep 1
	./bench_throughput --sender 127.0.0.1 --type tcp --port 20001 --bytes 100M
	@sleep 1
	@pkill -f "bench_throughput --receiver" || true
	@echo ""
	@echo "========================================"
	@echo " All local benchmarks complete"
	@echo "========================================"

# ============================================================================
# Help
# ============================================================================

.PHONY: help
help:
	@echo "Unified Benchmark Suite"
	@echo ""
	@echo "Build targets:"
	@echo "  all                  - Build all benchmarks"
	@echo "  bench_rtt            - Build RTT benchmark"
	@echo "  bench_throughput     - Build throughput benchmark"
	@echo "  bench_latency        - Build latency microbenchmark"
	@echo "  static               - Build static binaries"
	@echo "  clean                - Remove built files"
	@echo ""
	@echo "Run targets (vsock):"
	@echo "  run-rtt-server                    - Start RTT server (vsock)"
	@echo "  run-rtt-client CID=<n>            - Run RTT client (vsock)"
	@echo "  run-throughput-receiver           - Start throughput receiver (vsock)"
	@echo "  run-throughput-sender CID=<n>     - Run throughput sender (vsock)"
	@echo ""
	@echo "Run targets (framevsock):"
	@echo "  run-rtt-framevsock-server         - Start RTT server (framevsock)"
	@echo "  run-rtt-framevsock-client CID=<n> - Run RTT client (framevsock)"
	@echo "  run-throughput-framevsock-receiver"
	@echo "  run-throughput-framevsock-sender CID=<n>"
	@echo ""
	@echo "Run targets (TCP - for local testing):"
	@echo "  run-rtt-tcp-server                - Start RTT server (TCP)"
	@echo "  run-rtt-tcp-client                - Run RTT client (TCP, localhost)"
	@echo "  run-throughput-tcp-receiver       - Start throughput receiver (TCP)"
	@echo "  run-throughput-tcp-sender         - Run throughput sender (TCP)"
	@echo ""
	@echo "Run targets (Unix socket):"
	@echo "  run-rtt-unix-server               - Start RTT server (Unix)"
	@echo "  run-rtt-unix-client               - Run RTT client (Unix)"
	@echo ""
	@echo "Run targets (latency):"
	@echo "  run-latency                       - Run all latency tests"
	@echo "  run-latency-vmcall                - Run VMCALL test only"
	@echo "  run-latency-json                  - Output in JSON format"
	@echo "  run-latency-csv                   - Output in CSV format"
	@echo ""
	@echo "Other targets:"
	@echo "  run-all-local                     - Run all local benchmarks"
	@echo "  install PREFIX=/path              - Install to PREFIX"
	@echo "  help                              - Show this help"
	@echo ""
	@echo "Build options:"
	@echo "  DEBUG=1    - Build with debug symbols"
	@echo "  ASAN=1     - Build with AddressSanitizer"
	@echo ""
	@echo "Examples:"
	@echo "  make && make run-latency"
	@echo "  make run-rtt-client CID=2"
	@echo "  make run-throughput-sender CID=3"
	@echo "  make run-all-local"
