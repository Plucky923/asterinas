# SPDX-License-Identifier: MPL-2.0

SUBDIRS := \
	mmap \

C_OBJS_FILTER := bench_memory
EXTRA_C_FLAGS := -O2

# Shared config for comparisons (override on make command line)
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

# Page-rand warm sweep (page-stride, load-only by default).
MEM_PAGE_RAND_REPEAT ?= 200
MEM_PAGE_RAND_DO_STORE ?= 0
MEM_PAGE_RAND_SEED ?= 12345
MEM_PAGE_RAND_RUNS ?= 1

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

COMPARE_TARGETS = $(OBJ_OUTPUT_DIR)/bench_memory_page_seq_cold \
	$(OBJ_OUTPUT_DIR)/bench_memory_page_seq_warm \
	$(OBJ_OUTPUT_DIR)/bench_memory_page_rand_warm \
	$(OBJ_OUTPUT_DIR)/bench_memory_word_seq_warm
COMPARE_NAMES = bench_memory_page_seq_cold bench_memory_page_seq_warm \
	bench_memory_page_rand_warm bench_memory_word_seq_warm
PAGE_RAND_WARM_NAMES = $(foreach size,$(PAGE_RAND_WARM_SIZES),bench_memory_page_rand_warm_$(size))
PAGE_RAND_WARM_TARGETS = $(addprefix $(OBJ_OUTPUT_DIR)/,$(PAGE_RAND_WARM_NAMES))

include ../common/Makefile

.PHONY: compare_all page_rand_warm_sweep clean info

all: compare_all page_rand_warm_sweep

compare_all: $(COMPARE_TARGETS)
	@echo "Built page/word compare benchmarks"

page_rand_warm_sweep: $(PAGE_RAND_WARM_TARGETS)
	@echo "Built page-rand warm sweep targets"

$(COMPARE_NAMES): %: $(OBJ_OUTPUT_DIR)/%
$(PAGE_RAND_WARM_NAMES): %: $(OBJ_OUTPUT_DIR)/%

# page/word compare targets focus on page-level effects or TLB-hit baselines.
# Use static BSS array to match FrameVM guest allocation behavior.
define COMPARE_RULE
$(OBJ_OUTPUT_DIR)/bench_memory_$(1): bench_memory.c | $(OBJ_OUTPUT_DIR) $(DEP_OUTPUT_DIR)
	$$(CC) $$(C_FLAGS) $$(EXTRA_C_FLAGS) \
		-DWORKSET_BYTES=$$(MEM_COMPARE_WORKSET_BYTES) \
		-DREPEAT=$(4) \
		-DACCESS_PATTERN=$(2) \
		-DWARMUP=$(3) \
		-DMEM_DO_STORE=$$(MEM_COMPARE_DO_STORE) \
		-DMEM_SEED=$$(MEM_COMPARE_SEED) \
		-DMEASURE_RUNS=$$(MEM_COMPARE_RUNS) \
		-DMEM_FIXED_CONFIG=1 \
		-DMEM_USE_STATIC_ARRAY=1 \
		-o $$@ $$<
	@echo "CC <= $$@"
endef

$(eval $(call COMPARE_RULE,page_rand_warm,3,1,$(MEM_PAGE_RAND_WARM_REPEAT)))
$(eval $(call COMPARE_RULE,word_seq_warm,0,1,$(MEM_WORD_SEQ_WARM_REPEAT)))

# Warm page-seq baseline for PF delta (store enabled by default).
$(OBJ_OUTPUT_DIR)/bench_memory_page_seq_warm: bench_memory.c | $(OBJ_OUTPUT_DIR) $(DEP_OUTPUT_DIR)
	$(CC) $(C_FLAGS) $(EXTRA_C_FLAGS) \
		-DWORKSET_BYTES=$(MEM_COMPARE_WORKSET_BYTES) \
		-DREPEAT=$(MEM_PAGE_SEQ_WARM_REPEAT) \
		-DACCESS_PATTERN=2 \
		-DWARMUP=1 \
		-DMEM_DO_STORE=$(MEM_PAGE_SEQ_WARM_DO_STORE) \
		-DMEM_SEED=$(MEM_COMPARE_SEED) \
		-DMEASURE_RUNS=$(MEM_COMPARE_RUNS) \
		-DMEM_FIXED_CONFIG=1 \
		-DMEM_USE_STATIC_ARRAY=1 \
		-o $@ $<
	@echo "CC <= $@"

# Canonical cold page-seq target (write-first-touch, no warmup).
$(OBJ_OUTPUT_DIR)/bench_memory_page_seq_cold: bench_memory.c | $(OBJ_OUTPUT_DIR) $(DEP_OUTPUT_DIR)
	$(CC) $(C_FLAGS) $(EXTRA_C_FLAGS) \
		-DWORKSET_BYTES=$(MEM_COMPARE_WORKSET_BYTES) \
		-DREPEAT=$(MEM_PAGE_SEQ_COLD_REPEAT) \
		-DACCESS_PATTERN=2 \
		-DWARMUP=0 \
		-DMEM_DO_STORE=$(MEM_PAGE_SEQ_COLD_DO_STORE) \
		-DMEM_SEED=$(MEM_COMPARE_SEED) \
		-DMEASURE_RUNS=$(MEM_COMPARE_RUNS) \
		-DMEM_FIXED_CONFIG=1 \
		-DMEM_USE_STATIC_ARRAY=1 \
		-o $@ $<
	@echo "CC <= $@"

# page-rand warm sweep (random vs sequential is similar under page-stride).
define PAGE_RAND_WARM_RULE
$(OBJ_OUTPUT_DIR)/bench_memory_page_rand_warm_$(1): bench_memory.c | $(OBJ_OUTPUT_DIR) $(DEP_OUTPUT_DIR)
	$$(CC) $$(C_FLAGS) $$(EXTRA_C_FLAGS) \
		-DWORKSET_BYTES=$$(PAGE_RAND_WARM_BYTES_$(1)) \
		-DREPEAT=$$(MEM_PAGE_RAND_REPEAT) \
		-DACCESS_PATTERN=3 \
		-DWARMUP=1 \
		-DMEM_DO_STORE=$$(MEM_PAGE_RAND_DO_STORE) \
		-DMEM_SEED=$$(MEM_PAGE_RAND_SEED) \
		-DMEASURE_RUNS=$$(MEM_PAGE_RAND_RUNS) \
		-DMEM_FIXED_CONFIG=1 \
		-DMEM_USE_STATIC_ARRAY=1 \
		-o $$@ $$<
	@echo "CC <= $$@"
endef

$(foreach size,$(PAGE_RAND_WARM_SIZES),$(eval $(call PAGE_RAND_WARM_RULE,$(size))))

clean:
	@rm -f $(COMPARE_TARGETS) $(PAGE_RAND_WARM_TARGETS)
	@echo "Cleaned memory benchmark binaries"

info:
	@echo "=== Memory Targets (page/word compare) ==="
	@echo "page_seq_cold: bench_memory_page_seq_cold (write-first-touch)"
	@echo "page_seq_warm: bench_memory_page_seq_warm (warm write baseline)"
	@echo "page_rand_warm: bench_memory_page_rand_warm"
	@echo "word_seq_warm: bench_memory_word_seq_warm"
	@echo "page_rand_warm_sizes: $(PAGE_RAND_WARM_SIZES)"
	@echo "Built binaries:"
	@ls -lh $(COMPARE_TARGETS) $(PAGE_RAND_WARM_TARGETS) 2>/dev/null || echo "No binaries built yet"
