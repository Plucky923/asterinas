# SPDX-License-Identifier: MPL-2.0

include ../test_common.mk

EXTRA_C_FLAGS := -static -O2

# KVM-based benchmarks need to be built separately (uses KVM, can't be static)
.PHONY: mini_hypervisor
mini_hypervisor:
	gcc -O2 -o $(BUILD_DIR)/mini_hypervisor mini_hypervisor.c

.PHONY: bench_vmexit_precise
bench_vmexit_precise:
	gcc -O2 -o $(BUILD_DIR)/bench_vmexit_precise bench_vmexit_precise.c
