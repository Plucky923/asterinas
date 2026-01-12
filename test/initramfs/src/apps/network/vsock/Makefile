# SPDX-License-Identifier: MPL-2.0

# Vsock smoke tests and benchmarks.
include ../../common/Makefile

$(OBJ_OUTPUT_DIR)/vsock_multi_sender: vsock_multi_sender.c | $(OBJ_OUTPUT_DIR) $(DEP_OUTPUT_DIR)
	@$(CC) $(C_FLAGS) $< -o $@ $(EXTRA_C_FLAGS) -lpthread \
		-MMD -MF $(DEP_OUTPUT_DIR)/vsock_multi_sender.d
	@echo "CC <= $@"
