# SPDX-License-Identifier: MPL-2.0

# Custom Makefile for vsock_perf
# Only compile client programs for the guest initramfs
# Server programs are for host-side use only

MAIN_MAKEFILE := $(firstword $(MAKEFILE_LIST))
INCLUDE_MAKEFILE := $(lastword $(MAKEFILE_LIST))
CUR_DIR := $(shell dirname $(realpath $(MAIN_MAKEFILE)))
CUR_DIR_NAME := $(shell basename $(realpath $(CUR_DIR)))
BUILD_DIR := $(CUR_DIR)/../../../build
OBJ_OUTPUT_DIR := $(BUILD_DIR)/initramfs/test/$(CUR_DIR_NAME)
DEP_OUTPUT_DIR := $(BUILD_DIR)/dep/$(CUR_DIR_NAME)

# Only compile client programs for the guest
CLIENT_SRCS := vsock_throughput_client.c vsock_latency_client.c
CLIENT_OBJS := $(addprefix $(OBJ_OUTPUT_DIR)/,$(CLIENT_SRCS:%.c=%))
CLIENT_DEPS := $(addprefix $(DEP_OUTPUT_DIR)/,$(CLIENT_SRCS:%.c=%.d))

# Server programs for host (not part of initramfs)
SERVER_SRCS := vsock_throughput_server.c vsock_latency_server.c
SERVER_OBJS := $(addprefix $(CUR_DIR)/,$(SERVER_SRCS:%.c=%))

CC ?= gcc
C_FLAGS += -Wall -Werror

.PHONY: all
all: $(CLIENT_OBJS)

$(OBJ_OUTPUT_DIR) $(DEP_OUTPUT_DIR):
	@mkdir -p $@

$(OBJ_OUTPUT_DIR)/%: %.c | $(OBJ_OUTPUT_DIR) $(DEP_OUTPUT_DIR)
	@$(CC) $(C_FLAGS) $< -o $@ $(EXTRA_C_FLAGS) \
		-MMD -MF $(DEP_OUTPUT_DIR)/$*.d
	@echo "CC <= $@"

-include $(CLIENT_DEPS)

# Host server targets (compile locally, not for initramfs)
.PHONY: host-servers
host-servers: $(SERVER_OBJS)

$(CUR_DIR)/vsock_throughput_server: vsock_throughput_server.c
	@$(CC) $(C_FLAGS) $< -o $@
	@echo "CC (host) <= $@"

$(CUR_DIR)/vsock_latency_server: vsock_latency_server.c
	@$(CC) $(C_FLAGS) $< -o $@
	@echo "CC (host) <= $@"

.PHONY: clean-host
clean-host:
	@rm -f $(SERVER_OBJS)
