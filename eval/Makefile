# Sole command entrypoint for Kernelet Syscall & MM evaluation (`poc/eval/`).
SHELL := /bin/bash
EVAL_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
BUILD_DIR ?= $(EVAL_DIR)/.build
export TMPDIR := $(BUILD_DIR)/tmp
export PYTHONDONTWRITEBYTECODE := 1

SELFCHECK_TARGETS ?= L,A,K
TARGETS ?= L,A,K,K_vma
ROUNDS ?= 5
TAG ?= eval
JOBS ?= $(shell nproc)
BUILD_PTI ?= 0
PAYLOAD_MODE ?= auto
LINUX_PROFILE ?= perf-base

QEMU_PID ?=
CASE ?= sys.lm.null
PROFILE_TARGET ?= K
LIVE_STEXT ?=
KO_TEXT_BASE ?=
KO_UNLIKELY_BASE ?=
KO_SECTIONS ?=
KERNELET_BASE ?=
KERNELET_IMAGE ?= $(BUILD_DIR)/kernelet-image.elf

.PHONY: all test check-configs check-freshness build-kernels build-payload build-payload-nix build-payload-native ensure-artifacts selfcheck run run-pti audit profile profile-case clean

all: test

test:
	@mkdir -p $(TMPDIR)
	@cd $(EVAL_DIR) && python3 -m unittest discover -s host/tests -v

check-configs:
	@cd $(EVAL_DIR) && python3 -m host.cli check-config --config $(BUILD_DIR)/linux-perf-base/.config --profile perf-base
	@if [ -f "$(BUILD_DIR)/linux-perf-pti/.config" ]; then \
		cd $(EVAL_DIR) && python3 -m host.cli check-config --config $(BUILD_DIR)/linux-perf-pti/.config --profile perf-pti; \
	fi

check-freshness:
	@cd $(EVAL_DIR) && python3 -m host.cli check-freshness --build-dir $(BUILD_DIR) $(if $(filter 1,$(BUILD_PTI)),--pti,)

build-kernels:
	@mkdir -p $(TMPDIR)
	@BUILD_DIR=$(BUILD_DIR) JOBS=$(JOBS) BUILD_PTI=$(BUILD_PTI) bash $(EVAL_DIR)/scripts/build_kernels.sh

build-payload-native:
	@mkdir -p $(TMPDIR)
	@BUILD_DIR=$(BUILD_DIR) JOBS=$(JOBS) BUILD_PTI=$(BUILD_PTI) bash $(EVAL_DIR)/scripts/build_native_payload.sh

build-payload-nix:
	@mkdir -p $(TMPDIR)
	@BUILD_DIR=$(BUILD_DIR) JOBS=$(JOBS) BUILD_PTI=$(BUILD_PTI) bash $(EVAL_DIR)/scripts/build_nix_payload.sh

build-payload:
	@mkdir -p $(TMPDIR)
	@if [ "$(PAYLOAD_MODE)" = "nix" ]; then \
		BUILD_DIR=$(BUILD_DIR) JOBS=$(JOBS) BUILD_PTI=$(BUILD_PTI) bash $(EVAL_DIR)/scripts/build_nix_payload.sh; \
	elif [ "$(PAYLOAD_MODE)" = "native" ]; then \
		BUILD_DIR=$(BUILD_DIR) JOBS=$(JOBS) BUILD_PTI=$(BUILD_PTI) bash $(EVAL_DIR)/scripts/build_native_payload.sh; \
	elif command -v nix-build >/dev/null 2>&1; then \
		BUILD_DIR=$(BUILD_DIR) JOBS=$(JOBS) BUILD_PTI=$(BUILD_PTI) bash $(EVAL_DIR)/scripts/build_nix_payload.sh; \
	else \
		BUILD_DIR=$(BUILD_DIR) JOBS=$(JOBS) BUILD_PTI=$(BUILD_PTI) bash $(EVAL_DIR)/scripts/build_native_payload.sh; \
	fi

ensure-artifacts: build-kernels build-payload check-freshness

selfcheck: ensure-artifacts
	@mkdir -p $(TMPDIR)
	@cd $(EVAL_DIR) && python3 -m host.cli run \
		--targets $(SELFCHECK_TARGETS) \
		--rounds 1 \
		--group selfcheck \
		--linux-profile $(LINUX_PROFILE) \
		--tag selfcheck

run: ensure-artifacts
	@mkdir -p $(TMPDIR)
	@cd $(EVAL_DIR) && python3 -m host.cli run \
		--targets $(TARGETS) \
		--rounds $(ROUNDS) \
		--linux-profile $(LINUX_PROFILE) \
		--tag $(TAG)

run-pti:
	@$(MAKE) BUILD_PTI=1 LINUX_PROFILE=perf-pti TARGETS=$(TARGETS) ROUNDS=$(ROUNDS) TAG=$(TAG)-pti run

audit: ensure-artifacts
	@mkdir -p $(TMPDIR)
	@cd $(EVAL_DIR) && python3 -m host.cli run \
		--targets K,K_vma \
		--rounds 1 \
		--audit \
		--linux-profile $(LINUX_PROFILE) \
		--tag $(TAG)-audit

profile:
	@mkdir -p $(TMPDIR)
	@test -n "$(QEMU_PID)" || { echo "usage: make profile QEMU_PID=<pid> LIVE_STEXT=0x... KO_TEXT_BASE=0x... KO_UNLIKELY_BASE=0x... KERNELET_BASE=0x..." >&2; exit 2; }
	@cd $(EVAL_DIR) && python3 -m host.cli profile \
		--system-map $(BUILD_DIR)/linux-perf-base/System.map \
		$(if $(LIVE_STEXT),--live-stext $(LIVE_STEXT),) \
		--require-nokaslr \
		--ko $(BUILD_DIR)/endovisor.ko \
		$(if $(KO_TEXT_BASE),--ko-section .text=$(KO_TEXT_BASE),) \
		$(if $(KO_UNLIKELY_BASE),--ko-section .text.unlikely=$(KO_UNLIKELY_BASE),) \
		$(foreach s,$(KO_SECTIONS),--ko-section $(s)) \
		$(if $(KERNELET_IMAGE),--kernelet-image $(KERNELET_IMAGE),) \
		$(if $(KERNELET_BASE),--kernelet-base $(KERNELET_BASE),) \
		--pid $(QEMU_PID)

profile-case: ensure-artifacts
	@mkdir -p $(TMPDIR)
	@cd $(EVAL_DIR) && python3 -m host.cli profile-case \
		--case $(CASE) \
		--target $(PROFILE_TARGET) \
		--linux-profile $(LINUX_PROFILE)

clean:
	@rm -rf $(BUILD_DIR)
