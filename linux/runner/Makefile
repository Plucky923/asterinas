CC ?= gcc
CFLAGS := -O2 -Wall -Wextra -static -pthread -I../endovisor/uapi
OUT_DIR ?= $(CURDIR)
export TMPDIR := $(OUT_DIR)/.tmp

.PHONY: all clean

all: $(OUT_DIR)/run-kernelet

$(OUT_DIR)/run-kernelet: run-kernelet.c ../endovisor/uapi/endovisor.h
	mkdir -p $(OUT_DIR)/.tmp
	$(CC) $(CFLAGS) -o $@ run-kernelet.c

clean:
	rm -rf $(OUT_DIR)/run-kernelet $(OUT_DIR)/.tmp
