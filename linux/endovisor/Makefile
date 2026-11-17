# SPDX-License-Identifier: GPL-2.0
# Kbuild file for `endovisor.ko`.

obj-m += endovisor.o

endovisor-y := main.o image.o grant.o space.o carrier.o watch.o switch.o

ccflags-y += -O2

LINUX_DIR ?= $(abspath $(CURDIR)/../../../prototype/.build/linux-6.12)
JOBS ?= 8

.PHONY: all clean

all:
	$(MAKE) -C $(LINUX_DIR) ARCH=x86_64 -j$(JOBS) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(LINUX_DIR) ARCH=x86_64 M=$(CURDIR) clean
