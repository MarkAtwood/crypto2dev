# SPDX-License-Identifier: GPL-2.0-only
# Makefile — crypto2dev kernel modules
#
# Builds two modules:
#   crypto2dev.ko          — framework (no wolfCrypt dependency)
#   crypto2dev_wolfssl.ko  — wolfSSL provider (requires WOLFCRYPT_DIR)
#
# Usage:
#   # Both modules (wolfSSL provider enabled):
#   make WOLFCRYPT_DIR=/path/to/wolfssl \
#        KBUILD_EXTRA_SYMBOLS=/path/to/wolfssl/linuxkm/Module.symvers
#
#   # Framework only (stub mode — do not load wolfSSL provider):
#   make
#
# The kernel build tree is located via /lib/modules/$(uname -r)/build.
# Override with KDIR if building for a different kernel.

KDIR ?= /lib/modules/$(shell uname -r)/build
WOLFCRYPT_DIR ?=

# Pass WOLFCRYPT_DIR into the Kbuild environment so Kbuild can set per-file
# CFLAGS and include paths for crypto2dev_wolfssl.ko only.
export WOLFCRYPT_DIR

.PHONY: all clean modules_install

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean

modules_install:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules_install
