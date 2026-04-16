# SPDX-License-Identifier: GPL-2.0-only
#
# tests/kernel/Makefile — build all kernel test modules
#
# Usage (from this directory, with wolfCrypt available):
#   make -C /lib/modules/$(uname -r)/build M=$(pwd) \
#        WOLFCRYPT_DIR=/path/to/wolfssl KBUILD_EXTRA_SYMBOLS=...
#
# Without wolfCrypt: omit WOLFCRYPT_DIR; wolfssl provider tests will not build.
#
# The test modules require the main crypto2dev.ko to be loaded.  They do not
# register into the kernel crypto API; they call crypto2dev internals directly
# via Module.symvers.
#
# KBUILD_EXTRA_SYMBOLS must point to BOTH:
#   $(WOLFCRYPT_DIR)/Module.symvers   (wolfCrypt exported symbols)
#   $(TOP)/Module.symvers             (crypto2dev exported symbols)
#
# Set TOP to the repo root if running out-of-tree:
#   make M=$(pwd) TOP=/path/to/wolfkm ...

WOLFCRYPT_DIR ?=
TOP           ?= $(shell cd ../.. && pwd)

# Compiler and cross-compilation flags (inherited from kbuild environment)
ccflags-y := -I$(TOP)/include
ifneq ($(WOLFCRYPT_DIR),)
ccflags-y += -I$(WOLFCRYPT_DIR)
endif

# Extra symbol tables so test modules can link against crypto2dev and wolfCrypt.
KBUILD_EXTRA_SYMBOLS ?=
ifneq ($(WOLFCRYPT_DIR),)
KBUILD_EXTRA_SYMBOLS += $(WOLFCRYPT_DIR)/Module.symvers
endif
KBUILD_EXTRA_SYMBOLS += $(TOP)/Module.symvers

obj-m := \
	test_fips_gate.o \
	test_shash.o \
	test_aead.o \
	test_rng.o \
	test_skcipher.o \
	test_akcipher.o \
	test_kpp.o

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) \
		TOP=$(TOP) WOLFCRYPT_DIR=$(WOLFCRYPT_DIR) \
		modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) clean
