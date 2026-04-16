# SPDX-License-Identifier: GPL-2.0-only
# Kbuild — object lists for crypto2dev.ko and crypto2dev_wolfssl.ko
#
# crypto2dev.ko: pure framework — no wolfCrypt symbols.
# crypto2dev_wolfssl.ko: wolfSSL provider — depends on wolfcrypt.ko.
#
# WOLFCRYPT_DIR is required only for crypto2dev_wolfssl.ko.

obj-m += crypto2dev.o

crypto2dev-objs := \
	src/crypto2dev_main.o \
	src/provider/crypto2dev_registry.o \
	src/cdev/crypto2dev_cdev.o \
	src/cdev/crypto2dev_fd.o

# Include path for the framework module
ccflags-y += -I$(src)/include

# crypto2dev_kcapi.ko — kernel crypto API provider (no external deps, always built)
obj-m += crypto2dev_kcapi.o

crypto2dev_kcapi-objs := \
	src/providers/kcapi/kcapi_provider.o \
	src/providers/kcapi/kcapi_skcipher.o \
	src/providers/kcapi/kcapi_hash.o \
	src/providers/kcapi/kcapi_aead.o \
	src/providers/kcapi/kcapi_kdf.o

# crypto2dev_wolfssl.ko is only built when WOLFCRYPT_DIR is provided.
# Stub mode = do not build or load the wolfssl provider module at all.
ifneq ($(WOLFCRYPT_DIR),)

obj-m += crypto2dev_wolfssl.o

crypto2dev_wolfssl-objs := \
	src/providers/wolfssl/wolfssl_provider.o \
	src/providers/wolfssl/wolfssl_aes_cbc.o \
	src/providers/wolfssl/wolfssl_aes_gcm.o \
	src/providers/wolfssl/wolfssl_sha.o \
	src/providers/wolfssl/wolfssl_hmac.o \
	src/providers/wolfssl/wolfssl_cmac.o \
	src/providers/wolfssl/wolfssl_kdf.o \
	src/providers/wolfssl/wolfssl_rsa.o \
	src/providers/wolfssl/wolfssl_ec_key.o \
	src/providers/wolfssl/wolfssl_ecdh.o \
	src/providers/wolfssl/wolfssl_ecdsa.o

# Per-file flags: wolfCrypt headers
WOLFSSL_CFLAGS := -I$(WOLFCRYPT_DIR) -DWOLFSSL_LINUXKM \
                  -DWOLFSSL_USE_OPTIONS_H \
                  -DNO_ASN_TIME \
                  -isystem $(shell $(CC) -print-file-name=include)
CFLAGS_src/providers/wolfssl/wolfssl_provider.o := $(WOLFSSL_CFLAGS)
CFLAGS_src/providers/wolfssl/wolfssl_aes_cbc.o  := $(WOLFSSL_CFLAGS)
CFLAGS_src/providers/wolfssl/wolfssl_aes_gcm.o  := $(WOLFSSL_CFLAGS)
CFLAGS_src/providers/wolfssl/wolfssl_sha.o      := $(WOLFSSL_CFLAGS)
CFLAGS_src/providers/wolfssl/wolfssl_hmac.o     := $(WOLFSSL_CFLAGS)
CFLAGS_src/providers/wolfssl/wolfssl_cmac.o     := $(WOLFSSL_CFLAGS)
CFLAGS_src/providers/wolfssl/wolfssl_kdf.o      := $(WOLFSSL_CFLAGS)
CFLAGS_src/providers/wolfssl/wolfssl_rsa.o      := $(WOLFSSL_CFLAGS)
CFLAGS_src/providers/wolfssl/wolfssl_ec_key.o   := $(WOLFSSL_CFLAGS)
CFLAGS_src/providers/wolfssl/wolfssl_ecdh.o     := $(WOLFSSL_CFLAGS)
CFLAGS_src/providers/wolfssl/wolfssl_ecdsa.o    := $(WOLFSSL_CFLAGS)

endif
