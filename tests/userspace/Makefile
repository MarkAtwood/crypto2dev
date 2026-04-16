# SPDX-License-Identifier: GPL-2.0-only
#
# tests/userspace/Makefile — build userspace test binaries
#
# Usage:
#   make          — build all test binaries in-place
#   make clean    — remove built binaries and objects
#
# Run (requires root with relevant modules loaded):
#   sudo ./test_chardev
#   sudo ./test_af_alg
#   sudo ./test_concurrent

CC     := gcc
CFLAGS := -Wall -Wextra -O2 -g

# Path to UAPI headers (uapi/crypto2dev_ioctl.h)
UAPI_INC := -I../../include

PROGS := test_chardev test_concurrent test_af_alg test_kdf test_asym

.PHONY: all clean

all: $(PROGS)

test_chardev: test_chardev.c
	$(CC) $(CFLAGS) $(UAPI_INC) -o $@ $<

test_concurrent: test_concurrent.c
	$(CC) $(CFLAGS) $(UAPI_INC) -pthread -o $@ $<

test_af_alg: test_af_alg.c
	$(CC) $(CFLAGS) -o $@ $<

test_kdf: test_kdf.c
	$(CC) $(CFLAGS) $(UAPI_INC) -I../vectors -o $@ $<

test_asym: test_asym.c
	$(CC) $(CFLAGS) $(UAPI_INC) -I../vectors -o $@ $<

clean:
	rm -f $(PROGS)
