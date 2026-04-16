#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# test_dm_crypt.sh — dm-crypt loopback encryption round-trip test
#
# Usage: sudo ./tests/userspace/test_dm_crypt.sh
#
# Creates a 64 MB loopback image, opens it as a plain dm-crypt device using
# aes-xts-plain64 (--key-size 256, i.e. AES-128-XTS with two 128-bit sub-keys),
# writes a known 1 MB pattern of all-zero bytes, closes and reopens with the
# same key, reads back the pattern, and verifies it is unchanged.
#
# Checks /proc/crypto for a wolfSSL/wolfCrypt xts(aes) driver and warns if
# none is found, but does not fail on that check alone.
#
# NOTE: The hardcoded key below is a TEST KEY ONLY. It is NOT secret and MUST
# NOT be used for any production or security purpose.

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

IMAGE=/tmp/wolfkm-test-dm.img
IMAGE_SIZE_MB=64
DM_NAME=wolfkm-test-dm
DM_DEV=/dev/mapper/${DM_NAME}

# 64 hex characters = 32 bytes = 256 bits total XTS key.
# With --key-size 256, cryptsetup splits this as two 128-bit AES sub-keys
# (AES-128-XTS).  NOT FOR PRODUCTION USE.
TEST_KEY_HEX=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff

PATTERN_SIZE_BYTES=$((1024 * 1024))   # 1 MB
PATTERN_BS=4096
PATTERN_COUNT=$(( PATTERN_SIZE_BYTES / PATTERN_BS ))

KEYFILE=                              # set in setup_keyfile(), cleared in cleanup

# ---------------------------------------------------------------------------
# Cleanup trap
# ---------------------------------------------------------------------------

cleanup() {
    local exit_code=$?
    set +e   # do not abort on cleanup failures

    if [ -e "${DM_DEV}" ]; then
        cryptsetup close "${DM_NAME}" 2>/dev/null
    fi

    if [ -n "${LOOP_DEV:-}" ]; then
        losetup -d "${LOOP_DEV}" 2>/dev/null
    fi

    if [ -n "${KEYFILE}" ] && [ -f "${KEYFILE}" ]; then
        # Zero the key file before removal (key material hygiene)
        dd if=/dev/zero of="${KEYFILE}" bs=$(wc -c < "${KEYFILE}") count=1 \
            status=none 2>/dev/null || true
        rm -f "${KEYFILE}"
        KEYFILE=
    fi

    if [ -f "${IMAGE}" ]; then
        rm -f "${IMAGE}"
    fi

    exit "${exit_code}"
}

trap cleanup EXIT

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

pass() { printf "[PASS] %s\n" "$*"; }
fail() { printf "[FAIL] %s\n" "$*" >&2; exit 1; }
warn() { printf "[WARN] %s\n" "$*" >&2; }
info() { printf "[INFO] %s\n" "$*"; }

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        fail "This test must be run as root (needs losetup, cryptsetup, dm-crypt)."
    fi
}

check_tools() {
    local missing=0
    for tool in losetup cryptsetup dd xxd od; do
        if ! command -v "${tool}" >/dev/null 2>&1; then
            warn "Required tool not found: ${tool}"
            missing=1
        fi
    done
    if [ "${missing}" -ne 0 ]; then
        fail "One or more required tools are missing; install them and retry."
    fi
}

setup_keyfile() {
    KEYFILE=$(mktemp /tmp/wolfkm-test-key.XXXXXX)
    chmod 600 "${KEYFILE}"
    # Convert hex key to raw binary bytes
    printf '%s' "${TEST_KEY_HEX}" | xxd -r -p > "${KEYFILE}"
    local written
    written=$(wc -c < "${KEYFILE}")
    if [ "${written}" -ne 32 ]; then
        fail "Key file has ${written} bytes; expected 32 (256-bit XTS key)."
    fi
}

create_image() {
    info "Creating ${IMAGE_SIZE_MB} MB image at ${IMAGE} ..."
    dd if=/dev/zero of="${IMAGE}" bs=1M count="${IMAGE_SIZE_MB}" status=none
    pass "Image created."
}

setup_loop() {
    LOOP_DEV=$(losetup -f --show "${IMAGE}")
    if [ -z "${LOOP_DEV}" ]; then
        fail "losetup did not return a loop device path."
    fi
    info "Loop device: ${LOOP_DEV}"
}

open_dm() {
    cryptsetup open \
        --type plain \
        --cipher aes-xts-plain64 \
        --key-size 256 \
        --key-file "${KEYFILE}" \
        "${LOOP_DEV}" "${DM_NAME}"
    if [ ! -e "${DM_DEV}" ]; then
        fail "dm-crypt device ${DM_DEV} did not appear after cryptsetup open."
    fi
    info "dm-crypt device opened: ${DM_DEV}"
}

close_dm() {
    cryptsetup close "${DM_NAME}"
    if [ -e "${DM_DEV}" ]; then
        fail "dm-crypt device ${DM_DEV} still present after cryptsetup close."
    fi
    info "dm-crypt device closed."
}

write_pattern() {
    info "Writing ${PATTERN_SIZE_BYTES} bytes of zero pattern to ${DM_DEV} ..."
    dd if=/dev/zero of="${DM_DEV}" bs="${PATTERN_BS}" count="${PATTERN_COUNT}" \
        status=none oflag=direct
    pass "Pattern written."
}

verify_pattern() {
    info "Reading back ${PATTERN_SIZE_BYTES} bytes from ${DM_DEV} ..."
    local readback
    readback=$(mktemp /tmp/wolfkm-test-readback.XXXXXX)

    dd if="${DM_DEV}" of="${readback}" bs="${PATTERN_BS}" count="${PATTERN_COUNT}" \
        status=none iflag=direct

    # Verify: every byte must be 0x00
    local nonzero
    nonzero=$(od -A n -t x1 "${readback}" | tr -s ' \n' '\n' | \
              grep -cv '^00$' || true)
    rm -f "${readback}"

    if [ "${nonzero}" -ne 0 ]; then
        fail "Pattern mismatch: ${nonzero} non-zero byte(s) found after round-trip."
    fi
    pass "Pattern verified: all ${PATTERN_SIZE_BYTES} bytes are 0x00 after round-trip."
}

check_proc_crypto() {
    info "Checking /proc/crypto for wolfSSL/wolfCrypt xts(aes) driver ..."
    if [ ! -r /proc/crypto ]; then
        warn "/proc/crypto is not readable; skipping driver check."
        return
    fi

    # Parse /proc/crypto blocks: each algorithm is separated by a blank line.
    # Look for blocks whose 'name' line contains 'xts' and whose 'driver' line
    # contains 'wolf' (case-insensitive).
    local found=0
    local in_xts_block=0
    local block_has_wolf=0

    while IFS= read -r line; do
        if [ -z "${line}" ]; then
            # End of block
            if [ "${in_xts_block}" -eq 1 ] && [ "${block_has_wolf}" -eq 1 ]; then
                found=1
            fi
            in_xts_block=0
            block_has_wolf=0
            continue
        fi

        case "${line}" in
            name*xts*)
                in_xts_block=1
                ;;
            driver*[Ww][Oo][Ll][Ff]*)
                block_has_wolf=1
                ;;
        esac
    done < /proc/crypto

    # Handle last block if file does not end with a blank line
    if [ "${in_xts_block}" -eq 1 ] && [ "${block_has_wolf}" -eq 1 ]; then
        found=1
    fi

    if [ "${found}" -eq 1 ]; then
        pass "/proc/crypto: wolfSSL/wolfCrypt xts(aes) driver is active."
    else
        warn "/proc/crypto: no wolfSSL/wolfCrypt xts(aes) driver found." \
             " crypto2dev.ko may not be loaded, or wolfcrypt.ko is not providing xts."
        warn "Test continues — driver presence is advisory, not required for pass."
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    printf "\n=== crypto2dev dm-crypt round-trip test ===\n\n"

    check_root
    check_tools

    setup_keyfile
    create_image
    setup_loop

    # --- First open: write the known pattern ---
    open_dm
    write_pattern
    close_dm

    # --- Second open with identical key: verify the pattern survives ---
    open_dm
    verify_pattern
    close_dm

    # --- Advisory: check that wolfcrypt xts driver is serving the request ---
    check_proc_crypto

    printf "\n=== PASS: dm-crypt round-trip test completed successfully ===\n\n"
    exit 0
}

main "$@"
