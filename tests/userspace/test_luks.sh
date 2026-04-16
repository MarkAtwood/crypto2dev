#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# test_luks.sh — LUKS2 full-disk encryption roundtrip test
#
# Usage: sudo ./tests/userspace/test_luks.sh
#
# Creates a 256 MB loopback LUKS2 volume, formats it ext4, writes 100 MB of
# random data, records its sha256sum, closes and reopens the volume, and
# verifies the sha256sum matches.  Checks /proc/crypto for a wolfCrypt xts
# entry and emits a warning if none is found (does not fail on absence).
#
# Requires: losetup, cryptsetup, mkfs.ext4, sha256sum, dd, awk
# Must be run as root.

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
IMG_FILE="/tmp/wolfkm-test-luks.img"
DM_NAME="wolfkm-test-luks"
MNT_POINT="/tmp/wolfkm-test-luks-mnt"
PASSPHRASE="wolfkm-test-passphrase-2024"
IMG_SIZE_MB=256
DATA_SIZE_MB=100
TEST_FILE="test-data.bin"

# These are set during setup; cleanup checks before acting.
LOOP_DEV=""

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------
cleanup() {
    local rc=$?

    # Unmount if mounted
    if mountpoint -q "${MNT_POINT}" 2>/dev/null; then
        umount "${MNT_POINT}" || true
    fi

    # Close dm-crypt device if open
    if [ -e "/dev/mapper/${DM_NAME}" ]; then
        cryptsetup close "${DM_NAME}" || true
    fi

    # Detach loop device if set
    if [ -n "${LOOP_DEV}" ] && losetup "${LOOP_DEV}" &>/dev/null; then
        losetup -d "${LOOP_DEV}" || true
    fi

    # Remove image file
    if [ -f "${IMG_FILE}" ]; then
        rm -f "${IMG_FILE}" || true
    fi

    # Remove mount point if we created it
    if [ -d "${MNT_POINT}" ]; then
        rmdir "${MNT_POINT}" 2>/dev/null || true
    fi

    exit "${rc}"
}

trap cleanup EXIT

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: this script must be run as root" >&2
    exit 1
fi

for tool in losetup cryptsetup mkfs.ext4 sha256sum dd awk mountpoint; do
    if ! command -v "${tool}" &>/dev/null; then
        echo "ERROR: required tool not found: ${tool}" >&2
        exit 1
    fi
done

# ---------------------------------------------------------------------------
# Check /proc/crypto for wolfCrypt xts entry (informational only)
# ---------------------------------------------------------------------------
echo "INFO: checking /proc/crypto for wolfCrypt xts driver..."
if awk '
    /^name/ { name = $0 }
    /^driver/ { driver = $0 }
    /xts/ && (tolower(name) ~ /wolf/ || tolower(driver) ~ /wolf/) { found=1 }
    END { exit (found ? 0 : 1) }
' /proc/crypto 2>/dev/null; then
    echo "INFO: wolfCrypt xts entry found in /proc/crypto"
else
    echo "WARNING: no wolfCrypt xts entry found in /proc/crypto" \
         "— crypto2dev may not be loaded or xts is served by another driver"
fi

# ---------------------------------------------------------------------------
# Create loopback image
# ---------------------------------------------------------------------------
echo "INFO: creating ${IMG_SIZE_MB} MB image at ${IMG_FILE}..."
dd if=/dev/zero of="${IMG_FILE}" bs=1M count="${IMG_SIZE_MB}" status=none

echo "INFO: attaching loop device..."
LOOP_DEV="$(losetup -f --show "${IMG_FILE}")"
echo "INFO: loop device is ${LOOP_DEV}"

# ---------------------------------------------------------------------------
# LUKS2 format
# ---------------------------------------------------------------------------
echo "INFO: formatting LUKS2 volume..."
echo -n "${PASSPHRASE}" | cryptsetup luksFormat \
    --type luks2 \
    --cipher aes-xts-plain64 \
    --hash sha256 \
    --iter-time 100 \
    --batch-mode \
    --key-file=- \
    "${LOOP_DEV}"

# ---------------------------------------------------------------------------
# Open and create filesystem
# ---------------------------------------------------------------------------
echo "INFO: opening LUKS2 volume..."
echo -n "${PASSPHRASE}" | cryptsetup open \
    --key-file=- \
    "${LOOP_DEV}" "${DM_NAME}"

echo "INFO: creating ext4 filesystem..."
mkfs.ext4 -q "/dev/mapper/${DM_NAME}"

mkdir -p "${MNT_POINT}"

echo "INFO: mounting ext4 filesystem..."
mount "/dev/mapper/${DM_NAME}" "${MNT_POINT}"

# ---------------------------------------------------------------------------
# Write test data and record checksum
# ---------------------------------------------------------------------------
echo "INFO: writing ${DATA_SIZE_MB} MB of random data..."
dd if=/dev/urandom of="${MNT_POINT}/${TEST_FILE}" \
    bs=1M count="${DATA_SIZE_MB}" status=none

echo "INFO: computing sha256sum of test data..."
EXPECTED_HASH="$(sha256sum "${MNT_POINT}/${TEST_FILE}" | awk '{print $1}')"
echo "INFO: sha256sum = ${EXPECTED_HASH}"

# ---------------------------------------------------------------------------
# Unmount and close
# ---------------------------------------------------------------------------
echo "INFO: unmounting..."
umount "${MNT_POINT}"

echo "INFO: closing LUKS volume..."
cryptsetup close "${DM_NAME}"

# ---------------------------------------------------------------------------
# Reopen and verify
# ---------------------------------------------------------------------------
echo "INFO: reopening LUKS volume..."
echo -n "${PASSPHRASE}" | cryptsetup open \
    --key-file=- \
    "${LOOP_DEV}" "${DM_NAME}"

echo "INFO: remounting ext4 filesystem..."
mount "/dev/mapper/${DM_NAME}" "${MNT_POINT}"

echo "INFO: verifying sha256sum..."
ACTUAL_HASH="$(sha256sum "${MNT_POINT}/${TEST_FILE}" | awk '{print $1}')"
echo "INFO: sha256sum = ${ACTUAL_HASH}"

if [ "${ACTUAL_HASH}" != "${EXPECTED_HASH}" ]; then
    echo "FAIL: sha256sum mismatch after LUKS reopen" >&2
    echo "  expected: ${EXPECTED_HASH}" >&2
    echo "  actual:   ${ACTUAL_HASH}" >&2
    exit 1
fi

echo "PASS: sha256sum verified after LUKS roundtrip"
