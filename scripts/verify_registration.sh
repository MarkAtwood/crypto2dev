#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# verify_registration.sh — verify wolfcrypt.ko algorithm registrations in /proc/crypto
#
# This script checks wolfCrypt's kernel crypto API registrations (wolfcrypt.ko),
# NOT crypto2dev.ko's chardev interface. It is a prerequisite check: wolfcrypt.ko
# must be loaded and its algorithms registered before crypto2dev tests are meaningful.
#
# Checks that all expected wolfkm algorithms are registered in the kernel
# crypto API with the correct driver name and priority.
#
# Run as root with wolfcrypt.ko loaded:
#   sudo ./scripts/verify_registration.sh
#
# Called by tests/ci/test-on-aws.sh as the first integration check after
# module load. Exits 0 if all algorithms pass; exits 1 with diagnostics
# otherwise.

set -euo pipefail

# ANSI color codes (suppressed when not a terminal)
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' NC=''
fi

# Expected wolfkm algorithms — each must appear in /proc/crypto with
# a "wolfkm" driver and priority 300.
EXPECTED_ALGOS=(
    "cbc(aes)"
    "ctr(aes)"
    "xts(aes)"
    "gcm(aes)"
    "ccm(aes)"
    "sha256"
    "sha384"
    "sha512"
    "sha3-256"
    "sha3-512"
    "hmac(sha256)"
    "hmac(sha384)"
    "hmac(sha512)"
    "cmac(aes)"
    "stdrng"
    "rsa"
    "ecdh-nist-p256"
    "ecdh-nist-p384"
    "dh"
)

EXPECTED_PRIORITY=300

pass_count=0
fail_count=0

echo "wolfkm /proc/crypto registration check"
echo "======================================="

if [ ! -r /proc/crypto ]; then
    echo -e "${RED}ERROR${NC}: /proc/crypto not readable — kernel crypto API unavailable?"
    exit 1
fi

#
# parse_proc_crypto ALGO — extract driver and priority for ALGO from /proc/crypto.
# Prints "driver=<driver> priority=<prio>" on success.
# Returns 1 if the algorithm is not found.
#
parse_proc_crypto() {
    local algo="$1"
    local in_block=0
    local found_driver="" found_priority=""

    while IFS= read -r line; do
        # Blank line = end of stanza
        if [[ -z "$line" ]]; then
            if [[ $in_block -eq 1 ]]; then
                if [[ -n "$found_driver" && -n "$found_priority" ]]; then
                    echo "driver=${found_driver} priority=${found_priority}"
                    return 0
                fi
            fi
            in_block=0
            found_driver=""
            found_priority=""
            continue
        fi

        local key val
        key="${line%%:*}"
        val="${line#*: }"
        # Trim trailing whitespace from key
        key="${key%"${key##*[![:space:]]}"}"

        if [[ "$key" == "name" ]]; then
            if [[ "$val" == "$algo" ]]; then
                in_block=1
            else
                in_block=0
            fi
        elif [[ $in_block -eq 1 ]]; then
            if [[ "$key" == "driver" ]]; then
                found_driver="$val"
            elif [[ "$key" == "priority" ]]; then
                found_priority="$val"
            fi
        fi
    done < /proc/crypto

    # Handle final stanza (no trailing blank line)
    if [[ $in_block -eq 1 && -n "$found_driver" && -n "$found_priority" ]]; then
        echo "driver=${found_driver} priority=${found_priority}"
        return 0
    fi

    return 1
}

for algo in "${EXPECTED_ALGOS[@]}"; do
    info=""
    if ! info=$(parse_proc_crypto "$algo" 2>/dev/null); then
        echo -e "  ${RED}FAIL${NC}  $algo — not found in /proc/crypto"
        (( fail_count++ )) || true
        continue
    fi

    driver="${info#driver=}"
    driver="${driver%% *}"
    priority_str="${info#* priority=}"

    # Check driver name contains "wolfkm"
    if [[ "$driver" != *wolfkm* ]]; then
        echo -e "  ${RED}FAIL${NC}  $algo — driver=\"$driver\" (expected wolfkm)"
        (( fail_count++ )) || true
        continue
    fi

    # Check priority
    priority="${priority_str//[^0-9]/}"
    if [[ "$priority" != "$EXPECTED_PRIORITY" ]]; then
        echo -e "  ${YELLOW}WARN${NC}  $algo — driver=\"$driver\" priority=$priority (expected $EXPECTED_PRIORITY)"
        (( fail_count++ )) || true
        continue
    fi

    echo -e "  ${GREEN}PASS${NC}  $algo — driver=\"$driver\" priority=$priority"
    (( pass_count++ )) || true
done

echo ""
echo "${pass_count} passed, ${fail_count} failed"

if [[ $fail_count -gt 0 ]]; then
    echo -e "${RED}FAIL${NC}: not all wolfkm algorithms are registered correctly"
    exit 1
fi

echo -e "${GREEN}PASS${NC}: all wolfkm algorithms registered correctly"
exit 0
