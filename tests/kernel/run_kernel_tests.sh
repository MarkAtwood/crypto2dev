#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# run_kernel_tests.sh — load wolfCrypt and crypto2dev, run all kernel test modules
#
# Usage:
#   sudo ./run_kernel_tests.sh /path/to/wolfcrypt.ko /path/to/crypto2dev.ko
#
# Environment:
#   TEST_TIMEOUT   per-module insmod timeout in seconds (default: 30)
#   VERBOSE        set to 1 to show all dmesg lines from each test
#
# Exit codes:
#   0  — all test modules passed
#   1  — one or more test modules failed or timed out
#   2  — usage error or wolfcrypt.ko/crypto2dev.ko not found

set -euo pipefail

WOLFCRYPT_KO="${1:-}"
CRYPTO2DEV_KO="${2:-}"
TEST_TIMEOUT="${TEST_TIMEOUT:-30}"
VERBOSE="${VERBOSE:-0}"
# Space-separated list of module names to skip (no .ko suffix).
# Used in CI to skip modules that test wolfcrypt.ko's kernel crypto API
# registrations rather than crypto2dev's chardev interface.
SKIP_MODULES="${SKIP_MODULES:-}"

# ANSI colours
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RESET='\033[0m'

pass_count=0
fail_count=0

die() {
	echo -e "${RED}ERROR:${RESET} $*" >&2
	exit 2
}

usage() {
	echo "Usage: sudo $0 /path/to/wolfcrypt.ko /path/to/crypto2dev.ko" >&2
	exit 2
}

log_pass() { echo -e "${GREEN}  PASS${RESET} $*"; ((pass_count++)) || true; }
log_fail() { echo -e "${RED}  FAIL${RESET} $*" >&2; ((fail_count++)) || true; }
log_skip() { echo -e "${YELLOW}  SKIP${RESET} $*"; }

# ── Argument validation ────────────────────────────────────────────────────

[[ -z "$WOLFCRYPT_KO"  ]] && usage
[[ -z "$CRYPTO2DEV_KO" ]] && usage
[[ "$(id -u)" -ne 0 ]]   && die "must be run as root"

[[ -f "$WOLFCRYPT_KO"  ]] || die "wolfcrypt.ko not found: $WOLFCRYPT_KO"
[[ -f "$CRYPTO2DEV_KO" ]] || die "crypto2dev.ko not found: $CRYPTO2DEV_KO"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Load framework modules (idempotent — skip if already loaded) ───────────

WOLFCRYPT_LOADED_HERE=0
CRYPTO2DEV_LOADED_HERE=0

cleanup() {
	echo ""
	if [[ $CRYPTO2DEV_LOADED_HERE -eq 1 ]]; then
		echo "Unloading crypto2dev.ko ..."
		rmmod crypto2dev 2>/dev/null || true
	fi
	if [[ $WOLFCRYPT_LOADED_HERE -eq 1 ]]; then
		echo "Unloading wolfcrypt.ko ..."
		rmmod libwolfssl 2>/dev/null || true
	fi
}
trap cleanup EXIT

if lsmod | grep -q "^libwolfssl "; then
	echo "wolfcrypt.ko already loaded — skipping insmod"
else
	echo "Loading wolfcrypt.ko ..."
	insmod "$WOLFCRYPT_KO" || die "insmod wolfcrypt.ko failed"
	WOLFCRYPT_LOADED_HERE=1
fi

if lsmod | grep -q "^crypto2dev "; then
	echo "crypto2dev.ko already loaded — skipping insmod"
else
	echo "Loading crypto2dev.ko ..."
	insmod "$CRYPTO2DEV_KO" || {
		[[ $WOLFCRYPT_LOADED_HERE -eq 1 ]] && rmmod libwolfssl 2>/dev/null || true
		die "insmod crypto2dev.ko failed"
	}
	CRYPTO2DEV_LOADED_HERE=1
fi

# ── Discover test modules ──────────────────────────────────────────────────

TEST_MODULES=(
	test_fips_gate
	test_shash
	test_aead
	test_rng
	test_skcipher
	test_akcipher
	test_kpp
)

echo ""
echo "Running ${#TEST_MODULES[@]} kernel test module(s)..."
echo ""

overall_start=$(date +%s)

# ── Per-module runner ──────────────────────────────────────────────────────

run_test_module() {
	local name="$1"
	local ko_path="$SCRIPT_DIR/${name}.ko"

	printf "%-30s " "$name"

	if echo " $SKIP_MODULES " | grep -qw "$name"; then
		log_skip "skipped via SKIP_MODULES"
		return 0
	fi

	if [[ ! -f "$ko_path" ]]; then
		log_skip "not built: $ko_path"
		return 0
	fi

	# Record dmesg cursor before load
	local before
	before=$(dmesg --time-format iso 2>/dev/null | wc -l || dmesg | wc -l)

	# insmod with timeout
	local ret=0
	timeout "$TEST_TIMEOUT" insmod "$ko_path" || ret=$?
	if [[ $ret -eq 124 ]]; then
		log_fail "timed out after ${TEST_TIMEOUT}s"
		return 1
	elif [[ $ret -ne 0 ]]; then
		log_fail "insmod failed (exit $ret)"
		return 1
	fi

	# Brief pause for module init to complete and write dmesg
	sleep 0.5

	# Capture dmesg lines added since before the load
	local module_log
	module_log=$(dmesg 2>/dev/null | tail -n "+$((before + 1))")

	# Unload test module
	rmmod "$name" 2>/dev/null || true

	# Count PASS/FAIL lines from the module
	local n_pass n_fail
	n_pass=$(echo "$module_log" | grep -cE "\[.*PASS\]|: PASS" || true)
	n_fail=$(echo "$module_log" | grep -cE "\[.*FAIL\]|: FAIL|BUG:|Oops:|kernel BUG" || true)

	if [[ $VERBOSE -eq 1 ]]; then
		echo ""
		echo "$module_log" | sed 's/^/    | /'
		echo ""
	fi

	if [[ $n_fail -gt 0 ]]; then
		log_fail "$n_fail failure(s), $n_pass pass(es)"
		if [[ $VERBOSE -eq 0 ]]; then
			echo "$module_log" | grep -E "\[.*FAIL\]|: FAIL|BUG:|Oops:" | \
				head -5 | sed 's/^/    | /' >&2
		fi
		return 1
	elif [[ $n_pass -eq 0 ]]; then
		# No PASS/FAIL lines — might be a module that just doesn't emit them
		# Check for any error-like messages
		if echo "$module_log" | grep -qiE "error|failed|cannot"; then
			log_fail "no PASS lines found; potential errors in dmesg"
			echo "$module_log" | grep -iE "error|failed|cannot" | \
				head -5 | sed 's/^/    | /' >&2
			return 1
		else
			log_skip "no PASS/FAIL lines in dmesg (module may not emit them)"
		fi
	else
		log_pass "$n_pass test(s)"
	fi
	return 0
}

for mod in "${TEST_MODULES[@]}"; do
	run_test_module "$mod" || true
done

# ── Post-run BUG/Oops check ────────────────────────────────────────────────

echo ""
echo "Checking dmesg for BUG/Oops since module load..."
if dmesg | grep -E "^.*\[ *[0-9]+\.[0-9]+\] (BUG:|Oops:)" | grep -v "BUG: warning" | head -5; then
	log_fail "kernel BUG or Oops detected in dmesg"
fi

# ── Summary ────────────────────────────────────────────────────────────────

overall_end=$(date +%s)
elapsed=$((overall_end - overall_start))

echo ""
echo "────────────────────────────────────────────"
if [[ $fail_count -eq 0 ]]; then
	echo -e "${GREEN}PASS${RESET}: $pass_count module(s) passed, 0 failed (${elapsed}s)"
else
	echo -e "${RED}FAIL${RESET}: $pass_count passed, $fail_count failed (${elapsed}s)"
fi
echo "────────────────────────────────────────────"

[[ $fail_count -eq 0 ]]
