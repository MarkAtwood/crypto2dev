#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# test_fips_gate_ftrace.sh — ftrace-based FIPS gate ordering verification
#
# For each tested operation, enables function tracing on wolfssl_fips_gate
# and the relevant provider callback, performs one operation via
# /dev/crypto2dev, then parses the trace buffer to confirm that
# wolfssl_fips_gate appears before the provider callback in the call
# sequence.
#
# Usage: sudo ./tests/userspace/test_fips_gate_ftrace.sh
#
# Prerequisites:
#   - /dev/crypto2dev exists (wolfcrypt.ko, crypto2dev.ko,
#     crypto2dev_wolfssl.ko all loaded)
#   - /sys/kernel/debug/tracing/ exists (debugfs mounted)
#   - Running as root (or with write access to tracefs)
#
# Operations tested:
#   AES-CBC encrypt   : wolfssl_fips_gate + wolfssl_aes_cbc_update
#   AES-GCM encrypt   : wolfssl_fips_gate + wolfssl_aes_gcm_update
#   SHA-256 hash      : wolfssl_fips_gate + wolfssl_sha_update
#   HMAC-SHA256       : wolfssl_fips_gate + wolfssl_hmac_update
#
# Exit codes:
#   0  all tests passed or skipped
#   1  one or more tests failed

set -uo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TRACEFS=/sys/kernel/debug/tracing
DEVICE=/dev/crypto2dev
GATE_FN=wolfssl_fips_gate

# ---------------------------------------------------------------------------
# Result tracking
# ---------------------------------------------------------------------------

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

pass() { printf "[PASS] %s\n" "$*"; PASS_COUNT=$(( PASS_COUNT + 1 )); }
fail() { printf "[FAIL] %s\n" "$*" >&2; FAIL_COUNT=$(( FAIL_COUNT + 1 )); }
skip() { printf "[SKIP] %s\n" "$*"; SKIP_COUNT=$(( SKIP_COUNT + 1 )); }
info() { printf "[INFO] %s\n" "$*"; }

# ---------------------------------------------------------------------------
# Saved ftrace state (restored by cleanup)
# ---------------------------------------------------------------------------

SAVED_TRACER=
SAVED_FILTER=
SAVED_TRACING_ON=

# ---------------------------------------------------------------------------
# Cleanup — always restore ftrace state
# ---------------------------------------------------------------------------

cleanup() {
    set +e

    # Disable tracing before restoring to avoid partial state races
    echo 0 > "${TRACEFS}/tracing_on" 2>/dev/null

    if [ -n "${SAVED_TRACER}" ]; then
        echo "${SAVED_TRACER}" > "${TRACEFS}/current_tracer" 2>/dev/null
    fi

    if [ -n "${SAVED_FILTER}" ]; then
        echo "${SAVED_FILTER}" > "${TRACEFS}/set_ftrace_filter" 2>/dev/null
    else
        # Clear filter if we had none saved (empty file = trace all)
        echo > "${TRACEFS}/set_ftrace_filter" 2>/dev/null
    fi

    if [ -n "${SAVED_TRACING_ON}" ]; then
        echo "${SAVED_TRACING_ON}" > "${TRACEFS}/tracing_on" 2>/dev/null
    fi
}

trap cleanup EXIT

# ---------------------------------------------------------------------------
# Prerequisite checks
# ---------------------------------------------------------------------------

check_prerequisites() {
    local ok=1

    if [ "$(id -u)" -ne 0 ]; then
        printf "ERROR: must run as root\n" >&2
        ok=0
    fi

    if [ ! -c "${DEVICE}" ]; then
        printf "ERROR: %s not found — are wolfcrypt.ko, crypto2dev.ko, and crypto2dev_wolfssl.ko loaded?\n" \
            "${DEVICE}" >&2
        ok=0
    fi

    if [ ! -d "${TRACEFS}" ]; then
        printf "ERROR: %s not found — is debugfs mounted? (mount -t debugfs none /sys/kernel/debug)\n" \
            "${TRACEFS}" >&2
        ok=0
    fi

    if [ ! -w "${TRACEFS}/current_tracer" ]; then
        printf "ERROR: cannot write to %s/current_tracer — insufficient permissions\n" \
            "${TRACEFS}" >&2
        ok=0
    fi

    if ! command -v python3 >/dev/null 2>&1; then
        printf "ERROR: python3 is required for ioctl operations\n" >&2
        ok=0
    fi

    if [ "${ok}" -ne 1 ]; then
        exit 1
    fi
}

# ---------------------------------------------------------------------------
# Save current ftrace state
# ---------------------------------------------------------------------------

save_ftrace_state() {
    SAVED_TRACER=$(cat "${TRACEFS}/current_tracer" 2>/dev/null || true)
    SAVED_FILTER=$(cat "${TRACEFS}/set_ftrace_filter" 2>/dev/null || true)
    SAVED_TRACING_ON=$(cat "${TRACEFS}/tracing_on" 2>/dev/null || true)
}

# ---------------------------------------------------------------------------
# ftrace helpers
# ---------------------------------------------------------------------------

ftrace_reset() {
    # Stop tracing, clear buffer, reset to nop
    echo 0 > "${TRACEFS}/tracing_on"
    echo nop > "${TRACEFS}/current_tracer"
    echo > "${TRACEFS}/set_ftrace_filter"
    echo > "${TRACEFS}/trace"
}

ftrace_arm() {
    local gate_fn="$1"
    local callback_fn="$2"

    echo nop > "${TRACEFS}/current_tracer"
    echo > "${TRACEFS}/trace"
    # Set filter: trace only the two functions we care about.
    # Writing the first function with > overwrites; append the second with >>.
    echo "${gate_fn}" > "${TRACEFS}/set_ftrace_filter"
    echo "${callback_fn}" >> "${TRACEFS}/set_ftrace_filter"
    echo function > "${TRACEFS}/current_tracer"
    echo 1 > "${TRACEFS}/tracing_on"
}

ftrace_disarm() {
    echo 0 > "${TRACEFS}/tracing_on"
    echo nop > "${TRACEFS}/current_tracer"
}

# Read the trace buffer and return it on stdout.
ftrace_read() {
    cat "${TRACEFS}/trace"
}

# ---------------------------------------------------------------------------
# Trace ordering analysis
#
# Reads the trace buffer (stdin) and verifies that gate_fn appears at least
# once before callback_fn.
#
# Returns:
#   0  gate appeared before callback (PASS)
#   1  callback appeared before gate, or gate missing, or callback missing
#   2  callback not present in trace at all (SKIP)
# ---------------------------------------------------------------------------

check_ordering() {
    local gate_fn="$1"
    local callback_fn="$2"
    local trace_data="$3"

    local gate_line=0
    local cb_line=0
    local linenum=0

    # Walk through trace lines in order.  Lines starting with '#' are
    # comments emitted by ftrace (header, version, etc.) — skip them.
    while IFS= read -r line; do
        linenum=$(( linenum + 1 ))

        # Skip ftrace comment/header lines
        case "${line}" in
            \#*) continue ;;
            *) ;;
        esac

        # Skip blank lines
        [ -z "${line}" ] && continue

        # Check for gate function in the function column.
        # Trace format: "  <task>-<pid>  [cpu]  <ts>: <function> <-caller>"
        # The function name appears between the last colon-space and the
        # space-arrow (<-).  We match by looking for the function name as
        # a word in the line.
        if [ "${gate_line}" -eq 0 ]; then
            case "${line}" in
                *" ${gate_fn} "* | *" ${gate_fn}"$* | *":${gate_fn} "*)
                    gate_line=${linenum}
                    ;;
            esac
        fi

        if [ "${cb_line}" -eq 0 ]; then
            case "${line}" in
                *" ${callback_fn} "* | *" ${callback_fn}"$* | *":${callback_fn} "*)
                    cb_line=${linenum}
                    ;;
            esac
        fi

        # Once both are found we can stop reading
        if [ "${gate_line}" -gt 0 ] && [ "${cb_line}" -gt 0 ]; then
            break
        fi
    done <<< "${trace_data}"

    if [ "${cb_line}" -eq 0 ]; then
        # Callback not found in trace — operation may not have reached update()
        return 2
    fi

    if [ "${gate_line}" -eq 0 ]; then
        # Gate never called — FIPS gate is absent (FAIL)
        return 1
    fi

    if [ "${gate_line}" -lt "${cb_line}" ]; then
        return 0   # gate before callback: correct
    else
        return 1   # callback before gate, or same line (should not happen): wrong
    fi
}

# ---------------------------------------------------------------------------
# Python helper — perform one crypto2dev operation
#
# Invoked as a here-doc passed to python3.  The operation type is
# passed via environment variable C2D_OP_TYPE.
#
# Ioctl number derivation (Linux ioctl encoding, 64-bit):
#   _IO(type,nr)      = (0<<30)|(0<<16)|(type<<8)|nr
#   _IOW(type,nr,sz)  = (2<<30)|(sz<<16)|(type<<8)|nr
#   _IOR(type,nr,sz)  = (1<<30)|(sz<<16)|(type<<8)|nr
#   _IOWR(type,nr,sz) = (3<<30)|(sz<<16)|(type<<8)|nr
#
# Struct sizes (from crypto2dev_ioctl.h):
#   crypto2dev_init_op : algo[64]+provider[32]+op(4)+keylen(4)+key[128]+key_fd(4)+_pad[4] = 240
#   crypto2dev_iv_op   : iv[32]+ivlen(4) = 36
#   crypto2dev_aad_op  : aad[256]+aadlen(4) = 260
# ---------------------------------------------------------------------------

# Run a single-operation Python script and return its exit code.
# The caller passes the operation name as the first argument; the script
# is selected by that name.
run_python_op() {
    local op_name="$1"
    python3 - "${op_name}" <<'PYEOF'
import sys
import os
import struct
import fcntl

# ---------------------------------------------------------------------------
# Ioctl number constants (computed from header definitions)
# ---------------------------------------------------------------------------

IOC_MAGIC  = 0xC2

# struct sizes
INIT_SZ    = 240   # algo[64]+provider[32]+op(4)+keylen(4)+key[128]+key_fd(4)+_pad[4]
IV_SZ      = 36    # iv[32]+ivlen(4)
AAD_SZ     = 260   # aad[256]+aadlen(4)

def _IOW(t, n, sz):
    return (2 << 30) | (sz << 16) | (t << 8) | n

def _IO(t, n):
    return (0 << 30) | (0 << 16) | (t << 8) | n

IOC_INIT     = _IOW(IOC_MAGIC, 1,  INIT_SZ)
IOC_SET_IV   = _IOW(IOC_MAGIC, 2,  IV_SZ)
IOC_SET_AAD  = _IOW(IOC_MAGIC, 3,  AAD_SZ)
IOC_FINALIZE = _IO(IOC_MAGIC,  21)

# CRYPTO2DEV_OP_ENCRYPT = 1, CRYPTO2DEV_OP_HASH = 3
OP_ENCRYPT = 1
OP_HASH    = 3

DEVICE = "/dev/crypto2dev"

# ---------------------------------------------------------------------------
# Struct builders
# ---------------------------------------------------------------------------

def build_init_op(algo, op, key=b"", provider=b"wolfssl"):
    """Build a crypto2dev_init_op struct (240 bytes)."""
    algo_b     = algo.encode()[:63] + b"\x00"
    algo_b     = algo_b.ljust(64, b"\x00")
    prov_b     = provider[:31] + b"\x00"
    prov_b     = prov_b.ljust(32, b"\x00")
    key_b      = (key + b"\x00" * 128)[:128]
    keylen     = len(key)
    # op(u32) + keylen(u32) + key[128] + key_fd(s32=-1) + _pad[4]
    rest = struct.pack("=II128siI", op, keylen, key_b, -1, 0)
    return algo_b + prov_b + rest

def build_iv_op(iv):
    """Build a crypto2dev_iv_op struct (36 bytes)."""
    iv_b   = (iv + b"\x00" * 32)[:32]
    ivlen  = len(iv)
    return iv_b + struct.pack("=I", ivlen)

def build_aad_op(aad):
    """Build a crypto2dev_aad_op struct (260 bytes)."""
    aad_b  = (aad + b"\x00" * 256)[:256]
    aadlen = len(aad)
    return aad_b + struct.pack("=I", aadlen)

# ---------------------------------------------------------------------------
# Per-operation runners
# ---------------------------------------------------------------------------

def op_aes_cbc_encrypt():
    """
    AES-128-CBC encrypt: INIT -> SET_IV -> write(16B) -> FINALIZE -> read
    Uses NIST CAVP vector (AES-128-CBC, 16-byte plaintext):
      Key : 2b7e151628aed2a6abf7158809cf4f3c
      IV  : 000102030405060708090a0b0c0d0e0f
      PT  : 6bc1bee22e409f96e93d7e117393172a
    """
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    iv  = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt  = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")

    fd = os.open(DEVICE, os.O_RDWR)
    try:
        init_s = build_init_op(b"cbc(aes)", OP_ENCRYPT, key)
        fcntl.ioctl(fd, IOC_INIT, bytearray(init_s))

        iv_s = build_iv_op(iv)
        fcntl.ioctl(fd, IOC_SET_IV, bytearray(iv_s))

        os.write(fd, pt)
        fcntl.ioctl(fd, IOC_FINALIZE)
        os.read(fd, 64)
    finally:
        os.close(fd)

def op_aes_gcm_encrypt():
    """
    AES-128-GCM encrypt: INIT -> SET_IV -> SET_AAD -> write(16B) -> FINALIZE
    Uses NIST GCMVS vector (Test Case 4, 128-bit key):
      Key   : feffe9928665731c6d6a8f9467308308
      Nonce : cafebabefacedbaddecaf888
      PT    : d9313225f88406e5a55909c5aff5269a
      AAD   : feedfacedeadbeeffeedfacedeadbeef
    """
    key   = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
    nonce = bytes.fromhex("cafebabefacedbaddecaf888")
    pt    = bytes.fromhex("d9313225f88406e5a55909c5aff5269a")
    aad   = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeef")

    fd = os.open(DEVICE, os.O_RDWR)
    try:
        init_s = build_init_op(b"gcm(aes)", OP_ENCRYPT, key)
        fcntl.ioctl(fd, IOC_INIT, bytearray(init_s))

        iv_s = build_iv_op(nonce)
        fcntl.ioctl(fd, IOC_SET_IV, bytearray(iv_s))

        aad_s = build_aad_op(aad)
        fcntl.ioctl(fd, IOC_SET_AAD, bytearray(aad_s))

        os.write(fd, pt)
        fcntl.ioctl(fd, IOC_FINALIZE)
        os.read(fd, 256)
    finally:
        os.close(fd)

def op_sha256_hash():
    """
    SHA-256 hash: INIT -> write(3B "abc") -> FINALIZE -> read(32B)
    NIST FIPS 180-4 example: SHA-256("abc")
    """
    msg = b"abc"

    fd = os.open(DEVICE, os.O_RDWR)
    try:
        init_s = build_init_op(b"sha256", OP_HASH)
        fcntl.ioctl(fd, IOC_INIT, bytearray(init_s))

        os.write(fd, msg)
        fcntl.ioctl(fd, IOC_FINALIZE)
        os.read(fd, 32)
    finally:
        os.close(fd)

def op_hmac_sha256():
    """
    HMAC-SHA-256: INIT -> write(8B) -> FINALIZE -> read(32B)
    RFC 4231 Test Case 1:
      Key   : 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (20 bytes)
      Data  : 4869205468657265 ("Hi There")
    """
    key  = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    data = bytes.fromhex("4869205468657265")

    fd = os.open(DEVICE, os.O_RDWR)
    try:
        init_s = build_init_op(b"hmac(sha256)", OP_HASH, key)
        fcntl.ioctl(fd, IOC_INIT, bytearray(init_s))

        os.write(fd, data)
        fcntl.ioctl(fd, IOC_FINALIZE)
        os.read(fd, 32)
    finally:
        os.close(fd)

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

OPERATIONS = {
    "aes_cbc_encrypt": op_aes_cbc_encrypt,
    "aes_gcm_encrypt": op_aes_gcm_encrypt,
    "sha256_hash":     op_sha256_hash,
    "hmac_sha256":     op_hmac_sha256,
}

if len(sys.argv) < 2 or sys.argv[1] not in OPERATIONS:
    print("usage: %s <op_name>" % sys.argv[0], file=sys.stderr)
    print("available:", " ".join(OPERATIONS.keys()), file=sys.stderr)
    sys.exit(1)

try:
    OPERATIONS[sys.argv[1]]()
    sys.exit(0)
except OSError as e:
    print("ERROR: operation %s failed: %s" % (sys.argv[1], e), file=sys.stderr)
    sys.exit(1)
PYEOF
}

# ---------------------------------------------------------------------------
# Core test runner
#
# run_ftrace_test <test_name> <op_name> <gate_fn> <callback_fn>
#
# Clears the trace buffer, arms ftrace for the two named functions,
# executes the operation, disarms ftrace, then checks ordering.
# ---------------------------------------------------------------------------

run_ftrace_test() {
    local test_name="$1"
    local op_name="$2"
    local gate_fn="$3"
    local callback_fn="$4"

    # Verify both function names are known to ftrace before arming.
    # ftrace silently ignores unknown functions; if the filter file is empty
    # after writing, the function is not found in the symbol table.
    ftrace_reset

    # Probe gate function availability
    echo "${gate_fn}" > "${TRACEFS}/set_ftrace_filter" 2>/dev/null
    local gate_present
    gate_present=$(cat "${TRACEFS}/set_ftrace_filter" 2>/dev/null | tr -d '[:space:]')
    if [ -z "${gate_present}" ]; then
        skip "${test_name}: ${gate_fn} not found in ftrace symbol table (module not loaded?)"
        return
    fi

    # Probe callback function availability
    echo "${callback_fn}" > "${TRACEFS}/set_ftrace_filter" 2>/dev/null
    local cb_present
    cb_present=$(cat "${TRACEFS}/set_ftrace_filter" 2>/dev/null | tr -d '[:space:]')
    if [ -z "${cb_present}" ]; then
        skip "${test_name}: ${callback_fn} not found in ftrace symbol table (module not loaded?)"
        return
    fi

    # Arm ftrace for both functions
    ftrace_arm "${gate_fn}" "${callback_fn}"

    # Perform the operation — ignore the return code here; even if the ioctl
    # returns an error (e.g. stub mode), the functions may still have been
    # called.  We check the trace for ordering, not the operation result.
    run_python_op "${op_name}" >/dev/null 2>&1 || true

    # Disarm ftrace before reading to avoid capturing unrelated calls
    ftrace_disarm

    # Capture trace buffer
    local trace_data
    trace_data=$(ftrace_read)

    # Analyse ordering
    local result
    check_ordering "${gate_fn}" "${callback_fn}" "${trace_data}"
    result=$?

    case "${result}" in
        0)
            pass "${test_name}: ${gate_fn} called before ${callback_fn}"
            ;;
        1)
            fail "${test_name}: ordering violation — ${callback_fn} before ${gate_fn}, or gate missing"
            # Emit relevant trace lines for diagnosis
            printf "  Trace excerpt:\n" >&2
            printf "%s\n" "${trace_data}" | grep -E "${gate_fn}|${callback_fn}" \
                | head -20 >&2 || true
            ;;
        2)
            skip "${test_name}: ${callback_fn} not observed in trace (provider may buffer until finalize, or algo not supported)"
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    printf "\n=== crypto2dev FIPS gate ftrace ordering tests ===\n\n"

    check_prerequisites
    save_ftrace_state

    # Bring ftrace to a known clean state
    ftrace_reset

    # -----------------------------------------------------------------------
    # Test 1: AES-CBC encrypt
    #   The update() callback is wolfssl_aes_cbc_update.
    #   The FIPS gate is wolfssl_fips_gate.
    #   write() -> update() path; gate must precede update.
    # -----------------------------------------------------------------------
    run_ftrace_test \
        "AES-CBC encrypt: gate before wolfssl_aes_cbc_update" \
        "aes_cbc_encrypt" \
        "${GATE_FN}" \
        "wolfssl_aes_cbc_update"

    # -----------------------------------------------------------------------
    # Test 2: AES-GCM encrypt
    #   The update() callback is wolfssl_aes_gcm_update.
    # -----------------------------------------------------------------------
    run_ftrace_test \
        "AES-GCM encrypt: gate before wolfssl_aes_gcm_update" \
        "aes_gcm_encrypt" \
        "${GATE_FN}" \
        "wolfssl_aes_gcm_update"

    # -----------------------------------------------------------------------
    # Test 3: SHA-256 hash
    #   The update() callback is wolfssl_sha_update (shared across SHA variants).
    # -----------------------------------------------------------------------
    run_ftrace_test \
        "SHA-256 hash: gate before wolfssl_sha_update" \
        "sha256_hash" \
        "${GATE_FN}" \
        "wolfssl_sha_update"

    # -----------------------------------------------------------------------
    # Test 4: HMAC-SHA256
    #   The update() callback is wolfssl_hmac_update (shared across HMAC variants).
    # -----------------------------------------------------------------------
    run_ftrace_test \
        "HMAC-SHA256: gate before wolfssl_hmac_update" \
        "hmac_sha256" \
        "${GATE_FN}" \
        "wolfssl_hmac_update"

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    printf "\n"
    printf "Results: %d passed, %d skipped, %d failed\n" \
        "${PASS_COUNT}" "${SKIP_COUNT}" "${FAIL_COUNT}"
    printf "\n"

    if [ "${FAIL_COUNT}" -gt 0 ]; then
        printf "FAIL: %d test(s) reported ordering violations\n" \
            "${FAIL_COUNT}" >&2
        exit 1
    fi

    printf "PASS: all %d executed test(s) confirmed gate ordering\n" \
        "${PASS_COUNT}"
    exit 0
}

main "$@"
