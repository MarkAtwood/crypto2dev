#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# check_uapi_layout.sh — pahole UAPI struct layout verification for crypto2dev
#
# Verifies that all 15 UAPI structs defined in include/uapi/crypto2dev_ioctl.h
# have zero padding holes.  A hole is ABI-visible padding inserted by the
# compiler to satisfy alignment; any hole may differ between 32-bit and 64-bit
# hosts and is therefore a UAPI stability bug.
#
# Requires: pahole (from the 'dwarves' package)
# Requires: crypto2dev.ko built with CONFIG_DEBUG_INFO=y (Ubuntu default: yes)
#
# Usage:
#   ./scripts/check_uapi_layout.sh <crypto2dev.ko> [additional.ko ...]
#
# The script checks each .ko argument against all 15 structs and reports the
# first module that contains the struct.  If a struct is not found in any of
# the supplied modules it is reported as NOT FOUND.
#
# Note on 32-bit: this script only checks the native (host) word size.
# 32-bit layout verification requires a separate 32-bit build — that is not
# performed here.
#
# Exit codes:
#   0 — all 15 structs verified hole-free
#   1 — one or more holes found (definite UAPI ABI bug)
#   2 — structs not found in module (debug info absent — cannot verify)

set -euo pipefail

# ── Colour helpers ────────────────────────────────────────────────────────────

if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' NC=''
fi

# ── Usage check ───────────────────────────────────────────────────────────────

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <crypto2dev.ko> [additional.ko ...]" >&2
    exit 1
fi

# ── pahole availability ───────────────────────────────────────────────────────

if ! command -v pahole >/dev/null 2>&1; then
    echo "ERROR: pahole not found — install the 'dwarves' package:" >&2
    echo "  sudo apt-get install dwarves      # Debian/Ubuntu" >&2
    echo "  sudo dnf install dwarves          # Fedora/RHEL" >&2
    exit 1
fi

# ── DWARF debug info check ────────────────────────────────────────────────────
#
# pahole requires DWARF debug info.  When absent it prints an error to stderr
# and exits non-zero.  Check the first supplied module before the per-struct
# loop so the error message is clear.

FIRST_KO="$1"
if [[ ! -f "$FIRST_KO" ]]; then
    echo "ERROR: module not found: $FIRST_KO" >&2
    exit 1
fi

PAHOLE_PROBE_ERR=""
PAHOLE_PROBE_OUT=""
PAHOLE_PROBE_RC=0
PAHOLE_PROBE_OUT=$(pahole "$FIRST_KO" 2>/tmp/pahole_probe_err.$$) || PAHOLE_PROBE_RC=$?
PAHOLE_PROBE_ERR=$(cat /tmp/pahole_probe_err.$$ 2>/dev/null || true)
rm -f /tmp/pahole_probe_err.$$

if [[ $PAHOLE_PROBE_RC -ne 0 ]] || \
   echo "$PAHOLE_PROBE_ERR" | grep -qiE "no debug|no symbol|no debugging|not an ELF|couldn't load"; then
    echo ""
    echo -e "${RED}ERROR${NC}: Module has no DWARF debug info — rebuild with CONFIG_DEBUG_INFO=y"
    echo ""
    echo "  Typical cause: the module was built without debug information."
    echo "  Ubuntu and most distro kernels have CONFIG_DEBUG_INFO=y by default."
    echo "  If building from source: ensure CONFIG_DEBUG_INFO=y in .config."
    echo "  For an out-of-tree module: make sure the kernel build tree has"
    echo "  debug info enabled (check /boot/config-\$(uname -r))."
    echo ""
    if [[ -n "$PAHOLE_PROBE_ERR" ]]; then
        echo "  pahole output: $PAHOLE_PROBE_ERR"
    fi
    exit 1
fi

# ── Struct list ───────────────────────────────────────────────────────────────
#
# All 15 UAPI structs defined in include/uapi/crypto2dev_ioctl.h.

UAPI_STRUCTS=(
    crypto2dev_init_op
    crypto2dev_iv_op
    crypto2dev_aad_op
    crypto2dev_tag_op
    crypto2dev_sign_op
    crypto2dev_verify_op
    crypto2dev_agree_op
    crypto2dev_status
    crypto2dev_fd_state_info
    crypto2dev_key_import_op
    crypto2dev_key_generate_op
    crypto2dev_key_info
    crypto2dev_key_export_op
    crypto2dev_algo_info
    crypto2dev_kdf_op
)

TOTAL=${#UAPI_STRUCTS[@]}

# ── Per-struct hole check ─────────────────────────────────────────────────────

pass_count=0
fail_count=0
notfound_count=0

echo ""
echo "crypto2dev UAPI struct layout verification (pahole)"
echo "===================================================="
echo "Module(s): $*"
echo "pahole:    $(pahole --version 2>/dev/null || echo 'unknown version')"
echo ""

for struct in "${UAPI_STRUCTS[@]}"; do

    # Try each supplied module until we find the struct.
    found_in=""
    pahole_out=""
    pahole_err=""

    for ko in "$@"; do
        if [[ ! -f "$ko" ]]; then
            continue
        fi
        out=""
        err=""
        rc=0
        out=$(pahole -C "$struct" "$ko" 2>/tmp/pahole_err.$$) || rc=$?
        err=$(cat /tmp/pahole_err.$$ 2>/dev/null || true)
        rm -f /tmp/pahole_err.$$

        # pahole exits 0 and produces empty output when the struct is not in
        # the given module; it exits 0 with output when it is found.
        if [[ $rc -eq 0 && -n "$out" ]]; then
            found_in="$ko"
            pahole_out="$out"
            pahole_err="$err"
            break
        fi
    done

    if [[ -z "$found_in" ]]; then
        echo -e "  ${YELLOW}NOT FOUND${NC}  $struct"
        (( notfound_count++ )) || true
        continue
    fi

    # Check for hole lines: "/* N bytes hole, ..." inserted by pahole.
    if echo "$pahole_out" | grep -qE '/\*[[:space:]]+[0-9]+ bytes? hole'; then
        echo -e "  ${RED}FAIL${NC}       $struct  ($found_in)"
        # Show the hole lines indented for easy diagnosis.
        echo "$pahole_out" \
            | grep -E '/\*[[:space:]]+[0-9]+ bytes? hole' \
            | sed 's/^/               /'
        (( fail_count++ )) || true
    else
        # Extract struct size from pahole output for informational purposes.
        size_line=$(echo "$pahole_out" | grep -E '^/\*[[:space:]]+size:' | head -1 || true)
        if [[ -n "$size_line" ]]; then
            size_info=$(echo "$size_line" | grep -oE 'size:[[:space:]]*[0-9]+' | tr -d ' ')
            echo -e "  ${GREEN}PASS${NC}       $struct  ($size_info)"
        else
            echo -e "  ${GREEN}PASS${NC}       $struct"
        fi
        (( pass_count++ )) || true
    fi

done

rm -f /tmp/pahole_probe_err.$$

# ── 32-bit note ───────────────────────────────────────────────────────────────

echo ""
echo "Note: 32-bit layout verification was not performed."
echo "      32-bit requires a separate cross-compiled build (ARCH=i386)."
echo "      Struct hole status above reflects the native $(uname -m) build only."

# ── Summary ───────────────────────────────────────────────────────────────────

hole_free=$pass_count
checked=$(( pass_count + fail_count ))

echo ""
echo "======================================================"
printf "  %d/%d structs verified hole-free\n" "$hole_free" "$TOTAL"
if [[ $fail_count -gt 0 ]]; then
    printf "  %d struct(s) have holes — UAPI ABI bug\n" "$fail_count"
fi
if [[ $notfound_count -gt 0 ]]; then
    printf "  %d struct(s) not found in supplied module(s)\n" "$notfound_count"
fi
echo "======================================================"
echo ""

if [[ $fail_count -gt 0 ]]; then
    echo -e "${RED}FAIL${NC}: struct holes detected — add explicit padding or reorder fields"
    exit 1
fi

if [[ $notfound_count -gt 0 ]]; then
    echo -e "${YELLOW}WARN${NC}: some structs were not found — ensure debug info is present"
    # Exit 2: cannot verify (no DWARF), but no holes proven.  Distro kernels
    # built without CONFIG_DEBUG_INFO will hit this path.
    exit 2
fi

echo -e "${GREEN}PASS${NC}: all $TOTAL UAPI structs are hole-free"
exit 0
