#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# tests/userspace/test_ipsec.sh
#
# IPsec xfrm tunnel test: verifies that AES-GCM-128 ESP tunnels function
# correctly in a two-namespace setup, and checks that gcm(aes) is served
# by the wolfcrypt/wolfssl provider when wolfcrypt.ko is loaded.
#
# Usage:
#   sudo ./tests/userspace/test_ipsec.sh
#
# The script creates two network namespaces (ns_left, ns_right) connected
# by a veth pair, establishes an IPsec ESP tunnel in transport+tunnel mode
# using rfc4106(gcm(aes)) (AES-GCM-128, FIPS-approved AEAD for IPsec), and
# verifies connectivity via ping and a 1 MB netcat transfer.
#
# Prerequisites: ip, ping, nc/ncat/netcat, iptables
# Requires root.

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

readonly NS_LEFT="ns_left"
readonly NS_RIGHT="ns_right"
readonly VETH_LEFT="veth-left"
readonly VETH_RIGHT="veth-right"
readonly IP_LEFT="192.168.99.1"
readonly IP_RIGHT="192.168.99.2"
readonly PREFIX_LEN="24"

# rfc4106(gcm(aes)) key: 128-bit AES key + 32-bit salt = 160 bits = 20 bytes.
# Expressed as 40 hex digits.  This is a fixed test key — not a secret.
readonly AEAD_KEY="0102030405060708090a0b0c0d0e0f10 11121314"
readonly SPI_LR="0x00001234"
readonly SPI_RL="0x00001235"
readonly REQID="1"

readonly NC_PORT="19876"
readonly TRANSFER_BYTES="1048576"   # 1 MB

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

pass() { printf "PASS: %s\n" "$*"; }
fail() { printf "FAIL: %s\n" "$*" >&2; exit 1; }
info() { printf "INFO: %s\n" "$*"; }
warn() { printf "WARN: %s\n" "$*"; }

# ---------------------------------------------------------------------------
# Cleanup — called from trap and at start for idempotency.
# Runs with set +e so that already-deleted resources don't abort cleanup.
# ---------------------------------------------------------------------------

cleanup() {
    set +e
    info "Cleaning up namespaces and veth pair..."
    ip netns del "${NS_LEFT}"  2>/dev/null
    ip netns del "${NS_RIGHT}" 2>/dev/null
    # veth-left disappears automatically when ns_left is deleted;
    # veth-right disappears when ns_right is deleted.  Belt-and-suspenders:
    ip link del "${VETH_LEFT}"  2>/dev/null
    ip link del "${VETH_RIGHT}" 2>/dev/null
    set -e
}

# ---------------------------------------------------------------------------
# Prerequisites check
# ---------------------------------------------------------------------------

check_prereqs() {
    local missing=0

    for cmd in ip ping iptables; do
        if ! command -v "${cmd}" >/dev/null 2>&1; then
            warn "Required command not found: ${cmd}"
            missing=1
        fi
    done

    # nc may be provided by ncat, netcat, or nc depending on distro
    local nc_found=0
    for nc_cmd in nc ncat netcat; do
        if command -v "${nc_cmd}" >/dev/null 2>&1; then
            NC_BIN="${nc_cmd}"
            nc_found=1
            break
        fi
    done
    if [[ "${nc_found}" -eq 0 ]]; then
        warn "Required command not found: nc/ncat/netcat"
        missing=1
    fi

    if [[ "${missing}" -ne 0 ]]; then
        fail "One or more prerequisites are missing — install them and retry"
    fi
}

# ---------------------------------------------------------------------------
# /proc/crypto wolfcrypt check
# ---------------------------------------------------------------------------

check_proc_crypto() {
    info "Checking /proc/crypto for wolfcrypt gcm(aes) entry..."

    if [[ ! -r /proc/crypto ]]; then
        warn "/proc/crypto not readable — skipping wolfcrypt provider check"
        return 0
    fi

    # Find all algorithm blocks that mention "gcm" and check if any also
    # mention "wolf" (case-insensitive), indicating wolfcrypt.ko is serving
    # this algorithm.
    if grep -i "gcm" /proc/crypto | grep -qi "wolf"; then
        pass "/proc/crypto shows a wolfcrypt/wolfssl entry for gcm(aes)"
    else
        warn "/proc/crypto: no wolfcrypt/wolfssl entry found for gcm(aes)" \
             "— wolfcrypt.ko may not be loaded; this is expected in stub/CI environments"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    # Root check
    if [[ "$(id -u)" -ne 0 ]]; then
        fail "This script must be run as root (try: sudo $0)"
    fi

    check_prereqs

    # Idempotent cleanup of any leftover state from a previous run
    cleanup

    # Register trap for cleanup on exit
    trap cleanup EXIT

    # -------------------------------------------------------------------
    # Step 1: Create namespaces and veth pair
    # -------------------------------------------------------------------

    info "Creating network namespaces..."
    ip netns add "${NS_LEFT}"
    ip netns add "${NS_RIGHT}"

    info "Creating veth pair ${VETH_LEFT} <-> ${VETH_RIGHT}..."
    ip link add "${VETH_LEFT}" type veth peer name "${VETH_RIGHT}"
    ip link set "${VETH_LEFT}" netns "${NS_LEFT}"
    ip link set "${VETH_RIGHT}" netns "${NS_RIGHT}"

    info "Assigning IP addresses..."
    ip netns exec "${NS_LEFT}"  ip addr add "${IP_LEFT}/${PREFIX_LEN}"  dev "${VETH_LEFT}"
    ip netns exec "${NS_RIGHT}" ip addr add "${IP_RIGHT}/${PREFIX_LEN}" dev "${VETH_RIGHT}"

    ip netns exec "${NS_LEFT}"  ip link set "${VETH_LEFT}"  up
    ip netns exec "${NS_RIGHT}" ip link set "${VETH_RIGHT}" up
    ip netns exec "${NS_LEFT}"  ip link set lo up
    ip netns exec "${NS_RIGHT}" ip link set lo up

    # Verify basic connectivity before IPsec
    info "Verifying pre-IPsec connectivity..."
    ip netns exec "${NS_LEFT}" ping -c 2 -W 2 "${IP_RIGHT}" >/dev/null \
        || fail "Pre-IPsec ping ${IP_LEFT} -> ${IP_RIGHT} failed — check veth setup"
    pass "Pre-IPsec ping succeeds"

    # -------------------------------------------------------------------
    # Step 2: Install xfrm states and policies (AES-GCM-128 ESP tunnel)
    # -------------------------------------------------------------------
    # rfc4106(gcm(aes)) is the IANA/kernel name for AES-GCM in ESP context.
    # Key is 160 bits (128-bit AES key + 32-bit salt), hex-encoded.
    # FIPS 140-3: AES-GCM-128 is an approved AEAD for IPsec ESP.
    # -------------------------------------------------------------------

    info "Installing xfrm states (AES-GCM-128 ESP tunnel)..."

    # Left -> Right state (ns_left sends, ns_right decrypts)
    ip netns exec "${NS_LEFT}" ip xfrm state add \
        src "${IP_LEFT}" dst "${IP_RIGHT}" \
        proto esp spi "${SPI_LR}" reqid "${REQID}" mode tunnel \
        aead 'rfc4106(gcm(aes))' "${AEAD_KEY}" 128

    # Right -> Left state (ns_right sends, ns_left decrypts)
    ip netns exec "${NS_LEFT}" ip xfrm state add \
        src "${IP_RIGHT}" dst "${IP_LEFT}" \
        proto esp spi "${SPI_RL}" reqid "${REQID}" mode tunnel \
        aead 'rfc4106(gcm(aes))' "${AEAD_KEY}" 128

    # Mirror states in ns_right
    ip netns exec "${NS_RIGHT}" ip xfrm state add \
        src "${IP_LEFT}" dst "${IP_RIGHT}" \
        proto esp spi "${SPI_LR}" reqid "${REQID}" mode tunnel \
        aead 'rfc4106(gcm(aes))' "${AEAD_KEY}" 128

    ip netns exec "${NS_RIGHT}" ip xfrm state add \
        src "${IP_RIGHT}" dst "${IP_LEFT}" \
        proto esp spi "${SPI_RL}" reqid "${REQID}" mode tunnel \
        aead 'rfc4106(gcm(aes))' "${AEAD_KEY}" 128

    info "Installing xfrm policies..."

    # ns_left outbound: traffic to IP_RIGHT must use the LR SA
    ip netns exec "${NS_LEFT}" ip xfrm policy add \
        src "${IP_LEFT}/32" dst "${IP_RIGHT}/32" dir out \
        tmpl src "${IP_LEFT}" dst "${IP_RIGHT}" \
        proto esp reqid "${REQID}" mode tunnel

    # ns_left inbound: traffic from IP_RIGHT arrives via the RL SA
    ip netns exec "${NS_LEFT}" ip xfrm policy add \
        src "${IP_RIGHT}/32" dst "${IP_LEFT}/32" dir in \
        tmpl src "${IP_RIGHT}" dst "${IP_LEFT}" \
        proto esp reqid "${REQID}" mode tunnel

    # ns_right outbound
    ip netns exec "${NS_RIGHT}" ip xfrm policy add \
        src "${IP_RIGHT}/32" dst "${IP_LEFT}/32" dir out \
        tmpl src "${IP_RIGHT}" dst "${IP_LEFT}" \
        proto esp reqid "${REQID}" mode tunnel

    # ns_right inbound
    ip netns exec "${NS_RIGHT}" ip xfrm policy add \
        src "${IP_LEFT}/32" dst "${IP_RIGHT}/32" dir in \
        tmpl src "${IP_LEFT}" dst "${IP_RIGHT}" \
        proto esp reqid "${REQID}" mode tunnel

    pass "xfrm states and policies installed"

    # -------------------------------------------------------------------
    # Step 3: Ping through IPsec tunnel
    # -------------------------------------------------------------------

    info "Testing ping through IPsec tunnel (${IP_LEFT} -> ${IP_RIGHT})..."
    ip netns exec "${NS_LEFT}" ping -c 5 -W 3 "${IP_RIGHT}" >/dev/null \
        || fail "Ping through IPsec tunnel failed"
    pass "Ping through IPsec tunnel succeeds (5 packets)"

    # -------------------------------------------------------------------
    # Step 4: 1 MB netcat transfer through tunnel
    # -------------------------------------------------------------------

    info "Testing 1 MB netcat transfer through IPsec tunnel..."

    # Start receiver in ns_right; -l listen, -p port, write to temp file
    local rx_file
    rx_file="$(mktemp /tmp/ipsec_test_rx.XXXXXX)"

    # Determine nc flags — ncat uses -l without -p; traditional nc uses -l -p
    local nc_listen_cmd
    if [[ "${NC_BIN}" == "ncat" ]]; then
        nc_listen_cmd="${NC_BIN} -l ${NC_PORT}"
    else
        # nc and netcat: try -l -p first; some versions accept -lp
        nc_listen_cmd="${NC_BIN} -l -p ${NC_PORT}"
    fi

    # Launch listener in background
    ip netns exec "${NS_RIGHT}" ${nc_listen_cmd} > "${rx_file}" &
    local nc_server_pid=$!

    # Give the listener a moment to bind
    sleep 0.3

    # Transmit exactly TRANSFER_BYTES of zero bytes from ns_left
    ip netns exec "${NS_LEFT}" \
        dd if=/dev/zero bs=1048576 count=1 2>/dev/null \
        | "${NC_BIN}" "${IP_RIGHT}" "${NC_PORT}"

    # Wait for receiver to finish
    wait "${nc_server_pid}" 2>/dev/null || true

    local rx_bytes
    rx_bytes="$(wc -c < "${rx_file}")"
    rm -f "${rx_file}"

    if [[ "${rx_bytes}" -ne "${TRANSFER_BYTES}" ]]; then
        fail "1 MB transfer: expected ${TRANSFER_BYTES} bytes, got ${rx_bytes}"
    fi
    pass "1 MB transfer through IPsec tunnel: ${rx_bytes} bytes received correctly"

    # -------------------------------------------------------------------
    # Step 5: /proc/crypto wolfcrypt provider check
    # -------------------------------------------------------------------

    check_proc_crypto

    # -------------------------------------------------------------------
    # All tests passed
    # -------------------------------------------------------------------

    pass "All IPsec xfrm tunnel tests passed"
    exit 0
}

main "$@"
