#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# tests/ci/qemu_test.sh
#
# Local QEMU test harness for crypto2dev.ko.
#
# Boots a Debian bookworm cloud image in QEMU, builds crypto2dev in stub mode
# (no wolfCrypt required), loads the modules, verifies /dev/crypto2dev exists,
# and runs the userspace test suite.
#
# This harness is complementary to test-on-aws.sh: it runs locally without
# AWS credentials and is suitable for quick iteration on a development machine.
#
# ============================================================================
# PREREQUISITES
# ============================================================================
#
#   qemu-system-x86_64   — apt install qemu-system-x86
#   genisoimage           — apt install genisoimage  (for cloud-init seed ISO)
#   ssh, scp, rsync       — standard OpenSSH tools
#   wget                  — to download cloud image (once; then cached)
#
# ============================================================================
# ENVIRONMENT VARIABLES
# ============================================================================
#
#   QEMU_IMG_DIR    — image cache directory (default: ~/.cache/crypto2dev-qemu)
#   KERNEL_VERSIONS — documented for future multi-version support; this harness
#                     currently uses the Debian bookworm cloud image's built-in
#                     kernel (6.1 LTS) rather than downloading separate bzImages.
#                     The variable is accepted and printed but has no effect on
#                     which kernel is booted.
#   KEEP_VM         — set to 1 to leave QEMU running after the test (debugging)
#   QEMU_MEMORY     — VM RAM in megabytes (default: 2048)
#   QEMU_CPUS       — vCPU count (default: 2)
#
# ============================================================================
# USAGE
# ============================================================================
#
#   # From the wolfkm repo root:
#   ./tests/ci/qemu_test.sh
#
#   # Keep VM alive after test for manual debugging:
#   KEEP_VM=1 ./tests/ci/qemu_test.sh
#
#   # Custom image cache:
#   QEMU_IMG_DIR=/data/qemu-images ./tests/ci/qemu_test.sh
#
# ============================================================================

set -euo pipefail

# ── Help ──────────────────────────────────────────────────────────────────────

usage() {
    grep '^#' "$0" | grep -v '^#!/' | sed 's/^# \{0,2\}//' | \
        sed -n '/^tests\/ci\/qemu_test/,/^====*$/p'
    cat <<'EOF'
Usage: ./tests/ci/qemu_test.sh [--help]

  --help    Print this message and exit.

Environment variables: see header comment above.
EOF
}

for arg in "$@"; do
    case "$arg" in
        --help|-h) usage; exit 0 ;;
        *) echo "ERROR: unknown argument: $arg" >&2; usage >&2; exit 1 ;;
    esac
done

# ── Locate repo root ──────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WOLFKM_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ── Configuration ─────────────────────────────────────────────────────────────

QEMU_IMG_DIR="${QEMU_IMG_DIR:-$HOME/.cache/crypto2dev-qemu}"
KERNEL_VERSIONS="${KERNEL_VERSIONS:-5.15 6.8}"
KEEP_VM="${KEEP_VM:-0}"
QEMU_MEMORY="${QEMU_MEMORY:-2048}"
QEMU_CPUS="${QEMU_CPUS:-2}"

# Debian bookworm (12) genericcloud image — boots fast, ships openssh-server,
# comes with kernel 6.1 LTS.  The nocloud variant requires no cloud metadata
# service and accepts a local seed ISO for cloud-init.
DEBIAN_IMAGE_NAME="debian-12-genericcloud-amd64.qcow2"
DEBIAN_IMAGE_URL="https://cloud.debian.org/images/cloud/bookworm/latest/${DEBIAN_IMAGE_NAME}"

# SSH port: pick a random high port to allow concurrent test runs.
SSH_PORT=$(( 10000 + RANDOM % 20000 ))

# ── State ─────────────────────────────────────────────────────────────────────

QEMU_PID=""
SSH_KEY=""
WORK_DIR=""
TESTS_PASSED=0
TESTS_FAILED=0

# ── Logging helpers ───────────────────────────────────────────────────────────

log()  { echo "=== $(date +%H:%M:%S) $*"; }
pass() { echo "  PASS: $*"; TESTS_PASSED=$(( TESTS_PASSED + 1 )); }
fail() { echo "  FAIL: $*"; TESTS_FAILED=$(( TESTS_FAILED + 1 )); }
skip() { echo "  SKIP: $*"; }

# ── Cleanup ───────────────────────────────────────────────────────────────────

cleanup() {
    local rc=$?

    if [[ "$KEEP_VM" == "1" && -n "$QEMU_PID" ]]; then
        log "KEEP_VM=1 — QEMU left running (pid $QEMU_PID)"
        log "  SSH: ssh -p $SSH_PORT -i $SSH_KEY -o StrictHostKeyChecking=no root@localhost"
        log "  Kill: kill $QEMU_PID"
    elif [[ -n "$QEMU_PID" ]]; then
        if kill -0 "$QEMU_PID" 2>/dev/null; then
            log "Stopping QEMU (pid $QEMU_PID)..."
            kill "$QEMU_PID" 2>/dev/null || true
            # Wait briefly so the process actually exits before we return.
            local i
            for i in 1 2 3 4 5; do
                kill -0 "$QEMU_PID" 2>/dev/null || break
                sleep 1
            done
        fi
    fi

    if [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then
        rm -rf "$WORK_DIR"
    fi

    return $rc
}

trap cleanup EXIT

# ── Prerequisite check ────────────────────────────────────────────────────────

check_prerequisites() {
    local missing=0

    if ! command -v qemu-system-x86_64 &>/dev/null; then
        echo "SKIP: qemu-system-x86_64 not found."
        echo "      Install with: sudo apt install qemu-system-x86"
        exit 0
    fi

    for tool in ssh scp rsync wget genisoimage; do
        if ! command -v "$tool" &>/dev/null; then
            echo "ERROR: required tool not found: $tool" >&2
            missing=$(( missing + 1 ))
        fi
    done

    if [[ $missing -gt 0 ]]; then
        echo "Install missing tools and retry." >&2
        exit 1
    fi
}

# ── Image management ──────────────────────────────────────────────────────────

fetch_image() {
    mkdir -p "$QEMU_IMG_DIR"
    local dest="$QEMU_IMG_DIR/$DEBIAN_IMAGE_NAME"

    if [[ -f "$dest" ]]; then
        log "Cloud image already cached: $dest"
        return 0
    fi

    log "Downloading Debian bookworm cloud image..."
    log "  URL: $DEBIAN_IMAGE_URL"
    log "  Destination: $dest"
    wget --quiet --show-progress -O "${dest}.tmp" "$DEBIAN_IMAGE_URL"
    mv "${dest}.tmp" "$dest"
    log "Download complete: $(du -sh "$dest" | cut -f1)"
}

# Create a working copy of the image so the cached original stays pristine.
# The copy is placed in WORK_DIR and deleted on exit.
create_working_image() {
    log "Creating working copy of cloud image..."
    cp "$QEMU_IMG_DIR/$DEBIAN_IMAGE_NAME" "$WORK_DIR/disk.qcow2"
    # Resize to 8 GB to give the build enough space.
    qemu-img resize "$WORK_DIR/disk.qcow2" 8G &>/dev/null
    log "Working image ready: $(du -sh "$WORK_DIR/disk.qcow2" | cut -f1)"
}

# ── Cloud-init seed ISO ───────────────────────────────────────────────────────
#
# The Debian genericcloud image uses cloud-init for first-boot configuration.
# We inject:
#   - An SSH authorized key for the root account
#   - A root password (for console fallback during debugging)
#   - A hostname
#   - Package list: linux-headers, build-essential, rsync, kmod
#
# The nocloud datasource reads user-data and meta-data from a local ISO
# labeled "cidata".  We build the ISO with genisoimage.

create_seed_iso() {
    log "Generating cloud-init seed ISO..."

    # Generate an ephemeral SSH keypair for this run.
    ssh-keygen -t ed25519 -f "$WORK_DIR/id_ed25519" -N "" -C "crypto2dev-qemu-test" \
        -q 2>/dev/null
    SSH_KEY="$WORK_DIR/id_ed25519"
    local pubkey
    pubkey="$(cat "$WORK_DIR/id_ed25519.pub")"

    # meta-data: minimal cloud-init instance identity
    cat > "$WORK_DIR/meta-data" <<EOF
instance-id: crypto2dev-qemu-test
local-hostname: crypto2dev-qemu
EOF

    # user-data: configure root SSH access and install build deps on first boot
    cat > "$WORK_DIR/user-data" <<EOF
#cloud-config
users:
  - name: root
    lock_passwd: false
    ssh_authorized_keys:
      - ${pubkey}

ssh_pwauth: false
disable_root: false

# Grow the root partition to fill the resized disk on first boot.
growpart:
  mode: auto
  devices: [/]
resize_rootfs: true

# Install build dependencies during cloud-init so the VM is immediately
# ready to build kernel modules after SSH becomes available.
packages:
  - build-essential
  - linux-headers-amd64
  - rsync
  - kmod
  - gcc

package_update: true
package_upgrade: false

# Signal that cloud-init is done; speeds up boot detection.
final_message: "cloud-init done"
EOF

    genisoimage \
        -output "$WORK_DIR/seed.iso" \
        -volid cidata \
        -joliet \
        -rock \
        "$WORK_DIR/user-data" \
        "$WORK_DIR/meta-data" \
        2>/dev/null

    log "Seed ISO created: $(du -sh "$WORK_DIR/seed.iso" | cut -f1)"
}

# ── QEMU launch ───────────────────────────────────────────────────────────────

start_qemu() {
    log "Starting QEMU (memory: ${QEMU_MEMORY}M, cpus: ${QEMU_CPUS}, ssh port: ${SSH_PORT})..."

    qemu-system-x86_64 \
        -name "crypto2dev-qemu-test" \
        -m "${QEMU_MEMORY}" \
        -smp "${QEMU_CPUS}" \
        -nographic \
        -no-reboot \
        -drive "file=$WORK_DIR/disk.qcow2,format=qcow2,if=virtio,discard=unmap" \
        -drive "file=$WORK_DIR/seed.iso,format=raw,if=virtio,readonly=on" \
        -netdev "user,id=net0,hostfwd=tcp::${SSH_PORT}-:22" \
        -device "virtio-net-pci,netdev=net0" \
        -cpu host \
        -enable-kvm \
        -serial file:"$WORK_DIR/console.log" \
        &>/dev/null &

    QEMU_PID=$!
    log "QEMU started (pid $QEMU_PID)"
}

# ── SSH helpers ───────────────────────────────────────────────────────────────

vm_ssh() {
    ssh \
        -p "$SSH_PORT" \
        -i "$SSH_KEY" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 \
        -o ServerAliveInterval=15 \
        -o ServerAliveCountMax=6 \
        -o LogLevel=ERROR \
        "root@localhost" \
        "$@"
}

vm_ssh_script() {
    vm_ssh 'bash -s'
}

wait_for_ssh() {
    local max_seconds="${1:-180}"
    local deadline=$(( $(date +%s) + max_seconds ))
    local attempt=0

    log "Waiting for SSH (up to ${max_seconds}s)..."

    while (( $(date +%s) < deadline )); do
        attempt=$(( attempt + 1 ))
        if vm_ssh 'true' 2>/dev/null; then
            log "SSH ready after ${attempt} attempts"
            return 0
        fi

        # Check whether QEMU itself is still running.
        if ! kill -0 "$QEMU_PID" 2>/dev/null; then
            echo "ERROR: QEMU process exited unexpectedly" >&2
            echo "--- console.log ---" >&2
            tail -40 "$WORK_DIR/console.log" >&2 || true
            return 1
        fi

        sleep 5
    done

    echo "ERROR: SSH not available after ${max_seconds}s" >&2
    echo "--- console.log (last 40 lines) ---" >&2
    tail -40 "$WORK_DIR/console.log" >&2 || true
    return 1
}

# Wait for cloud-init to finish so that packages are installed before we
# proceed.  cloud-init writes /var/lib/cloud/instance/boot-finished on
# completion.  We poll for that file rather than sleeping a fixed duration.
wait_for_cloud_init() {
    local max_seconds="${1:-300}"
    local deadline=$(( $(date +%s) + max_seconds ))

    log "Waiting for cloud-init to complete (up to ${max_seconds}s)..."

    while (( $(date +%s) < deadline )); do
        if vm_ssh 'test -f /var/lib/cloud/instance/boot-finished' 2>/dev/null; then
            log "cloud-init complete"
            return 0
        fi
        sleep 10
    done

    echo "ERROR: cloud-init did not complete within ${max_seconds}s" >&2
    vm_ssh 'cloud-init status --long 2>/dev/null || true' >&2 || true
    return 1
}

# ── Build phase ───────────────────────────────────────────────────────────────

upload_source() {
    log "Uploading wolfkm source tree..."
    rsync \
        --archive \
        --exclude='.git' \
        --exclude='*.o' \
        --exclude='*.ko' \
        --exclude='.tmp_versions' \
        --exclude='Module.symvers' \
        --exclude='modules.order' \
        --exclude='*.mod' \
        --exclude='*.mod.c' \
        --rsh="ssh -p $SSH_PORT -i $SSH_KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR" \
        "$WOLFKM_ROOT/" \
        "root@localhost:/root/wolfkm/"
    log "Upload complete"
    pass "Source tree uploaded"
}

build_stub_mode() {
    log "Building crypto2dev in stub mode (no wolfCrypt)..."

    vm_ssh_script <<'BUILD'
set -euo pipefail
cd /root/wolfkm

KVER=$(uname -r)
echo "Kernel: $KVER"

# Verify kernel headers are present.
if [ ! -d "/lib/modules/${KVER}/build" ]; then
    echo "ERROR: kernel headers not found at /lib/modules/${KVER}/build" >&2
    exit 1
fi

# Build framework + kcapi provider; no WOLFCRYPT_DIR means stub mode.
make -C "/lib/modules/${KVER}/build" M="$(pwd)" modules 2>&1 | tail -10

echo "Build output:"
ls -lh crypto2dev.ko crypto2dev_kcapi.ko
BUILD

    pass "crypto2dev.ko and crypto2dev_kcapi.ko built in stub mode"
}

# ── Module load phase ─────────────────────────────────────────────────────────

load_modules() {
    log "Loading crypto2dev.ko and crypto2dev_kcapi.ko..."

    vm_ssh_script <<'LOAD'
set -euo pipefail

# Load framework module first.
insmod /root/wolfkm/crypto2dev.ko
echo "crypto2dev.ko loaded"

# Load kcapi provider (uses kernel's built-in algorithms; no wolfCrypt needed).
insmod /root/wolfkm/crypto2dev_kcapi.ko
echo "crypto2dev_kcapi.ko loaded"

lsmod | grep crypto2dev
LOAD

    pass "Modules loaded"
}

# ── Acceptance criteria ───────────────────────────────────────────────────────

check_chardev_exists() {
    log "Checking /dev/crypto2dev..."

    if vm_ssh 'test -c /dev/crypto2dev' 2>/dev/null; then
        pass "/dev/crypto2dev character device exists"
    else
        fail "/dev/crypto2dev not found after module load"
        vm_ssh 'dmesg | tail -20 || true' || true
        return 1
    fi
}

run_open_ioctl_sanity() {
    log "Running open/ioctl sanity check..."

    # Use test_chardev if it was built, otherwise do a minimal inline check.
    if vm_ssh 'test -x /root/wolfkm/tests/userspace/test_chardev' 2>/dev/null; then
        log "  Using test_chardev binary"
        if vm_ssh 'cd /root/wolfkm/tests/userspace && ./test_chardev' 2>/dev/null; then
            pass "test_chardev passed"
        else
            fail "test_chardev failed"
        fi
    else
        # Build userspace tests inside the VM.
        log "  Building userspace tests inside VM..."
        vm_ssh_script <<'BUILD_TESTS'
set -euo pipefail
cd /root/wolfkm/tests/userspace
make 2>&1 | tail -5
echo "Userspace tests built"
BUILD_TESTS

        if vm_ssh 'cd /root/wolfkm/tests/userspace && ./test_chardev' 2>/dev/null; then
            pass "test_chardev passed"
        else
            fail "test_chardev failed"
        fi
    fi
}

check_dmesg_clean() {
    log "Checking dmesg for BUG/Oops..."

    if vm_ssh 'dmesg | grep -qE "BUG:|Oops:|kernel BUG"' 2>/dev/null; then
        fail "kernel BUG or Oops detected in dmesg"
        vm_ssh 'dmesg | grep -E "BUG:|Oops:|kernel BUG" | head -20 || true' || true
    else
        pass "No kernel BUG or Oops in dmesg"
    fi
}

# ── Diagnostics (always printed) ──────────────────────────────────────────────

print_diagnostics() {
    log "Diagnostics"
    echo "--- kernel version ---"
    vm_ssh 'uname -r' || true
    echo "--- loaded modules ---"
    vm_ssh 'lsmod | grep crypto2dev || echo "(none)"' || true
    echo "--- dmesg (crypto2dev) ---"
    vm_ssh 'dmesg | grep -i crypto2dev | tail -20 || echo "(none)"' || true
}

# ── Main ──────────────────────────────────────────────────────────────────────

main() {
    log "crypto2dev QEMU test harness"
    log "  Repo:            $WOLFKM_ROOT"
    log "  Image cache:     $QEMU_IMG_DIR"
    log "  KERNEL_VERSIONS: $KERNEL_VERSIONS (informational; boot uses cloud image kernel)"
    log "  SSH port:        $SSH_PORT"

    check_prerequisites

    WORK_DIR="$(mktemp -d /tmp/crypto2dev-qemu-XXXXXX)"
    log "Work directory: $WORK_DIR"

    # Phase 1: prepare image
    fetch_image
    create_working_image
    create_seed_iso

    # Phase 2: boot VM
    start_qemu
    wait_for_ssh 180
    wait_for_cloud_init 300

    KVER=$(vm_ssh 'uname -r')
    log "VM kernel: $KVER"

    # Phase 3: build
    upload_source
    build_stub_mode

    # Phase 4: load and verify
    load_modules
    check_chardev_exists
    run_open_ioctl_sanity
    check_dmesg_clean

    # Phase 5: diagnostics
    print_diagnostics

    # ── Summary ───────────────────────────────────────────────────────────────

    echo ""
    echo "======================================================"
    echo " crypto2dev QEMU stub-mode test results"
    echo " Kernel:  $KVER"
    echo " Passed:  $TESTS_PASSED"
    echo " Failed:  $TESTS_FAILED"
    echo "======================================================"

    [[ $TESTS_FAILED -eq 0 ]] || exit 1
}

main "$@"
