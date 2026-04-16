#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# tests/ci/test-on-aws.sh
#
# Provisions an EC2 instance, builds wolfSSL as a kernel module (wolfcrypt.ko),
# uploads this wolfkm repo, builds wolfkm.ko, loads both modules, and runs the
# test suite.  Tears everything down unless KEEP_INSTANCE=1.
#
# Mirrors the structure of build-test-wolfguard-aws.sh (in ~/TICKETS/zScalar/).
# wolfkm does not require Ubuntu Pro / FIPS kernel; standard Ubuntu kernels work.
# Use UBUNTU_VERSION=22.04 for kernel 5.15 or UBUNTU_VERSION=24.04 for 6.8+.
#
# ============================================================================
# PREREQUISITES
# ============================================================================
#
#   1. AWS CLI v2 installed and configured:
#        aws configure sso
#        aws sso login --profile <your-profile>
#
#   2. IAM permissions:
#        ec2:RunInstances, TerminateInstances, DescribeInstances,
#        DescribeImages, DescribeVpcs,
#        ec2:CreateKeyPair, DeleteKeyPair,
#        ec2:CreateSecurityGroup, DeleteSecurityGroup,
#        ec2:AuthorizeSecurityGroupIngress, ec2:CreateTags,
#        sts:GetCallerIdentity
#
#   3. rsync installed locally (to upload wolfkm source tree)
#
# ============================================================================
# ENVIRONMENT VARIABLES
# ============================================================================
#
#   Required:
#     AWS_PROFILE       — AWS CLI profile name (or pass as $1)
#
#   Optional:
#     AWS_REGION        — default: us-west-2
#     INSTANCE_TYPE     — default: c5.2xlarge (8 vCPU, 16 GB — fast build)
#     DISK_SIZE_GB      — default: 30
#     DISTRO            — ubuntu|fedora|debian|centos|rocky|rhel|al2023 (default: ubuntu)
#                         ubuntu: Ubuntu 22.04/24.04, apt-get, user=ubuntu
#                         fedora: Fedora latest, dnf, user=fedora
#                         debian: Debian 12 Bookworm, apt-get, user=admin
#                         centos: CentOS Stream 9, dnf, user=ec2-user
#                         rocky:  Rocky Linux 9, dnf, user=rocky
#                         rhel:   RHEL 9 PAYG (AWS Marketplace), dnf, user=ec2-user
#                         al2023: Amazon Linux 2023, dnf, user=ec2-user
#     UBUNTU_VERSION    — 22.04 or 24.04 (ubuntu distro only, default: 22.04)
#     ARM64             — set to 1 for ARM64/Graviton (ubuntu only, uses c7g.2xlarge)
#     FIPS_MODE         — set to 1 to enable FIPS kernel/mode before testing
#                         Ubuntu: requires UA_TOKEN (Ubuntu Pro attach + fips-updates)
#                         Rocky/CentOS/RHEL/AL2023: fips-mode-setup + reboot (no token)
#     UA_TOKEN          — Ubuntu Pro attach token (required for Ubuntu FIPS)
#     WOLFSSL_REPO      — default: https://github.com/wolfSSL/wolfssl
#     WOLFSSL_REF       — default: master
#     WOLFKM_WOLFCRYPT_KO_NAME
#                       — name of the wolfSSL linuxkm module (default: libwolfssl)
#                         Set to match whatever MODULE_SOFTDEP wolfkm declares
#     KEEP_INSTANCE     — set to 1 to leave instance running for debugging
#     SSH_KEY_PATH      — where to store ephemeral SSH key (default: /tmp)
#     KASAN_BUILD       — set to 1 to build and boot a KASAN+lockdep kernel
#                         before running tests (Ubuntu only). Adds ~45-60 min.
#                         Catches: use-after-free (KASAN), lock ordering violations
#                         (PROVE_LOCKING), sleeping-in-atomic (DEBUG_ATOMIC_SLEEP).
#                         Kernel config: CONFIG_KASAN=y, CONFIG_PROVE_LOCKING=y,
#                         CONFIG_DEBUG_ATOMIC_SLEEP=y.
#
# ============================================================================
# USAGE
# ============================================================================
#
#   # From the wolfkm repo root:
#   ./tests/ci/test-on-aws.sh AdministratorAccess-921772462201
#
#   # Ubuntu 24.04 (kernel 6.8):
#   UBUNTU_VERSION=24.04 ./tests/ci/test-on-aws.sh <profile>
#
#   # Other distros:
#   DISTRO=fedora  ./tests/ci/test-on-aws.sh <profile>
#   DISTRO=debian  ./tests/ci/test-on-aws.sh <profile>
#   DISTRO=centos  ./tests/ci/test-on-aws.sh <profile>
#   DISTRO=rocky   ./tests/ci/test-on-aws.sh <profile>
#   DISTRO=al2023  ./tests/ci/test-on-aws.sh <profile>
#
#   # FIPS mode (Rocky/RHEL-family — no token needed):
#   DISTRO=rocky FIPS_MODE=1 ./tests/ci/test-on-aws.sh <profile>
#   DISTRO=rhel  FIPS_MODE=1 ./tests/ci/test-on-aws.sh <profile>
#
#   # Ubuntu FIPS (requires Ubuntu Pro token):
#   FIPS_MODE=1 UA_TOKEN=<token> ./tests/ci/test-on-aws.sh <profile>
#
#   # ARM64 / Graviton 3 (Ubuntu only):
#   ARM64=1 ./tests/ci/test-on-aws.sh <profile>
#
#   # Keep instance alive after test for debugging:
#   KEEP_INSTANCE=1 ./tests/ci/test-on-aws.sh <profile>
#
#   # KASAN + lockdep kernel (Ubuntu only, adds ~60 min):
#   KASAN_BUILD=1 ./tests/ci/test-on-aws.sh <profile>
#
# ============================================================================

set -euo pipefail

# ── Locate wolfkm repo root ──────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WOLFKM_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ── Parameters ───────────────────────────────────────────────────────────────

AWS_PROFILE="${1:-${AWS_PROFILE:-}}"
if [[ -z "$AWS_PROFILE" ]]; then
    echo "ERROR: AWS_PROFILE not set."
    echo "Usage: $0 <aws-profile>"
    exit 1
fi

AWS_REGION="${AWS_REGION:-us-west-2}"
# ARM64=1: use ARM64 AMI and Graviton instance type instead of x86-64.
ARM64="${ARM64:-0}"
INSTANCE_TYPE="${INSTANCE_TYPE:-}"    # set per ARM64 below if not overridden
# KASAN kernel build needs ~50+ GB: 5 GB base + 1 GB source + 10–15 GB KASAN
# build objects + 5 GB debian staging dir + wolfSSL/wolfkm builds.
# Standard distro tests fit in 30 GB.
if [[ "${KASAN_BUILD:-0}" == "1" ]]; then
    DISK_SIZE_GB="${DISK_SIZE_GB:-60}"
else
    DISK_SIZE_GB="${DISK_SIZE_GB:-30}"
fi
DISTRO="${DISTRO:-ubuntu}"
UBUNTU_VERSION="${UBUNTU_VERSION:-22.04}"
WOLFSSL_REPO="${WOLFSSL_REPO:-https://github.com/wolfSSL/wolfssl}"
WOLFSSL_REF="${WOLFSSL_REF:-master}"
WOLFKM_WOLFCRYPT_KO_NAME="${WOLFKM_WOLFCRYPT_KO_NAME:-libwolfssl}"
KEEP_INSTANCE="${KEEP_INSTANCE:-0}"
SSH_KEY_PATH="${SSH_KEY_PATH:-/tmp}"
KASAN_BUILD="${KASAN_BUILD:-0}"
# FIPS_MODE=1: enable FIPS kernel/mode before building.
# Ubuntu: requires UA_TOKEN (Ubuntu Pro attach + fips-updates + reboot).
# Rocky/CentOS/RHEL-family: uses fips-mode-setup + reboot (no token needed).
FIPS_MODE="${FIPS_MODE:-0}"
PRO_TOKEN="${UA_TOKEN:-${PRO_TOKEN:-}}"

# ── Distro-specific settings ──────────────────────────────────────────────────
# AMI_OWNER / AMI_NAME_PATTERN: passed to describe-images for latest-AMI lookup.
# INSTANCE_USER: SSH login user for the launched instance.
# PKG_FAMILY: apt or dnf — selects BUILD_DEPS branch.

case "$DISTRO" in
    ubuntu)
        case "$UBUNTU_VERSION" in
            22.04) AMI_NAME_PATTERN="ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*" ;;
            # Ubuntu 24.04 (Noble) moved from hvm-ssd to hvm-ssd-gp3 storage type
            24.04) AMI_NAME_PATTERN="ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*" ;;
            *) echo "ERROR: UBUNTU_VERSION must be 22.04 or 24.04"; exit 1 ;;
        esac
        AMI_OWNER="099720109477"
        INSTANCE_USER="ubuntu"
        PKG_FAMILY="apt"
        ;;
    fedora)
        # Fedora Cloud official AMIs (Fedora project AWS account)
        AMI_OWNER="125523088429"
        AMI_NAME_PATTERN="Fedora-Cloud-Base-*x86_64*"
        INSTANCE_USER="fedora"
        PKG_FAMILY="dnf"
        ;;
    debian)
        # Debian official AMIs (Debian project AWS account)
        AMI_OWNER="136693071363"
        AMI_NAME_PATTERN="debian-12-amd64-*"
        INSTANCE_USER="admin"
        PKG_FAMILY="apt"
        ;;
    centos)
        # CentOS Stream 9 official AMIs (owner 125523088429 = CentOS project)
        AMI_OWNER="125523088429"
        AMI_NAME_PATTERN="CentOS Stream 9 x86_64*"
        INSTANCE_USER="ec2-user"
        PKG_FAMILY="dnf"
        ;;
    rocky)
        # Rocky Linux 9 official AMIs (Rocky Linux Foundation)
        AMI_OWNER="792107900819"
        AMI_NAME_PATTERN="Rocky-9-EC2-Base-9.*x86_64"
        INSTANCE_USER="rocky"
        PKG_FAMILY="dnf"
        ;;
    rhel)
        # RHEL 9 via AWS Marketplace PAYG (Red Hat Inc.)
        # Hourly RHEL subscription cost is baked into the EC2 price.
        AMI_OWNER="309956199498"
        AMI_NAME_PATTERN="RHEL-9.*_HVM-*-x86_64-*-Hourly2-GP3"
        INSTANCE_USER="ec2-user"
        PKG_FAMILY="dnf"
        ;;
    al2023)
        # Amazon Linux 2023 — kernel-6.1 variant (stable; 6.12 and 6.18 also available)
        AMI_OWNER="137112412989"
        AMI_NAME_PATTERN="al2023-ami-2023*kernel-6.1-x86_64"
        INSTANCE_USER="ec2-user"
        PKG_FAMILY="dnf"
        ;;
    *)
        echo "ERROR: DISTRO must be ubuntu|fedora|debian|centos|rocky|rhel|al2023, got: $DISTRO"
        exit 1
        ;;
esac

# ── ARM64 / Graviton overrides ────────────────────────────────────────────────
#
# ARM64=1: switch to the arm64 AMI variant (same distro, different arch) and
# use a Graviton 3 instance (c7g.2xlarge).  Currently only Ubuntu is supported.
# The AMI name pattern replaces 'amd64'/'x86_64' with 'arm64'/'aarch64'.

if [[ "$ARM64" == "1" ]]; then
    if [[ "$DISTRO" != "ubuntu" ]]; then
        echo "ERROR: ARM64=1 is currently only supported for DISTRO=ubuntu" >&2
        exit 1
    fi
    # Ubuntu 22.04 ARM64 AMI — same owner, arch in the name
    case "$UBUNTU_VERSION" in
        22.04) AMI_NAME_PATTERN="ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-arm64-server-*" ;;
        24.04) AMI_NAME_PATTERN="ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-arm64-server-*" ;;
    esac
    : "${INSTANCE_TYPE:=c7g.2xlarge}"   # Graviton 3; override with INSTANCE_TYPE=
    RUN_ID_SUFFIX="-arm64"
    KERN_ARCH="arm64"
    # No Intel ASM on ARM64; wolfSSL auto-detects ARM features via --enable-armasm
    WOLFSSL_ASM_OPT=""
else
    : "${INSTANCE_TYPE:=c5.2xlarge}"
    RUN_ID_SUFFIX=""
    KERN_ARCH="x86_64"
    WOLFSSL_ASM_OPT="--enable-intelasm"
fi

# ── AWS CLI shorthand ─────────────────────────────────────────────────────────

A="--profile $AWS_PROFILE --region $AWS_REGION"

# ── Run ID and ephemeral resource names ──────────────────────────────────────

RUN_ID="wolfkm-${DISTRO}${RUN_ID_SUFFIX}-$(date +%Y%m%d-%H%M%S)"
KEY_NAME="$RUN_ID"
SG_NAME="$RUN_ID"
KEY_FILE="$SSH_KEY_PATH/${RUN_ID}.pem"

INSTANCE_ID=""
SG_ID=""
PUBLIC_IP=""

# ── Test counters ─────────────────────────────────────────────────────────────

TESTS_PASSED=0
TESTS_FAILED=0

# ── Logging helpers ───────────────────────────────────────────────────────────

log()  { echo "=== $(date +%H:%M:%S) $*"; }
pass() { echo "  PASS: $*"; TESTS_PASSED=$((TESTS_PASSED + 1)); }
fail() { echo "  FAIL: $*"; TESTS_FAILED=$((TESTS_FAILED + 1)); }
skip() { echo "  SKIP: $*"; }

# ── SSH helpers ───────────────────────────────────────────────────────────────

remote() {
    ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=10 \
        -o ServerAliveInterval=30 \
        -o ServerAliveCountMax=6 \
        -i "$KEY_FILE" \
        "${INSTANCE_USER}@$PUBLIC_IP" \
        "$@"
}

remote_script() {
    ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=10 \
        -o ServerAliveInterval=30 \
        -o ServerAliveCountMax=6 \
        -i "$KEY_FILE" \
        "${INSTANCE_USER}@$PUBLIC_IP" \
        'bash -s'
}

wait_for_ssh() {
    local attempts="${1:-36}"   # default 3 minutes
    for i in $(seq 1 "$attempts"); do
        if remote 'true' 2>/dev/null; then return 0; fi
        sleep 5
    done
    echo "ERROR: SSH not available after $((attempts * 5)) seconds"
    return 1
}

# Like wait_for_ssh but streams EC2 serial console output while waiting.
# Useful after a reboot to see what the kernel is doing.
wait_for_ssh_with_console() {
    local max_wait="${1:-300}"
    local poll=10
    local seen_lines=0
    local deadline=$(( $(date +%s) + max_wait ))

    echo "--- streaming EC2 serial console (max ${max_wait}s) ---"

    while (( $(date +%s) < deadline )); do
        if remote 'true' 2>/dev/null; then
            echo "--- SSH ready ---"
            return 0
        fi

        local out
        out=$(aws ec2 get-console-output $A \
                  --instance-id "$INSTANCE_ID" --latest \
                  --output text 2>/dev/null || true)
        if [[ -n "$out" ]]; then
            local total
            total=$(echo "$out" | wc -l)
            if (( total > seen_lines )); then
                echo "$out" | tail -n "+$(( seen_lines + 1 ))"
                seen_lines=$total
            fi
        fi

        sleep $poll
    done

    echo "ERROR: SSH not available after ${max_wait}s"
    return 1
}

# ── Cleanup ────────────────────────────────────────────────────────────────────

cleanup() {
    local rc=$?
    echo ""
    log "Cleanup"

    if [[ "$KEEP_INSTANCE" == "1" && -n "$INSTANCE_ID" ]]; then
        log "KEEP_INSTANCE=1 — instance left running"
        log "  Instance: $INSTANCE_ID ($PUBLIC_IP)"
        log "  SSH:      ssh -i $KEY_FILE ${INSTANCE_USER}@$PUBLIC_IP"
        log "  Terminate: aws ec2 terminate-instances $A --instance-ids $INSTANCE_ID"
        return $rc
    fi

    if [[ -n "$INSTANCE_ID" ]]; then
        log "Terminating $INSTANCE_ID..."
        aws ec2 terminate-instances $A --instance-ids "$INSTANCE_ID" \
            --query 'TerminatingInstances[0].CurrentState.Name' \
            --output text 2>/dev/null || true
        aws ec2 wait instance-terminated $A \
            --instance-ids "$INSTANCE_ID" 2>/dev/null || sleep 30
    fi

    [[ -n "${KEY_NAME:-}" ]] && \
        aws ec2 delete-key-pair $A --key-name "$KEY_NAME" 2>/dev/null || true
    [[ -n "${SG_ID:-}" ]] && \
        aws ec2 delete-security-group $A --group-id "$SG_ID" 2>/dev/null || true
    rm -f "$KEY_FILE"

    log "Cleanup complete"
    return $rc
}

trap cleanup EXIT

# ── Phase 0: Provision EC2 ────────────────────────────────────────────────────

log "Verifying AWS credentials (profile: $AWS_PROFILE, region: $AWS_REGION)"
CALLER=$(aws sts get-caller-identity $A --query 'Arn' --output text)
log "Authenticated as: $CALLER"

log "Finding latest $DISTRO AMI..."
AMI_ID=$(aws ec2 describe-images $A \
    --owners "$AMI_OWNER" \
    --filters \
        "Name=name,Values=$AMI_NAME_PATTERN" \
        "Name=state,Values=available" \
    --query 'Images | sort_by(@, &CreationDate) | [-1].ImageId' \
    --output text)
if [[ -z "$AMI_ID" || "$AMI_ID" == "None" ]]; then
    echo "ERROR: No AMI found for distro=$DISTRO owner=$AMI_OWNER pattern=$AMI_NAME_PATTERN"
    exit 1
fi
log "AMI: $AMI_ID"

log "Creating SSH key pair: $KEY_NAME"
aws ec2 create-key-pair $A \
    --key-name "$KEY_NAME" \
    --key-type rsa \
    --key-format pem \
    --query 'KeyMaterial' \
    --output text > "$KEY_FILE"
chmod 600 "$KEY_FILE"

log "Creating security group: $SG_NAME"
VPC_ID=$(aws ec2 describe-vpcs $A \
    --filters "Name=is-default,Values=true" \
    --query 'Vpcs[0].VpcId' --output text)
SG_ID=$(aws ec2 create-security-group $A \
    --group-name "$SG_NAME" \
    --description "wolfkm-test ($RUN_ID)" \
    --vpc-id "$VPC_ID" \
    --query 'GroupId' --output text)
aws ec2 authorize-security-group-ingress $A \
    --group-id "$SG_ID" \
    --protocol tcp --port 22 --cidr 0.0.0.0/0 > /dev/null

log "Launching $INSTANCE_TYPE instance ($DISTRO)..."
INSTANCE_ID=$(aws ec2 run-instances $A \
    --image-id "$AMI_ID" \
    --instance-type "$INSTANCE_TYPE" \
    --key-name "$KEY_NAME" \
    --security-group-ids "$SG_ID" \
    --block-device-mappings \
        "[{\"DeviceName\":\"/dev/sda1\",\"Ebs\":{\"VolumeSize\":${DISK_SIZE_GB},\"VolumeType\":\"gp3\"}}]" \
    --tag-specifications \
        "ResourceType=instance,Tags=[{Key=Name,Value=$RUN_ID},{Key=Project,Value=wolfkm}]" \
    --query 'Instances[0].InstanceId' \
    --output text)
log "Instance: $INSTANCE_ID"

log "Waiting for instance to be running..."
aws ec2 wait instance-running $A --instance-ids "$INSTANCE_ID"

PUBLIC_IP=$(aws ec2 describe-instances $A \
    --instance-ids "$INSTANCE_ID" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' \
    --output text)
log "Public IP: $PUBLIC_IP"

log "Waiting for SSH..."
wait_for_ssh_with_console 300
KVER=$(remote 'uname -r')
log "Connected. Kernel: $KVER"

# ── Phase 0.5: FIPS enable (optional) ────────────────────────────────────────
#
# When FIPS_MODE=1, enable the FIPS kernel/mode and reboot before building.
# Ubuntu: Ubuntu Pro attach + fips-updates + reboot → switches to 5.15-fips kernel.
# DNF-family (Rocky/CentOS/RHEL): fips-mode-setup --enable + reboot (same kernel,
#   FIPS enforcement active).  No token needed for RHEL-family.

if [[ "$FIPS_MODE" == "1" ]]; then
    if [[ "$DISTRO" == "ubuntu" ]]; then
        if [[ -z "$PRO_TOKEN" ]]; then
            echo "ERROR: UA_TOKEN is required for Ubuntu FIPS (export UA_TOKEN=<ubuntu-pro-token>)" >&2
            exit 1
        fi
        log "Enabling Ubuntu Pro FIPS (this takes several minutes)..."
        remote_script <<FIPS_ENABLE_UBUNTU
set -eo pipefail
sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    ubuntu-advantage-tools daemonize > /dev/null 2>&1
sudo pro attach "${PRO_TOKEN}" --no-auto-enable
sudo pro enable esm-apps esm-infra --assume-yes
sudo DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y -qq > /dev/null 2>&1
sudo pro enable fips-updates --assume-yes
echo "Ubuntu Pro FIPS enabled — reboot pending"
FIPS_ENABLE_UBUNTU
        pass "Ubuntu Pro FIPS enabled"

        log "Rebooting into FIPS kernel..."
        remote 'sudo reboot' 2>/dev/null || true
        sleep 10
        wait_for_ssh_with_console 600

        KVER=$(remote 'uname -r')
        log "FIPS kernel: $KVER"
        if [[ "$KVER" != *"-fips" ]]; then
            fail "Expected -fips kernel after reboot, got: $KVER"
        fi
        pass "Rebooted into FIPS kernel: $KVER"

    elif [[ "$PKG_FAMILY" == "dnf" ]]; then
        log "Enabling FIPS mode (fips-mode-setup)..."
        remote_script <<FIPS_ENABLE_DNF
set -eo pipefail
# fips-mode-setup is in crypto-policies-scripts on RHEL-family
sudo dnf install -y -q crypto-policies-scripts > /dev/null 2>&1 || true
sudo fips-mode-setup --enable
echo "FIPS mode enabled — reboot pending"
FIPS_ENABLE_DNF
        pass "FIPS mode enabled"

        log "Rebooting into FIPS mode..."
        remote 'sudo reboot' 2>/dev/null || true
        sleep 10
        wait_for_ssh_with_console 300

        KVER=$(remote 'uname -r')
        log "Post-FIPS reboot kernel: $KVER"
        remote 'fips-mode-setup --check' || fail "FIPS mode not active after reboot"
        pass "FIPS mode active: $KVER"

    else
        echo "ERROR: FIPS_MODE=1 is not supported for PKG_FAMILY=$PKG_FAMILY" >&2
        exit 1
    fi
fi

# ── Phase 0.8: Kernel/kernel-devel version alignment (DNF-family only) ───────
#
# On RHEL AMIs, the running kernel may predate the latest kernel-devel in RHUI.
# Building a module against mismatched kernel-devel produces a wrong vermagic
# string, causing insmod to reject the module with "Invalid module format".
# Fix: update the kernel to match the latest available and reboot if needed.
# On Rocky/AL2023/Fedora where the AMI is already current, dnf reports
# "nothing to do" and no reboot occurs.
#
# FIPS note: on RHEL, fips=1 is a persistent GRUB boot parameter that survives
# a kernel update + reboot, so FIPS mode remains active after this step.

if [[ "$PKG_FAMILY" == "dnf" ]]; then
    log "Ensuring kernel/kernel-devel version alignment..."
    KVER_BEFORE=$(remote 'uname -r')
    remote 'sudo dnf update -y -q kernel kernel-core kernel-modules >/dev/null 2>&1 || true'
    LATEST_KVER=$(remote 'rpm -q --last kernel 2>/dev/null | head -1 | sed "s/kernel-//;s/ .*//"')
    if [[ -n "$LATEST_KVER" && "$LATEST_KVER" != "$KVER_BEFORE" ]]; then
        log "Kernel updated from ${KVER_BEFORE} to ${LATEST_KVER}, rebooting..."
        remote 'sudo reboot' 2>/dev/null || true
        sleep 10
        wait_for_ssh_with_console 300
        KVER=$(remote 'uname -r')
        log "Rebooted into kernel: $KVER"
        pass "Kernel updated to match kernel-devel: $KVER"
    else
        log "Kernel already current: $KVER_BEFORE"
    fi
fi

# ── Phase 1: Build dependencies ───────────────────────────────────────────────
#
# gcc-12 for Ubuntu 24.04 (kernel 6.8+); gcc-11 for Ubuntu 22.04 (kernel 5.15).
# gawk: wolfSSL linuxkm Makefile uses gawk-specific syntax; Ubuntu ships mawk.
# openssl/libssl-dev: required for scripts/sign-file (kernel module signing).
# linux-headers: install after boot so we get the right version.
# NOTE: for Ubuntu FIPS, KVER is now the -fips kernel — headers must match.

KMAJ=$(remote 'uname -r | cut -d. -f1')
# Ubuntu uses versioned gcc (gcc-12 for 6.x kernels, gcc-11 for 5.x).
# Other distros ship a suitable default gcc.
if [[ "$DISTRO" == "ubuntu" ]]; then
    if [[ "$KMAJ" -ge 6 ]]; then KGCC=gcc-12; else KGCC=gcc-11; fi
else
    KGCC=gcc
fi
log "Kernel major: $KMAJ — using compiler: $KGCC"

log "Installing build dependencies..."
if [[ "$PKG_FAMILY" == "apt" ]]; then
    remote_script <<BUILD_DEPS_APT
set -eo pipefail
# Retry apt-get update: on fresh EC2 instances the apt cache may not be
# initialized yet, causing transient GPG InRelease signature split errors.
APT_OK=0
for attempt in 1 2 3; do
    if sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq; then
        APT_OK=1
        break
    fi
    echo "apt-get update attempt \${attempt} failed; retrying in 10s..."
    sleep 10
done
[ "\${APT_OK}" = "1" ] || { echo "apt-get update failed after 3 attempts"; exit 1; }
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    build-essential autoconf automake libtool \
    gcc-11 gcc-12 \
    gawk git kmod rsync \
    openssl libssl-dev \
    dwarves \
    linux-headers-\$(uname -r) > /dev/null 2>&1
echo "Build dependencies installed"
BUILD_DEPS_APT
elif [[ "$PKG_FAMILY" == "dnf" ]]; then
    remote_script <<BUILD_DEPS_DNF
set -eo pipefail
# Retry dnf: on fresh instances the dnf cache may not be initialized.
DNF_OK=0
for attempt in 1 2 3; do
    if sudo dnf makecache -q; then
        DNF_OK=1
        break
    fi
    echo "dnf makecache attempt \${attempt} failed; retrying in 10s..."
    sleep 10
done
[ "\${DNF_OK}" = "1" ] || { echo "dnf makecache failed after 3 attempts"; exit 1; }
# CRB (CodeReady Builder) repo: Rocky Linux uses 'crb'; RHEL PAYG (RHUI) uses a
# different name.  Try both — one will be a no-op on whichever distro this is.
# Fedora/AL2023 have all packages in default repos; this is harmless for them.
sudo dnf config-manager --set-enabled crb > /dev/null 2>&1 || \
sudo dnf config-manager --set-enabled \
    "codeready-builder-for-rhel-9-rhui-rpms" > /dev/null 2>&1 || true
# kernel-devel must match the running kernel exactly.
KVER=\$(uname -r)
sudo dnf install -y -q \
    make gcc gcc-c++ \
    autoconf automake libtool \
    gawk git kmod rsync \
    openssl openssl-devel \
    dwarves \
    elfutils-libelf-devel \
    glibc-static \
    kernel-devel-\${KVER} > /dev/null 2>&1 || \
sudo dnf install -y -q \
    make gcc gcc-c++ \
    autoconf automake libtool \
    gawk git kmod rsync \
    openssl openssl-devel \
    dwarves \
    elfutils-libelf-devel \
    glibc-static \
    kernel-devel > /dev/null 2>&1
echo "Build dependencies installed"
BUILD_DEPS_DNF
fi

pass "Build dependencies installed"

# ── Phase 1.5: Build and boot KASAN+lockdep kernel ───────────────────────────
#
# Builds a custom kernel with CONFIG_KASAN=y, CONFIG_PROVE_LOCKING=y,
# CONFIG_DEBUG_ATOMIC_SLEEP=y from the Ubuntu source package for the running
# kernel version.  The wolfSSL and wolfkm modules are then built against
# the KASAN kernel tree.  This phase adds ~45-60 minutes on c5.2xlarge.
#
# Kernel config changes applied on top of the running kernel's .config:
#   CONFIG_KASAN=y                  — shadow-based memory error detector
#   CONFIG_KASAN_GENERIC=y          — generic (software) KASAN variant
#   CONFIG_PROVE_LOCKING=y          — lockdep: lock ordering and deadlock detection
#   CONFIG_DEBUG_ATOMIC_SLEEP=y     — detect sleeping in atomic context
#   CONFIG_DEBUG_LIST=y             — catch list_head corruption
#   CONFIG_DEBUG_SG=y               — catch scatterlist corruption
#   CONFIG_RANDOMIZE_BASE=n         — disable KASLR (cleaner KASAN splat addresses)
#   CONFIG_FRAME_WARN=0             — suppress stack frame warnings (KASAN inflates)
#   CONFIG_SYSTEM_TRUSTED_KEYS=""   — allow our ephemeral signing key
#   CONFIG_SYSTEM_REVOCATION_KEYS=""

if [[ "$KASAN_BUILD" == "1" && "$DISTRO" != "ubuntu" ]]; then
    log "WARNING: KASAN_BUILD=1 is only supported on Ubuntu (uses dpkg/grub); skipping for $DISTRO"
elif [[ "$KASAN_BUILD" == "1" ]]; then
    log "Phase 1.5: Building KASAN+lockdep kernel (~45-60 min on ${INSTANCE_TYPE})..."

    remote_script <<'KASAN_KERNEL_BUILD'
set -e
log() { echo "=== $(date +%H:%M:%S) $*"; }

# ── Install kernel build dependencies ────────────────────────────────────────

log "Installing kernel build dependencies..."
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    libelf-dev flex bison bc dwarves debhelper rsync libssl-dev \
    cpio tar xz-utils 2>&1 | tail -3

# ── Get Ubuntu kernel source ──────────────────────────────────────────────────

KVER=$(uname -r)

# KASAN build always uses the GA 5.15 generic kernel as its base.
# Ubuntu 22.04 HWE (6.8-aws) does not publish deb-src, so we cannot
# build a KASAN variant of the running kernel on HWE instances.
# Install the GA generic kernel + headers, then build a 5.15-kasan kernel.
log "Installing GA 5.15 generic kernel for KASAN base..."
UBUNTU_REL=$(lsb_release -cs)
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    linux-image-generic linux-headers-generic \
    dpkg-dev libssl-dev libelf-dev bison flex bc > /dev/null 2>&1

# Find the installed generic kernel config to use as KASAN base
KASAN_BASE_KVER=$(ls /boot/config-*-generic 2>/dev/null | sort -V | tail -1 | sed 's|.*/config-||')
if [[ -z "$KASAN_BASE_KVER" ]]; then
    echo "ERROR: no generic kernel config found in /boot" >&2; exit 1
fi
log "KASAN base kernel: ${KASAN_BASE_KVER}"
KVER_SHORT=$(echo "${KASAN_BASE_KVER}" | sed 's/-generic//' | cut -d'-' -f1,2)

# Enable deb-src for main + updates + security (all three needed so that
# 'apt-get source linux' fetches the SRU-updated kernel matching the installed
# GA generic kernel, not the original jammy release version from 2022).
# Example: linux-image-5.15.0-176-generic comes from jammy-updates, not jammy.
for SUITE in "${UBUNTU_REL}" "${UBUNTU_REL}-updates" "${UBUNTU_REL}-security"; do
    if ! grep -q "^deb-src.*${SUITE} main" /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null; then
        echo "deb-src http://archive.ubuntu.com/ubuntu ${SUITE} main restricted" \
            | sudo tee -a /etc/apt/sources.list
    fi
done
sudo apt-get update -qq

mkdir -p ~/linux-kasan-build
cd ~/linux-kasan-build

# Download the GA 'linux' source package (provides the 5.15 generic kernel).
# NOTE: linux-image-xxx-generic resolves to 'linux-signed' (a meta-package),
# NOT the kernel source tree.  Use 'linux' directly for the source.
log "Getting kernel source for ${KASAN_BASE_KVER}..."
apt-get source --download-only linux 2>&1 | tail -5
dpkg-source -x linux_*.dsc linux-kasan

cd linux-kasan

# dpkg-source -x does not always restore execute bits on kernel scripts.
# The build system requires execute bits on scripts/ to proceed.
find . -path ./debian -prune -o -name "*.sh" -print0 | xargs -0 chmod +x 2>/dev/null || true
chmod +x scripts/kconfig/merge_config.sh scripts/pahole-flags.sh \
         scripts/pahole-version.sh scripts/config 2>/dev/null || true

# ── Configure KASAN + lockdep ─────────────────────────────────────────────────

log "Configuring kernel with KASAN+lockdep..."
cp /boot/config-${KASAN_BASE_KVER} .config
make olddefconfig ARCH=x86_64 2>&1 | tail -3

# Enable KASAN and debugging options
scripts/config --enable CONFIG_KASAN
scripts/config --enable CONFIG_KASAN_GENERIC
scripts/config --enable CONFIG_KASAN_INLINE
scripts/config --enable CONFIG_PROVE_LOCKING
scripts/config --enable CONFIG_DEBUG_ATOMIC_SLEEP
scripts/config --enable CONFIG_DEBUG_LIST
scripts/config --enable CONFIG_DEBUG_SG
scripts/config --disable CONFIG_RANDOMIZE_BASE
scripts/config --set-val CONFIG_FRAME_WARN 0
scripts/config --set-str CONFIG_SYSTEM_TRUSTED_KEYS ""
scripts/config --set-str CONFIG_SYSTEM_REVOCATION_KEYS ""
# Reboot 30 s after a panic so the machine comes back up on fallback kernel
scripts/config --set-val CONFIG_PANIC_TIMEOUT 30
# EC2 uses GRUB_FORCE_PARTUUID (initrdless boot): NVMe drivers must be built-in,
# not modules — without an initrd, a module NVMe driver can't find the root device.
scripts/config --enable CONFIG_NVME_CORE
scripts/config --enable CONFIG_BLK_DEV_NVME
# Skip DWARF debug info: we don't need the 6GB linux-image-dbg.deb.
# KASAN backtraces use kallsyms (always built-in), not DWARF.
# This saves ~45 min: faster compile + no xz-compression of debug symbols.
scripts/config --enable CONFIG_DEBUG_INFO_NONE

# Resolve any config dependencies
make olddefconfig ARCH=x86_64 2>&1 | tail -3
log "KASAN config applied"

# ── Build kernel ──────────────────────────────────────────────────────────────

log "Building KASAN kernel (this takes ~45-60 min)..."
make -j$(nproc) ARCH=x86_64 LOCALVERSION=-kasan deb-pkg 2>&1 | tail -10
log "KASAN kernel built"

# ── Install ───────────────────────────────────────────────────────────────────

cd ~/linux-kasan-build
log "Installing KASAN kernel packages..."
sudo dpkg -i linux-image-*-kasan_*.deb linux-headers-*-kasan_*.deb

# Set KASAN kernel as one-shot next boot using grub-reboot.
# grub-reboot is one-shot: after a single boot (successful or panic-reboot),
# the entry resets to the saved default.  This means a KASAN kernel panic that
# forces a reboot (CONFIG_PANIC_TIMEOUT=30) will fall back to the HWE kernel
# and SSH will be available for CI to diagnose.
#
# GRUB_DEFAULT=saved is required for grub-reboot to work.
# Use GRUB entry IDs (not display titles) — IDs are stable and unambiguous.
KASAN_KVER=$(ls /boot/vmlinuz-*-kasan 2>/dev/null | sort -V | tail -1 | sed 's|.*/vmlinuz-||')
log "KASAN kernel version: ${KASAN_KVER}"
sudo sed -i 's/^GRUB_DEFAULT=.*/GRUB_DEFAULT=saved/' /etc/default/grub
sudo update-grub 2>&1 | tail -3

# Dump GRUB entries for the KASAN kernel for diagnostics
log "GRUB entries for KASAN kernel:"
sudo grep -E "submenu.*Advanced|menuentry.*${KASAN_KVER}" /boot/grub/grub.cfg | head -5 || true

# Extract GRUB entry IDs from grub.cfg (more reliable than matching display titles)
KASAN_SUBMENU_ID=$(sudo grep -oP "(?<= ')gnulinux-advanced-[a-f0-9-]+(?=')" /boot/grub/grub.cfg | head -1)
KASAN_ENTRY_ID=$(sudo grep -oP "(?<= ')gnulinux-${KASAN_KVER}-advanced-[a-f0-9-]+(?=')" /boot/grub/grub.cfg | head -1)
log "GRUB submenu ID: '${KASAN_SUBMENU_ID}'"
log "GRUB entry ID:   '${KASAN_ENTRY_ID}'"

if [[ -n "${KASAN_SUBMENU_ID}" && -n "${KASAN_ENTRY_ID}" ]]; then
    sudo grub-reboot "${KASAN_SUBMENU_ID}>${KASAN_ENTRY_ID}"
else
    log "WARNING: GRUB entry IDs not found, falling back to title matching"
    sudo grub-reboot "Advanced options for Ubuntu>Ubuntu, with Linux ${KASAN_KVER}"
fi
sudo cat /boot/grub/grubenv 2>/dev/null || true
log "KASAN kernel installed; rebooting into ${KASAN_KVER}..."
KASAN_KERNEL_BUILD

    pass "KASAN kernel built and installed"

    log "Rebooting into KASAN kernel (waiting up to 15 minutes — KASAN init is slow)..."
    remote "sudo reboot" || true
    sleep 30
    wait_for_ssh_with_console 900

    KVER=$(remote 'uname -r')
    KMAJ=$(remote 'uname -r | cut -d. -f1')
    if [[ "$KMAJ" -ge 6 ]]; then KGCC=gcc-12; else KGCC=gcc-11; fi
    log "KASAN kernel running: $KVER (compiler: $KGCC)"

    # Verify KASAN is active
    if remote 'grep -q "CONFIG_KASAN=y" /boot/config-$(uname -r)' 2>/dev/null; then
        pass "KASAN enabled in running kernel"
    else
        fail "KASAN not found in kernel config — check kernel build"
    fi

    # Verify lockdep is active
    if remote 'grep -q "CONFIG_PROVE_LOCKING=y" /boot/config-$(uname -r)' 2>/dev/null; then
        pass "PROVE_LOCKING (lockdep) enabled in running kernel"
    else
        fail "PROVE_LOCKING not found in kernel config"
    fi
fi

# ── Phase 2: Build wolfSSL linuxkm (wolfcrypt.ko) ────────────────────────────
#
# This produces the wolfSSL linuxkm kernel module that wolfkm depends on.
# We build a non-FIPS wolfSSL here for general testing.  For FIPS testing,
# adapt this phase from build-test-wolfguard-aws.sh (requires a commercial
# wolfSSL tarball and Ubuntu Pro FIPS kernel).
#
# --enable-cryptonly: kernel module only, no TLS layer
# --enable-linuxkm:   build the kernel module
# --enable-intelasm:  AES-NI, SHA-NI hardware acceleration
# --enable-aes, --enable-aesgcm, etc.: algorithms wolfkm registers

log "Cloning wolfSSL ($WOLFSSL_REF)..."
remote "git clone --quiet --depth=1 --branch ${WOLFSSL_REF} ${WOLFSSL_REPO} ~/wolfssl"

log "Building wolfSSL linuxkm module..."
remote_script <<WOLFSSL_KM
set -e
cd ~/wolfssl
./autogen.sh --quiet 2>&1 | tail -2

# DRBG is on by default; no separate --enable-drbg flag in current wolfSSL.
./configure --quiet \
    --enable-cryptonly \
    --enable-linuxkm \
    ${WOLFSSL_ASM_OPT} \
    --enable-aes \
    --enable-aesgcm \
    --enable-aesccm \
    --enable-aesctr \
    --enable-aesxts \
    --enable-sha256 --enable-sha384 --enable-sha512 \
    --enable-sha3 \
    --enable-hmac \
    --enable-cmac \
    --enable-rsa \
    --enable-ecc \
    --enable-dh \
    --enable-keygen \
    --with-linux-source=/lib/modules/\$(uname -r)/build \
    CC=${KGCC} HOSTCC=${KGCC}

# 'linuxkm' is a directory, not a make target; the default target builds it.
# wolfSSL's build system tries to self-sign libwolfssl.ko.signed as part of the
# default 'all' target.  That signing step fails because our ephemeral key is
# not generated until Phase 3.  Accept make failure as long as the .ko itself
# was produced — the signing failure does not affect the .ko binary.
make ARCH=${KERN_ARCH} CC=${KGCC} HOSTCC=${KGCC} -j\$(nproc) 2>&1 | tail -5 || true
ls -lh linuxkm/libwolfssl.ko
echo "wolfSSL linuxkm built"
WOLFSSL_KM

pass "wolfSSL linuxkm (wolfcrypt.ko) built"

# ── Phase 3: Generate ephemeral module-signing key ────────────────────────────
#
# Ubuntu kernels have CONFIG_MODULE_SIG=y; modules must be signed to load
# without errors.  We generate a throwaway key per test run.

log "Generating ephemeral module-signing key..."
remote_script <<SIGN_KEY
set -e
mkdir -p ~/signing
openssl req -new -x509 -newkey rsa:2048 -nodes \
    -keyout ~/signing/key.pem \
    -out    ~/signing/cert.pem \
    -days   3650 \
    -subj   "/CN=wolfkm-test/O=wolfSSL" 2>/dev/null

# Ensure scripts/sign-file is available (some kernel-headers packages omit it)
SIGN_FILE="/lib/modules/\$(uname -r)/build/scripts/sign-file"
if [ ! -x "\$SIGN_FILE" ]; then
    echo "sign-file binary missing — compiling from source"
    gcc -o "\$SIGN_FILE" \
        "/lib/modules/\$(uname -r)/build/scripts/sign-file.c" \
        -lcrypto -lssl
fi
echo "Module-signing key ready; sign-file: \$(ls \$SIGN_FILE)"
SIGN_KEY

# Sign the wolfSSL module
log "Signing wolfSSL linuxkm module..."
remote_script <<SIGN_WOLFSSL
set -e
KVER=\$(uname -r)
"/lib/modules/\${KVER}/build/scripts/sign-file" sha256 \
    ~/signing/key.pem ~/signing/cert.pem \
    ~/wolfssl/linuxkm/libwolfssl.ko
echo "Signed: \$(ls -lh ~/wolfssl/linuxkm/libwolfssl.ko)"
SIGN_WOLFSSL

# ── Phase 4: Upload wolfkm source tree ───────────────────────────────────────
#
# wolfkm has no git remote — rsync from the local workspace.

log "Uploading wolfkm source tree (from $WOLFKM_ROOT)..."
rsync -az --exclude='.git' --exclude='*.o' --exclude='*.ko' \
    --exclude='.tmp_versions' --exclude='Module.symvers' \
    --exclude='modules.order' \
    -e "ssh -o StrictHostKeyChecking=no -i $KEY_FILE" \
    "$WOLFKM_ROOT/" \
    "${INSTANCE_USER}@$PUBLIC_IP:~/wolfkm/"
log "Upload complete"
pass "wolfkm source tree uploaded"

# ── Phase 5: Build wolfkm.ko ──────────────────────────────────────────────────
#
# WOLFCRYPT_DIR points to the wolfSSL source tree containing the linuxkm
# headers and Module.symvers exported by libwolfssl.ko.
# KBUILD_EXTRA_SYMBOLS resolves wolfkm's dependencies on wolfCrypt symbols.

log "Building wolfkm.ko..."
remote_script <<WOLFKM_BUILD
set -eo pipefail
KVER=\$(uname -r)
WOLFSSL_SRC=~/wolfssl

cd ~/wolfkm

make -C /lib/modules/\${KVER}/build \
    M=\$(pwd) \
    WOLFCRYPT_DIR=\${WOLFSSL_SRC} \
    KBUILD_EXTRA_SYMBOLS=\${WOLFSSL_SRC}/linuxkm/Module.symvers \
    WOLFKM_HAVE_WOLFCRYPT=1 \
    CC=${KGCC} \
    ARCH=${KERN_ARCH} \
    -j\$(nproc) 2>&1 | tail -10

ls -lh crypto2dev.ko crypto2dev_wolfssl.ko
WOLFKM_BUILD

pass "crypto2dev.ko and crypto2dev_wolfssl.ko built"

# Sign crypto2dev.ko and crypto2dev_wolfssl.ko
log "Signing crypto2dev.ko and crypto2dev_wolfssl.ko..."
remote_script <<SIGN_WOLFKM
set -e
KVER=\$(uname -r)
"/lib/modules/\${KVER}/build/scripts/sign-file" sha256 \
    ~/signing/key.pem ~/signing/cert.pem \
    ~/wolfkm/crypto2dev.ko
echo "Signed: \$(ls -lh ~/wolfkm/crypto2dev.ko)"
"/lib/modules/\${KVER}/build/scripts/sign-file" sha256 \
    ~/signing/key.pem ~/signing/cert.pem \
    ~/wolfkm/crypto2dev_wolfssl.ko
echo "Signed: \$(ls -lh ~/wolfkm/crypto2dev_wolfssl.ko)"
SIGN_WOLFKM

# ── Phase 5.5: UAPI struct layout verification (pahole) ──────────────────────
#
# Verifies that all 15 UAPI structs in crypto2dev_ioctl.h have zero holes.
# Holes indicate padding that is ABI-visible and may differ between 32-bit
# and 64-bit hosts — any hole is a UAPI stability bug.
# Requires CONFIG_DEBUG_INFO=y in the running kernel (Ubuntu default: yes).

log "Running pahole UAPI struct layout verification..."
if remote 'command -v pahole' 2>/dev/null; then
    if remote '[ -x ~/wolfkm/scripts/check_uapi_layout.sh ]'; then
        # Exit 0: all verified hole-free → PASS
        # Exit 2: structs not found (no DWARF — distro kernel without debug info) → SKIP
        # Exit 1: holes found → FAIL
        PAHOLE_RC=0
        remote "bash ~/wolfkm/scripts/check_uapi_layout.sh ~/wolfkm/crypto2dev.ko" || PAHOLE_RC=$?
        case "$PAHOLE_RC" in
            0) pass "UAPI structs: zero holes (pahole verified)" ;;
            2) skip "UAPI struct layout: debug info not present in module (CONFIG_DEBUG_INFO=n on this distro)" ;;
            *) fail "UAPI struct holes detected — see pahole output above" ;;
        esac
    else
        skip "scripts/check_uapi_layout.sh not yet present"
    fi
else
    skip "pahole not installed — install 'dwarves' package for UAPI layout verification"
fi

# ── Phase 6: Load modules ─────────────────────────────────────────────────────
#
# Load order is mandatory: wolfcrypt (libwolfssl) first, then wolfkm.

log "Loading wolfSSL linuxkm module (wolfcrypt)..."
remote "sudo insmod ~/wolfssl/linuxkm/libwolfssl.ko"

remote 'lsmod | grep -i wolfssl' && \
    pass "wolfSSL linuxkm loaded" || fail "wolfSSL linuxkm not found in lsmod"

DMESG_WOLFSSL=$(remote 'sudo dmesg | grep -i "wolfssl\|wolfcrypt" | tail -5 || true')
log "dmesg (wolfssl): $DMESG_WOLFSSL"

log "Loading crypto2dev.ko (framework)..."
remote "sudo insmod ~/wolfkm/crypto2dev.ko"

remote 'lsmod | grep "^crypto2dev "' && \
    pass "crypto2dev.ko loaded" || fail "crypto2dev not found in lsmod"

log "Loading crypto2dev_wolfssl.ko (wolfSSL provider)..."
remote "sudo insmod ~/wolfkm/crypto2dev_wolfssl.ko"

remote 'lsmod | grep crypto2dev_wolfssl' && \
    pass "crypto2dev_wolfssl.ko loaded" || fail "crypto2dev_wolfssl not found in lsmod"

DMESG_C2D=$(remote 'sudo dmesg | grep -i "crypto2dev" | tail -10 || true')
log "dmesg (crypto2dev): $DMESG_C2D"

# STUB MODE warning would appear in crypto2dev_wolfssl dmesg; should not be present
if remote 'sudo dmesg | grep -q "STUB MODE"' 2>/dev/null; then
    fail "crypto2dev_wolfssl loaded in STUB MODE — wolfCrypt integration not working"
fi

# ── Phase 7: Registration verification ───────────────────────────────────────
#
# crypto2dev does NOT register into the kernel crypto API (/proc/crypto).
# Algorithm enumeration is via sysfs: /sys/class/misc/crypto2dev/algorithms.
# Verify that at least the expected set of algorithms is registered there.

log "Verifying algorithm registrations in sysfs..."

# Expected algorithms from the wolfssl provider
EXPECTED_SYSFS_ALGOS="cbc(aes) gcm(aes) sha256 hmac(sha256)"
SYSFS_PATH="/sys/class/misc/crypto2dev/algorithms"
SYSFS_FAIL=0
for ALGO in $EXPECTED_SYSFS_ALGOS; do
    if remote "grep -q '^${ALGO}:' ${SYSFS_PATH}" 2>/dev/null; then
        pass "sysfs: ${ALGO} registered"
    else
        fail "sysfs: ${ALGO} not found in ${SYSFS_PATH}"
        SYSFS_FAIL=1
    fi
done

# Note: scripts/verify_registration.sh checks wolfcrypt.ko /proc/crypto
# registrations (FIPS builds only — wolfkm driver at priority 300).
# That check is orthogonal to crypto2dev's chardev interface and is skipped
# in non-FIPS CI builds where Intel AESNI drivers take priority.
skip "verify_registration.sh (/proc/crypto) — skipped for non-FIPS wolfSSL build" || true

# ── Phase 8: Kernel test modules ─────────────────────────────────────────────
#
# Build and run the in-kernel test suite if test source is present.

log "Building and running kernel test modules..."

if remote '[ -f ~/wolfkm/tests/kernel/Makefile ]'; then
    remote_script <<KERNEL_TESTS
set -eo pipefail
KVER=\$(uname -r)
cd ~/wolfkm/tests/kernel

# WOLFCRYPT_DIR must point to the linuxkm/ subdir (that is where Module.symvers
# lives).  Do NOT pass KBUILD_EXTRA_SYMBOLS on the command line: make treats
# command-line variables as override variables, which prevents the += in the
# test Makefile from appending crypto2dev's Module.symvers.  Instead let the
# test Makefile build KBUILD_EXTRA_SYMBOLS via its own += chain using TOP and
# WOLFCRYPT_DIR.
make -C /lib/modules/\${KVER}/build \
    M=\$(pwd) \
    TOP=~/wolfkm \
    WOLFCRYPT_DIR=~/wolfssl/linuxkm \
    CRYPTO2DEV_HAVE_WOLFCRYPT=1 \
    CC=${KGCC} \
    ARCH=${KERN_ARCH} \
    -j\$(nproc) 2>&1 | tail -10
ls ~/wolfkm/tests/kernel/test_fips_gate.ko
echo "Kernel test modules built"
KERNEL_TESTS
    pass "Kernel test modules built"

    if remote '[ -x ~/wolfkm/tests/kernel/run_kernel_tests.sh ]'; then
        log "Running kernel test modules..."
        # test_rng, test_akcipher, test_kpp exercise wolfcrypt.ko's kernel
        # crypto API registrations (stdrng, crypto_alloc_sig, ECDH kpp API),
        # not the crypto2dev chardev interface.  They require a full FIPS
        # wolfcrypt.ko build to pass and are skipped here.
        remote "sudo SKIP_MODULES='test_rng test_akcipher test_kpp' \
            bash ~/wolfkm/tests/kernel/run_kernel_tests.sh \
            ~/wolfssl/linuxkm/libwolfssl.ko ~/wolfkm/crypto2dev.ko" && \
            pass "Kernel test suite passed" || \
            fail "Kernel test suite had failures (see dmesg above)"
    else
        skip "tests/kernel/run_kernel_tests.sh not yet present"
    fi
else
    skip "tests/kernel/Makefile not yet present — kernel tests not built"
fi

# ── Phase 9: Userspace tests ──────────────────────────────────────────────────
#
# Build and run the chardev / AF_ALG userspace tests if present.

log "Building and running userspace tests..."

if remote '[ -f ~/wolfkm/tests/userspace/Makefile ]'; then
    remote_script <<USERSPACE_TESTS
set -eo pipefail
cd ~/wolfkm/tests/userspace
# Force rebuild: rsync preserves source timestamps so make may not see pre-built
# binaries as stale even if they were compiled against an older header version.
make clean
make -j\$(nproc) 2>&1 | tail -5
echo "Userspace tests built"
USERSPACE_TESTS
    pass "Userspace tests built"

    if remote '[ -x ~/wolfkm/tests/userspace/test_chardev ]'; then
        # Diagnostic: compile and run a tiny C program that prints the actual
        # ioctl number from the real header — catches struct size mismatches.
        remote_script <<CHARDEV_DIAG
ls -la /dev/crypto2dev || echo "WARN: /dev/crypto2dev missing"
sudo dmesg | grep "crypto2dev.*minor\|crypto2dev.*regist" | tail -5 || true
cat > /tmp/ioctl_check.c << 'IOCTLEOF'
#include <stdio.h>
#include "uapi/crypto2dev_ioctl.h"
int main(void) {
    printf("sizeof(crypto2dev_init_op) = %zu\n",
           sizeof(struct crypto2dev_init_op));
    printf("CRYPTO2DEV_IOC_INIT        = 0x%08lx\n",
           (unsigned long)CRYPTO2DEV_IOC_INIT);
    return 0;
}
IOCTLEOF
gcc -I\${HOME}/wolfkm/include /tmp/ioctl_check.c -o /tmp/ioctl_check || echo "WARN: ioctl_check compile failed"
/tmp/ioctl_check
CHARDEV_DIAG
        log "Running test_chardev..."
        remote 'sudo ~/wolfkm/tests/userspace/test_chardev' && \
            pass "test_chardev passed" || \
            fail "test_chardev failed"
    else
        skip "tests/userspace/test_chardev not yet compiled"
    fi

    # test_af_alg exercises wolfcrypt.ko's kernel crypto API registrations via
    # AF_ALG sockets. crypto2dev intentionally does NOT register into the kernel
    # crypto API, so this test is orthogonal to the chardev interface.
    # Skip it in CI to avoid false failures from Intel AESNI priority.
    skip "test_af_alg — tests AF_ALG (wolfcrypt.ko KCapi), not crypto2dev chardev"

    if remote '[ -x ~/wolfkm/tests/userspace/test_concurrent ]'; then
        log "Running test_concurrent (60s provider-cycling stress)..."
        remote "sudo ~/wolfkm/tests/userspace/test_concurrent \
            -t 8 -d 60 -k ~/wolfkm/crypto2dev_wolfssl.ko" && \
            pass "test_concurrent passed" || \
            fail "test_concurrent failed"
    else
        skip "tests/userspace/test_concurrent not yet compiled"
    fi

    if remote '[ -x ~/wolfkm/tests/userspace/test_fips_gate_ftrace.sh ]'; then
        log "Running test_fips_gate_ftrace (ftrace FIPS gate ordering)..."
        remote 'sudo bash ~/wolfkm/tests/userspace/test_fips_gate_ftrace.sh' && \
            pass "test_fips_gate_ftrace passed" || \
            fail "test_fips_gate_ftrace failed"
    else
        skip "tests/userspace/test_fips_gate_ftrace.sh not present"
    fi
else
    skip "tests/userspace/Makefile not yet present — userspace tests not built"
fi

# ── Phase 10: Diagnostics ─────────────────────────────────────────────────────

log "Diagnostics..."
log "Kernel: $(remote 'uname -r')"
log "lsmod (wolfssl/crypto2dev):"
remote 'lsmod | grep -E "wolfssl|crypto2dev" || echo "(none)"'
log "/proc/crypto (crypto2dev algorithms):"
remote 'grep -B2 "crypto2dev" /proc/crypto || echo "(none found)"'
log "dmesg tail:"
remote 'sudo dmesg | tail -20'

# Check for KASAN/lockdep splats (only meaningful under KASAN_BUILD=1)
if [[ "$KASAN_BUILD" == "1" ]]; then
    log "Checking for KASAN/lockdep splats..."
    if remote 'sudo dmesg | grep -qE "BUG: KASAN|WARNING: lockdep|BUG: sleeping function"' 2>/dev/null; then
        fail "KASAN/lockdep splat detected — see dmesg above"
        remote 'sudo dmesg | grep -E "BUG: KASAN|WARNING: lockdep|BUG: sleeping function" | head -20'
    else
        pass "No KASAN/lockdep splats in dmesg"
    fi
fi

# ── Unload modules (reverse order) ───────────────────────────────────────────

log "Unloading modules..."
remote 'sudo rmmod crypto2dev_wolfssl 2>/dev/null && echo "crypto2dev_wolfssl unloaded" || echo "crypto2dev_wolfssl not loaded"'
remote 'sudo rmmod crypto2dev 2>/dev/null && echo "crypto2dev unloaded" || echo "crypto2dev not loaded"'
remote "sudo rmmod ${WOLFKM_WOLFCRYPT_KO_NAME} 2>/dev/null && \
    echo '${WOLFKM_WOLFCRYPT_KO_NAME} unloaded' || \
    echo '${WOLFKM_WOLFCRYPT_KO_NAME} not loaded'"

# Verify clean unload (no oops, no BUG)
if remote 'sudo dmesg | grep -qE "BUG:|Oops:|kernel BUG"' 2>/dev/null; then
    fail "kernel BUG or Oops detected in dmesg — check output above"
else
    pass "Clean unload — no kernel BUG or Oops in dmesg"
fi

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "======================================================"
echo " crypto2dev build/test results"
echo " Modules: crypto2dev.ko + crypto2dev_wolfssl.ko"
echo " Run:     $RUN_ID"
echo " Kernel:  $KVER"
echo " Distro:  $DISTRO"
echo " Arch:    $([ "${ARM64:-0}" = "1" ] && echo arm64 || echo x86_64)"
echo " FIPS:    ${FIPS_MODE}"
echo " KASAN:   ${KASAN_BUILD}"
echo " Passed:  $TESTS_PASSED"
echo " Failed:  $TESTS_FAILED"
echo "======================================================"

[[ $TESTS_FAILED -eq 0 ]] || exit 1
