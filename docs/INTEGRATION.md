# crypto2dev Integration Guide

Target audience: Linux sysadmins and security engineers deploying crypto2dev
in any configuration — FIPS-validated deployments and non-FIPS deployments alike.

---

## Overview

The wolfSSL kernel stack is two separate layers with distinct roles.
Understanding which layer serves which consumer is required before deployment.

**Layer 1 — wolfcrypt.ko (wolfSSL linuxkm module)**

`wolfcrypt.ko` is the wolfSSL Linux kernel module. It provides:

- All cryptographic implementations (AES, SHA, ECDH, RSA, etc.)
- FIPS 140-3 power-on self-test (POST) and integrity verification
- Kernel crypto API registrations at priority 300 with driver names
  matching the `wolfkm` pattern

This is the layer consumed by `dm-crypt`, IPsec (`xfrm`), TLS kernel
offload, and any other in-kernel consumer that uses the kernel crypto API.
`wolfcrypt.ko` is built from the wolfSSL source tree. It is not part of
this repository.

**Layer 2 — crypto2dev.ko (this repository)**

`crypto2dev.ko` provides the `/dev/crypto2dev` character device. It
gives userspace programs direct access to wolfCrypt (or the kernel crypto
API via the kcapi provider) without going through OpenSSL, GnuTLS, or
the AF_ALG socket interface.

`crypto2dev.ko` does NOT register into the kernel crypto API. It does
not affect `dm-crypt`, IPsec, or any other in-kernel consumer.

Provider modules attach to the framework at load time:

- `crypto2dev_wolfssl.ko` — calls wolfCrypt directly through wolfcrypt.ko;
  FIPS 140-3 gate enforced on every operation when wolfcrypt.ko is a FIPS build
- `crypto2dev_kcapi.ko` — routes through the kernel crypto API; no
  independent FIPS boundary

Load order is mandatory: `wolfcrypt.ko` first, then `crypto2dev.ko`,
then any provider modules.

**Which layer do I need?**

| Consumer | Layer |
|---|---|
| dm-crypt / LUKS | wolfcrypt.ko only |
| IPsec / xfrm | wolfcrypt.ko only |
| Userspace application via /dev/crypto2dev | crypto2dev.ko + provider |
| Both | Load all three modules |

---

## Prerequisites

**Kernel version**: 5.10 or later. Tested on Ubuntu 22.04 (5.15) and
Ubuntu 24.04 (6.8). Earlier kernels may work but are not supported.

**wolfcrypt.ko**: Must be pre-built from the wolfSSL source tree with
`--enable-linuxkm --enable-linuxkm-defaults --enable-fips=v5`. The
resulting module file is typically named `libwolfssl.ko` (the default
`WOLFKM_WOLFCRYPT_KO_NAME`). The build produces a `Module.symvers`
file that crypto2dev needs at build time.

**Kernel headers**: The running kernel's build tree must be present at
`/lib/modules/$(uname -r)/build`. On Debian/Ubuntu: `apt install
linux-headers-$(uname -r)`.

**Secure Boot**: If `CONFIG_MODULE_SIG_FORCE` is enabled on the target
kernel (common on Ubuntu Pro FIPS kernels), both `wolfcrypt.ko` and
`crypto2dev.ko` must be signed with a key enrolled in the system's
Machine Owner Key (MOK) database. Unsigned modules will be rejected at
`insmod`. Signing is out of scope for this guide; consult your
distribution's Secure Boot documentation.

**Permissions**: Loading kernel modules requires `CAP_SYS_MODULE`
(typically root). The `/dev/crypto2dev` device node is created with
mode `0600` owned by root. Grant access to non-root users via a udev
rule or group ownership change as appropriate for your environment.

---

## Installation

### Build crypto2dev.ko

```bash
# With wolfSSL provider (recommended for FIPS deployments):
make WOLFCRYPT_DIR=/path/to/wolfssl/source \
     KBUILD_EXTRA_SYMBOLS=/path/to/wolfssl/linuxkm/Module.symvers

# Framework only (no wolfSSL dependency; loads stub provider):
make
```

This produces three module files in the repo root:

```
crypto2dev.ko           # framework — always required
crypto2dev_wolfssl.ko   # wolfSSL provider (FIPS-gated when wolfcrypt built with FIPS)
crypto2dev_kcapi.ko     # kernel crypto API provider (non-FIPS)
```

### Load modules

Modules must be loaded in this order:

```bash
# Step 1: wolfSSL kernel module (provides wolfCrypt symbols)
# The filename depends on how wolfSSL was built; default is libwolfssl.ko
sudo insmod /path/to/wolfssl/linuxkm/libwolfssl.ko

# Step 2: crypto2dev framework
sudo insmod crypto2dev.ko

# Step 3: provider (choose one or both)
sudo insmod crypto2dev_wolfssl.ko   # wolfSSL provider — requires step 1
sudo insmod crypto2dev_kcapi.ko     # kcapi provider — no extra deps
```

After step 2, `/dev/crypto2dev` appears. No algorithms are available
until at least one provider module is loaded (step 3).

### Optional: modprobe.d configuration

To load modules automatically at boot via `modprobe`:

```bash
# Install modules to the standard location
sudo make modules_install

# Create dependency and ordering config
sudo tee /etc/modprobe.d/crypto2dev.conf <<'EOF'
# Load wolfSSL provider when crypto2dev is loaded
softdep crypto2dev pre: libwolfssl
softdep crypto2dev_wolfssl pre: crypto2dev libwolfssl
EOF

sudo depmod -a
```

Then at boot (or on demand):

```bash
sudo modprobe crypto2dev_wolfssl
```

`modprobe` will pull in `libwolfssl` and `crypto2dev` in dependency
order before loading the provider.

---

## Verification

### Step 1: Confirm wolfcrypt.ko registrations

Before testing crypto2dev, confirm that `wolfcrypt.ko` has registered
its algorithms in the kernel crypto API correctly:

```bash
sudo ./scripts/verify_registration.sh
```

Expected output (all algorithms pass):

```
wolfkm /proc/crypto registration check
=======================================
  PASS  cbc(aes) — driver="wolfkm-cbc-aes" priority=300
  PASS  ctr(aes) — driver="wolfkm-ctr-aes" priority=300
  PASS  xts(aes) — driver="wolfkm-xts-aes" priority=300
  PASS  gcm(aes) — driver="wolfkm-gcm-aes" priority=300
  PASS  sha256 — driver="wolfkm-sha256" priority=300
  PASS  sha384 — driver="wolfkm-sha384" priority=300
  PASS  sha512 — driver="wolfkm-sha512" priority=300
  PASS  hmac(sha256) — driver="wolfkm-hmac-sha256" priority=300
  PASS  rsa — driver="wolfkm-rsa" priority=300
  PASS  ecdh-nist-p256 — driver="wolfkm-ecdh-p256" priority=300
  ...
19 passed, 0 failed
PASS: all wolfkm algorithms registered correctly
```

If any algorithm fails, `wolfcrypt.ko` is not loaded correctly. Check
`dmesg` for POST or integrity check failures before proceeding.

### Step 2: Confirm crypto2dev algorithm availability

After loading `crypto2dev.ko` and at least one provider:

```bash
cat /sys/class/misc/crypto2dev/algorithms
```

Expected output with both providers loaded:

```
cbc(aes):wolfssl:1:0
gcm(aes):wolfssl:1:0
sha256:wolfssl:1:0
hmac(sha256):wolfssl:1:0
cbc(aes):kcapi:0:0
gcm(aes):kcapi:0:0
...
```

Format per line: `algorithm:provider:has_fips_gate:has_key_ops`

The `wolfssl` provider lines show `has_fips_gate=1`, confirming the
FIPS 140-3 gate is active. If the sysfs file is empty, no provider
module is loaded.

### Step 3: Confirm device node

```bash
ls -l /dev/crypto2dev
```

Expected:

```
crw------- 1 root root 10, 55 Apr 18 09:00 /dev/crypto2dev
```

---

## Userspace Access via /dev/crypto2dev

Userspace programs interact with `/dev/crypto2dev` via `open(2)`,
`read(2)`, `write(2)`, and `ioctl(2)`. The device uses a
file-descriptor-per-operation model: each open file descriptor
represents either a pending crypto operation or a key object.

For the full API reference including ioctl structures, error codes,
algorithm name strings, and code examples, see:

    docs/programmers_guide.md

---

## Kernel Crypto API Consumers

`dm-crypt`, IPsec, and other in-kernel consumers that use the kernel
crypto API do NOT interact with `crypto2dev.ko`. They use `wolfcrypt.ko`
directly through the kernel's standard `crypto_alloc_*` interfaces.

`crypto2dev.ko` is transparent to these consumers. Loading or unloading
`crypto2dev.ko` has no effect on dm-crypt or IPsec behavior.

### dm-crypt / LUKS

Once `wolfcrypt.ko` is loaded and its algorithms are verified (see
Verification above), `dm-crypt` automatically selects wolfCrypt
implementations because they are registered at priority 300, higher than
the built-in software implementations.

Confirm which driver is selected for a LUKS volume:

```bash
# After opening a LUKS device:
sudo cryptsetup status /dev/mapper/myluksdev | grep cipher
grep "cbc(aes)" /proc/crypto | grep "^driver"
```

The driver line should contain `wolfkm`.

### IPsec

The `xfrm` subsystem selects encryption and authentication algorithms
from the kernel crypto API using the same priority mechanism. No
configuration change is needed beyond loading `wolfcrypt.ko`. Verify
with:

```bash
grep -E "^(name|driver|priority)" /proc/crypto | grep -A2 "^name.*cbc.aes"
```

---

## Troubleshooting

### `insmod: ERROR: could not insert module crypto2dev.ko: Unknown symbol in module`

`wolfcrypt.ko` is not loaded or was built against a different kernel
version. Load `wolfcrypt.ko` first and confirm it was built against the
running kernel:

```bash
dmesg | tail -20
lsmod | grep wolfssl
```

### `insmod: ERROR: could not insert module crypto2dev_wolfssl.ko: Unknown symbol in module`

Either `wolfcrypt.ko` is not loaded, or `crypto2dev.ko` is not loaded,
or `KBUILD_EXTRA_SYMBOLS` was not set when building `crypto2dev_wolfssl.ko`.
Load in order: wolfcrypt, crypto2dev, then the provider.

### `dmesg` shows: `wolfcrypt: FIPS POST failure`

wolfCrypt's power-on self-test failed. The module will not allow crypto
operations. This is a FIPS 140-3 mandatory response to a self-test
failure. Do not attempt to work around it. Contact wolfSSL support with
the exact POST error string from `dmesg`.

### `cat /sys/class/misc/crypto2dev/algorithms` is empty

No provider module is loaded. Load `crypto2dev_wolfssl.ko` or
`crypto2dev_kcapi.ko`.

### `scripts/verify_registration.sh` fails for one or more algorithms

The `wolfkm` driver is not the highest-priority provider for the failing
algorithm. Another module may have registered the same algorithm at a
higher priority, or `wolfcrypt.ko` did not complete its module_init
successfully. Check:

```bash
dmesg | grep -i "wolfkm\|wolfcrypt\|fips"
grep -A5 "^name.*cbc.aes" /proc/crypto
```

### `/dev/crypto2dev` does not appear after `insmod crypto2dev.ko`

Check `dmesg` for `misc_register` failures. The minor number allocation
can fail if the system has exhausted miscdevice minor numbers (unlikely
but possible on heavily configured systems).

### Operations return `EACCES` (permission denied, errno 13)

The FIPS 140-3 gate rejected the request. wolfCrypt is in a degraded or
error state. Check:

```bash
dmesg | grep -i "fips\|wolfcrypt"
```

A FIPS self-test failure puts wolfCrypt into a permanent error state
that requires a module reload to clear — and even then will fail again
if the underlying cause (hardware fault, binary tampering) persists.
