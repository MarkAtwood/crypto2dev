# crypto2dev

A Linux kernel module that exposes kernel-managed cryptography to userspace via
`/dev/crypto2dev` — a clean file-descriptor interface with explicit provider
selection, predictable failure semantics, and no silent fallback.

The provider model is the core design: `crypto2dev.ko` owns the chardev API and
session lifecycle; separate provider modules supply the crypto. Two providers
ship with the project, and third parties can write their own. This makes
crypto2dev a standardized userspace interface to any crypto resource the kernel
manages — a validated library, a hardware accelerator, an HSM driver, or the
kernel crypto API itself.

When used with a FIPS-validated build of wolfcrypt.ko (CMVP cert #4718), every
operation either goes through the certified module or fails — no priority games,
no "probably FIPS." When used with a non-FIPS wolfcrypt.ko, or with the bundled
`crypto2dev_kcapi.ko` provider, it provides the same interface without the FIPS
gate.

**Target users:** Any application that needs reliable, provider-pinned kernel
crypto — FIPS-mandated deployments (federal agencies, FedRAMP, DoD/DISA STIG,
HIPAA/NIST), deployments with dedicated crypto hardware that needs a clean
userspace API, and any project that wants explicit provider selection rather than
AF_ALG's highest-priority dispatch.

**Powered by [wolfSSL](https://www.wolfssl.com/).** wolfCrypt is the most
widely deployed FIPS-validated cryptography library in embedded and kernel
environments. It holds FIPS 140-2 validations (certs #2425 and #3389) and
FIPS 140-3 validation (cert #4718). `wolfcrypt.ko` already serves dm-crypt,
IPsec/xfrm, and AF_ALG on Linux systems with and without formal FIPS
requirements; `crypto2dev` adds a dedicated userspace interface on top of the
same library.

**Roadmap:** Companion userspace providers for **OpenSSL 3** and **NSS** are
planned, both backed by `/dev/crypto2dev`. Applications using OpenSSL or NSS
APIs will route their crypto through the same CMVP certificate — without any
code changes. `crypto2dev` is the stable kernel ABI those providers will sit
on top of.

---

## Supported algorithms

AES-CBC, AES-GCM, SHA-256/384/512, SHA3-256/384/512,
HMAC-SHA-256/384/512, CMAC-AES,
HKDF-SHA-256/384/512, PBKDF2-SHA-256/384/512,
RSA-2048/4096 (sign/verify/keygen),
ECDSA P-256/P-384 (sign/verify/keygen),
ECDH P-256/P-384 + HKDF (key agreement; raw shared secret never leaves the provider).

Full list at runtime: `cat /sys/class/misc/crypto2dev/algorithms`

---

## Why not AF_ALG?

AF_ALG dispatches through `crypto_alloc_*` — it gets the highest-priority
implementation for the requested algorithm name. Three things it cannot do:

1. **Require a CMVP-certified implementation.** An AF_ALG socket for
   `"cbc(aes)"` uses whatever has the highest priority. A hardware accelerator
   without a FIPS certificate can silently outrank wolfCrypt.

2. **Fail when the validated module is absent.** If `wolfcrypt.ko` is not
   loaded, AF_ALG answers with the kernel's software implementation. There is
   no "fail if the FIPS module is unavailable" knob.

3. **Detect mid-session FIPS degradation.** `wolfCrypt_GetStatus_fips()` is
   not on the AF_ALG call path. If wolfCrypt's periodic self-test fails after
   boot, AF_ALG sessions continue silently.

`crypto2dev` addresses all three when used with a FIPS build of wolfcrypt.ko:

- `CRYPTO2DEV_IOC_REQUIRE_FIPS` makes `INIT` return `-ENOENT` if no FIPS
  provider is loaded — the operation never starts.
- Once a FIPS-capable wolfCrypt provider loads, all non-FIPS providers are
  unreachable via lookup — no priority games, no fallback.
- Every operation entry point calls `wolfCrypt_GetStatus_fips()` and returns
  `-EACCES` if the module has degraded.

The auditor's question is "can you demonstrate that this operation went through
the CMVP-certified module?" With AF_ALG, the answer is "probably." With
`crypto2dev` and a FIPS wolfCrypt provider, the answer is "yes, by construction,
or the operation did not complete."

---

## Architecture

```
  userspace application
        │ open("/dev/crypto2dev")
        │ ioctl / write() / read()
        ▼
  crypto2dev.ko          — chardev interface, session lifecycle, provider dispatch
        │ provider ops vtable
        ├────────────────────────────┬────────────────────────────┐
        ▼                            ▼                            ▼
  crypto2dev_wolfssl.ko     crypto2dev_kcapi.ko          (your provider)
  (FIPS-gated when wolfcrypt (no FIPS gate)               crypto2dev_myhw.ko
   built with FIPS support)
        │ wolfCrypt symbols          │ crypto_alloc_*             │ driver API
        ▼                            ▼                            ▼
  wolfcrypt.ko               kernel crypto API           hardware driver
  (FIPS build: CMVP #4718;   (/proc/crypto)              (HSM, accelerator,
   non-FIPS: no gate)                                      TPM, etc.)
```

Two providers ship with the project; third-party providers can be written for
any crypto resource the kernel manages (hardware accelerators, HSMs, TPM-backed
operations, vendor crypto drivers):

- **`crypto2dev_wolfssl.ko`** — calls `wolfcrypt.ko` directly. When wolfcrypt.ko
  is built with FIPS support: two-layer FIPS gate — non-validated paths are
  hard-disabled and every operation checks `wolfCrypt_GetStatus_fips()` (CMVP
  cert #4718). When wolfcrypt.ko is a non-FIPS build: no gate, full wolfCrypt
  functionality, no certification boundary.

- **`crypto2dev_kcapi.ko`** — delegates to the kernel's own crypto API. No
  FIPS gate; no extra dependencies. Exposes any algorithm registered in
  `/proc/crypto`, including hardware-accelerated implementations.

`wolfcrypt.ko` also registers wolfCrypt algorithms into the kernel crypto API
at priority 300 — independently of crypto2dev. dm-crypt, IPsec/xfrm, and AF_ALG
pick them up automatically from there.

---

## Load order

```bash
insmod wolfcrypt.ko                  # required if using wolfssl provider
insmod crypto2dev.ko                 # core — owns /dev/crypto2dev
insmod crypto2dev_wolfssl.ko         # wolfSSL provider (optional; FIPS-gated if wolfcrypt built with FIPS)
insmod crypto2dev_kcapi.ko           # non-FIPS provider (optional)
```

At least one provider must be loaded before any operation succeeds.

When wolfcrypt.ko is a FIPS build, loading `crypto2dev_wolfssl.ko` activates
FIPS enforcement: `crypto2dev_kcapi.ko` algorithms become unreachable via
lookup. Both modules may coexist; the kcapi algorithms remain visible in sysfs
for diagnostics only. With a non-FIPS wolfcrypt.ko, no lockout occurs — both
providers are reachable.

---

## Quick start

Copy `include/uapi/crypto2dev_ioctl.h` into your project, or install it to
`/usr/include/linux/` and use `<linux/crypto2dev_ioctl.h>`.

```c
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include "crypto2dev_ioctl.h"    /* from include/uapi/ in this repo */

/* error handling omitted for brevity — check every ioctl return value */

int fd = open("/dev/crypto2dev", O_RDWR);

/* Optional: require FIPS — INIT fails with -ENOENT if no FIPS provider loaded */
ioctl(fd, CRYPTO2DEV_IOC_REQUIRE_FIPS);

struct crypto2dev_init_op init = {
    .algo   = "gcm(aes)",
    .op     = CRYPTO2DEV_OP_ENCRYPT,
    .keylen = 32,
    .key_fd = -1,              /* -1 = inline key (symmetric); KEY fd for asymmetric */
};
memcpy(init.key, key, 32);
ioctl(fd, CRYPTO2DEV_IOC_INIT, &init);
explicit_bzero(init.key, sizeof(init.key));

struct crypto2dev_iv_op iv_op = { .ivlen = 12 };
ioctl(fd, CRYPTO2DEV_IOC_GEN_IV, &iv_op);   /* FIPS-approved DRBG inside boundary */

write(fd, plaintext, len);
ioctl(fd, CRYPTO2DEV_IOC_FINALIZE);
read(fd, ciphertext, len);

struct crypto2dev_tag_op tag_op = { .taglen = 16 };
ioctl(fd, CRYPTO2DEV_IOC_GET_TAG, &tag_op);

close(fd);
```

See `docs/programmers_guide.md` for complete examples including asymmetric
operations, error handling, and the key fd workflow.

---

## Build

```bash
# With wolfCrypt headers and a running kernel build tree:
make -C /lib/modules/$(uname -r)/build M=$(pwd) \
     WOLFCRYPT_DIR=/path/to/wolfssl

# Without wolfCrypt headers — builds crypto2dev.ko + crypto2dev_kcapi.ko only:
make -C /lib/modules/$(uname -r)/build M=$(pwd)
```

Tested on kernel 5.15 (Ubuntu 22.04 LTS) and 6.8 (Ubuntu 24.04 LTS).

For deployment, Secure Boot signing, and AWS-based kernel testing, see
`docs/INTEGRATION.md`.

---

## Sysfs

```bash
cat /sys/class/misc/crypto2dev/algorithms     # algo:provider:fips:has_key_ops per line
cat /sys/class/misc/crypto2dev/providers      # name:is_fips:version per line
cat /sys/class/misc/crypto2dev/fips_state     # 0=no provider, 1=operational, 2=degraded
```

---

## Documentation

| File | Contents |
|------|----------|
| `DESIGN.md` | Architecture, UAPI contract, provider API, FIPS enforcement, design decisions |
| `docs/programmers_guide.md` | Userspace API reference, ioctl reference, complete examples |
| `docs/INTEGRATION.md` | Deployment, load order, Secure Boot, troubleshooting |
| `docs/announce-lkml.txt` | Rationale, anticipated upstream concerns, AF_ALG comparison |
| `docs/prfaq.md` | Product-level Q&A — who this is for and why |
| `include/uapi/crypto2dev_ioctl.h` | Definitive UAPI reference |

---

## Ecosystem

Planned companion projects:

- **OpenSSL 3 provider** — drop-in FIPS coverage for any application that
  already uses OpenSSL 3. No code changes required; the provider intercepts
  the standard OpenSSL API and routes operations through `/dev/crypto2dev`.

- **NSS provider** — same for applications using Mozilla's NSS (Firefox,
  Thunderbird, most Red Hat/Fedora system crypto). FIPS coverage from the same
  CMVP certificate, without relinking or rewriting.

Both projects use `crypto2dev` as the stable kernel ABI. Upgrading the kernel
module does not require recompiling or recertifying the userspace providers.

---

## Why not upstream?

`wolfcrypt.ko`'s FIPS validation is bound to a specific binary artifact
identified by an HMAC-SHA256 integrity check over the module image. Rebuilding
from source — even with no changes — produces a different binary and voids the
validation. CMVP certificates are not "build your own" artifacts.

`crypto2dev.ko` and `crypto2dev_kcapi.ko` have no such constraint and could in
principle go in-tree; that conversation is worth having. The three modules in
this repository ship together for simplicity; `wolfcrypt.ko` is maintained
separately by wolfSSL. See `docs/announce-lkml.txt` for a full discussion of
anticipated upstream review feedback.

---

## License

GPL-2.0-only, to match the kernel. `wolfcrypt.ko` is dual-licensed
(GPL-2.0 + wolfSSL commercial) and maintained separately by wolfSSL;
production FIPS deployments require a wolfSSL commercial license for that module.
