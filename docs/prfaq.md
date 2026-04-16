# crypto2dev — PR/FAQ

*Internal document. Amazon-style press release + FAQ for product clarity.*

---

## Press Release (internal draft)

**wolfSSL Releases crypto2dev: FIPS 140-3 Validated Cryptography for Linux
Userspace Applications**

*A Linux kernel module that finally closes the gap between CMVP certification
and userspace crypto*

wolfSSL today released `crypto2dev`, an open-source Linux kernel module that
gives userspace applications direct access to FIPS 140-3 validated
cryptography via a file-descriptor interface at `/dev/crypto2dev`.

Federal contractors, healthcare organizations, and other deployments operating
under CMVP mandates have had no complete solution for userspace FIPS crypto on
Linux. The kernel's AF_ALG interface exposes cryptographic primitives to
userspace but provides no mechanism to require a CMVP-certified implementation
or to fail if one is unavailable. `crypto2dev` closes that gap: when wolfCrypt's
FIPS module is loaded, every operation is gated through the validated boundary
and non-validated code paths are hard-disabled.

`crypto2dev` uses a provider model. The core module (`crypto2dev.ko`) owns the
chardev interface and session lifecycle. wolfSSL's provider
(`crypto2dev_wolfssl.ko`) delegates all crypto to `wolfcrypt.ko` — wolfCrypt's
CMVP-validated Linux kernel module under certificate #4718. The same
certificate that covers wolfCrypt in userspace (libwolfssl) and in the kernel
(wolfcrypt.ko for dm-crypt and IPsec) now also covers userspace applications
that go through `/dev/crypto2dev`.

"Organizations with FIPS mandates have been duct-taping together solutions
that don't actually satisfy their auditors," said [exec name], wolfSSL. "This
is the clean path."

`crypto2dev` is available at https://github.com/wolfssl/crypto2dev under
GPL-2.0-only. wolfcrypt.ko requires a wolfSSL commercial license for
production FIPS deployments.

---

## FAQ

### Who is this for?

Organizations under legal or contractual mandates that require cryptography
from a **CMVP-certified module** as defined in FIPS PUB 140-3. Specifically:

- Federal agencies and their contractors operating under FISMA
- FedRAMP-authorized cloud service providers
- DoD contractors under DISA STIGs
- Healthcare organizations where HIPAA intersects with NIST guidance
- Any contract that says "FIPS 140-2/140-3 validated" in the crypto requirements

If none of those apply to you, `crypto2dev` is functional and well-designed
but you are probably fine with AF_ALG or a userspace TLS library.

---

### What problem does this solve?

There is a gap between what CMVP auditors require and what Linux provides:

**What auditors require:** "Demonstrate that the cryptographic operation was
performed by a module listed in the CMVP validation database, under the
conditions described in its Security Policy."

**What Linux provides:** `CONFIG_CRYPTO_FIPS` restricts the approved algorithm
list and runs self-tests, but carries no CMVP certificate. AF_ALG exposes
kernel crypto to userspace but cannot pin operations to a specific
implementation or fail when a FIPS module is absent.

**What `crypto2dev` provides:** A userspace interface where:
- `REQUIRE_FIPS` fails at session start if no certified module is loaded
- Once a FIPS provider is registered, all non-certified paths are
  hard-disabled — no priority games, no fallbacks
- Every operation checks the module's operational status and returns
  `-EACCES` if the module has degraded
- The audit trail is: CMVP cert # → `wolfcrypt.ko` → `crypto2dev_wolfssl.ko` →
  `/dev/crypto2dev` → application

---

### Why can't I just use AF_ALG?

AF_ALG dispatches through `crypto_alloc_*`. It gets the highest-priority
implementation for the requested algorithm name. Three things it cannot do:

**1. Require a specific validated implementation.**
A `SOCK_SEQPACKET` socket for `"cbc(aes)"` will use whatever implementation
has the highest priority. A hardware accelerator without a FIPS certificate
can silently outrank wolfCrypt. You asked for AES-CBC; you got it; from where
is not something AF_ALG tells you or enforces.

**2. Fail when the validated module is not loaded.**
If `wolfcrypt.ko` is not running, AF_ALG answers with the kernel's software
implementation. There is no `REQUIRE_FIPS` equivalent. The application has
no way to assert "this operation must come from a CMVP-certified module or
not complete at all."

**3. Detect that the module has degraded.**
`wolfCrypt_GetStatus_fips()` is not on the AF_ALG call path. If wolfCrypt's
periodic self-test fails after boot, AF_ALG sessions continue operating,
dispatching to whatever the kernel provides. No notification, no failure.

`crypto2dev` closes all three gaps. See `docs/announce-lkml.txt` for the
full technical argument.

FIPS compliance is not a design preference. The target organizations inherited
these requirements as a condition of doing business. Their auditor will ask for
a CMVP certificate number. That ends the conversation.

---

### Why can't I just link libwolfssl in userspace?

For TLS connections and direct library use, that works and is often the right
answer. `crypto2dev` is for applications that want FIPS-gated crypto *without*
bundling a crypto library — the same way they use the rest of the kernel's
services.

Additionally: in-kernel consumers (dm-crypt, IPsec/xfrm, NFS Kerberos) cannot
call a userspace library. `wolfcrypt.ko` handles them. `crypto2dev` bridges the
wolfCrypt FIPS boundary to userspace using the same validated binary.

**Ecosystem:** A companion project is planned — a userspace OpenSSL 3 provider
and a userspace NSS provider, both backed by `/dev/crypto2dev`. Applications
using OpenSSL 3 or NSS APIs will route their crypto through wolfCrypt without
code changes, with FIPS coverage from the same CMVP certificate. `crypto2dev`
is the stable kernel interface those providers will sit on top of.

---

### Does this replace wolfcrypt.ko's kernel crypto API registrations?

No. They are independent paths for different consumers.

`wolfcrypt.ko` registers wolfCrypt implementations into the kernel crypto API
at priority 300. dm-crypt, IPsec/xfrm, and AF_ALG all pick them up from there
automatically. That path is completely unaffected by whether `crypto2dev.ko` is
loaded.

`crypto2dev` is the additional path for userspace applications that need
explicit FIPS pinning and per-session key lifecycle — the things AF_ALG does
not provide.

---

### Why is this out-of-tree?

`wolfcrypt.ko`'s FIPS validation is bound to a specific compiled binary. The
CMVP certificate covers the module's exact binary artifact identified by an
HMAC-SHA256 integrity check over the module image. Merging the wolfCrypt source
into the Linux kernel tree and rebuilding it — even with no source changes —
produces a different binary and voids the validation.

`crypto2dev.ko` and `crypto2dev_kcapi.ko` have no such constraint and could go
in-tree. If the kernel community is interested in that, the conversation is
worth having. We ship all four modules together from one repository for
simplicity.

---

### What happens if I load crypto2dev_wolfssl.ko but not crypto2dev_kcapi.ko?

All algorithm lookups go to wolfCrypt. The `fips_state` sysfs file shows `1`
(operational) once wolfCrypt's POST passes. Operations return `-EACCES` if
wolfCrypt degrades.

---

### What happens if I load both providers?

Both register their algorithms. Because `crypto2dev_wolfssl.ko` has `is_fips=1`,
Layer 1 FIPS enforcement kicks in: all kcapi algorithms become unreachable via
lookup. Both modules remain loaded; kcapi algorithms remain visible in
`/sys/class/misc/crypto2dev/algorithms` for diagnostics, but no application
request can reach them.

This is by design and is not configurable. FIPS enforcement is binary: once a
FIPS module is present, non-FIPS paths are closed. There is no opt-out.

---

### Can I use this without the FIPS wolfCrypt module?

Yes. `crypto2dev_kcapi.ko` has no dependency on `wolfcrypt.ko` and works with
the kernel's built-in crypto. Neither provides FIPS coverage.

---

### What kernel versions are supported?

Tested on kernel 5.15 (Ubuntu 22.04 LTS) and 6.8 (Ubuntu 24.04 LTS). The
module uses standard kernel APIs with compatibility shims for version
differences in a small number of calls (see `src/crypto2dev_compat.h`).

---

### How does it interact with dm-crypt and IPsec?

It does not interact with them at all. dm-crypt and IPsec use the kernel
crypto API directly. When `wolfcrypt.ko` is loaded, it registers wolfCrypt
implementations at priority 300 and those consumers pick them up automatically
— with or without `crypto2dev.ko` being present.

`crypto2dev` is purely a userspace-facing interface. It does not register into
the kernel crypto API and does not affect in-kernel consumers.

---

### What algorithms are supported?

Under the wolfCrypt provider (FIPS-validated):
AES-CBC, AES-GCM, SHA-256/384/512, SHA3-256/384/512, HMAC-SHA-256/384/512,
CMAC-AES, HKDF-SHA-256/384/512, PBKDF2-SHA-256/384/512,
RSA-2048/4096 (sign/verify), ECDSA P-256/P-384 (sign/verify),
ECDH P-256/P-384 + HKDF (key agreement, raw Z never leaves provider).

Full list: `cat /sys/class/misc/crypto2dev/algorithms`

---

### Why do asymmetric keys use write-before-ioctl instead of embedding in the ioctl struct?

Two reasons, both independently sufficient:

**Key size.** Asymmetric keys — and especially post-quantum keys — are large:

| Key | Size |
|-----|------|
| EC P-256 private (raw scalar) | 32 B |
| RSA-2048 private (PKCS#8 DER) | ~1.2 KB |
| RSA-4096 private (PKCS#8 DER) | ~2.4 KB |
| ML-DSA-44 private | 2560 B |
| ML-DSA-65 private | 4032 B |
| ML-DSA-87 private | 4896 B |

Embedding key bytes in an ioctl struct would place up to 8192 bytes on the
kernel stack for every `KEY_IMPORT` call — even for tiny EC keys — far
exceeding the kernel's ~1 KB stack frame guideline. The write-before-ioctl
pattern allocates exactly what the key requires on the heap, then zeroes and
frees it after import. Post-quantum key sizes will only grow; accommodating
them requires only raising `CRYPTO2DEV_KEY_IMPORT_MAXLEN`, with no ABI change
and no ioctl struct change.

**Security.** A large on-stack plaintext key copy increases the window during
which key material is present in memory in a disclosable location. Heap
allocation zeroed immediately after import is the right pattern regardless of
size.

### What does FIPS 140-3 actually require that drives this design?

The major constraints that directly shaped the API:

- **Validated module boundary:** Operations must be performed by the certified
  module, not by unvalidated code. Layer 1 FIPS enforcement enforces this.
- **Key zeroization:** Key material must be destroyed before memory is released.
  Every provider callback uses `memzero_explicit()`. `memset()` is not acceptable
  because the compiler may elide it.
- **Approved RNG:** IV generation must use an approved DRBG (CTR_DRBG per
  SP 800-90A). `GEN_IV` calls `wc_RNG_GenerateBlock` inside the validated
  boundary. Callers cannot inject externally-generated IVs and call them FIPS.
- **Minimum key and parameter sizes:** AES ≥ 128 bits, RSA ≥ 2048 bits,
  EC ≥ P-256, GCM nonce exactly 96 bits, GCM tag ≥ 96 bits. These are FIPS
  constraints, not implementation choices, and are enforced before calling
  wolfCrypt.
- **Raw DH output (Z) must not leave the boundary:** `DO_AGREE` performs
  ECDH + HKDF inside the provider. The raw shared secret Z is computed and
  consumed entirely within wolfCrypt. Only the HKDF-derived OKM is returned.
  Exposing Z violates SP 800-56A.
