# crypto2dev Design Document

## Overview

`crypto2dev.ko` is a Linux kernel module that exposes wolfCrypt's FIPS-validated
cryptography to userspace via a chardev at `/dev/crypto2dev`. Every crypto
operation is delegated to wolfCrypt (via `wolfcrypt.ko`). This module does not
implement any cryptographic algorithm.

**What this module does:**
- Accepts connections to `/dev/crypto2dev` (one fd per session)
- Routes ioctls and read/write operations to registered crypto providers
- Enforces FIPS mode: once a FIPS-validated provider loads, all non-FIPS paths
  are hard-disabled

**What this module does not do:**
- Implement any cryptography — all crypto goes through provider callbacks
- Register into the kernel crypto API — that is done by `wolfcrypt.ko`'s linuxkm layer
- Multiplex multiple sessions on a single fd — each fd is exactly one session

**Planned ecosystem:** A companion project will provide a userspace OpenSSL 3
provider and a userspace NSS provider, both backed by `/dev/crypto2dev`.
Applications using OpenSSL 3 or NSS APIs will route their crypto through
wolfCrypt without code changes. `crypto2dev` is the stable kernel interface
those providers will sit on top of.

---

## Relationship to the Linux Crypto Stack

### Why not AF_ALG?

`AF_ALG` (`socket(AF_ALG, SOCK_SEQPACKET, 0)`) is the kernel's existing
interface for exposing crypto to userspace. It dispatches through
`crypto_alloc_*` — it gets whatever implementation has the highest priority for
the requested algorithm name. It cannot:

1. **Require a CMVP-certified implementation.** A hardware accelerator without
   a FIPS certificate can silently outrank wolfCrypt on priority. The caller has
   no way to assert "this operation must use the validated module."

2. **Fail when the validated module is not loaded.** If `wolfcrypt.ko` is absent,
   AF_ALG answers with the kernel's software fallback. There is no equivalent to
   `REQUIRE_FIPS`.

3. **Detect mid-session FIPS degradation.** `wolfCrypt_GetStatus_fips()` is not
   on the AF_ALG call path. A degraded wolfCrypt module does not cause AF_ALG
   operations to fail.

For deployments under FIPS 140-3 compliance mandates, the auditor's question is
"can you demonstrate that this operation went through the CMVP-certified module?"
AF_ALG cannot provide that guarantee. This is not a design preference —
CMVP compliance is a non-negotiable external requirement for the target
deployments, and AF_ALG is architecturally incapable of meeting it.

### Why not just extend AF_ALG?

Making AF_ALG provider-aware would require per-socket FIPS enforcement, hard
failure semantics for certification absence, and provider identity tracking —
changes to a subsystem with a large stable ABI used by millions of systems.
That is a significantly larger and riskier change than a focused chardev that
handles exactly the FIPS userspace use case.

### Why not register into the kernel crypto API?

`wolfcrypt.ko` already does. wolfCrypt's implementations register at priority
300 and are available to dm-crypt, IPsec/xfrm, AF_ALG, and all kernel
consumers. That path is complete and independent of crypto2dev. crypto2dev is
the additional FIPS-pinned path for userspace applications — it is a consumer
of `wolfcrypt.ko`, not a competitor to kernel crypto API registrants.

### Why not the kernel keyring for key management?

Two independent reasons:

**FIPS gating.** The keyring routes crypto operations through the kernel crypto
API — which returns to the AF_ALG problem. A keyring-dispatched ECDSA sign has
no guarantee of using the wolfCrypt FIPS boundary. KEY fds in crypto2dev hold
key context directly inside the provider; the same two-layer FIPS gate applies
to every sign, verify, and agree operation.

**Key size — especially post-quantum.** Asymmetric keys are large. Embedding
key material in an ioctl struct would require up to `CRYPTO2DEV_KEY_IMPORT_MAXLEN`
(8192 bytes) on the kernel stack for every `KEY_IMPORT` call, far exceeding the
kernel's ~1 KB stack frame guideline. The write-before-ioctl pattern (caller
writes raw key bytes to the fd, then calls `KEY_IMPORT` with metadata only)
allocates exactly what the key requires on the heap:

  EC P-256 private (raw scalar):        32 B
  RSA-2048 private (PKCS#8 DER):     ~1.2 KB
  RSA-4096 private (PKCS#8 DER):     ~2.4 KB
  ML-DSA-44 private:                 2560 B
  ML-DSA-65 private:                 4032 B
  ML-DSA-87 private:                 4896 B  ← current maximum

Post-quantum key sizes will only grow. The write-before-ioctl pattern scales to
any future PQ scheme by raising `CRYPTO2DEV_KEY_IMPORT_MAXLEN` — no ABI change,
no ioctl struct size change, no stack pressure.

---

## Module Layout

```
include/
  crypto2dev_provider.h         # GPL-only provider registration API
  uapi/
    crypto2dev_ioctl.h          # userspace-visible ioctl definitions

src/
  crypto2dev_main.c             # module_init / module_exit
  cdev/
    crypto2dev_cdev.c           # misc_device registration, sysfs attributes
    crypto2dev_fd.c             # per-fd state machine and all ioctl handlers
    crypto2dev_fd.h             # fd internal header
  provider/
    crypto2dev_registry.c       # global provider registry and lookup

  providers/
    wolfssl/                    # FIPS provider: wraps wolfCrypt directly
      wolfssl_provider.c        # registration (.is_fips = 1)
      wolfssl_provider.h        # wolfssl provider internal header
      wolfssl_aes_cbc.c         # "cbc(aes)"
      wolfssl_aes_gcm.c         # "gcm(aes)"
      wolfssl_sha.c             # "sha256", "sha384", "sha512", "sha3-256"
      wolfssl_hmac.c            # "hmac(sha256)", "hmac(sha384)", "hmac(sha512)"
      wolfssl_cmac.c            # "cmac(aes)"
      wolfssl_rsa.c             # "rsa-2048", "rsa-4096" (sign/verify/key ops)
      wolfssl_ecdsa.c           # "ecdsa-p256", "ecdsa-p384"
      wolfssl_ecdh.c            # "ecdh-p256", "ecdh-p384" via DO_AGREE
      wolfssl_ec_key.c          # shared EC key management (used by ecdsa + ecdh)
      wolfssl_ec_key.h          # EC key internal header
      wolfssl_kdf.c             # "hkdf(sha*)", "pbkdf2(sha*)" via DO_KDF
    kcapi/                      # non-FIPS provider: kernel crypto API
      kcapi_provider.c          # registration (.is_fips = 0)
      kcapi_skcipher.c          # "cbc(aes)", "ctr(aes)", "xts(aes)"
      kcapi_hash.c              # sha*, hmac*, "cmac(aes)"
      kcapi_aead.c              # "gcm(aes)"
      kcapi_kdf.c               # "hkdf(sha*)", "pbkdf2(sha*)" via DO_KDF
    example/                    # skeleton for hardware accelerator providers
      example_provider.c        # not compiled by default
```

**Load order is mandatory:**
```
insmod wolfcrypt.ko
insmod crypto2dev.ko
insmod crypto2dev_wolfssl.ko      # optional, provides FIPS algorithms
insmod crypto2dev_kcapi.ko        # optional, provides non-FIPS fallback
```

---

## File Descriptor Model

Each `open("/dev/crypto2dev")` produces one fd. The fd transitions through three
exclusive states:

```
UNSET (initial state)
  │
  ├─ CRYPTO2DEV_IOC_INIT ──────────────────────────► OPERATION
  │                                                    │
  │  (cipher/hash session; data via write/read)        │
  │                                                    ▼ close()
  │
  ├─ CRYPTO2DEV_IOC_KEY_IMPORT ────────────────────► KEY
  ├─ CRYPTO2DEV_IOC_KEY_GENERATE ──────────────────► KEY
  │                                                    │
  │  (asymmetric key holder; used as key_fd in        │
  │   DO_SIGN, DO_VERIFY, DO_AGREE ioctls)            ▼ close()
  │
  └─ close()  (frees inbuf if any write() was done)
```

There is no way to go back from OPERATION or KEY to UNSET. RESET re-arms a
finished OPERATION session without changing its type.

### UNSET fd

An UNSET fd accumulates write() data into `inbuf`. This data is consumed by
`KEY_IMPORT` (raw key material written before the ioctl) or `DO_KDF`. No read()
is possible on an UNSET fd.

### OPERATION fd

Created by `CRYPTO2DEV_IOC_INIT`. Holds a provider session context for one
symmetric cipher or hash operation. Data flows through write(), optional
intermediate read() drains, an explicit FINALIZE, and a final read() drain:

1. `SET_IV` or `GEN_IV` (required before write() for algorithms with an IV)
2. `SET_AAD` (AEAD algorithms, required before first write())
3. `SET_TAG` (AEAD decrypt, required before first write())
4. `write()` — calls `ops->update()` immediately; any output produced is
   appended to outbuf and is available for `read()` at any time. Multiple
   write()/read() cycles are allowed before FINALIZE.
5. `CRYPTO2DEV_IOC_FINALIZE` — signals end-of-input; calls `ops->finalize()`
   once; appends final output (last cipher block, digest, GCM tag) to outbuf;
   sets `finalized=true`. write() after FINALIZE returns -EINVAL.
6. `read()` — drains outbuf. Before FINALIZE, returns whatever update() has
   produced so far (0 bytes is valid for hash/MAC, which buffer internally).
   After FINALIZE, returns 0 (EOF) once outbuf is fully drained.
7. `GET_TAG` (AEAD encrypt, after FINALIZE and drain)
8. `RESET` — re-arms for a new encrypt/decrypt with the same key; clears
   outbuf, `finalized`, `error`, and `iv_set` flags. IV must be re-supplied
   via SET_IV or GEN_IV before the next write().

The `error` flag is set if any update() or finalize() call fails. A session in
error state returns -EIO on all write/read/ioctl until RESET.

### KEY fd

Created by `KEY_IMPORT` or `KEY_GENERATE`. Holds one asymmetric key object
(private key, public key, or key pair). KEY fds are asymmetric-only; symmetric
keys are always supplied inline in INIT.

A KEY fd is passed by file descriptor number to DO_SIGN, DO_VERIFY, DO_AGREE.
The operation reads the key from the KEY fd without modifying it.

`KEY_EXPORT_PRIVATE` (if the key was created with exportable=1) places the
private key bytes in outbuf; subsequent read() drains them. Public key export
is available directly via read() once the KEY fd is initialized.

---

## Streaming I/O Model

### State Machine

```
OPERATION fd states:

  [READY]
    │  write() → update() → output in outbuf
    │  read()  → drain outbuf (may return 0 bytes for hash)
    │
    ↓ FINALIZE ioctl → finalize() → outbuf gets final output
  [FINALIZED]
    │  write() → -EINVAL
    │  read()  → drain outbuf; returns 0 (EOF) when empty
    │
    ↓ RESET ioctl
  [READY] (same key, cleared IV, empty outbuf)
```

State transitions:
- `INIT` → READY
- `FINALIZE` (from READY only) → FINALIZED; idempotent not allowed (second FINALIZE → -EINVAL)
- `RESET` (from FINALIZED only) → READY; RESET on READY → -EINVAL

### UAPI Contract

**write(fd, buf, count)**
- Calls `ops->update(ctx, buf, count, out, outbuf_avail, &produced)` immediately.
- Any bytes produced by update() are appended to outbuf.
- Returns `count` on success (full write; partial writes are not possible at the
  framework level because wolfCrypt processes all input before returning).
- Returns -EINVAL if `finalized=true` (write after FINALIZE).
- Returns -EIO if `error=true`.
- Returns -EINVAL if `iv_set=false` and `ops->set_iv != NULL` (IV required).

**read(fd, buf, count)**
- Drains bytes from outbuf, up to `count`.
- Returns the number of bytes copied (may be 0 if outbuf is empty).
- Returns 0 (EOF) only when `finalized=true` AND `outbuf_drained >= outbuf_len`.
- Never calls finalize() — that is the FINALIZE ioctl's job.
- Returns -EIO if `error=true`.

**CRYPTO2DEV_IOC_FINALIZE** (slot 21, `_IO`)
- Calls `ops->finalize(ctx, out, outbuf_avail, &produced)` and appends to outbuf.
- Sets `finalized=true` on success.
- Returns -EINVAL if already finalized.
- Returns -EINVAL if `iv_set=false` and `ops->set_iv != NULL`.
- Returns -EIO on finalize() failure; sets `error=true`.

**CRYPTO2DEV_IOC_RESET** (slot 19)
- Requires `finalized=true`; returns -EINVAL if called on a READY session.
- Calls `ops->sess_reset(ctx)` if provided.
- Clears: outbuf (zeroes and resets pointers), `finalized`, `error`, `iv_set`.
- Wakes poll waiters.

### Provider Contract

**`update(ctx, in, inlen, out, outbuf_size, *outlen)`**

- MUST process all complete blocks in `in[0..inlen)` immediately.
- MUST write output bytes into `out[0..*outlen)`, where `*outlen <= outbuf_size`.
- MAY buffer at most one incomplete trailing block (e.g. AES-CBC tail).
- For hash, HMAC, CMAC: updates internal state; sets `*outlen = 0`.
- For CBC: outputs `floor(inlen / AES_BLOCK_SIZE) * AES_BLOCK_SIZE` bytes
  (holds the partial tail). More precisely: if the provider already holds
  a partial tail T from a prior update(), it concatenates T+in, processes
  complete blocks, emits those, and holds the new tail. inlen=0 is a no-op.
- For GCM: passes data to wc_AesGcmEncryptUpdate/wc_AesGcmDecryptUpdate;
  output size matches input size for the authenticated plaintext portion.
- Returns 0 on success, negative errno on failure.

**`finalize(ctx, out, outbuf_size, *outlen)`**

- Processes any buffered tail and produces final output.
- For CBC encrypt: pads and encrypts the final block; `*outlen = AES_BLOCK_SIZE`.
- For CBC decrypt: decrypts and strips padding from final block.
- For hash/HMAC/CMAC: produces digest; `*outlen = digest_size`.
- For GCM encrypt: finalizes AAD and produces auth tag via `get_tag()` path;
  `*outlen = 0` (tag is retrieved separately via GET_TAG ioctl).
- For GCM decrypt: verifies auth tag; returns -EBADMSG on failure (constant-time).
- May be called with a zero-byte tail (caller wrote only complete blocks).
- Returns 0 on success, negative errno on failure.

**AEAD SECURITY NOTE**: GCM decrypt tag comparison MUST be constant-time.
Delegate to `wc_AesGcmDecrypt()` or `crypto_aead_decrypt()` — never memcmp().

---

## UAPI Contract

Magic byte: `0xC2`

### Size Limits

| Constant | Value | Purpose |
|---|---|---|
| `CRYPTO2DEV_ALGO_MAXLEN` | 64 | algorithm name buffer |
| `CRYPTO2DEV_PROVIDER_MAXLEN` | 32 | provider name buffer |
| `CRYPTO2DEV_KEY_MAXLEN` | 128 | inline key in INIT |
| `CRYPTO2DEV_IV_MAXLEN` | 32 | IV/nonce in SET_IV/GEN_IV |
| `CRYPTO2DEV_TAG_MAXLEN` | 16 | AEAD authentication tag |
| `CRYPTO2DEV_HASH_MAXLEN` | 64 | max digest (SHA-512) |
| `CRYPTO2DEV_SIG_MAXLEN` | 512 | max signature (RSA-4096 DER) |
| `CRYPTO2DEV_KEY_IMPORT_MAXLEN` | 8192 | max imported key (ML-DSA-87) |
| `CRYPTO2DEV_PUBKEY_MAXLEN` | 256 | max public key (P-521 uncompressed) |

### Named Constants

```c
/* op field in INIT */
CRYPTO2DEV_OP_ENCRYPT = 1
CRYPTO2DEV_OP_DECRYPT = 2
CRYPTO2DEV_OP_HASH    = 3

/* key_type field in KEY_IMPORT / KEY_GET_INFO */
CRYPTO2DEV_KEY_PRIVATE = 1
CRYPTO2DEV_KEY_PUBLIC  = 2
CRYPTO2DEV_KEY_PAIR    = 3

/* fd_type field in GET_STATE */
CRYPTO2DEV_FDTYPE_UNSET     = 0
CRYPTO2DEV_FDTYPE_OPERATION = 1
CRYPTO2DEV_FDTYPE_KEY       = 2

/* fips_state field in STATUS */
CRYPTO2DEV_FIPS_NO_PROVIDER     = 0   /* no FIPS provider loaded */
CRYPTO2DEV_FIPS_OPERATIONAL     = 1   /* all FIPS gates passing */
CRYPTO2DEV_FIPS_NOT_OPERATIONAL = 2   /* a FIPS gate is failing */
```

### Ioctl Table

| Command | Slot | Dir | Struct | Notes |
|---|---|---|---|---|
| `CRYPTO2DEV_IOC_INIT` | 1 | W | `crypto2dev_init_op` | Promote UNSET → OPERATION |
| `CRYPTO2DEV_IOC_SET_IV` | 2 | W | `crypto2dev_iv_op` | Set IV before write() |
| `CRYPTO2DEV_IOC_SET_AAD` | 3 | W | `crypto2dev_aad_op` | Set AEAD AAD before write() |
| `CRYPTO2DEV_IOC_GET_TAG` | 4 | R | `crypto2dev_tag_op` | Get AEAD tag after read() |
| `CRYPTO2DEV_IOC_SET_TAG` | 5 | W | `crypto2dev_tag_op` | Set AEAD tag before write() (decrypt) |
| *(reserved)* | 6, 7 | — | — | Do not use |
| `CRYPTO2DEV_IOC_GEN_IV` | 8 | RW | `crypto2dev_iv_op` | Generate IV and return it |
| `CRYPTO2DEV_IOC_STATUS` | 9 | R | `crypto2dev_status` | Module FIPS state, algo count |
| `CRYPTO2DEV_IOC_GET_STATE` | 10 | R | `crypto2dev_fd_state_info` | Per-fd session state |
| `CRYPTO2DEV_IOC_KEY_IMPORT` | 11 | W | `crypto2dev_key_import_op` | Promote UNSET → KEY |
| `CRYPTO2DEV_IOC_KEY_GENERATE` | 12 | W | `crypto2dev_key_generate_op` | Promote UNSET → KEY |
| `CRYPTO2DEV_IOC_KEY_GET_INFO` | 13 | R | `crypto2dev_key_info` | Query KEY fd |
| `CRYPTO2DEV_IOC_KEY_EXPORT_PRIVATE` | 14 | RW | `crypto2dev_key_export_op` | Stage private key for read() |
| *(tombstone)* | 15 | — | — | Was LIST_ALGOS; use sysfs |
| `CRYPTO2DEV_IOC_DO_SIGN` | 16 | RW | `crypto2dev_sign_op` | One-shot asymmetric sign |
| `CRYPTO2DEV_IOC_DO_VERIFY` | 17 | RW | `crypto2dev_verify_op` | One-shot signature verify |
| `CRYPTO2DEV_IOC_DO_AGREE` | 18 | RW | `crypto2dev_agree_op` | One-shot ECDH + HKDF |
| `CRYPTO2DEV_IOC_RESET` | 19 | — | (none) | Re-arm OPERATION fd (from FINALIZED only) |
| `CRYPTO2DEV_IOC_REQUIRE_FIPS` | 20 | — | (none) | Require FIPS mode before INIT |
| `CRYPTO2DEV_IOC_FINALIZE` | 21 | — | (none) | Signal end-of-input; calls finalize() |
| `CRYPTO2DEV_IOC_DO_KDF` | 22 | W | `crypto2dev_kdf_op` | Derive key from IKM; promotes UNSET → KEY |

DO_SIGN, DO_VERIFY, DO_AGREE may be called on any fd type; they reference the
key via `key_fd` field (a file descriptor number of a KEY fd).

### Key Struct Layouts

```c
struct crypto2dev_init_op {
    char  algo    [64];   /* e.g. "cbc(aes)", "sha256" */
    char  provider[32];   /* e.g. "wolfssl", or "" for any */
    __u32 op;             /* CRYPTO2DEV_OP_ENCRYPT / DECRYPT / HASH */
    __u32 keylen;         /* inline key length in bytes */
    __u8  key[128];       /* inline key bytes */
    __s32 key_fd;         /* reserved; must be -1 */
    __u8  _pad[4];        /* reserved; must be 0 */
};

struct crypto2dev_sign_op {
    __s32 key_fd;
    __u8  _pad[4];
    char  hash_algo[64];  /* hash name, e.g. "sha256" */
    __u32 digest_len;
    __u8  digest[64];     /* pre-computed digest; never a raw message */
    __u32 sig_len;        /* [out] */
    __u8  sig[512];       /* [out] DER-encoded signature */
};

struct crypto2dev_agree_op {
    __s32 key_fd;
    __u8  _pad[4];
    __u32 peer_pubkey_len;
    __u8  peer_pubkey[256];
    __u32 salt_len;       /* 0 = RFC 5869 default */
    __u8  salt[64];
    __u32 info_len;
    __u8  info[128];
    __u32 okm_len;        /* [in] requested OKM bytes */
    __u8  okm[256];       /* [out] derived key material */
};
```

### Algorithm Enumeration

Algorithm discovery is via sysfs, not via ioctl:

```
/sys/class/misc/crypto2dev/algorithms
```

One line per registered algorithm:

```
cbc(aes):wolfssl:1:0
gcm(aes):wolfssl:1:0
sha256:wolfssl:1:0
...
cbc(aes):kcapi:0:0
```

Format: `algo:provider:has_fips_gate:has_key_ops`

---

## Provider API

Providers are separate kernel modules that register algorithm implementations
with the crypto2dev framework.

### struct crypto2dev_provider

```c
struct crypto2dev_provider {
    const char *name;                          /* e.g. "wolfssl", "kcapi" */
    u32 is_fips;                               /* 1 = FIPS-validated boundary */
    const struct crypto2dev_algo_ops **algos;  /* NULL-terminated array */
    u32 num_algos;
    struct module *owner;                      /* THIS_MODULE */
    struct list_head list;                     /* framework-internal */
};
```

**`is_fips`**: Set to 1 if this provider's algorithms are implemented inside a
FIPS 140-3 validated cryptographic boundary. Once any provider with `is_fips=1`
registers, the framework enters FIPS mode and all non-FIPS providers become
invisible to algorithm lookup.

### struct crypto2dev_algo_ops

The per-algorithm vtable. All callbacks except `sess_init`, `sess_free`,
`update`, and `finalize` are optional (NULL = not supported).

```c
struct crypto2dev_algo_ops {
    const char *algo;              /* canonical name, e.g. "cbc(aes)" */

    /* FIPS gate — called before every crypto operation. */
    int (*fips_gate)(void);        /* returns 0 if operational, -EACCES if not */

    /* Session lifecycle */
    int  (*sess_init)(void **ctx, u32 op, const u8 *key, u32 keylen);
    void (*sess_free)(void *ctx);
    int  (*sess_reset)(void *ctx); /* optional: re-arm session, same key, clear IV */

    /* IV / nonce */
    int  (*set_iv)(void *ctx, const u8 *iv, u32 ivlen);    /* optional */
    int  (*gen_iv)(void *ctx, u8 *iv, u32 ivlen);          /* optional */

    /* AEAD only */
    int  (*set_aad)(void *ctx, const u8 *aad, u32 aadlen); /* optional */
    int  (*set_tag)(void *ctx, const u8 *tag, u32 taglen); /* optional, decrypt */
    int  (*get_tag)(void *ctx, u8 *tag, u32 *taglen);      /* optional, encrypt */

    /* Data path */
    int  (*update)(void *ctx, const u8 *in, size_t inlen,
                   u8 *out, size_t outbuf_size, size_t *outlen);
    int  (*finalize)(void *ctx, u8 *out, size_t outbuf_size, size_t *outlen);

    /* Asymmetric operations */
    int  (*sign)(void *key_ctx, const char *hash_algo,
                 const u8 *digest, u32 digest_len,
                 u8 *sig, u32 sig_bufsz, u32 *sig_len);     /* optional */
    int  (*verify)(void *key_ctx, const char *hash_algo,
                   const u8 *digest, u32 digest_len,
                   const u8 *sig, u32 sig_len);              /* optional */
    int  (*agree)(void *key_ctx,
                  const u8 *peer_pubkey, u32 peer_pubkey_len,
                  const u8 *salt, u32 salt_len,
                  const u8 *info, u32 info_len,
                  u8 *okm, u32 okm_len);                     /* optional */

    /* Key management */
    int  (*key_import)(void **key_ctx, u32 key_type,
                       const u8 *raw, u32 rawlen);           /* optional */
    int  (*key_generate)(void **key_ctx);                    /* optional */
    int  (*key_export_public)(void *key_ctx,
                              u8 *out, u32 bufsz, u32 *outlen); /* optional */
    int  (*key_export_private)(void *key_ctx,
                               u8 *out, u32 bufsz, u32 *outlen); /* optional */
    void (*key_free)(void *key_ctx);                         /* optional */
};
```

### Callback Contracts

**`fips_gate()`**: Called by the framework before every operation that touches
cryptographic state. NOT called for `sess_free` or `key_free` — cleanup must
always proceed regardless of FIPS status.

**`sess_init(ctx, op, key, keylen)`**: Allocate and initialize a session context.
On failure, `*ctx` must be NULL and all partial allocations must be freed. The
framework calls `sess_free` only if `sess_init` succeeds.

**`gen_iv(ctx, iv, ivlen)`**: Generate a random IV using the provider's
approved DRBG. For wolfssl providers, this calls `wc_RNG_GenerateBlock` using
a `WC_RNG` embedded in the session context — the entropy stays inside the FIPS
boundary. If `gen_iv` is NULL, the framework falls back to `get_random_bytes()`.

**`agree()`**: Computes ECDH + HKDF. The raw shared secret Z must never leave
the provider — the provider runs HKDF internally and returns only the OKM.

**`update()` / `finalize()`**: The framework calls update() on every write()
and passes the available outbuf space as `outbuf_size`. The provider writes at
most `outbuf_size` bytes and sets `*outlen`. If `*outlen > outbuf_size`, the
framework emits `WARN_ON` and returns -EIO — providers must never overflow. See
§"Streaming I/O Model → Provider Contract" for the block-buffering and output-
size rules for each algorithm class. Hash/HMAC/CMAC providers return
`*outlen = 0` from update() (state update only; digest produced by finalize()).

### Registering a Provider

```c
static const struct crypto2dev_algo_ops *my_algos[] = {
    &my_aes_cbc_ops,
    &my_sha256_ops,
    NULL,
};

static struct crypto2dev_provider my_provider = {
    .name      = "myhw",
    .is_fips   = 0,       /* or 1 if FIPS-validated */
    .algos     = my_algos,
    .num_algos = 2,
    .owner     = THIS_MODULE,
};

static int __init my_init(void) {
    return crypto2dev_register_provider(&my_provider);
}
static void __exit my_exit(void) {
    crypto2dev_unregister_provider(&my_provider);
}
```

---

## FIPS Enforcement *(FIPS 140-3 — not negotiable)*

Everything in this section is driven by FIPS 140-3 requirements. None of it
is a design preference. Removing or weakening any of these mechanisms is a
compliance failure, not a simplification.

The framework implements two independent, complementary FIPS enforcement layers.

### Layer 1: Registry-level enforcement (provider visibility)

`crypto2dev_registry.c` maintains `atomic_t fips_provider_count`. When any
provider with `is_fips=1` registers, this counter is incremented (inside the
write lock so readers see a consistent state).

`crypto2dev_lookup_algo()` reads this counter before walking the provider list.
If non-zero ("FIPS mode active"), any provider entry with `is_fips=0` is skipped
entirely — it does not exist for the purpose of this lookup. This applies even
when the caller names a specific non-FIPS provider. Once wolfssl is loaded, kcapi
cannot be reached regardless of what the caller requests.

Counter update happens inside the write lock to prevent a race where a reader
sees a newly-added FIPS provider in the list but still reads `fips_mode=false`.

**FIPS mode activation is one-way during a kernel session.** Once any FIPS
provider loads, `fips_provider_count > 0` and all non-FIPS paths are
invisible. This state reverts only when every FIPS provider has unloaded
(i.e., `fips_provider_count` returns to 0). In a typical production deployment
wolfssl is loaded at boot and never unloaded — FIPS mode is effectively
permanent for the lifetime of the kernel session.

This is intentional and required. A system that transitions in and out of FIPS
mode during operation would have an unpredictable security boundary. FIPS
enforcement must be monotonic: once activated, it does not deactivate while
any FIPS-validated module is present.

### No runtime disable

There is no ioctl, sysfs attribute, or module parameter to disable FIPS
enforcement. Once `fips_provider_count > 0`, non-FIPS providers are invisible
to all lookups and there is no mechanism to make them visible again short of
unloading the FIPS provider module (`rmmod crypto2dev_wolfssl`), which
decrements the counter and returns it to 0. Adding a runtime disable knob
would be a CMVP audit finding: FIPS 140-3 requires that the approved security
boundary remain active whenever a validated module is loaded.

### Layer 2: Per-operation gating (provider-side check)

Each FIPS provider sets `fips_gate` callbacks on its algo_ops. The framework
calls `ops->fips_gate()` at the start of every crypto operation. For wolfssl,
this calls `wolfCrypt_GetStatus_fips()` — the wolfCrypt module's self-test
and integrity check. If the FIPS module is not operational (e.g., a POST failed
at boot), the gate returns -EACCES and the operation is rejected.

These two layers serve different purposes and neither is sufficient alone:

- **Layer 1** prevents routing to unvalidated code paths
- **Layer 2** prevents operations when the validated module itself is unhealthy

**Why Layer 1 cannot be replaced by Layer 2 alone:**
The `CRYPTO2DEV_IOC_INIT` ioctl accepts a `provider` field. A caller can
request `provider="kcapi"` explicitly. Without Layer 1, that request would
succeed when a FIPS provider is loaded — the lookup would find kcapi,
kcapi has `fips_gate=NULL` so the framework skips the gate check, and
non-FIPS crypto executes. Layer 1 closes this hole: once any FIPS provider
is loaded, a request naming `provider="kcapi"` returns -ENOENT. There is
no way to reach a non-FIPS provider regardless of what the caller requests.

**Why Layer 2 cannot be replaced by Layer 1 alone:**
Layer 1 ensures the correct provider is selected. Layer 2 ensures the
selected provider's FIPS module is currently healthy. wolfCrypt runs
periodic self-tests; a POST or integrity check failure can degrade the
FIPS boundary after a session starts. Layer 1 cannot detect this —
it only knows which provider to route to, not whether that provider's
cryptographic module is still operational.

Do not remove either layer. Do not merge them. They are orthogonal.

### REQUIRE_FIPS ioctl

`CRYPTO2DEV_IOC_REQUIRE_FIPS` (slot 20) marks an UNSET fd. When a subsequent
INIT is attempted on that fd, if `crypto2dev_fips_provider_loaded()` returns
false (no FIPS provider currently loaded), INIT fails with -ENOENT.

This ioctl only matters when no FIPS provider is loaded. When any FIPS provider
is loaded, Layer 1 already enforces FIPS-only dispatch for all lookups regardless
of this flag.

### FIPS Algorithm Parameter Constraints *(FIPS 140-3 — not negotiable)*

These constraints are external mandates from FIPS 140-3 and its referenced
standards. They are not internal design choices and cannot be relaxed under
any circumstance.

| Parameter | Constraint | Authority |
|---|---|---|
| AES key size | Minimum 128 bits (16 bytes) | FIPS 197 |
| RSA key size | Minimum 2048 bits (256 bytes) | SP 800-131A |
| EC curve | P-256 minimum; P-192 and smaller not approved | SP 800-186 |
| GCM nonce length | Exactly 96 bits (12 bytes) | SP 800-38D |
| GCM authentication tag | Minimum 96 bits (12 bytes) | SP 800-38D |
| IV/nonce generation | Must use FIPS-approved DRBG within the validated boundary | SP 800-90A |
| ECDH shared secret Z | Must not leave the validated boundary | SP 800-56A |

Providers must enforce these at the provider level before calling wolfCrypt.
wolfCrypt may enforce some of them internally in FIPS builds, but relying on
that is not sufficient — the provider is the documented enforcement point for
this module's FIPS boundary.

### FIPS Aggregate State

`CRYPTO2DEV_IOC_STATUS` returns a `fips_state` field computed by
`crypto2dev_fips_aggregate()`:

| Value | Meaning |
|---|---|
| `CRYPTO2DEV_FIPS_NO_PROVIDER` (0) | No provider with a `fips_gate` callback is loaded |
| `CRYPTO2DEV_FIPS_OPERATIONAL` (1) | At least one FIPS provider loaded; all `fips_gate()` calls return 0 |
| `CRYPTO2DEV_FIPS_NOT_OPERATIONAL` (2) | At least one `fips_gate()` is returning non-zero |

---

## Algorithm Coverage

| Algorithm | wolfssl | kcapi | Notes |
|---|---|---|---|
| `cbc(aes)` | FIPS | yes | wolfssl wins when loaded |
| `ctr(aes)` | — | yes | kcapi only |
| `xts(aes)` | — | yes | kcapi only; unavailable in FIPS mode |
| `gcm(aes)` | FIPS | yes | wolfssl wins when loaded |
| `cmac(aes)` | FIPS | yes | wolfssl wins when loaded |
| `sha256` | FIPS | yes | wolfssl wins when loaded |
| `sha384` | FIPS | yes | wolfssl wins when loaded |
| `sha512` | FIPS | yes | wolfssl wins when loaded |
| `sha3-256` | FIPS | yes | wolfssl wins when loaded |
| `sha3-384` | FIPS | yes | wolfssl wins when loaded |
| `sha3-512` | FIPS | yes | wolfssl wins when loaded |
| `hmac(sha256)` | FIPS | yes | wolfssl wins when loaded |
| `hmac(sha384)` | FIPS | yes | wolfssl wins when loaded |
| `hmac(sha512)` | FIPS | yes | wolfssl wins when loaded |
| `rsa-2048` | FIPS | — | wolfssl only; sign/verify |
| `rsa-4096` | FIPS | — | wolfssl only; sign/verify |
| `ecdsa-p256` | FIPS | — | wolfssl only |
| `ecdsa-p384` | FIPS | — | wolfssl only |
| `ecdh-p256` | FIPS | — | wolfssl only; via DO_AGREE (ECDH+HKDF inline) |
| `ecdh-p384` | FIPS | — | wolfssl only; via DO_AGREE (ECDH+HKDF inline) |
| `hkdf(sha256)` | FIPS | yes | via DO_KDF; SP 800-56C Rev2 |
| `hkdf(sha384)` | FIPS | yes | via DO_KDF |
| `hkdf(sha512)` | FIPS | yes | via DO_KDF |
| `pbkdf2(sha256)` | FIPS | yes | via DO_KDF; iterations ≥ 1000; salt ≥ 16 bytes |
| `pbkdf2(sha384)` | FIPS | yes | via DO_KDF; iterations ≥ 1000; salt ≥ 16 bytes |
| `pbkdf2(sha512)` | FIPS | yes | via DO_KDF; iterations ≥ 1000; salt ≥ 16 bytes |

"wolfssl wins" means that once `crypto2dev_wolfssl.ko` is loaded, the kcapi
implementation for that algorithm becomes unreachable — Layer 1 enforcement.
`ctr(aes)` and `xts(aes)` have no wolfssl implementation, so they are unavailable
when FIPS mode is active.

---

## In-Device Key Derivation

`CRYPTO2DEV_IOC_DO_KDF` derives a symmetric key from input keying material
and promotes the calling fd to a KEY fd. The derived key is usable wherever
any other KEY fd is accepted.

### Purpose

KDF inside the module keeps two sensitive values — the IKM and the derived key
— from appearing in userspace memory simultaneously. For FIPS 140-3 operational
environments this is required: SP 800-133 mandates that a KDF-derived key be
generated and first used inside the FIPS cryptographic boundary.

Implemented in wolfssl and kcapi providers.

### Supported Algorithms

| `algo` string     | Standard         | Notes                          |
|---|---|---|
| `hkdf(sha256)`    | RFC 5869         | FIPS 140-3 approved (SP 800-56C Rev2) |
| `hkdf(sha384)`    | RFC 5869         | FIPS 140-3 approved            |
| `hkdf(sha512)`    | RFC 5869         | FIPS 140-3 approved            |
| `pbkdf2(sha256)`  | RFC 8018         | FIPS 140-3 approved; iterations ≥ 1000 |
| `pbkdf2(sha1)`    | RFC 8018         | Allowed for compatibility; SHA-1 is deprecated |

### UAPI Struct

```c
struct crypto2dev_kdf_op {
    char  algo[CRYPTO2DEV_ALGO_MAXLEN];     /* 'hkdf(sha256)', 'pbkdf2(sha256)', ... */
    char  out_algo[CRYPTO2DEV_ALGO_MAXLEN]; /* target algo for derived key, e.g. 'cbc(aes)' */
    __u32 out_keylen;    /* derived key length in bytes (max 64 for v1) */
    __s32 ikm_fd;        /* KEY fd for HKDF IKM; -1 = use inbuf (written via write()) */
    __u8  salt[64];      /* salt (HKDF: optional; PBKDF2: required) */
    __u32 salt_len;      /* effective bytes in salt[] */
    __u8  info[256];     /* HKDF context/label; ignored for PBKDF2 */
    __u32 info_len;      /* effective bytes in info[] */
    __u32 iterations;    /* PBKDF2 only; HKDF ignores; framework enforces ≥ 1000 */
    __u8  _pad[4];       /* reserved; must be zero */
};
```

The struct carries no raw key bytes. The IKM is supplied either via write()
(stored in inbuf) or via a KEY fd. The derived key is returned only as a KEY
fd — it never appears in userspace memory.

### Fd Lifecycle

```
open("/dev/crypto2dev")       → fd is UNSET
write(fd, ikm_bytes, n)       → ikm stored in inbuf (only if ikm_fd == -1)
ioctl(fd, DO_KDF, &kdf_op)    → inbuf (or IKM from ikm_fd) consumed;
                                 fd promoted to KEY fd (symmetric key)
inbuf cleared by memzero_explicit after ioctl
```

For a password-based key (PBKDF2):
```
write(fd, password, n)         → password stored in inbuf
ioctl(fd, DO_KDF, &kdf_op)     → password consumed, derived key installed
```

The inbuf write data is zeroized immediately after the ioctl regardless of
success or failure.

For key-chaining (HKDF only — PBKDF2 requires write()):
```
fd1 = open("/dev/crypto2dev")    → UNSET fd for stage 1
write(fd1, ikm_bytes, n)         → raw IKM stored in inbuf
ioctl(fd1, DO_KDF, &kdf_op)      → fd1 promoted to KEY fd (stage 1 derived key)

fd2 = open("/dev/crypto2dev")    → UNSET fd for stage 2
ioctl(fd2, DO_KDF, {.ikm_fd=fd1, ...})
                                  → IKM extracted from fd1 (in-kernel only);
                                     fd2 promoted to KEY fd (stage 2 derived key)
```
Key material never crosses the FIPS boundary during chaining.

### Provider Callback

```c
int (*kdf)(void *key_ctx_unused,
           const char *algo,
           const u8 *ikm, u32 ikm_len,
           const u8 *salt, u32 salt_len,
           const u8 *info, u32 info_len,
           u32 iterations,
           u8 *out_key, u32 out_keylen);
```

The callback writes raw derived key bytes into `out_key[out_keylen]`. The
framework then imports these bytes as a symmetric KEY fd via key_import,
and calls `memzero_explicit(out_key, out_keylen)` before freeing the temporary
buffer. The provider never returns key bytes to userspace.

The `kdf` callback is a new field on `struct crypto2dev_algo_ops` added when
implementation begins. Providers that do not implement KDF leave it NULL; the
framework returns `-EOPNOTSUPP`.

### FIPS Constraints *(FIPS 140-3 — not negotiable)*

- HKDF: approved per SP 800-56C Rev2. No minimum IKM size in the standard,
  but passing empty IKM is rejected with `-EINVAL`.
- PBKDF2: iterations must be ≥ 1000 (SP 800-132). The framework enforces this
  limit before calling the provider.
- `out_keylen` must be ≤ 64 bytes for v1 (covers AES-256 and SHA-512 digest).
- Both the IKM and the derived key must remain inside the FIPS boundary:
  IKM is consumed from inbuf or an in-kernel KEY fd; output is placed directly
  into a new KEY fd. Neither is copied to userspace.

---

## Locking Model

**Per-fd mutex** (`state->lock`): A single sleeping mutex protects all fields of
`crypto2dev_fd_state`. Held across every provider callback invocation. Providers
may sleep. Never held across `fget()`/`fput()` for a different fd.

**Provider registry rwlock** (`provider_lock`): A single rwlock protects the
`provider_list` and `fips_provider_count`. Readers hold it during lookup,
enumerate, count, and fips_aggregate. Writers hold it during register and
unregister. The atomic counter is updated inside the write lock to maintain a
consistent view for readers.

**Module refcount**: `try_module_get()` is called inside the read lock during
lookup. The reference is held until session close. `module_put()` is called
without any lock.

---

## Key Material Handling *(FIPS 140-3 — not negotiable)*

FIPS 140-3 requires that key material be destroyed before memory is released.
`memzero_explicit()` is used throughout — not `memset()`, not `bzero()`. The
compiler may optimize away a plain `memset()` when the buffer goes out of
scope; `memzero_explicit()` is a compiler barrier that prevents this. This
applies on every exit path — error paths included, not only the happy path.

Inline keys (INIT op) are:
- Copied from userspace into the kernel stack by `ioctl_init()`
- Passed to `ops->sess_init()` and erased from the stack with `memzero_explicit()`
  in `out_zeroize` regardless of success or failure
- Held in provider-managed ctx until `sess_free()`; providers must zero with
  `memzero_explicit()` before kfree

KEY fd private key bytes:
- Imported from inbuf (write-before-ioctl pattern); inbuf zeroed after import
- Held in provider-managed key_ctx; zeroed by `key_free()` on close
- Exported private key bytes placed in outbuf by `KEY_EXPORT_PRIVATE`; zeroed
  on next RESET or close

---

## Design Decisions

**No enums, no flag bits. Hard rule.**

This is not a style preference. It is a design constraint enforced at review.
Any patch adding a `typedef enum`, anonymous `enum`, `flags` field, or
bitmask constant to any header will be rejected.

Algorithm names are strings (`"cbc(aes)"`). Provider names are strings
(`"wolfssl"`). New behaviors get new ioctls or new named struct fields —
never a new bit in a `flags` word, never a new enum value.

*Why strings:* An enum-identified algorithm requires a header change and
recompile of every caller to add a new one. A string does not. Out-of-tree
providers and existing userspace binaries continue to work after new
algorithms are registered.

*Why no flags:* A `__u32 flags` field starts with one bit and ends with
thirty-two, each combination untested, each interaction a future bug. The
combinatorial state space doubles with every new flag. We add a new ioctl
or a new named field instead — the cost is one slot number, the benefit is
an unambiguous, independently testable behavior.

The only integer codes in this module are small, permanently-closed sets
whose full membership is fixed in the current header and will never grow:
op direction (ENCRYPT/DECRYPT), fd type (UNSET/OPERATION/KEY), key type
(PUBLIC/PRIVATE/SYMMETRIC), FIPS aggregate state (OPERATIONAL/DEGRADED/
NOT_OPERATIONAL). Everything else is a string.

**write()+read() data path, not ioctl scatter-gather.** Bulk data moves through
the normal file I/O path. This avoids large ioctl structs, works with standard
POSIX I/O tooling, and lets the kernel handle partial copies naturally.

**IV required before write() when set_iv != NULL.** The `iv_set` flag in
fd_state prevents accidental IV reuse. RESET clears `iv_set`, forcing the
caller to supply a fresh IV for each message under the same key. GEN_IV uses
the provider's own DRBG — for FIPS providers, wolfCrypt's FIPS-approved DRBG
— to keep IV generation inside the validated cryptographic boundary.
*(GEN_IV using the FIPS DRBG is a FIPS 140-3 requirement — not negotiable.
Generating IVs outside the validated boundary and injecting them is not
an approved pattern.)*

**ECDH+HKDF combined in agree().** *(SP 800-56A Rev 3 §5.8 / FIPS 140-3 — not negotiable)*

The raw Diffie-Hellman output Z never leaves the provider. The provider runs
HKDF internally and returns only the derived key material (OKM). FIPS 140-3
and SP 800-56A Rev 3 §5.8 prohibit the raw shared secret from crossing the
validated cryptographic boundary. Exposing Z to userspace — even transiently —
is a compliance failure regardless of what the caller does with it.

*Why KDF is provider responsibility, not caller responsibility:* Z must not
cross the module boundary even for an instant. Giving callers raw Z and
expecting them to apply HKDF themselves would require Z to be visible in
userspace memory — a FIPS 140-3 boundary violation. The HKDF parameters
(salt, info, okm_len) are carried in the ioctl struct so the caller retains
full control over the KDF output while Z stays inside the boundary.

**KEY_IMPORT uses write-before-ioctl.**

Key material is written to the fd via `write(2)` before calling
`CRYPTO2DEV_IOC_KEY_IMPORT`. The ioctl struct (`crypto2dev_key_import_op`)
carries only metadata: algo name, key type, keylen, exportable flag. The
actual key bytes are never in the ioctl struct.

*Why:* Asymmetric keys are large, and post-quantum keys are very large.

| Key type | Format | Size |
|---|---|---|
| EC P-256 private | PKCS#8 DER | ~138 bytes |
| RSA-2048 private | PKCS#8 DER | ~1.2 KB |
| RSA-4096 private | PKCS#8 DER | ~2.4 KB |
| ML-DSA-44 private | raw | 2560 bytes |
| ML-DSA-65 private | raw | 4032 bytes |
| ML-DSA-87 private | raw | 4896 bytes |

If the raw key bytes lived in the ioctl struct, the struct would need to
accommodate the largest supported key (currently ML-DSA-87 at 4896 bytes,
so `CRYPTO2DEV_KEY_IMPORT_MAXLEN = 8192` with headroom). That allocation
would land on the kernel stack on every `KEY_IMPORT` call — including 32-byte
EC key imports — and would push the ioctl's stack frame well past the 1 KB
guideline for kernel stack usage.

The write-before-ioctl pattern transfers exactly as many bytes as the key
requires. The `inbuf` is a heap allocation that grows to fit. After
`KEY_IMPORT` consumes it, `inbuf_clear()` calls `memzero_explicit` and
frees it.

A secondary benefit: the ioctl struct contains only fixed-width integer
types and short string fields with no pointer members. This means it is
layout-identical on 32-bit and 64-bit userspace. No `compat_ioctl` handler
is needed and none will ever be needed. See "No compat_ioctl" below.

Do not embed raw key bytes in any ioctl struct. If a future key format
exceeds `CRYPTO2DEV_KEY_IMPORT_MAXLEN`, raise the constant — do not
redesign the pattern.

**KEY_EXPORT_PRIVATE targets FIPS 140-3 Level 1 only.** *(SP 800-38F)*

Plaintext private key export (`exportable = 1`) is permissible under FIPS 140-3
Level 1. Level 2 and above require that private keys leave a cryptographic module
only in encrypted (key-wrapped) form per SP 800-38F.

*Design choice:* This interface provides plaintext export for Level 1 use cases
(key backup, migration, testing). Level 2+ deployments must set `exportable = 0`
at key creation time and treat private keys as non-exportable for their entire
lifetime. The `exportable` flag in `crypto2dev_key_import_op` / `key_generate`
is a deliberate design point — setting it to 0 makes `KEY_EXPORT_PRIVATE` return
`-EACCES`, enforcing non-exportability at the kernel level without requiring any
caller-side policy.

**No compat_ioctl.** All ioctl structs contain only fixed-size integer types and
byte arrays with explicit padding. There are no pointer fields. 32-bit and 64-bit
userspace use identical struct layouts.

**Sysfs for algorithm enumeration.** LIST_ALGOS (slot 15) was removed. Algorithm
discovery is via `/sys/class/misc/crypto2dev/algorithms`. Sysfs is readable by
standard shell tools and does not require an open session fd.
