# crypto2dev `/dev/crypto2dev` Programmer's Guide

This guide covers everything needed to use the `/dev/crypto2dev` character device
from userspace C programs. The device is provided by the `crypto2dev.ko` kernel
module, which routes crypto operations to whichever provider module is loaded.
Two providers ship with the project: `crypto2dev_kcapi.ko` (uses the kernel
crypto API) and `crypto2dev_wolfssl.ko` (calls wolfCrypt directly, with a
FIPS 140-3 gate).

---

## Prerequisites

The following must be true before any program can use `/dev/crypto2dev`:

```bash
# Framework module must be loaded first
lsmod | grep crypto2dev      # crypto2dev.ko — provides /dev/crypto2dev

# At least one provider must be loaded
# Option A: kernel crypto API provider (no extra deps)
lsmod | grep crypto2dev_kcapi

# Option B: wolfSSL provider (requires wolfcrypt.ko)
lsmod | grep wolfcrypt       # wolfcrypt.ko — required by wolfSSL provider
lsmod | grep crypto2dev_wolfssl

# Device node must exist
ls -l /dev/crypto2dev     # crw------- root root
```

The device node is created by `misc_register` at module load. If it is missing,
`crypto2dev.ko` did not load cleanly — check `dmesg | grep crypto2dev`.

If no provider is loaded, `CRYPTO2DEV_IOC_INIT` returns `ENOENT` for any
algorithm. If the wolfSSL provider is loaded and wolfCrypt is not
FIPS_OPERATIONAL, all crypto operations return `EACCES`.

---

## The fd-as-session Model

Each open file descriptor is an independent session. The fd starts in the UNSET
state and is promoted to exactly one of two types:

**OPERATION fd** — performs symmetric/AEAD/hash crypto. Promoted by
`CRYPTO2DEV_IOC_INIT`. The workflow is:
```
open()  →  INIT  →  [SET_IV]  →  write()  →  read()  →  close()
```

**KEY fd** — holds a cryptographic key object. Promoted by `KEY_IMPORT` or
`KEY_GENERATE`. A KEY fd is passed directly to a one-shot asymmetric ioctl
(`DO_SIGN`, `DO_VERIFY`, `DO_AGREE`) by file descriptor number. After the
asymmetric ioctl returns, the KEY fd may be closed independently.
```
open()  →  write(key_bytes)  →  KEY_IMPORT | KEY_GENERATE  →  [pass fd to DO_SIGN/DO_VERIFY/DO_AGREE]  →  close()
```

**Asymmetric operations** (sign, verify, key agreement) are not OPERATION fds.
They are one-shot ioctls — `DO_SIGN`, `DO_VERIFY`, `DO_AGREE` — that carry all
inputs and outputs inline in the ioctl struct. No `INIT` is required; call them
on any open `crypto2dev` fd.

`close()` zeroizes all key material immediately regardless of fd type — no
separate "destroy" call exists.

An fd has exactly one type for its lifetime. To use two different types, open
two fds.

---

## Ioctl Reference

Include `<linux/crypto2dev.h>` for all struct definitions and `CRYPTO2DEV_IOC_*`
constants.

### Ioctl Slot Summary

| Slot | Name | Direction | Description |
|------|------|-----------|-------------|
| 1  | `CRYPTO2DEV_IOC_INIT`              | `_IOW`  | Configure OPERATION fd |
| 2  | `CRYPTO2DEV_IOC_SET_IV`            | `_IOW`  | Set IV or nonce |
| 3  | `CRYPTO2DEV_IOC_SET_AAD`           | `_IOW`  | Set AEAD additional data |
| 4  | `CRYPTO2DEV_IOC_GET_TAG`           | `_IOR`  | Retrieve AEAD auth tag |
| 5  | `CRYPTO2DEV_IOC_SET_TAG`           | `_IOW`  | Provide AEAD auth tag for decrypt |
| 6  | *(TOMBSTONE)*                      | —       | Do not use |
| 7  | *(TOMBSTONE)*                      | —       | Do not use |
| 8  | `CRYPTO2DEV_IOC_GEN_IV`            | `_IOWR` | Generate and set random IV |
| 9  | `CRYPTO2DEV_IOC_STATUS`            | `_IOR`  | Module-level FIPS/version status |
| 10 | `CRYPTO2DEV_IOC_GET_STATE`         | `_IOR`  | Per-fd session introspection |
| 11 | `CRYPTO2DEV_IOC_KEY_IMPORT`        | `_IOW`  | Import key material into KEY fd |
| 12 | `CRYPTO2DEV_IOC_KEY_GENERATE`      | `_IOW`  | Generate new key pair into KEY fd |
| 13 | `CRYPTO2DEV_IOC_KEY_GET_INFO`      | `_IOR`  | Query KEY fd metadata |
| 14 | `CRYPTO2DEV_IOC_KEY_EXPORT_PRIVATE`| `_IOWR` | Retrieve private key bytes |
| 15 | *(TOMBSTONE — was LIST_ALGOS)*     | —       | Use sysfs instead |
| 16 | `CRYPTO2DEV_IOC_DO_SIGN`           | `_IOWR` | One-shot asymmetric sign |
| 17 | `CRYPTO2DEV_IOC_DO_VERIFY`         | `_IOWR` | One-shot signature verification |
| 18 | `CRYPTO2DEV_IOC_DO_AGREE`          | `_IOWR` | One-shot key agreement + HKDF |
| 19 | `CRYPTO2DEV_IOC_RESET`             | `_IO`   | Re-arm finalized OPERATION fd |
| 20 | `CRYPTO2DEV_IOC_REQUIRE_FIPS`      | `_IO`   | Require FIPS provider at INIT time |
| 21 | `CRYPTO2DEV_IOC_FINALIZE`          | `_IO`   | Signal end-of-input; calls finalize() |
| 22 | `CRYPTO2DEV_IOC_DO_KDF`            | `_IOW`  | Derive key from IKM; promotes UNSET → KEY fd |

### `CRYPTO2DEV_IOC_INIT` — configure an OPERATION fd

Must be called once before any `write()`. Can be called only once per fd
(use `RESET` to re-arm a completed session).

INIT is used for **symmetric ciphers, AEAD, and hash/MAC only**. Asymmetric
operations (sign, verify, key agreement) use the one-shot ioctls
`DO_SIGN`, `DO_VERIFY`, and `DO_AGREE` instead.

```c
struct crypto2dev_init_op init = {
    .algo     = "cbc(aes)",          /* algorithm name — see Algorithm Names */
    .provider = "",                   /* "" = first available; "wolfssl" or "kcapi" to pin */
    .op       = CRYPTO2DEV_OP_ENCRYPT,
    .keylen   = 32,                   /* bytes; 0 for un-keyed hash */
    .key_fd   = -1,                   /* MUST be -1; KEY fds are for asymmetric only */
};
memcpy(init.key, key, 32);
if (ioctl(fd, CRYPTO2DEV_IOC_INIT, &init) < 0) {
    perror("CRYPTO2DEV_IOC_INIT");
}
explicit_bzero(init.key, sizeof(init.key));
```

**Field notes:**

- `algo` — algorithm name string. Symmetric/hash/MAC/KDF algorithms use kernel
  crypto API names (e.g. `"cbc(aes)"`, `"sha256"`, `"hmac(sha256)"`). Asymmetric
  algorithms use crypto2dev's dash-separated form (e.g. `"ecdsa-p256"`,
  `"rsa-2048"`). See Algorithm Names below.
- `provider` — optional. Empty string selects the first registered provider for
  the algo. When the wolfSSL FIPS provider is loaded, non-FIPS providers are
  invisible to lookup regardless of what is requested here.
- `op` — one of: `CRYPTO2DEV_OP_ENCRYPT`, `DECRYPT`, `HASH`.
- `key` / `keylen` — inline key material. Zero out the struct after the call.
  Max size is `CRYPTO2DEV_KEY_MAXLEN` (128 bytes). Symmetric keys are always
  inline. KEY fds are for asymmetric keys only.
- `key_fd` — **reserved; must always be -1**. Passing `key_fd >= 0` returns
  `-EINVAL`. Symmetric keys (AES, HMAC, CMAC) are supplied inline via `key[]`.
  For asymmetric operations, use `DO_SIGN`, `DO_VERIFY`, or `DO_AGREE` directly.

**FIPS 140-3 key size constraints (not negotiable):**
- AES: minimum 16 bytes (128 bits). FIPS 197.
- HMAC key: any length (hash output security depends on the key; use at least
  the digest size in practice).
- RSA: minimum 256 bytes (2048 bits) at the KEY fd import step. SP 800-131A.
- EC: P-256 minimum; P-192 and smaller are not approved. SP 800-186.

**Operation codes:**

| Op | Used for |
|----|----------|
| `CRYPTO2DEV_OP_ENCRYPT` | Symmetric ciphers (CBC, CTR, XTS) and AEAD encrypt |
| `CRYPTO2DEV_OP_DECRYPT` | Symmetric ciphers and AEAD decrypt |
| `CRYPTO2DEV_OP_HASH`    | Hash (SHA-2/3), HMAC, CMAC |

**Errors:**
- `EINVAL` — unknown algo, bad key length, invalid op, or `key_fd != -1`
- `EBUSY` — fd already initialized; use `RESET` or open a new fd
- `ENOENT` — no provider registered for this algorithm (also returned by
  `REQUIRE_FIPS`-marked fds when no FIPS provider is loaded)
- `EACCES` — FIPS not operational (wolfSSL provider only)
- `ENOMEM` — kernel allocation failed

---

### `CRYPTO2DEV_IOC_SET_IV` — set IV or nonce

Must be called before `write()` for any algorithm that uses an IV.
Not needed for hash, MAC, or asymmetric algorithms.

```c
struct crypto2dev_iv_op iv_op = {
    .ivlen = 16,
    .iv    = { /* 16 bytes for CBC; 12 bytes for GCM */ },
};
if (ioctl(fd, CRYPTO2DEV_IOC_SET_IV, &iv_op) < 0) {
    perror("CRYPTO2DEV_IOC_SET_IV");
}
```

IV sizes by algorithm:

| Algorithm   | IV size | Notes |
|-------------|---------|-------|
| `cbc(aes)`  | 16 bytes | |
| `ctr(aes)`  | 16 bytes | |
| `xts(aes)`  | 16 bytes | |
| `gcm(aes)`  | 12 bytes | **FIPS 140-3 (SP 800-38D): GCM nonce must be exactly 96 bits (12 bytes).** |

**Never reuse an IV with the same key**, especially for GCM/CTR.

---

### `CRYPTO2DEV_IOC_GEN_IV` — generate and set a random IV

Generates a random IV, programs it into the session, and returns the IV bytes
to the caller. Avoids manual IV generation and eliminates IV reuse errors for
callers that always use a fresh random IV.

Must be called after `INIT` and before `write()`.

**FIPS 140-3 note:** When the wolfSSL provider is active, `GEN_IV` calls
`wc_RNG_GenerateBlock` using wolfCrypt's FIPS-approved DRBG. This keeps IV
generation inside the validated cryptographic boundary. Generating IVs outside
the validated boundary and injecting them is not an approved pattern per
SP 800-90A. *(FIPS 140-3 requirement — not negotiable.)*

```c
struct crypto2dev_iv_op iv_op = { .ivlen = 12 };  /* GCM: 12-byte nonce */
if (ioctl(fd, CRYPTO2DEV_IOC_GEN_IV, &iv_op) < 0) {
    perror("CRYPTO2DEV_IOC_GEN_IV");
}
/* iv_op.iv now contains the generated IV — transmit alongside ciphertext */
```

The `ivlen` field specifies the desired length on entry and the actual length
on return. The framework fills `iv[]` and sets it on the session via the
provider's `set_iv` callback.

---

### `CRYPTO2DEV_IOC_SET_AAD` — set Additional Authenticated Data (AEAD only)

For `gcm(aes)`. Call after `SET_IV` or `GEN_IV`, before `write()`.
Skip entirely if there is no AAD.

The AAD is copied inline into the struct (max `CRYPTO2DEV_AAD_MAXLEN` = 256 bytes),
which covers typical TLS, DTLS, and IPsec header sizes.

```c
uint8_t aad[] = { /* e.g. packet header */ };
struct crypto2dev_aad_op aad_op = { .aadlen = sizeof(aad) };
memcpy(aad_op.aad, aad, sizeof(aad));
if (ioctl(fd, CRYPTO2DEV_IOC_SET_AAD, &aad_op) < 0) {
    perror("CRYPTO2DEV_IOC_SET_AAD");
}
```

---

### `CRYPTO2DEV_IOC_GET_TAG` — retrieve auth tag after AEAD encrypt

Call after `read()` has returned the full ciphertext.

**FIPS 140-3 note:** Per SP 800-38D, the GCM authentication tag must be at
least 96 bits (12 bytes). A tag of exactly 16 bytes (128 bits) is standard.
Never truncate the tag below 12 bytes.

```c
struct crypto2dev_tag_op tag_op = { .taglen = 16 };
if (ioctl(fd, CRYPTO2DEV_IOC_GET_TAG, &tag_op) < 0) {
    perror("CRYPTO2DEV_IOC_GET_TAG");
}
/* tag_op.tag now contains the 16-byte authentication tag */
```

The tag must be transmitted alongside the ciphertext and provided to the
decrypt session via `SET_TAG`.

---

### `CRYPTO2DEV_IOC_SET_TAG` — provide auth tag before AEAD decrypt

Call after `SET_AAD`, before `write()`. The kernel verifies the tag after
decrypting and returns `EBADMSG` from `read()` if verification fails.

```c
struct crypto2dev_tag_op tag_op;
memcpy(tag_op.tag, received_tag, 16);
tag_op.taglen = 16;
if (ioctl(fd, CRYPTO2DEV_IOC_SET_TAG, &tag_op) < 0) {
    perror("CRYPTO2DEV_IOC_SET_TAG");
}
```

---

### `CRYPTO2DEV_IOC_DO_SIGN` — one-shot asymmetric sign (slot 16)

Signs a digest using the private key held in a KEY fd. Can be called on
**any** open `crypto2dev` fd — no prior `INIT` is required.

```c
/*
 * Sign a pre-computed SHA-256 digest.
 * key_fd must hold a KEY_PRIVATE or KEY_PAIR key.
 */
struct crypto2dev_sign_op sop = {
    .key_fd     = key_fd,
    .hash_algo  = "",    /* empty = digest[] is already the final hash */
    .digest_len = 32,
};
memcpy(sop.digest, digest, 32);

if (ioctl(fd, CRYPTO2DEV_IOC_DO_SIGN, &sop) < 0) {
    perror("CRYPTO2DEV_IOC_DO_SIGN");
}
/* sop.sig[0..sop.sig_len-1] contains the DER-encoded signature */
```

**Field notes:**

- `key_fd` — fd of a KEY fd holding `KEY_PRIVATE` or `KEY_PAIR`. The KEY fd
  must remain open for the duration of this call; it may be closed afterwards.
- `hash_algo` — names the hash algorithm used to produce `digest[]` (e.g.
  `"sha256"`). Required for RSA to build the PKCS#1 v1.5 DigestInfo prefix.
  The provider does **not** hash `digest[]` — it is always a pre-computed hash.
  Empty string is valid for ECDSA when the provider infers the hash from context.
- `digest_len` — byte count of data in `digest[]`. Must not exceed
  `CRYPTO2DEV_HASH_MAXLEN` (64).
- `digest[]` — input: pre-computed hash.
- `sig_len` — output: actual signature byte count written into `sig[]`.
- `sig[]` — output: DER-encoded signature (ECDSA) or PKCS#1 v1.5 / PSS (RSA).
  Buffer is `CRYPTO2DEV_SIG_MAXLEN` (512) bytes.

**Errors:**
- `EBADF` — `key_fd` is not a valid KEY fd
- `EACCES` — FIPS not operational, or FIPS rejects the algorithm
- `EINVAL` — `digest_len` is 0 or exceeds `CRYPTO2DEV_HASH_MAXLEN`
- `EOPNOTSUPP` — key algorithm does not support signing

---

### `CRYPTO2DEV_IOC_DO_VERIFY` — one-shot signature verification (slot 17)

Verifies a signature against a digest using the public key held in a KEY fd.
Can be called on any open `crypto2dev` fd.

```c
struct crypto2dev_verify_op vop = {
    .key_fd     = key_fd,
    .hash_algo  = "",    /* empty = digest[] is already the final hash */
    .digest_len = 32,
    .sig_len    = sig_bytes,
};
memcpy(vop.digest, digest, 32);
memcpy(vop.sig, received_sig, sig_bytes);

if (ioctl(fd, CRYPTO2DEV_IOC_DO_VERIFY, &vop) < 0) {
    if (errno == EBADMSG) {
        /* signature did not verify */
    } else {
        perror("CRYPTO2DEV_IOC_DO_VERIFY");
    }
}
```

**Field notes:**

- `key_fd` — fd of a KEY fd holding `KEY_PUBLIC`, `KEY_PRIVATE`, or `KEY_PAIR`.
  For ECDSA verification, a public key is sufficient.
- `hash_algo` — same semantics as `DO_SIGN`: names the algorithm that produced
  `digest[]`; the provider does not re-hash the input.
- `digest_len` — byte count of `digest[]`; must not exceed `CRYPTO2DEV_HASH_MAXLEN`.
- `sig_len` — byte count of the signature in `sig[]`.
- `sig[]` / `digest[]` — both are input-only fields.

**Errors:**
- `EBADMSG` — signature does not verify (not a syscall error; check `errno`)
- `EBADF` — `key_fd` is not a valid KEY fd
- `EACCES` — FIPS not operational
- `EINVAL` — `digest_len` or `sig_len` is 0 or out of range
- `EOPNOTSUPP` — key algorithm does not support verification

---

### `CRYPTO2DEV_IOC_DO_AGREE` — one-shot key agreement + HKDF (slot 18)

Performs ECDH key agreement and immediately derives key material using HKDF
(RFC 5869 / SP 800-56C rev2). The raw ECDH shared secret Z is computed and
consumed entirely inside the provider — it never crosses the validated
cryptographic boundary. The caller receives ready-to-use derived key material
in `okm[]`. Can be called on any open `crypto2dev` fd.

**FIPS 140-3 (SP 800-56A — not negotiable):** The raw Diffie-Hellman output Z
must never leave the validated boundary. Exposing Z to userspace — even
transiently — is a compliance failure. The HKDF parameters are specified
inline in the ioctl struct so that the entire ECDH+KDF operation completes
inside the provider.

```c
struct crypto2dev_agree_op aop = {
    .key_fd          = key_fd,
    .peer_pubkey_len = 65,
    .salt_len        = 0,      /* 0 = use HKDF default salt (RFC 5869 §2.2) */
    .info_len        = 4,
    .okm_len         = 32,     /* 256-bit derived key */
};
memcpy(aop.peer_pubkey, peer_pub, 65);
memcpy(aop.info, "tls1", 4);
if (ioctl(fd, CRYPTO2DEV_IOC_DO_AGREE, &aop) < 0) goto err;
/* aop.okm[0..31] is the 32-byte derived key — ready to use */
```

**Field notes:**

- `key_fd` — fd of a KEY fd holding a private key for a DH algorithm
  (`"ecdh-p256"`, `"ecdh-p384"`, etc.).
- `peer_pubkey_len` — byte count of the peer's public key in `peer_pubkey[]`.
- `peer_pubkey[]` — peer's public key; uncompressed EC point (`0x04 || X || Y`)
  for ECDH. Buffer is `CRYPTO2DEV_PUBKEY_MAXLEN` (256) bytes.
- `salt_len` — HKDF salt length. `0` means the RFC 5869 §2.2 default:
  an all-zero string of hash-output length bytes.
- `salt[]` — HKDF salt (ignored when `salt_len == 0`). Max `CRYPTO2DEV_KDF_SALT_MAXLEN` (64) bytes.
- `info_len` — HKDF context/info string length. `0` = empty info.
- `info[]` — HKDF protocol label (e.g. `"tls1"`, `"handshake data"`). Max `CRYPTO2DEV_KDF_INFO_MAXLEN` (128) bytes.
- `okm_len` — requested output key material length in bytes (1 to `CRYPTO2DEV_PUBKEY_MAXLEN`).
- `okm[]` — output: exactly `okm_len` bytes of derived key material, ready for
  use as a symmetric key or keying material without any further processing
  (SP 800-56A Rev 3 §5.8 — the raw ECDH output Z is processed through HKDF
  inside the provider before any data crosses the module boundary).

> **Do not apply an additional KDF to `okm[]`.** The HKDF step is performed
> inside the provider; the output is already compliant keying material.
> Applying HKDF (or any KDF) a second time produces non-standard key material
> and breaks protocol interoperability.

**FIPS 140-3 EC curve constraints (SP 800-186 — not negotiable):**
- P-256 is the minimum approved curve.
- P-192 and smaller are not approved and will be rejected.

**Errors:**
- `EBADF` — `key_fd` is not a valid KEY fd
- `EACCES` — FIPS not operational
- `EINVAL` — `peer_pubkey_len` is 0 or out of range; `okm_len` is 0 or exceeds maximum
- `EOPNOTSUPP` — key algorithm does not support key agreement

---

### `CRYPTO2DEV_IOC_RESET` — re-arm a finalized OPERATION fd (slot 19)

After `CRYPTO2DEV_IOC_FINALIZE` signals end-of-input, the fd enters the
FINALIZED state and further `write()` returns `-EINVAL`. `RESET` re-arms the
session so the same key and algorithm can be reused for a new operation without
opening a fresh fd.

`RESET` does **not** reset the IV — call `SET_IV` or `GEN_IV` again before
the next `write()` for cipher sessions.

```c
if (ioctl(fd, CRYPTO2DEV_IOC_RESET) < 0) {
    if (errno == EOPNOTSUPP) {
        /* provider does not implement sess_reset — open a new fd */
    } else {
        perror("CRYPTO2DEV_IOC_RESET");
    }
}
/* fd is now ready for another write() → read() cycle */
```

Takes no argument struct (`_IO` direction).

**Errors:**
- `EINVAL` — fd is not an OPERATION fd, or has not been initialized
- `EOPNOTSUPP` — the provider does not implement `sess_reset`; open a new fd

---

### `CRYPTO2DEV_IOC_REQUIRE_FIPS` — require FIPS provider at INIT time (slot 20)

Must be called on an UNSET fd before `CRYPTO2DEV_IOC_INIT`. Once set, any
subsequent `INIT` on this fd returns `-ENOENT` if no FIPS provider
(`is_fips == 1`) is currently loaded in the registry — even if a non-FIPS
provider could service the requested algorithm.

Takes no argument struct (`_IO` direction).

```c
int fd = open("/dev/crypto2dev", O_RDWR);
if (fd < 0) return -1;

/* Require FIPS — INIT will fail loudly if wolfssl is not loaded */
if (ioctl(fd, CRYPTO2DEV_IOC_REQUIRE_FIPS) < 0) {
    perror("CRYPTO2DEV_IOC_REQUIRE_FIPS");
    close(fd);
    return -1;
}

struct crypto2dev_init_op init = {
    .algo   = "cbc(aes)",
    .op     = CRYPTO2DEV_OP_ENCRYPT,
    .keylen = 32,
    .key_fd = -1,
};
memcpy(init.key, key, 32);
if (ioctl(fd, CRYPTO2DEV_IOC_INIT, &init) < 0) {
    /* -ENOENT here means no FIPS provider was loaded */
    perror("CRYPTO2DEV_IOC_INIT");
    close(fd);
    return -1;
}
explicit_bzero(init.key, sizeof(init.key));
```

**When this ioctl matters:** when the wolfSSL FIPS provider is loaded, the
registry already enforces FIPS-only dispatch for all lookups regardless of
this flag. `REQUIRE_FIPS` only matters in deployments where `crypto2dev_wolfssl.ko`
might not be loaded — it converts a silent fallback to a non-FIPS provider into
a hard `-ENOENT` failure.

**Errors:**
- `EBUSY` — fd is already initialized (not UNSET); must call on a fresh fd

---

### `CRYPTO2DEV_IOC_STATUS` — module-level status

Does not require an initialized session. Safe to call immediately after
`open()`. Does not invoke wolfCrypt.

```c
struct crypto2dev_status status;
if (ioctl(fd, CRYPTO2DEV_IOC_STATUS, &status) < 0) {
    perror("CRYPTO2DEV_IOC_STATUS");
}
printf("crypto2dev %s | FIPS: %u | algorithms: %u\n",
       status.version, status.fips_state, status.num_algorithms);
```

`fips_state` values:

| Value | Constant | Meaning |
|-------|----------|---------|
| `0` | `CRYPTO2DEV_FIPS_NO_PROVIDER` | No FIPS-gated provider loaded |
| `1` | `CRYPTO2DEV_FIPS_OPERATIONAL` | FIPS provider loaded and passing all self-tests |
| `2` | `CRYPTO2DEV_FIPS_NOT_OPERATIONAL` | FIPS provider loaded but POST/integrity failed |

With the wolfSSL provider, `fips_state == 1` means wolfCrypt's CMVP certificate
is active. State `2` means all crypto operations will return `-EACCES` until the
condition clears.

---

### `CRYPTO2DEV_IOC_GET_STATE` — per-fd session introspection

Returns the current type, configuration, and byte counters for this fd. Works
for both OPERATION and KEY fds. Does not invoke wolfCrypt.

```c
struct crypto2dev_fd_state_info state;
if (ioctl(fd, CRYPTO2DEV_IOC_GET_STATE, &state) < 0) {
    perror("CRYPTO2DEV_IOC_GET_STATE");
}

switch (state.fd_type) {
case CRYPTO2DEV_FDTYPE_UNSET:
    printf("fd: unset\n");
    break;
case CRYPTO2DEV_FDTYPE_OPERATION:
    printf("OPERATION | algo: %s | provider: %s | op: %u | in: %llu | out: %llu\n",
           state.algo, state.provider, state.op,
           (unsigned long long)state.bytes_written,
           (unsigned long long)state.bytes_read);
    break;
case CRYPTO2DEV_FDTYPE_KEY:
    printf("KEY | algo: %s | provider: %s | key_type: %u | exportable: %u\n",
           state.algo, state.provider, state.key_type, state.initialized);
    break;
}
```

`fd_type` is `CRYPTO2DEV_FDTYPE_UNSET` before any `INIT`/`KEY_IMPORT`/`KEY_GENERATE`
call, `CRYPTO2DEV_FDTYPE_OPERATION` after `INIT`, and `CRYPTO2DEV_FDTYPE_KEY` after
`KEY_IMPORT` or `KEY_GENERATE`.

---

## KEY fd Lifecycle

A KEY fd wraps a single cryptographic key object. Open a fresh fd, write the raw
key bytes (for `KEY_IMPORT`), call one of the KEY ioctls to load or generate a
key, then use the fd as needed. `close()` zeroizes the key.

KEY fds are for **asymmetric keys only** (RSA, EC, X25519). Symmetric keys (AES,
HMAC, CMAC) are always supplied inline in `INIT` via the `key[]` field.

**Typical usage pattern:**

```
open()  →  write(key_bytes)  →  KEY_IMPORT  →  pass fd to DO_SIGN/DO_VERIFY/DO_AGREE  →  close KEY fd
open()  →  KEY_GENERATE      →  read(pub_key)  →  pass fd to DO_AGREE  →  close KEY fd
```

### `CRYPTO2DEV_IOC_KEY_IMPORT` — import existing key material

Promotes an unset fd to a KEY fd by loading key bytes previously written to
the fd via `write()`. The ioctl struct carries only metadata — algo, provider,
key type, exportable flag, and keylen. The actual key bytes are in the fd's
write buffer (written via `write()` before calling this ioctl).

**Why write-before-ioctl:** Asymmetric and post-quantum keys are large. Embedding
key bytes in an ioctl struct would require up to `CRYPTO2DEV_KEY_IMPORT_MAXLEN`
(8192) bytes on the kernel stack for every `KEY_IMPORT` call, far exceeding the
1 KB kernel stack guideline. The write-before-ioctl pattern transfers exactly as
many bytes as the key requires via a heap-allocated buffer.

| Key type | Format | Approx. size |
|----------|--------|-------------|
| EC P-256 private | 32-byte raw big-endian scalar | 32 B |
| EC P-256 public | Uncompressed point `0x04 \|\| X(32) \|\| Y(32)` | 65 B |
| RSA-2048 private | DER-encoded PKCS#8 PrivateKeyInfo | ~1.2 KB |
| RSA-4096 private | DER-encoded PKCS#8 PrivateKeyInfo | ~2.4 KB |
| ML-DSA-87 private | raw | 4896 B |

```c
/* Import an EC P-256 private key (32-byte raw scalar) */
uint8_t privkey[32] = { /* ... */ };

int key_fd = open("/dev/crypto2dev", O_RDWR);
if (key_fd < 0) return -1;

/* Step 1: write key bytes to the fd */
if (write(key_fd, privkey, sizeof(privkey)) != (ssize_t)sizeof(privkey)) {
    close(key_fd);
    return -1;
}
explicit_bzero(privkey, sizeof(privkey));

/* Step 2: call KEY_IMPORT with metadata only — no key bytes in the struct */
struct crypto2dev_key_import_op op = {
    .algo       = "ecdsa-p256",
    .provider   = "wolfssl",
    .key_type   = CRYPTO2DEV_KEY_PRIVATE,
    .exportable = 0,          /* 1 = allow KEY_EXPORT_PRIVATE later */
    .keylen     = 32,         /* how many bytes from the write() to use */
};
if (ioctl(key_fd, CRYPTO2DEV_IOC_KEY_IMPORT, &op) < 0) {
    perror("CRYPTO2DEV_IOC_KEY_IMPORT");
    close(key_fd);
    return -1;
}
```

**Key formats:**

| Algorithm | Key type | Format |
|-----------|----------|--------|
| EC P-256 | `KEY_PRIVATE` | 32-byte raw big-endian scalar |
| EC P-256 | `KEY_PUBLIC` | Uncompressed point: `0x04 \|\| X(32) \|\| Y(32)` = 65 bytes |
| EC P-256 | `KEY_PAIR` | Private scalar only (32 bytes); public key is derived |
| EC P-384 | `KEY_PRIVATE` | 48-byte raw big-endian scalar |
| RSA | `KEY_PRIVATE` | DER-encoded PKCS#8 `PrivateKeyInfo` |
| RSA | `KEY_PUBLIC` | DER-encoded `SubjectPublicKeyInfo` |

**Errors:**
- `EBUSY` — fd already initialized
- `ENOENT` — no provider handles the algorithm
- `EOPNOTSUPP` — provider does not support key import
- `EINVAL` — bad `key_type`, `keylen`, or key format; or fewer bytes were written
  than `keylen` specifies

---

### `CRYPTO2DEV_IOC_KEY_GENERATE` — generate a new key pair

Promotes an unset fd to a KEY fd with a freshly-generated key pair. No key
material is supplied from userspace.

```c
struct crypto2dev_key_generate_op op = {
    .algo       = "ecdh-p256",
    .provider   = "wolfssl",
    .exportable = 1,    /* allow KEY_EXPORT_PRIVATE */
};
if (ioctl(key_fd, CRYPTO2DEV_IOC_KEY_GENERATE, &op) < 0) {
    perror("CRYPTO2DEV_IOC_KEY_GENERATE");
}
```

After success:
- `read()` on the KEY fd returns the public key bytes.
- `KEY_EXPORT_PRIVATE` retrieves the private key (if `exportable == 1`).

---

### `CRYPTO2DEV_IOC_KEY_GET_INFO` — query key metadata

Returns the algorithm, key type, provider, and public key length for a KEY fd.

```c
struct crypto2dev_key_info info;
if (ioctl(key_fd, CRYPTO2DEV_IOC_KEY_GET_INFO, &info) < 0) {
    perror("CRYPTO2DEV_IOC_KEY_GET_INFO");
}
printf("algo: %s | provider: %s | key_type: %u | pubkey_len: %u\n",
       info.algo, info.provider, info.key_type, info.public_key_len);
```

`public_key_len` is the exact byte count that `read()` will return. Allocate
this many bytes before reading the public key.

Returns `-EINVAL` if the fd is not a KEY fd.

---

### Reading the public key from a KEY fd

After `KEY_IMPORT` or `KEY_GENERATE`, `read()` on the KEY fd returns the public key.

```c
/* Query length first */
struct crypto2dev_key_info info;
ioctl(key_fd, CRYPTO2DEV_IOC_KEY_GET_INFO, &info);

uint8_t *pubkey = malloc(info.public_key_len);
ssize_t r = read(key_fd, pubkey, info.public_key_len);
if (r != (ssize_t)info.public_key_len) { /* error */ }
```

Reading does not consume or invalidate the key — it may be read again.

---

### `CRYPTO2DEV_IOC_KEY_EXPORT_PRIVATE` — retrieve private key bytes

Only valid when `exportable == 1` at import/generate time and `key_type` is
`KEY_PRIVATE` or `KEY_PAIR`. Returns `-EACCES` if not exportable.

> **FIPS 140-3 Level 2+ incompatibility (SP 800-38F):** Plaintext private key
> export is only valid for FIPS 140-3 **Level 1**. Level 2 and above require
> that private keys leave a cryptographic module only in encrypted
> (key-wrapped) form per SP 800-38F. If your deployment targets Level 2+:
>
> - Set `exportable = 0` at import/generate time. The ioctl will return
>   `-EACCES` if export is later attempted.
> - Private keys must remain non-exportable and managed entirely within
>   the kernel module for the lifetime of the key.
>
> This interface (`exportable = 1`) is appropriate for Level 1 key backup,
> migration, or testing scenarios only.

```c
uint8_t privbuf[CRYPTO2DEV_KEY_IMPORT_MAXLEN];   /* 8192 bytes */
struct crypto2dev_key_export_op op;
if (ioctl(key_fd, CRYPTO2DEV_IOC_KEY_EXPORT_PRIVATE, &op) < 0) {
    perror("CRYPTO2DEV_IOC_KEY_EXPORT_PRIVATE");
}
/* Read op.keylen bytes from the KEY fd */
ssize_t r = read(key_fd, privbuf, op.keylen);
if (r != (ssize_t)op.keylen) { /* error */ }
/* privbuf[0..op.keylen-1] contains the private key */
explicit_bzero(privbuf, sizeof(privbuf));   /* zeroize after use */
```

---

## Sysfs Interface

Three files are exposed under `/sys/class/misc/crypto2dev/`:

### `algorithms` — enumerate registered algorithms

```bash
cat /sys/class/misc/crypto2dev/algorithms
```

One line per registered algorithm, in the format `algo:provider:has_fips_gate:has_key_ops`.
Slot 15 (LIST_ALGOS ioctl) has been tombstoned; use this file instead.

```
cbc(aes):wolfssl:1:0
gcm(aes):wolfssl:1:0
sha256:wolfssl:1:0
hmac(sha256):wolfssl:1:0
ecdsa-p256:wolfssl:1:1
ecdh-p256:wolfssl:1:1
cbc(aes):kcapi:0:0
```

When the wolfSSL FIPS provider is loaded, kcapi entries are unreachable via
algorithm lookup (FIPS enforcement, Layer 1). They remain visible in sysfs for
diagnostic purposes only.

### `providers` — enumerate loaded providers

```bash
cat /sys/class/misc/crypto2dev/providers
```

One line per registered provider: `name:is_fips:version_string`. Fields 1 and 2
are fixed-position colon-delimited tokens; field 3 is the remainder of the line.

```
wolfssl:1:wolfCrypt FIPS v5.7.0 (CMVP #4718)
kcapi:0:Linux kernel crypto API 6.8.0-51-generic
```

`is_fips` is `1` if this provider's algorithms are inside a FIPS 140-3 validated
cryptographic boundary, `0` otherwise. The version string is whatever the
provider registers; future providers supply their own library version here.

### `fips_state` — machine-readable FIPS health

```bash
cat /sys/class/misc/crypto2dev/fips_state
```

Single integer. Intended for monitoring scripts and systemd conditions.

| Value | Meaning |
|-------|---------|
| `0` | No FIPS-gated provider loaded |
| `1` | FIPS provider loaded and all self-tests pass |
| `2` | FIPS provider loaded but degraded — all crypto returns `EACCES` |

Same values as the `fips_state` field in `CRYPTO2DEV_IOC_STATUS`, but readable
without opening the device or constructing an ioctl.

---

## Streaming write() / read()

Once initialized, data flows through an OPERATION fd via standard POSIX `write()`
and `read()`.

### Symmetric ciphers (CBC, CTR, XTS)

Each `write()` immediately calls `ops->update()` and appends any produced
output to the internal output buffer. For block ciphers, complete blocks are
processed immediately; any trailing partial block is held until the next
`write()` or `FINALIZE`. Call `CRYPTO2DEV_IOC_FINALIZE` when all input has
been written; then drain with `read()`.

```c
if (write(fd, plaintext, len) < 0) { perror("write"); }
if (ioctl(fd, CRYPTO2DEV_IOC_FINALIZE) < 0) { perror("FINALIZE"); }

ssize_t r = read(fd, ciphertext, len);
if (r < 0) { perror("read"); }
```

Multiple `write()` calls before `FINALIZE` are valid. `read()` may be called
at any point to drain output already produced by `update()`. Output length
equals input length. The device does not pad. For CBC, the total data written
must be a multiple of 16 bytes; `FINALIZE` returns `EINVAL` otherwise.

### Hash and HMAC

Feed data in any chunk sizes. Hash providers buffer all input internally and
produce no output from `write()`. Call `CRYPTO2DEV_IOC_FINALIZE` when all
data has been written; the digest is then available via `read()`. After
`FINALIZE`, further `write()` is an error.

```c
write(fd, chunk1, chunk1_len);
write(fd, chunk2, chunk2_len);
/* ... as many writes as needed ... */

if (ioctl(fd, CRYPTO2DEV_IOC_FINALIZE) < 0) { perror("FINALIZE"); }

uint8_t digest[32];
ssize_t r = read(fd, digest, sizeof(digest));
if (r != 32) { /* error */ }
```

Digest sizes:

| Algorithm       | Digest size |
|-----------------|-------------|
| `sha256`        | 32 bytes |
| `sha384`        | 48 bytes |
| `sha512`        | 64 bytes |
| `sha3-256`      | 32 bytes |
| `sha3-384`      | 48 bytes |
| `sha3-512`      | 64 bytes |
| `hmac(sha256)`  | 32 bytes |
| `hmac(sha384)`  | 48 bytes |
| `hmac(sha512)`  | 64 bytes |
| `cmac(aes)`     | 16 bytes |

### AEAD (GCM)

The tag is separate from the ciphertext. See the complete examples below.

### Asymmetric operations (SIGN, VERIFY, AGREE)

Asymmetric operations are **not** streaming. They use one-shot ioctls that
carry all inputs and outputs in the ioctl struct:

- `DO_SIGN` — provide `key_fd` + `digest[]`; receive `sig[]` on return.
- `DO_VERIFY` — provide `key_fd` + `digest[]` + `sig[]`; returns 0 or `-EBADMSG`.
- `DO_AGREE` — provide `key_fd` + `peer_pubkey[]` + HKDF params; receive `okm[]` on return.

These ioctls can be called on any open `crypto2dev` fd — no `INIT` is required.
See the dedicated sections above for full field descriptions and examples.

---

## Complete Examples

### AES-256-CBC Encrypt

```c
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/crypto2dev.h>

int crypto2dev_aes_cbc_encrypt(
    const uint8_t *key, size_t keylen,
    const uint8_t *iv,
    const uint8_t *plaintext, size_t len,
    uint8_t *ciphertext)
{
    int fd = open("/dev/crypto2dev", O_RDWR);
    if (fd < 0) return -1;

    struct crypto2dev_init_op init = {
        .algo   = "cbc(aes)",
        .op     = CRYPTO2DEV_OP_ENCRYPT,
        .keylen = (uint32_t)keylen,
        .key_fd = -1,
    };
    memcpy(init.key, key, keylen);

    if (ioctl(fd, CRYPTO2DEV_IOC_INIT, &init) < 0) goto err;
    explicit_bzero(init.key, sizeof(init.key));

    struct crypto2dev_iv_op iv_op = { .ivlen = 16 };
    memcpy(iv_op.iv, iv, 16);
    if (ioctl(fd, CRYPTO2DEV_IOC_SET_IV, &iv_op) < 0) goto err;

    if (write(fd, plaintext, len) != (ssize_t)len) goto err;
    if (ioctl(fd, CRYPTO2DEV_IOC_FINALIZE) < 0) goto err;
    if (read(fd, ciphertext, len) != (ssize_t)len) goto err;

    close(fd);
    return 0;

err:
    close(fd);
    return -1;
}
```

### AES-256-GCM Encrypt

```c
/*
 * Encrypt plaintext with AES-256-GCM.
 * nonce must be exactly 12 bytes (FIPS 140-3 / SP 800-38D).
 * ciphertext must be at least len bytes; tag receives exactly 16 bytes.
 */
int crypto2dev_aes_gcm_encrypt(
    const uint8_t *key,
    const uint8_t *nonce,    /* 12 bytes — must be exactly 96 bits */
    const uint8_t *aad, size_t aadlen,
    const uint8_t *plaintext, size_t len,
    uint8_t *ciphertext,
    uint8_t tag[16])
{
    int fd = open("/dev/crypto2dev", O_RDWR);
    if (fd < 0) return -1;

    struct crypto2dev_init_op init = {
        .algo   = "gcm(aes)",
        .op     = CRYPTO2DEV_OP_ENCRYPT,
        .keylen = 32,
        .key_fd = -1,
    };
    memcpy(init.key, key, 32);
    if (ioctl(fd, CRYPTO2DEV_IOC_INIT, &init) < 0) goto err;
    explicit_bzero(init.key, sizeof(init.key));

    struct crypto2dev_iv_op iv_op = { .ivlen = 12 };
    memcpy(iv_op.iv, nonce, 12);
    if (ioctl(fd, CRYPTO2DEV_IOC_SET_IV, &iv_op) < 0) goto err;

    if (aadlen > 0 && aadlen <= CRYPTO2DEV_AAD_MAXLEN) {
        struct crypto2dev_aad_op aad_op = { .aadlen = (uint32_t)aadlen };
        memcpy(aad_op.aad, aad, aadlen);
        if (ioctl(fd, CRYPTO2DEV_IOC_SET_AAD, &aad_op) < 0) goto err;
    }

    if (write(fd, plaintext, len) != (ssize_t)len) goto err;
    if (ioctl(fd, CRYPTO2DEV_IOC_FINALIZE) < 0) goto err;
    if (read(fd, ciphertext, len) != (ssize_t)len) goto err;

    struct crypto2dev_tag_op tag_op = { .taglen = 16 };
    if (ioctl(fd, CRYPTO2DEV_IOC_GET_TAG, &tag_op) < 0) goto err;
    memcpy(tag, tag_op.tag, 16);

    close(fd);
    return 0;

err:
    close(fd);
    return -1;
}
```

### AES-256-GCM Decrypt

```c
/*
 * Returns 0 on success, -EBADMSG if tag verification fails,
 * or another negative errno on error.
 */
int crypto2dev_aes_gcm_decrypt(
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *aad, size_t aadlen,
    const uint8_t *ciphertext, size_t len,
    const uint8_t *tag,
    uint8_t *plaintext)
{
    int fd = open("/dev/crypto2dev", O_RDWR);
    if (fd < 0) return -errno;

    struct crypto2dev_init_op init = {
        .algo   = "gcm(aes)",
        .op     = CRYPTO2DEV_OP_DECRYPT,
        .keylen = 32,
        .key_fd = -1,
    };
    memcpy(init.key, key, 32);
    if (ioctl(fd, CRYPTO2DEV_IOC_INIT, &init) < 0) goto err;
    explicit_bzero(init.key, sizeof(init.key));

    struct crypto2dev_iv_op iv_op = { .ivlen = 12 };
    memcpy(iv_op.iv, nonce, 12);
    if (ioctl(fd, CRYPTO2DEV_IOC_SET_IV, &iv_op) < 0) goto err;

    if (aadlen > 0 && aadlen <= CRYPTO2DEV_AAD_MAXLEN) {
        struct crypto2dev_aad_op aad_op = { .aadlen = (uint32_t)aadlen };
        memcpy(aad_op.aad, aad, aadlen);
        if (ioctl(fd, CRYPTO2DEV_IOC_SET_AAD, &aad_op) < 0) goto err;
    }

    struct crypto2dev_tag_op tag_op = { .taglen = 16 };
    memcpy(tag_op.tag, tag, 16);
    if (ioctl(fd, CRYPTO2DEV_IOC_SET_TAG, &tag_op) < 0) goto err;

    if (write(fd, ciphertext, len) != (ssize_t)len) goto err;
    if (ioctl(fd, CRYPTO2DEV_IOC_FINALIZE) < 0) goto err;

    ssize_t r = read(fd, plaintext, len);
    if (r < 0) {
        int saved = errno;
        close(fd);
        return -saved;   /* -EBADMSG if tag failed */
    }

    close(fd);
    return 0;

err:
    close(fd);
    return -errno;
}
```

### SHA-256 Hash

```c
int crypto2dev_sha256(const uint8_t *data, size_t len, uint8_t digest[32])
{
    int fd = open("/dev/crypto2dev", O_RDWR);
    if (fd < 0) return -1;

    struct crypto2dev_init_op init = {
        .algo   = "sha256",
        .op     = CRYPTO2DEV_OP_HASH,
        .keylen = 0,
        .key_fd = -1,
    };
    if (ioctl(fd, CRYPTO2DEV_IOC_INIT, &init) < 0) goto err;

    /* Feed data in chunks if desired */
    const size_t chunk = 65536;
    size_t off = 0;
    while (off < len) {
        size_t n = (len - off < chunk) ? len - off : chunk;
        if (write(fd, data + off, n) != (ssize_t)n) goto err;
        off += n;
    }

    if (ioctl(fd, CRYPTO2DEV_IOC_FINALIZE) < 0) goto err;
    if (read(fd, digest, 32) != 32) goto err;

    close(fd);
    return 0;

err:
    close(fd);
    return -1;
}
```

### HMAC-SHA256

```c
int crypto2dev_hmac_sha256(
    const uint8_t *key, size_t keylen,
    const uint8_t *data, size_t datalen,
    uint8_t mac[32])
{
    int fd = open("/dev/crypto2dev", O_RDWR);
    if (fd < 0) return -1;

    struct crypto2dev_init_op init = {
        .algo   = "hmac(sha256)",
        .op     = CRYPTO2DEV_OP_HASH,
        .keylen = (uint32_t)keylen,
        .key_fd = -1,
    };
    memcpy(init.key, key, keylen);
    if (ioctl(fd, CRYPTO2DEV_IOC_INIT, &init) < 0) goto err;
    explicit_bzero(init.key, sizeof(init.key));

    if (write(fd, data, datalen) != (ssize_t)datalen) goto err;
    if (ioctl(fd, CRYPTO2DEV_IOC_FINALIZE) < 0) goto err;
    if (read(fd, mac, 32) != 32) goto err;

    close(fd);
    return 0;

err:
    close(fd);
    return -1;
}
```

### ECDSA P-256 Sign (using DO_SIGN)

```c
/*
 * Sign a pre-computed SHA-256 digest using an EC P-256 private key.
 * privkey: 32-byte raw big-endian scalar
 * digest:  32-byte SHA-256 digest
 * sig:     output buffer, at least CRYPTO2DEV_SIG_MAXLEN bytes
 * siglen:  [out] actual signature length
 */
int crypto2dev_ecdsa_sign(
    const uint8_t privkey[32],
    const uint8_t digest[32],
    uint8_t *sig, uint32_t *siglen)
{
    /* Step 1: write private key bytes, then import into a KEY fd */
    int key_fd = open("/dev/crypto2dev", O_RDWR);
    if (key_fd < 0) return -1;

    if (write(key_fd, privkey, 32) != 32) {
        close(key_fd);
        return -1;
    }

    struct crypto2dev_key_import_op kiop = {
        .algo       = "ecdsa-p256",
        .provider   = "wolfssl",
        .key_type   = CRYPTO2DEV_KEY_PRIVATE,
        .exportable = 0,
        .keylen     = 32,
    };
    if (ioctl(key_fd, CRYPTO2DEV_IOC_KEY_IMPORT, &kiop) < 0) {
        close(key_fd);
        return -1;
    }

    /* Step 2: open any crypto2dev fd for the one-shot ioctl */
    int fd = open("/dev/crypto2dev", O_RDWR);
    if (fd < 0) { close(key_fd); return -1; }

    /* Step 3: sign — all inputs and outputs are in the struct */
    struct crypto2dev_sign_op sop = {
        .key_fd     = key_fd,
        .hash_algo  = "",    /* digest[] is already the SHA-256 hash */
        .digest_len = 32,
    };
    memcpy(sop.digest, digest, 32);

    if (ioctl(fd, CRYPTO2DEV_IOC_DO_SIGN, &sop) < 0) goto err;

    memcpy(sig, sop.sig, sop.sig_len);
    *siglen = sop.sig_len;

    close(key_fd);
    close(fd);
    return 0;

err:
    close(key_fd);
    close(fd);
    return -1;
}
```

### ECDH P-256 Key Agreement with HKDF (using DO_AGREE)

```c
/*
 * Generate an ephemeral P-256 key pair, perform ECDH with a peer's public
 * key, and derive 32 bytes of key material via HKDF.
 *
 * The raw ECDH shared secret Z is computed and consumed entirely inside
 * the wolfSSL provider. Only the HKDF-derived OKM is returned to userspace.
 * This is a FIPS 140-3 / SP 800-56A requirement — not optional.
 *
 * peer_pub:   65-byte uncompressed point (0x04 || X || Y)
 * our_pub:    output buffer for our ephemeral public key (65 bytes)
 * okm_out:    output buffer for 32-byte derived key material
 */
int crypto2dev_ecdh_p256(
    const uint8_t peer_pub[65],
    uint8_t our_pub[65],
    uint8_t okm_out[32])
{
    /* Step 1: generate ephemeral key pair into a KEY fd */
    int key_fd = open("/dev/crypto2dev", O_RDWR);
    if (key_fd < 0) return -1;

    struct crypto2dev_key_generate_op gen = {
        .algo       = "ecdh-p256",
        .provider   = "wolfssl",
        .exportable = 0,
    };
    if (ioctl(key_fd, CRYPTO2DEV_IOC_KEY_GENERATE, &gen) < 0) {
        close(key_fd);
        return -1;
    }

    /* Read our ephemeral public key to send to the peer */
    if (read(key_fd, our_pub, 65) != 65) { close(key_fd); return -1; }

    /* Step 2: open any crypto2dev fd for the one-shot ioctl */
    int fd = open("/dev/crypto2dev", O_RDWR);
    if (fd < 0) { close(key_fd); return -1; }

    /* Step 3: ECDH + HKDF — all inputs and outputs are in the struct.
     * Z never leaves the kernel; okm[] is the ready-to-use derived key. */
    struct crypto2dev_agree_op aop = {
        .key_fd          = key_fd,
        .peer_pubkey_len = 65,
        .salt_len        = 0,      /* 0 = use HKDF default salt */
        .info_len        = 4,
        .okm_len         = 32,     /* 256-bit derived key */
    };
    memcpy(aop.peer_pubkey, peer_pub, 65);
    memcpy(aop.info, "tls1", 4);
    if (ioctl(fd, CRYPTO2DEV_IOC_DO_AGREE, &aop) < 0) goto err;

    /* aop.okm[0..31] is the 32-byte derived key — ready to use */
    memcpy(okm_out, aop.okm, 32);

    close(key_fd);
    close(fd);
    return 0;

err:
    close(key_fd);
    close(fd);
    return -1;
}
```

---

## Algorithm Names

### Naming convention

Two formats are used, each for a distinct reason:

**`foo(bar)` — kernel crypto API names.** Symmetric ciphers, AEAD, hashes, MACs,
and KDFs use the same strings that appear in `/proc/crypto`. This is intentional:
these names are already standardized by the kernel, and callers familiar with the
Linux crypto API can use them without a translation step.

**`foo-bar` — crypto2dev asymmetric identifiers.** Asymmetric algorithms
(`ecdsa-p256`, `ecdh-p384`, `rsa-2048`, etc.) have no canonical equivalent in
`/proc/crypto`. The curve or key size is encoded in the name because it is part
of the algorithm identity — `rsa-2048` and `rsa-4096` are distinct registered
providers that cannot be used interchangeably. The dash-separated form avoids
confusion with kernel names while making the parameter explicit.

Use these exact strings in `crypto2dev_init_op.algo` (for `INIT`) or in
`crypto2dev_key_import_op.algo` / `crypto2dev_key_generate_op.algo` (for KEY fds).

### Symmetric ciphers (`CRYPTO2DEV_OP_ENCRYPT` / `CRYPTO2DEV_OP_DECRYPT`)

| Name        | Key sizes       | IV size | Notes |
|-------------|-----------------|---------|-------|
| `cbc(aes)`  | 16, 24, 32 B    | 16 B    | PKCS#7 padding is the caller's responsibility; min 16 B key (FIPS) |
| `ctr(aes)`  | 16, 24, 32 B    | 16 B    | Stream cipher; no padding needed; kcapi only — unavailable in FIPS mode |
| `xts(aes)`  | 32, 64 B (double)| 16 B   | Disk encryption; key is two concatenated AES keys; kcapi only — unavailable in FIPS mode |

### AEAD (`CRYPTO2DEV_OP_ENCRYPT` / `CRYPTO2DEV_OP_DECRYPT`)

| Name       | Key sizes    | Nonce size | Tag size | Notes |
|------------|--------------|------------|----------|-------|
| `gcm(aes)` | 16, 24, 32 B | **12 B exactly** | **16 B (min 12 B)** | FIPS 140-3 (SP 800-38D): nonce must be exactly 96 bits; tag must be at least 96 bits |

### Hashes (`CRYPTO2DEV_OP_HASH`, no key)

| Name      | Digest size | FIPS approved |
|-----------|-------------|---------------|
| `sha256`  | 32 B        | Yes           |
| `sha384`  | 48 B        | Yes           |
| `sha512`  | 64 B        | Yes           |
| `sha3-256`| 32 B        | Yes           |
| `sha3-384`| 48 B        | Yes           |
| `sha3-512`| 64 B        | Yes           |

### Keyed hashes (`CRYPTO2DEV_OP_HASH`, requires key)

| Name           | Key size  | Output size | Notes |
|----------------|-----------|-------------|-------|
| `hmac(sha256)` | any       | 32 B        | FIPS approved |
| `hmac(sha384)` | any       | 48 B        | FIPS approved |
| `hmac(sha512)` | any       | 64 B        | FIPS approved |
| `cmac(aes)`    | 16, 32 B  | 16 B        | FIPS approved |

### Asymmetric (used with `DO_SIGN` / `DO_VERIFY` / `DO_AGREE`, requires KEY fd)

| Name           | Ioctl           | Key type | Notes |
|----------------|-----------------|----------|-------|
| `ecdsa-p256`   | DO_SIGN/VERIFY  | EC P-256 | DER-encoded signature; P-256 is FIPS minimum curve |
| `ecdsa-p384`   | DO_SIGN/VERIFY  | EC P-384 | DER-encoded signature |
| `ecdh-p256`    | DO_AGREE        | EC P-256 | HKDF output in okm[]; Z never leaves kernel |
| `ecdh-p384`    | DO_AGREE        | EC P-384 | HKDF output in okm[]; Z never leaves kernel |
| `rsa-2048`     | DO_SIGN/VERIFY  | RSA      | PKCS#1 v1.5 / PSS; min 2048-bit key (FIPS, SP 800-131A) |
| `rsa-4096`     | DO_SIGN/VERIFY  | RSA      | PKCS#1 v1.5 / PSS |

Use `cat /sys/class/misc/crypto2dev/algorithms` to enumerate algorithms and
`cat /sys/class/misc/crypto2dev/providers` to see loaded providers with versions.

---

## Constants Reference

Key field-size constants defined in `<linux/crypto2dev.h>`:

| Constant | Value | Meaning |
|----------|-------|---------|
| `CRYPTO2DEV_ALGO_MAXLEN`      | 64   | Max algorithm name string length |
| `CRYPTO2DEV_PROVIDER_MAXLEN`  | 32   | Max provider name string length |
| `CRYPTO2DEV_KEY_MAXLEN`       | 128  | Max inline key size in `INIT` struct |
| `CRYPTO2DEV_IV_MAXLEN`        | 32   | Max IV / nonce buffer size |
| `CRYPTO2DEV_TAG_MAXLEN`       | 16   | Auth tag buffer size (GCM) |
| `CRYPTO2DEV_AAD_MAXLEN`       | 256  | Max AAD size for `SET_AAD` |
| `CRYPTO2DEV_HASH_MAXLEN`      | 64   | Max digest size (`sha512` = 64 B); used in `DO_SIGN`/`DO_VERIFY` |
| `CRYPTO2DEV_SIG_MAXLEN`       | 512  | Signature buffer size in `DO_SIGN`/`DO_VERIFY` |
| `CRYPTO2DEV_PUBKEY_MAXLEN`    | 256  | Public key / OKM buffer size in `DO_AGREE` |
| `CRYPTO2DEV_KEY_IMPORT_MAXLEN`| 8192 | Max key size for `KEY_IMPORT` (covers ML-DSA-87 at 4896 B) |
| `CRYPTO2DEV_KDF_SALT_MAXLEN`  | 64   | Max HKDF salt length in `DO_AGREE` |
| `CRYPTO2DEV_KDF_INFO_MAXLEN`  | 128  | Max HKDF info/label length in `DO_AGREE` |

---

## Error Reference

| `errno`       | Meaning |
|---------------|---------|
| `EACCES`      | FIPS not operational (wolfSSL provider) — check dmesg for wolfCrypt status |
| `EINVAL`      | Bad algorithm name, wrong key length, bad IV length, or invalid argument |
| `EBUSY`       | `CRYPTO2DEV_IOC_INIT`/`KEY_IMPORT`/`KEY_GENERATE`/`REQUIRE_FIPS` on an already-initialized fd |
| `ENOENT`      | No provider registered for the requested algorithm; also: `REQUIRE_FIPS` set and no FIPS provider is loaded |
| `ENODEV`      | `write()` or `read()` called before fd is initialized |
| `ENOSPC`      | `read()` buffer too small for the output |
| `EBADMSG`     | AEAD tag or signature verification failed |
| `EMSGSIZE`    | Input larger than the per-session maximum (1 MB) |
| `ENOMEM`      | Kernel allocation failed |
| `EFAULT`      | Bad userspace pointer |
| `ENOTTY`      | Unknown ioctl number |
| `EOPNOTSUPP`  | Operation not supported (e.g. provider has no key ops, or RESET not implemented) |

---

## Thread Safety

Each fd is an independent session with its own lock. Concurrent use of
**different** fds from multiple threads is safe with no additional locking.

Concurrent use of the **same** fd from multiple threads is safe at the kernel
level (the `crypto2dev_fd_state` mutex serializes access), but doing so will
produce interleaved writes and reads — the output will be meaningless. Give each
thread its own fd.

The common pattern for a multi-threaded worker pool:

```c
/* Each thread opens its own fd on startup */
void *worker_thread(void *arg)
{
    int fd = open("/dev/crypto2dev", O_RDWR);
    /* ... process work items using this fd ... */
    close(fd);
    return NULL;
}
```

---

## Gotchas

**Forgetting `SET_IV` before `write()`** — the kernel will reject the `write()`
with `EINVAL`. Always set the IV before the first write for CBC, CTR, XTS, and GCM.

**Reusing an IV with the same key in GCM/CTR** — the interface does not and
cannot enforce nonce uniqueness; enforcement is entirely the caller's
responsibility.

Nonce reuse in AES-GCM is catastrophic. Two ciphertexts encrypted under the
same key and nonce allow an attacker to recover the GHASH authentication key
(H = E_K(0^128)) using only XOR of the ciphertext streams. Once H is known:
- Every past and future ciphertext under that key can be forged — the attacker
  can produce a valid authentication tag for arbitrary chosen plaintext.
- Plaintext recovery is possible wherever the attacker knows any corresponding
  plaintext (known-plaintext attack on the keystream).

For **encrypt sessions**: use `GEN_IV`. It generates a random nonce internally
using the provider's FIPS-approved RNG and cannot reuse a prior value.

For **decrypt sessions**: `SET_IV` is required — the sender chose the nonce and
it must be reproduced exactly for decryption and tag verification. The caller
is responsible for ensuring the sender did not reuse nonces under the same key.

**CBC input not block-aligned** — `CRYPTO2DEV_IOC_FINALIZE` returns `EINVAL` if
the total data written is not a multiple of 16 bytes. The device does not pad.
Apply PKCS#7 padding before calling `write()`.

**Reading the tag before reading the ciphertext** — `GET_TAG` returns `EINVAL`
until `read()` has consumed all ciphertext output.

**Re-initializing an fd** — `CRYPTO2DEV_IOC_INIT` on an already-initialized fd
returns `EBUSY`. Use `RESET` to re-arm the same fd for a new symmetric/hash
operation, or open a new fd. `RESET` returns `EOPNOTSUPP` if the provider does
not implement it — in that case, open a new fd.

**Partial reads** — `read()` may return fewer bytes than requested if the
internal output buffer has been partially consumed. Loop until you have all
the bytes you need:

```c
size_t total = 0;
while (total < expected) {
    ssize_t r = read(fd, buf + total, expected - total);
    if (r <= 0) { /* handle error */ break; }
    total += r;
}
```

**Not zeroizing key material after `INIT`** — `init.key` sits in your process
memory. Call `explicit_bzero()` on it after the ioctl returns.

**Writing key bytes for `KEY_IMPORT` after the ioctl** — the write must come
**before** `KEY_IMPORT`, not after. The ioctl consumes the bytes that are
already in the fd's write buffer at call time.

**Not writing key bytes before `KEY_IMPORT`** — if fewer bytes have been
written than `op.keylen` specifies, `KEY_IMPORT` returns `-EINVAL`.

**AAD larger than 256 bytes** — `SET_AAD` uses an inline 256-byte buffer
(`CRYPTO2DEV_AAD_MAXLEN`). If your AAD is larger, split the message differently.
For most TLS/IPsec/DTLS headers, AAD fits comfortably.

**Passing a KEY fd of the wrong type to DO_SIGN** — `DO_SIGN` requires a
`KEY_PRIVATE` or `KEY_PAIR` key. Passing a `KEY_PUBLIC` fd returns `EOPNOTSUPP`.
`DO_VERIFY` accepts `KEY_PUBLIC`, `KEY_PRIVATE`, or `KEY_PAIR`.

**Closing the KEY fd before DO_SIGN/DO_VERIFY/DO_AGREE completes** — these
ioctls call `fget()` on `key_fd` at the start of the call, so a concurrent
`close()` from another thread will not break the ioctl. The KEY fd may be
closed once the ioctl returns.

**Setting key_fd to a non-negative value in INIT** — `key_fd` in the `INIT`
struct is reserved and must always be `-1`. Passing `key_fd >= 0` returns
`-EINVAL`. KEY fds are passed to asymmetric ioctls (`DO_SIGN`, `DO_VERIFY`,
`DO_AGREE`), not to `INIT`.

---

## Checking Module and FIPS Status

Before a batch of operations, verify the module is healthy:

```c
static int check_crypto2dev(void)
{
    int fd = open("/dev/crypto2dev", O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "crypto2dev: cannot open /dev/crypto2dev: %s\n",
                strerror(errno));
        return -1;
    }

    struct crypto2dev_status s;
    if (ioctl(fd, CRYPTO2DEV_IOC_STATUS, &s) < 0) {
        perror("CRYPTO2DEV_IOC_STATUS");
        close(fd);
        return -1;
    }
    close(fd);

    printf("crypto2dev %s | algorithms: %u | FIPS state: %u",
           s.version, s.num_algorithms, s.fips_state);

    switch (s.fips_state) {
    case CRYPTO2DEV_FIPS_NO_PROVIDER:
        printf(" (no FIPS-gated provider)\n");
        break;
    case CRYPTO2DEV_FIPS_OPERATIONAL:
        printf(" (OPERATIONAL — wolfCrypt CMVP cert active)\n");
        break;
    case CRYPTO2DEV_FIPS_NOT_OPERATIONAL:
        fprintf(stderr, " (NOT OPERATIONAL — all crypto will return EACCES)\n");
        return -1;
    }

    return 0;
}
```

---

## Compile and Link

No special libraries are needed. Include the UAPI header:

```c
#include <linux/crypto2dev.h>
```

Compile:

```bash
gcc -Wall -O2 -o myapp myapp.c
```

The header is installed to `/usr/include/linux/` by the crypto2dev package. If
building from source without installing, point the compiler at the repo:

```bash
gcc -Wall -O2 -I/path/to/crypto2dev/include/uapi -o myapp myapp.c
```
