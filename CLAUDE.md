# CLAUDE.md — crypto2dev

This file provides instructions and context for AI agents working on this project.
See `DESIGN.md` for architecture, API design, and open human-action items.

## What This Is

`crypto2dev.ko` provides a `/dev/crypto2dev` chardev for userspace access to
wolfCrypt's FIPS-validated crypto. It depends on `wolfcrypt.ko` (already built,
not in this repo), which provides every crypto implementation, FIPS
POST/integrity, kernel memory allocators, and the kernel crypto API
registrations.

**crypto2dev does not register into the kernel crypto API.** That is already
done by `wolfcrypt.ko`'s linuxkm layer. This module calls wolfcrypt.ko's
exported symbols directly.

**crypto2dev does not implement any cryptography.** If you find yourself calling
anything other than a wolfCrypt function to do a crypto operation, stop.

## Agent Teams

Every non-trivial task uses parallel subagents. Set this before any
implementation session:

```bash
export CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1
```

See `AGENTS.md` for the full context-husbanding rules, standard agent team
structure (WOLFCRYPT-AUDITOR / VECTOR-FINDER / KERNEL-READER / IMPLEMENTER /
REVIEWER), parallel workstream patterns, and subagent prompt templates.

**Core rule:** never load file contents into the orchestrator context.
Locate with Grep/Glob; delegate reading to subagents; get back summaries.
State lives in beads, not in context.

## Build

```bash
# Requires wolfcrypt.ko headers and a running kernel build tree
make -C /lib/modules/$(uname -r)/build M=$(pwd) WOLFCRYPT_DIR=/path/to/wolfcrypt

# Load order is mandatory
insmod wolfcrypt.ko
insmod crypto2dev.ko
```

Without `wolfcrypt.ko` headers, only `crypto2dev.ko` and `crypto2dev_kcapi.ko`
are built (the wolfssl provider requires wolfCrypt headers).

## Kernel Testing on AWS

Kernel modules cannot be meaningfully tested without a real kernel. Use the
provided AWS script for any test that requires loading modules:

```bash
# Ubuntu 22.04 (kernel 5.15) — standard target:
./tests/ci/test-on-aws.sh <aws-profile>

# Ubuntu 24.04 (kernel 6.8):
UBUNTU_VERSION=24.04 ./tests/ci/test-on-aws.sh <aws-profile>

# Keep instance running for debugging:
KEEP_INSTANCE=1 ./tests/ci/test-on-aws.sh <aws-profile>
```

The script provisions an EC2 instance, builds wolfSSL linuxkm (wolfcrypt.ko),
uploads this repo via rsync, builds and signs both modules, loads them in
order, and runs the userspace test suite against `/dev/crypto2dev`.

For FIPS kernel testing (Ubuntu Pro + 5.15-fips kernel), adapt
`~/TICKETS/zScalar/build-test-wolfguard-aws.sh` — that script handles the
Ubuntu Pro token, the FIPS kernel reboot, and module signing for
CONFIG_MODULE_SIG_FORCE kernels.

## Quality Gates

Run all of these before closing any beads issue that changes C code:

```bash
make -C /lib/modules/$(uname -r)/build M=$(pwd) WOLFCRYPT_DIR=... 2>&1 | grep -E "error:|warning:"
sudo tests/userspace/run_tests.sh wolfcrypt.ko crypto2dev.ko
```

`make` must succeed with zero errors and zero new warnings after every commit.

## Sources of Truth

Never guess at signatures, return codes, or kernel API behavior. Read the source.

| What you need | Where to look |
|---|---|
| wolfCrypt function signatures | `$(WOLFCRYPT_DIR)/wolfssl/wolfcrypt/*.h` |
| wolfCrypt error codes | `$(WOLFCRYPT_DIR)/wolfssl/wolfcrypt/error-crypt.h` |
| wolfCrypt FIPS state | `$(WOLFCRYPT_DIR)/wolfssl/wolfcrypt/fips.h` — `wolfCrypt_GetStatus_fips()` |
| Kernel crypto API types | `/usr/src/linux/include/crypto/` |
| Algorithm naming ground truth | `/proc/crypto` on a running kernel (without crypto2dev loaded) |
| Kernel return codes | `/usr/src/linux/include/uapi/asm-generic/errno-base.h` |
| Scatter-gather API | `/usr/src/linux/include/linux/scatterlist.h` |

## Code Style

- Linux kernel coding style: tabs, K&R braces, 80-column soft limit
- Logging: `pr_info/pr_err/pr_warn/pr_debug`, always prefixed `"crypto2dev: "`
- Exported symbols: `crypto2dev_` prefix
- ioctl commands: `CRYPTO2DEV_IOC_` prefix
- Error cleanup: goto chains — use the standard kernel pattern, not early returns
- No floating point, no userspace headers (`<stdio.h>`, `<stdlib.h>`, etc.)
- No sleeping in atomic or interrupt context

## Critical Design Rules

1. **crypto2dev does NOT implement crypto.** Call wolfCrypt. Never implement an
   algorithm manually, not even as a "temporary placeholder."

2. **FIPS gate is entry #0.** *(FIPS 140-3 operational requirement — not negotiable)*

   The very first line of every crypto entry point calls `crypto2dev_fips_gate()`.
   If it returns non-zero, return that value immediately — touch nothing else.
   No exceptions. A missed gate is a FIPS compliance failure, not a bug.
   One missed gate invalidates the entire CMVP certification.

3. **Key material zeroization is mandatory.** *(FIPS 140-3 — not negotiable)*

   Use `memzero_explicit()` — not `memset()`, not `bzero()`. The compiler may
   elide a plain `memset()` when the buffer goes out of scope. Zero on every
   exit path — error paths included, not only the happy path.

4. **No enums. No flags. Ever. This is a hard rule.**

   Any patch that adds a `typedef enum`, an anonymous `enum`, a `flags`
   field, or a bitmask constant to any header or source file in this repo
   will be rejected at review, regardless of how convenient it seems.

   **Why enums are banned:**
   Enums create a closed universe. Every new algorithm, mode, or operation
   requires a header change and a recompile of every caller — including
   out-of-tree modules and userspace binaries that cannot be recompiled.
   Strings do not. `"cbc(aes)"` worked yesterday, works today, and will
   work after the next five algorithms are added.

   **Why flag bits are banned:**
   A `__u32 flags` field starts with one bit and ends with thirty-two, each
   combination untested, each interaction a future bug. Flags accumulate
   complexity that is impossible to test fully and turns into permanent ABI
   debt. Every new flag doubles the combinatorial state space. If you need
   a new behavior, add a new ioctl or a new named field. The kernel has
   hundreds of examples of flag word ABI mistakes that cannot be fixed.
   We are not adding to that list.

   **The rule, stated precisely:**
   - Algorithm identification: strings (`"cbc(aes)"`), never integer IDs
   - Provider identification: strings, never enum values
   - New UAPI behaviors: new ioctls or new explicit named fields, never flag bits
   - `typedef enum` is banned from all UAPI and internal headers
   - Anonymous `enum` used as integer constants is banned
   - `#define` integer constants (e.g. `CRYPTO2DEV_OP_ENCRYPT`) are
     acceptable ONLY for small, permanently closed sets — things whose
     full set of values is listed right there in the header and will
     never grow. Current examples: op direction (encrypt/decrypt),
     fd type (UNSET/OPERATION/KEY), key type (PUBLIC/PRIVATE/SYMMETRIC),
     FIPS state (OPERATIONAL/DEGRADED/NOT_OPERATIONAL).
     When in doubt, use a string. There is no middle ground.

   **If a reviewer or automated tool suggests adding an enum or flags field,
   the answer is no. This is a design constraint, not a preference.**

5. **KEY_IMPORT uses write-before-ioctl. Do not embed raw key bytes in ioctl structs.**

   To import an asymmetric key, the caller writes the raw key bytes to the
   fd via `write(2)`, then calls `CRYPTO2DEV_IOC_KEY_IMPORT`. The ioctl
   struct carries only metadata: algo name, key type, keylen, exportable.

   This pattern exists because asymmetric keys are large, and post-quantum
   keys are very large:

   - EC P-256 private (PKCS#8 DER): ~138 bytes
   - RSA-2048 private (PKCS#8 DER): ~1.2 KB
   - RSA-4096 private (PKCS#8 DER): ~2.4 KB
   - ML-DSA-44 private: 2560 bytes
   - ML-DSA-65 private: 4032 bytes
   - ML-DSA-87 private: 4896 bytes  ← current maximum

   Embedding key bytes in the ioctl struct would require a struct large
   enough for the worst case (currently 8192 bytes with headroom for future
   PQ schemes). That allocation lands on the kernel stack on every
   `KEY_IMPORT` call — including tiny EC key imports — and violates the
   kernel's ~1 KB stack frame guideline.

   The write-before-ioctl pattern allocates exactly what the key requires,
   on the heap, then zeroes and frees it after import. If a future PQ key
   format exceeds `CRYPTO2DEV_KEY_IMPORT_MAXLEN`, raise the constant. Do
   not change the pattern.

---

## Paranoid Defensive Programming Checklist

Every function in this module must satisfy all of the following. These rules
are adapted from the go-wolfssl project's hardened CGO wrapper discipline,
translated to kernel C reality.

### 1. FIPS gate — first, always *(FIPS 140-3 — not negotiable)*

```c
static int crypto2dev_aes_encrypt(struct skcipher_request *req)
{
    int ret;

    ret = crypto2dev_fips_gate();   /* FIRST — FIPS 140-3 requirement */
    if (ret)
        return ret;
    ...
}
```

Never add a "fast path" that skips the gate. Never call wolfCrypt before
checking the gate. The gate must be the first executable statement —
before argument validation, before lock acquisition, before anything else.
Checking FIPS status after any other work is a violation regardless of
whether the other work is "harmless".

### 2. Return code discipline — two separate conventions

wolfCrypt functions: **0 = success**, negative = wolfCrypt error code.

```c
ret = wc_AesSetKey(&ctx->aes, key, keylen, iv, dir);
if (ret != 0)       /* wolfCrypt: check != 0, not < 0 */
    goto err_zero;
```

Kernel functions: negative errno on error, 0 or positive on success.

```c
ret = crypto_register_skcipher(&crypto2dev_cbc_aes_alg);
if (ret < 0)        /* kernel: check < 0 */
    goto err_unregister;
```

Never conflate the two conventions. When translating wolfCrypt errors to kernel
errors, map explicitly:
```c
/* wolfCrypt BAD_FUNC_ARG (-173) → kernel -EINVAL */
/* wolfCrypt MEMORY_E (-125)    → kernel -ENOMEM  */
/* wolfCrypt FIPS errors        → kernel -EACCES  */
```

### 3. Initialization before use

Every wolfCrypt struct must be zero-initialized and then passed to its
`wc_XxxInit()` function before any other call. Passing an uninitialized struct
to wolfCrypt is undefined behavior.

```c
struct crypto2dev_aes_ctx {
    Aes  aes;     /* must call wc_AesInit before wc_AesSetKey */
    bool inited;
};

static int crypto2dev_skcipher_init(struct crypto_skcipher *tfm)
{
    struct crypto2dev_aes_ctx *ctx = crypto_skcipher_ctx(tfm);
    memset(ctx, 0, sizeof(*ctx));   /* kernel guarantees kzalloc, but be explicit */
    return wc_AesInit(&ctx->aes, NULL, INVALID_DEVID);
}
```

### 4. Paired Init/Free — no leaks, cleanup on every error path

Every `wc_XxxInit()` must be paired with `wc_XxxFree()`. Use goto cleanup
to ensure Free is called on every error path after a successful Init.

```c
static int crypto2dev_session_new(...)
{
    int ret;
    struct crypto2dev_session *s = kzalloc(sizeof(*s), GFP_KERNEL);
    if (!s) return -ENOMEM;

    ret = wc_AesInit(&s->aes, NULL, INVALID_DEVID);
    if (ret != 0) { kfree(s); return -ENOMEM; }

    ret = wc_AesSetKey(...);
    if (ret != 0) { wc_AesFree(&s->aes); kfree(s); return -EINVAL; }
    ...
}
```

### 5. Key material zeroization — memzero_explicit, not memset *(FIPS 140-3 — not negotiable)*

```c
static void crypto2dev_skcipher_exit(struct crypto_skcipher *tfm)
{
    struct crypto2dev_aes_ctx *ctx = crypto_skcipher_ctx(tfm);
    wc_AesFree(&ctx->aes);
    memzero_explicit(ctx, sizeof(*ctx));    /* FIPS 140-3 requirement */
}
```

Zero in `.cra_exit` / session free / error unwind paths. Zero before kfree.
The compiler may optimize away a plain `memset()` even with a volatile cast —
`memzero_explicit` is a compiler barrier that prevents this. FIPS 140-3
requires that key material be destroyed before memory is released. A reviewer
who suggests "use memset — it's cleaner" is wrong.

### 6. Buffer size validation before wolfCrypt calls

Validate output buffer sizes against header constants **before** calling into
wolfCrypt. wolfCrypt will not bounds-check your kernel buffers.

```c
/* CORRECT */
if (req->cryptlen < AES_BLOCK_SIZE)
    return -EINVAL;
if (sg_nents_for_len(req->dst, req->cryptlen) < 0)
    return -EINVAL;

/* Then call wolfCrypt */
ret = wc_AesCbcEncrypt(...);
```

Use constants from wolfCrypt headers (`AES_BLOCK_SIZE`, `WC_SHA256_DIGEST_SIZE`,
etc.) — never magic numbers.

### 7. copy_from_user / copy_to_user — check every return

In ioctl handlers, every `copy_from_user` and `copy_to_user` returns the
number of bytes NOT copied. Zero means success.

```c
if (copy_from_user(&op, uarg, sizeof(op)))
    return -EFAULT;     /* must check, partial copies are bugs */

if (copy_to_user(uarg, &status, sizeof(status)))
    return -EFAULT;
```

Never ignore these. Never proceed after a non-zero return.

### 8. Input bounds — cap userspace sizes, reject oversized inputs

```c
#define CRYPTO2DEV_CRYPT_MAX_BYTES  (1U << 20)   /* 1 MB */

if (op.len > CRYPTO2DEV_CRYPT_MAX_BYTES)
    return -EMSGSIZE;
if (op.len == 0)
    return -EINVAL;
```

Validate every user-supplied length before allocating or passing to wolfCrypt.

### 9. Null pointer checks — check every C pointer return

```c
struct crypto2dev_session *s = crypto2dev_session_get(fd_state, op.ses);
if (!s)
    return -EINVAL;     /* never dereference without checking */
```

Check every pointer returned from wolfCrypt allocation functions for NULL.
Check every pointer from `crypto_skcipher_ctx()` etc. when the context could
conceivably be uninitialized.

### 10. wolfCrypt headers are required to build the wolfssl provider

The wolfssl provider (`crypto2dev_wolfssl.ko`) calls wolfCrypt directly and
requires wolfCrypt headers. Without `WOLFCRYPT_DIR`, the Kbuild skips the
wolfssl provider entirely — only `crypto2dev.ko` and `crypto2dev_kcapi.ko`
are built.

There is no stub mode. Do not add `#ifdef CRYPTO2DEV_HAVE_WOLFCRYPT` guards;
do not add placeholder implementations that bypass wolfCrypt. If you find
yourself adding a stub, stop and use the kcapi provider for testing instead.

### 11. Thread safety — wolfCrypt structs are not thread-safe

wolfCrypt AES, SHA, HMAC, RNG, etc. structs are **not safe for concurrent use**.
Session objects include a mutex; hold it across any wolfCrypt call:

```c
mutex_lock(&session->lock);
ret = wc_AesCbcEncrypt(...);
mutex_unlock(&session->lock);
```

Do not hold a spinlock across a wolfCrypt call — wolfCrypt may sleep (kmalloc,
etc. in non-atomic context).

### 12. FIPS restrictions — note them in comments *(FIPS 140-3 — not negotiable)*

FIPS 140-3 mandates minimum key sizes and approved algorithm parameters.
These are external constraints, not internal design choices. They cannot
be relaxed. Enforce them before calling wolfCrypt, and document the
specific FIPS requirement at the call site:

```c
/* FIPS 140-3: minimum RSA key size is 2048 bits */
if (keylen < 256)
    return -EINVAL;

/* FIPS 140-3: AES minimum key size is 128 bits */
if (keylen < 16)
    return -EINVAL;

/* FIPS 140-3: GCM nonce must be 96 bits (12 bytes) */
if (ivlen != 12)
    return -EINVAL;

/* FIPS 140-3: GCM authentication tag must be at least 96 bits (12 bytes) */
if (taglen < 12)
    return -EINVAL;

/* FIPS 140-3: minimum EC curve is P-256; P-192 and smaller are not approved */
if (curve_id == ECC_SECP192R1)
    return -EINVAL;
```

Read the wolfCrypt header comments and `wc_RunAllCast_fips` coverage before
assuming a function is unrestricted in FIPS mode.

---

## Test Design Constraint

**Never use the code under test as its own oracle.** A test that encrypts with
`wc_AesCbcEncrypt` and decrypts with `wc_AesCbcDecrypt` proves nothing about
correctness.

Acceptable oracles, in priority order:
1. NIST CAVP/ACVTS published vectors (hardcoded in `tests/vectors/*.h`)
2. RFC appendix vectors (cite RFC number and section in a comment)
3. OpenSSL CLI output (cite the exact command that produced the vector)

Hardcode expected values as `static const u8[]` arrays. Tests must be fully
offline and must not call out to any external service.

Every kernel test module must verify via `/proc/crypto` that crypto2dev — not
the built-in driver — is the selected implementation for the tested algorithm.

---

## Human Task Files

When you encounter something that requires human action (CMVP lab, legal
review, manual hardware testing, distro certification), do NOT leave a TODO
comment or create a beads issue for it. Create a file:

```
human_tasks/HUMAN_TASK_NNN_short_description.md
```

with:
- **Priority**: BLOCKING | HIGH | MEDIUM | LOW
- **Role**: who needs to do this
- **Description**, **Prerequisites**, **Acceptance criteria**

Numbered sequentially. Existing tasks are 001–010; new tasks start at 011.

---

## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` for full
workflow context and commands.

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

## Session Completion

**When ending a work session**, complete ALL steps.

1. File beads issues for remaining work
2. Run quality gates (if code changed): `make`, `scripts/verify_registration.sh` (checks wolfcrypt.ko /proc/crypto registrations — prerequisite for crypto2dev tests), tests
3. Update issue status — close finished work
4. Sync:
   ```bash
   git pull --rebase
   bd dolt push
   git status
   ```
5. Report to user — state what is ready to commit/push and wait for explicit approval

**git commit and git push require explicit user approval — never run them without asking.**
