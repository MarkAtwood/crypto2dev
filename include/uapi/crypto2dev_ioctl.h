/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
/*
 * crypto2dev_ioctl.h — userspace-visible ioctl definitions for /dev/crypto2dev
 *
 * Include this header in userspace applications to interact with the
 * crypto2dev character device.
 *
 * Design notes:
 *   - No enums, no flags. Algorithm names are strings. New behaviors get
 *     new ioctls or new named fields, never a new bit in a flags word.
 *     Exception: boolean parameters such as 'exportable' are __u32 fields
 *     with exactly two values (0/1). These are not flags — they cannot
 *     accumulate, combine, or grow into bitmasks. The no-flags rule targets
 *     bitmask fields where bits compose; it does not ban boolean parameters.
 *   - Each file descriptor is an independent session. open() creates an
 *     unset fd; close() zeroizes all key material and frees all resources.
 *   - poll(2)/select(2)/epoll(2) are supported. EPOLLOUT is set when the fd
 *     is initialized and ready to accept write(2) data. EPOLLIN is set when
 *     output bytes are available for read(2). Edge-triggered epoll (EPOLLET)
 *     works correctly. O_NONBLOCK has no effect: write(2) and read(2) are
 *     synchronous and complete inline — they do not block on async crypto.
 *   - An fd is promoted to either an OPERATION fd (via CRYPTO2DEV_IOC_INIT)
 *     or a KEY fd (via CRYPTO2DEV_IOC_KEY_IMPORT or CRYPTO2DEV_IOC_KEY_GENERATE).
 *     The type is fixed once set.
 *
 * KEY fds
 * -------
 * A KEY fd holds a single asymmetric key object (RSA, EC, X25519). The
 * private key never leaves the kernel unless the key was created with
 * exportable=1. Key fds are the unit of key lifecycle: close() zeroizes
 * and frees the key.
 *
 * KEY fds hold asymmetric keys (RSA, EC, X25519) or symmetric keys derived
 * via CRYPTO2DEV_IOC_DO_KDF (key_type CRYPTO2DEV_KEY_SYMMETRIC). Symmetric
 * KEY fds may be passed to CRYPTO2DEV_IOC_INIT via the key_fd field.
 * Asymmetric KEY fds passed to INIT are rejected with -EINVAL.
 *
 * For asymmetric sign/verify/agree, pass key_fd directly to the one-shot
 * ioctl (DO_SIGN, DO_VERIFY, DO_AGREE).
 *
 * Key import: write() the raw key bytes to the fd, then call KEY_IMPORT.
 *   The keylen field specifies how many bytes from the write buffer to use.
 *   Supports keys of any size up to CRYPTO2DEV_KEY_IMPORT_MAXLEN bytes.
 *
 * Key export: call KEY_EXPORT_PRIVATE — on success the private key bytes are
 *   placed in the fd's read buffer. Read them out with read(). The returned
 *   keylen field tells the caller how many bytes are available.
 *
 * OPERATION fds (symmetric ciphers and hash/MAC)
 * -----------------------------------------------
 * The workflow is:
 *   CRYPTO2DEV_IOC_INIT  →  [CRYPTO2DEV_IOC_SET_IV]  →  write()  →  read()
 *
 * write() passes data to the provider incrementally. read() flushes any
 * buffered output and then finalizes the operation (produces the digest for
 * hash, final ciphertext block for ciphers, etc.). After the first read(),
 * subsequent read() returns 0 (EOF) and subsequent write() returns -EINVAL.
 *
 * Error recovery: if write() or read() returns an error other than -EFAULT,
 * the session is dead. Subsequent write()/read() return -EIO. Call
 * CRYPTO2DEV_IOC_RESET to recover the fd for a new operation (same key).
 * -EFAULT from write() means the user pointer was bad and nothing was
 * consumed — the session is unchanged and the call may be retried.
 * -EFAULT from read() means output data was not copied but remains buffered
 * — read() may be retried with a valid pointer.
 *
 * Asymmetric operations (ECDSA sign/verify, ECDH key agreement)
 * --------------------------------------------------------------
 * Use the one-shot ioctls CRYPTO2DEV_IOC_DO_SIGN / DO_VERIFY / DO_AGREE.
 * These are self-contained: all inputs and outputs are in the ioctl struct.
 * They can be called on any open crypto2dev fd (no INIT required).
 */

#ifndef _UAPI_CRYPTO2DEV_IOCTL_H
#define _UAPI_CRYPTO2DEV_IOCTL_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define CRYPTO2DEV_IOC_MAGIC    0xC2

/* ── Field size limits ────────────────────────────────────────────────────── */

#define CRYPTO2DEV_ALGO_MAXLEN      64
#define CRYPTO2DEV_PROVIDER_MAXLEN  32
#define CRYPTO2DEV_KEY_MAXLEN      128   /* inline key in INIT — EC fits; RSA use KEY fd */
#define CRYPTO2DEV_IV_MAXLEN        32
#define CRYPTO2DEV_TAG_MAXLEN       16
#define CRYPTO2DEV_HASH_MAXLEN      64   /* max hash output (SHA-512 = 64 bytes) */
#define CRYPTO2DEV_SIG_MAXLEN      512   /* covers RSA-4096 DER signature */
#define CRYPTO2DEV_KEY_IMPORT_MAXLEN 8192 /* max key material size: write() or export;
                                              * covers ML-DSA-87 (4896 B) and similar PQ keys */
#define CRYPTO2DEV_PUBKEY_MAXLEN    256  /* covers P-521 uncompressed (133 B) */

/* ── Operation codes (for CRYPTO2DEV_IOC_INIT only) ──────────────────────── */

/* For symmetric ciphers and AEAD */
#define CRYPTO2DEV_OP_ENCRYPT   1
#define CRYPTO2DEV_OP_DECRYPT   2

/* For hash, HMAC, CMAC */
#define CRYPTO2DEV_OP_HASH      3

/* Asymmetric sign/verify/agree: use CRYPTO2DEV_IOC_DO_SIGN / DO_VERIFY / DO_AGREE.
 * These are one-shot ioctls that carry all inputs inline — no OPERATION fd needed. */

/* ── Key type codes (used in KEY_IMPORT, KEY_GENERATE, KEY_GET_INFO) ──────── */

#define CRYPTO2DEV_KEY_PRIVATE   1   /* private key only */
#define CRYPTO2DEV_KEY_PUBLIC    2   /* public key only */
#define CRYPTO2DEV_KEY_PAIR      3   /* key pair (public + private) */
#define CRYPTO2DEV_KEY_SYMMETRIC 4   /* symmetric key derived via DO_KDF */

/* ── OPERATION fd ioctls ──────────────────────────────────────────────────── */

/*
 * CRYPTO2DEV_IOC_INIT — configure this fd for one algorithm.
 *
 * Must be called once before any write(2), read(2), or other ioctl.
 * The fd type is locked to OPERATION after this call succeeds.
 *
 * algo:      null-terminated algorithm name, e.g. "cbc(aes)", "gcm(aes)",
 *            "sha256", "hmac(sha256)".
 * provider:  preferred provider name (e.g. "wolfssl", "kcapi"). Empty
 *            string selects the first registered provider for the algorithm.
 * op:        CRYPTO2DEV_OP_ENCRYPT / DECRYPT / HASH
 * keylen:    inline key length in bytes (0 for un-keyed hash)
 * key:       inline key material
 * key_fd:    normally -1 (inline key in key[]). Set to a KEY fd holding
 *            a CRYPTO2DEV_KEY_SYMMETRIC key (from a prior DO_KDF call) to
 *            supply the session key from that fd. All other KEY fd types
 *            (asymmetric) return -EINVAL — use DO_SIGN/DO_VERIFY/DO_AGREE.
 *
 * Asymmetric operations (sign, verify, key agreement) are not performed via
 * OPERATION fds. Use CRYPTO2DEV_IOC_DO_SIGN / DO_VERIFY / DO_AGREE instead.
 *
 * Returns 0 on success.
 * Returns -ENOENT   if no provider handles the algorithm.
 * Returns -EACCES   if the provider's FIPS gate is not OPERATIONAL.
 * Returns -EINVAL   if op, keylen, or key_fd is invalid.
 * Returns -EBUSY    if the fd is already initialized.
 */
struct crypto2dev_init_op {
	char  algo    [CRYPTO2DEV_ALGO_MAXLEN];
	char  provider[CRYPTO2DEV_PROVIDER_MAXLEN];
	__u32 op;
	__u32 keylen;
	__u8  key[CRYPTO2DEV_KEY_MAXLEN];
	__s32 key_fd;          /* -1 for inline key in key[]; or KEY fd holding
				* CRYPTO2DEV_KEY_SYMMETRIC to supply session key from fd */
	__u8  _pad[4];         /* reserved; must be zero */
};

/*
 * CRYPTO2DEV_IOC_SET_IV — provide IV or nonce before write(2).
 *
 * Must be called after CRYPTO2DEV_IOC_INIT and before write(2) for
 * algorithms that require an IV (CBC, CTR, GCM, etc.).
 * Not required for hash, MAC, or asymmetric algorithms.
 */
struct crypto2dev_iv_op {
	__u8  iv[CRYPTO2DEV_IV_MAXLEN];
	__u32 ivlen;
};

/*
 * CRYPTO2DEV_IOC_GEN_IV — generate a random IV, set it on the session,
 * and return it to the caller.
 *
 * The IV is generated using the kernel CSPRNG (get_random_bytes).
 * The caller must transmit the IV alongside the ciphertext. This ioctl
 * avoids the caller having to generate and manage IVs manually.
 *
 * ivlen: [in/out] on entry: desired IV length (algorithm-specific);
 *        on return: actual IV length written. The framework fills iv[]
 *        and programs it into the session via ops->set_iv().
 *
 * Must be called after CRYPTO2DEV_IOC_INIT and before write(2).
 */
/* struct crypto2dev_iv_op is reused for GEN_IV */

/*
 * CRYPTO2DEV_IOC_SET_AAD — provide additional authenticated data (AEAD only).
 *
 * Must be called after CRYPTO2DEV_IOC_SET_IV and before write(2) for AEAD.
 * The AAD is copied inline — for typical AEAD use cases (TLS, DTLS, IPsec
 * headers), AAD fits comfortably within CRYPTO2DEV_AAD_MAXLEN bytes.
 *
 * aadlen: length of the AAD in bytes (must be > 0)
 * aad:    AAD bytes
 */
#define CRYPTO2DEV_AAD_MAXLEN  256

struct crypto2dev_aad_op {
	__u8  aad[CRYPTO2DEV_AAD_MAXLEN];
	__u32 aadlen;
};

/*
 * CRYPTO2DEV_IOC_GET_TAG — retrieve authentication tag (AEAD encrypt only).
 * Must be called after read(2) for AEAD encryption.
 */
struct crypto2dev_tag_op {
	__u8  tag[CRYPTO2DEV_TAG_MAXLEN];
	__u32 taglen;
};

/*
 * CRYPTO2DEV_IOC_SET_TAG — provide auth tag before AEAD decrypt.
 * Must be called before write(2) for AEAD decryption.
 * read(2) returns -EBADMSG if verification fails.
 */
/* struct crypto2dev_tag_op is reused */

/*
 * CRYPTO2DEV_IOC_DO_SIGN — one-shot asymmetric sign.
 *
 * Signs a pre-computed digest using the private key held in the KEY fd
 * identified by key_fd. Can be called on any open crypto2dev fd — no prior
 * CRYPTO2DEV_IOC_INIT required.
 *
 * The caller is responsible for hashing the message before calling this
 * ioctl. Use a SHA OPERATION fd (CRYPTO2DEV_IOC_INIT with algo="sha256" etc.)
 * to produce the digest, then pass it here.
 *
 * key_fd:      [in]  fd of a KEY fd holding a private key (key_type KEY_PRIVATE
 *                    or KEY_PAIR).
 * hash_algo:   [in]  name of the hash algorithm used to produce digest[]
 *                    (e.g. "sha256"). Required for RSA — used to construct the
 *                    PKCS#1 v1.5 DigestInfo prefix. May be left empty for
 *                    algorithms that do not require it. The provider does NOT
 *                    hash digest[]; it is always a pre-computed digest.
 * digest_len:  [in]  length of digest[] in bytes.
 * digest:      [in]  pre-computed digest to sign.
 * sig_len:     [out] actual signature length written to sig[].
 * sig:         [out] DER-encoded signature (ECDSA) or PKCS#1 v1.5 (RSA).
 *
 * Returns 0 on success.
 * Returns -EBADF    if key_fd is not a valid KEY fd.
 * Returns -EACCES   if FIPS gate is not OPERATIONAL or FIPS rejects the op.
 * Returns -EINVAL   if digest_len is 0 or exceeds CRYPTO2DEV_HASH_MAXLEN.
 * Returns -EOPNOTSUPP if the key's algorithm does not support signing.
 */
struct crypto2dev_sign_op {
	__s32 key_fd;
	__u8  _pad[4];
	char  hash_algo[CRYPTO2DEV_ALGO_MAXLEN];
	__u32 digest_len;
	__u8  digest[CRYPTO2DEV_HASH_MAXLEN];
	__u32 sig_len;              /* [out] */
	__u8  sig[CRYPTO2DEV_SIG_MAXLEN]; /* [out] */
};

/*
 * CRYPTO2DEV_IOC_DO_VERIFY — one-shot asymmetric signature verification.
 *
 * Verifies a signature against a pre-computed digest using the public key
 * held in the KEY fd identified by key_fd. Can be called on any open
 * crypto2dev fd.
 *
 * hash_algo and digest[] have the same semantics as DO_SIGN: digest[] is
 * always a pre-computed digest; hash_algo names the algorithm that produced
 * it (required for RSA, optional for ECDSA).
 *
 * Returns 0 if the signature is valid.
 * Returns -EBADMSG  if the signature does not verify.
 * Returns -EBADF    if key_fd is not a valid KEY fd.
 * Returns -EACCES   if FIPS gate is not OPERATIONAL.
 * Returns -EINVAL   if digest_len or sig_len is 0 or out of range.
 * Returns -EOPNOTSUPP if the key's algorithm does not support verification.
 */
struct crypto2dev_verify_op {
	__s32 key_fd;
	__u8  _pad[4];
	char  hash_algo[CRYPTO2DEV_ALGO_MAXLEN];
	__u32 digest_len;
	__u8  digest[CRYPTO2DEV_HASH_MAXLEN];
	__u32 sig_len;
	__u8  sig[CRYPTO2DEV_SIG_MAXLEN];
};

/*
 * CRYPTO2DEV_IOC_DO_AGREE — one-shot key agreement with in-device KDF.
 *
 * Performs ECDH (or X25519) key agreement, then immediately derives key
 * material using HKDF (RFC 5869 / SP 800-56C rev2 one-step KDF). The raw
 * shared secret (Z value) never leaves the kernel. The caller receives
 * ready-to-use derived key material in okm[].
 *
 * Can be called on any open crypto2dev fd. No prior INIT required.
 *
 * key_fd:         [in]  KEY fd holding the local private key.
 * peer_pubkey_len:[in]  byte length of peer_pubkey[].
 * peer_pubkey:    [in]  peer's public key (uncompressed EC point or X25519 key).
 * salt_len:       [in]  HKDF salt length (0 = RFC 5869 §2.2 default: all-zero
 *                       salt of hash-length bytes).
 * salt:           [in]  HKDF salt bytes (ignored if salt_len == 0).
 * info_len:       [in]  HKDF context info length (0 = empty).
 * info:           [in]  HKDF context/info bytes (protocol-defined label).
 * okm_len:        [in]  requested output key material length in bytes
 *                       (1..CRYPTO2DEV_PUBKEY_MAXLEN).
 * okm:            [out] derived key material (okm_len bytes).
 *
 * Returns 0 on success.
 * Returns -EBADF    if key_fd is not a valid KEY fd with a private key.
 * Returns -EACCES   if FIPS gate is not OPERATIONAL.
 * Returns -EINVAL   if any length field is out of range.
 * Returns -EOPNOTSUPP if the key's algorithm does not support key agreement.
 */

/*
 * KDF constants — used in CRYPTO2DEV_IOC_DO_KDF.
 */
#define CRYPTO2DEV_KDF_SALT_MAXLEN   64   /* covers any hash output used as salt */
#define CRYPTO2DEV_KDF_INFO_MAXLEN  256   /* covers HKDF labels and standalone KDF info */
#define CRYPTO2DEV_KDF_OKM_MAXLEN    64   /* max derived key: 64 bytes (AES-256 = 32, SHA-512 = 64) */

struct crypto2dev_agree_op {
	__s32 key_fd;
	__u8  _pad[4];
	__u32 peer_pubkey_len;
	__u8  peer_pubkey[CRYPTO2DEV_PUBKEY_MAXLEN];

	/* HKDF inputs */
	__u32 salt_len;
	__u8  salt[CRYPTO2DEV_KDF_SALT_MAXLEN];
	__u32 info_len;
	__u8  info[CRYPTO2DEV_KDF_INFO_MAXLEN];
	__u32 okm_len;                         /* [in] requested OKM length */

	__u8  okm[CRYPTO2DEV_PUBKEY_MAXLEN];   /* [out] derived key material */
};

/*
 * CRYPTO2DEV_IOC_STATUS — module-level status query.
 *
 * Does not require a prior CRYPTO2DEV_IOC_INIT. Not FIPS-gated.
 *
 * fips_state:     Aggregate FIPS state across all registered providers.
 *                 CRYPTO2DEV_FIPS_NO_PROVIDER  (0): no FIPS-gated provider loaded.
 *                 CRYPTO2DEV_FIPS_OPERATIONAL  (1): FIPS provider(s) loaded and passing.
 *                 CRYPTO2DEV_FIPS_NOT_OPERATIONAL (2): FIPS provider loaded but failing.
 * num_algorithms: total number of algorithms registered across all providers.
 * version:        crypto2dev module version string.
 */
#define CRYPTO2DEV_FIPS_NO_PROVIDER     0
#define CRYPTO2DEV_FIPS_OPERATIONAL     1
#define CRYPTO2DEV_FIPS_NOT_OPERATIONAL 2

/*
 * Note: this struct was extended with _reserved[24] (total: 64 bytes).
 * CRYPTO2DEV_IOC_STATUS encodes sizeof(struct) in the ioctl command word
 * (_IOR macro, bits 29:16). Any userspace compiled against the previous
 * 40-byte layout will receive -ENOTTY until recompiled. This is a
 * deliberate ABI break made while the interface has no external users.
 * Future additions should use _reserved bytes and avoid further breaks.
 */
struct crypto2dev_status {
	__u32 fips_state;
	__u32 num_algorithms;
	char  version[32];
	__u8  _reserved[24]; /* reserved; must be zero */
};

/*
 * CRYPTO2DEV_IOC_GET_STATE — per-fd session introspection.
 * Not FIPS-gated. Works for both OPERATION and KEY fds.
 *
 * For OPERATION fds:
 *   algo, op, initialized, bytes_written, bytes_read are populated.
 *   provider is set to the serving provider name.
 *   finalized == 1 if finalize() has been called (read() has been issued).
 *   error == 1 if an unrecoverable error occurred; fd must be closed.
 *   iv_set == 1 if SET_IV or GEN_IV has been called since last RESET.
 *   fd_type == CRYPTO2DEV_FDTYPE_OPERATION.
 *
 * For KEY fds:
 *   algo, provider, key_type, key_exportable are populated.
 *   initialized == 1 once the key is ready.
 *   fd_type == CRYPTO2DEV_FDTYPE_KEY.
 *   bytes_written, bytes_read, finalized, error, iv_set are 0.
 *   inbuf_pending is the number of bytes written before KEY_IMPORT/KEY_GENERATE.
 */
#define CRYPTO2DEV_FDTYPE_UNSET     0
#define CRYPTO2DEV_FDTYPE_OPERATION 1
#define CRYPTO2DEV_FDTYPE_KEY       2

struct crypto2dev_fd_state_info {
	__u32 fd_type;   /* CRYPTO2DEV_FDTYPE_* */
	__u32 op;        /* CRYPTO2DEV_OP_* (OPERATION fds only) */
	__u32 initialized;
	__u32 key_type;  /* CRYPTO2DEV_KEY_* (KEY fds only) */
	char  algo    [CRYPTO2DEV_ALGO_MAXLEN];
	char  provider[CRYPTO2DEV_PROVIDER_MAXLEN];
	__u64 bytes_written;
	__u64 bytes_read;
	__u64 outbuf_pending; /* bytes available for read(): outbuf_len - outbuf_drained */
	__u64 inbuf_pending;  /* bytes accumulated in inbuf (pre-INIT write data) */
	/* OPERATION fd streaming state */
	__u32 finalized; /* 1 = finalize() called; subsequent write() returns -EINVAL */
	__u32 error;     /* 1 = unrecoverable error; fd must be closed */
	__u32 iv_set;        /* 1 = IV has been set via SET_IV or GEN_IV */
	__u32 require_fips;  /* 1 = REQUIRE_FIPS was set; INIT will reject non-FIPS providers */
	__u32 key_exportable; /* 1 = private key may be exported (KEY fds only) */
	__u32 outbuf_cap;     /* current output buffer capacity in bytes (0 if not yet allocated) */
};

/* ── KEY fd ioctls ────────────────────────────────────────────────────────── */

/*
 * CRYPTO2DEV_IOC_KEY_IMPORT — promote an unset fd to a KEY fd by importing
 * existing key material.
 *
 * Caller must write() the raw key bytes to the fd before calling this ioctl.
 * The write buffer is consumed by this ioctl and cleared afterwards.
 * Supports keys of any size (RSA, ML-DSA, etc.) up to KEY_IMPORT_MAXLEN.
 *
 * Key bytes are passed via write(2) before calling this ioctl, NOT embedded
 * in this struct. Rationale: RSA-4096 PKCS#8 is ~2.4 KB, ML-DSA-87 is 4896 B.
 * Embedding key bytes in the struct would place a worst-case 8192-byte struct
 * on the kernel stack on every KEY_IMPORT call — violating the ~1 KB stack
 * frame guideline and causing stack overflow on PQ key imports.
 * The write-before-ioctl pattern allocates exactly what the key requires,
 * on the heap, then zeroizes and frees after import. Do not embed key bytes
 * in this struct.
 *
 * algo:       algorithm for which this key will be used, e.g. "ecdsa(p256)",
 *             "ecdh(p384)", "rsa-pss". This determines the expected key format.
 * provider:   provider that will own the key. Empty string = first available.
 *             Must be specified if multiple providers support the algorithm,
 *             since the key object is provider-specific.
 * key_type:   CRYPTO2DEV_KEY_PRIVATE, _PUBLIC, or _PAIR.
 * exportable: 1 = private key bytes may be retrieved via KEY_EXPORT_PRIVATE;
 *             0 = private key is non-exportable (GET returns -EACCES).
 * keylen:     number of bytes from the preceding write() to use as the key.
 *
 * Key formats:
 *   EC private key (P-256): raw 32-byte big-endian scalar
 *   EC public key  (P-256): uncompressed point: 0x04 || X(32) || Y(32) = 65 bytes
 *   EC key pair    (P-256): private scalar only (32 bytes); public key derived
 *   RSA private key:        DER-encoded PKCS#8 PrivateKeyInfo
 *   RSA public key:         DER-encoded SubjectPublicKeyInfo
 *
 * Returns 0 on success; fd is now a KEY fd.
 * Returns -EBUSY  if the fd is already initialized.
 * Returns -ENOENT if no provider handles the algorithm.
 * Returns -EOPNOTSUPP if the provider does not support key import.
 * Returns -EINVAL if key_type, keylen, or key format is invalid, or if
 *                 fewer bytes than keylen were written before this ioctl.
 */
struct crypto2dev_key_import_op {
	char  algo    [CRYPTO2DEV_ALGO_MAXLEN];
	char  provider[CRYPTO2DEV_PROVIDER_MAXLEN];
	__u32 key_type;
	__u32 exportable;
	__u32 keylen;    /* byte count from preceding write() to use as key */
	__u8  _pad[4];   /* reserved; must be zero */
};

/*
 * CRYPTO2DEV_IOC_KEY_GENERATE — promote an unset fd to a KEY fd by generating
 * a new key pair.
 *
 * The key pair is generated using the provider's CSPRNG (wolfCrypt DRBG or
 * kernel RNG). No key material needs to be supplied from userspace.
 *
 * After this call:
 *   - read() on the KEY fd returns the public key bytes.
 *   - CRYPTO2DEV_IOC_KEY_EXPORT_PRIVATE retrieves the private key (if exportable).
 *   - The key may be used in INIT via key_fd.
 *
 * Returns 0 on success; fd is now a KEY fd with key_type == KEY_PAIR.
 */
struct crypto2dev_key_generate_op {
	char  algo    [CRYPTO2DEV_ALGO_MAXLEN];
	char  provider[CRYPTO2DEV_PROVIDER_MAXLEN];
	__u32 exportable;
	__u8  _pad[4];   /* reserved; must be zero */
};

/*
 * CRYPTO2DEV_IOC_KEY_GET_INFO — query metadata about a KEY fd.
 *
 * Safe to call on any fd; returns -EINVAL if the fd is not a KEY fd
 * or the key is not yet ready.
 */
struct crypto2dev_key_info {
	char  algo          [CRYPTO2DEV_ALGO_MAXLEN];
	char  provider      [CRYPTO2DEV_PROVIDER_MAXLEN];
	__u32 key_type;      /* CRYPTO2DEV_KEY_* */
	__u32 exportable;    /* 1 if private key can be exported */
	__u32 public_key_len; /* exact byte count returned by read() */
	__u8  _pad[4];        /* reserved */
};

/*
 * CRYPTO2DEV_IOC_KEY_EXPORT_PRIVATE — retrieve the private key via read().
 *
 * Only valid on a KEY fd with exportable == 1 and key_type == KEY_PRIVATE
 * or KEY_PAIR.  Returns -EACCES if exportable == 0.
 *
 * On success, the private key bytes are placed in the fd's read buffer and
 * keylen is set to their byte count. Call read(fd, buf, keylen) to retrieve
 * them. Subsequent read() calls return the public key as usual.
 *
 * keylen: [out] number of bytes available via read().
 *
 * Key format is the same as for KEY_IMPORT (raw scalar for EC, PKCS#8 for RSA).
 */
struct crypto2dev_key_export_op {
	__u32 keylen;   /* [out] bytes available via read() */
};

/* ── Algorithm listing ────────────────────────────────────────────────────── */

/*
 * Algorithm enumeration is available via sysfs, not an ioctl.
 * Read /sys/class/misc/crypto2dev/algorithms for a newline-separated list:
 *   algo:provider:has_fips_gate:has_key_ops
 *
 * crypto2dev_algo_info is the internal type used by the provider registry
 * (crypto2dev_enumerate_algos). It is defined here because the field sizes
 * come from this header's MAXLEN constants.
 */
struct crypto2dev_algo_info {
	char  algo          [CRYPTO2DEV_ALGO_MAXLEN];
	char  provider      [CRYPTO2DEV_PROVIDER_MAXLEN];
	__u32 has_fips_gate;   /* 1 if this algo's provider enforces FIPS gating */
	__u32 has_key_ops;     /* 1 if this algo supports KEY_IMPORT / KEY_GENERATE */
};

/* ── Ioctl command numbers ─────────────────────────────────────────────────── */

/* OPERATION fd ioctls */
#define CRYPTO2DEV_IOC_INIT              _IOW(CRYPTO2DEV_IOC_MAGIC,  1, struct crypto2dev_init_op)
#define CRYPTO2DEV_IOC_SET_IV            _IOW(CRYPTO2DEV_IOC_MAGIC,  2, struct crypto2dev_iv_op)
#define CRYPTO2DEV_IOC_SET_AAD           _IOW(CRYPTO2DEV_IOC_MAGIC,  3, struct crypto2dev_aad_op)
#define CRYPTO2DEV_IOC_GET_TAG           _IOR(CRYPTO2DEV_IOC_MAGIC,  4, struct crypto2dev_tag_op)
#define CRYPTO2DEV_IOC_SET_TAG           _IOW(CRYPTO2DEV_IOC_MAGIC,  5, struct crypto2dev_tag_op)
/* slots 6 and 7: available for future assignment */
#define CRYPTO2DEV_IOC_GEN_IV            _IOWR(CRYPTO2DEV_IOC_MAGIC, 8, struct crypto2dev_iv_op)

/* Module and session status */
#define CRYPTO2DEV_IOC_STATUS            _IOR(CRYPTO2DEV_IOC_MAGIC,  9, struct crypto2dev_status)  /* v2: 64 B */
#define CRYPTO2DEV_IOC_GET_STATE         _IOR(CRYPTO2DEV_IOC_MAGIC, 10, struct crypto2dev_fd_state_info)

/* KEY fd ioctls */
#define CRYPTO2DEV_IOC_KEY_IMPORT        _IOW(CRYPTO2DEV_IOC_MAGIC, 11, struct crypto2dev_key_import_op)
#define CRYPTO2DEV_IOC_KEY_GENERATE      _IOW(CRYPTO2DEV_IOC_MAGIC, 12, struct crypto2dev_key_generate_op)
#define CRYPTO2DEV_IOC_KEY_GET_INFO      _IOR(CRYPTO2DEV_IOC_MAGIC, 13, struct crypto2dev_key_info)
#define CRYPTO2DEV_IOC_KEY_EXPORT_PRIVATE _IOWR(CRYPTO2DEV_IOC_MAGIC, 14, struct crypto2dev_key_export_op)

/* slot 15: LIST_ALGOS removed — use /sys/class/misc/crypto2dev/algorithms */

/* One-shot asymmetric operations — callable on any open crypto2dev fd */
#define CRYPTO2DEV_IOC_DO_SIGN           _IOWR(CRYPTO2DEV_IOC_MAGIC, 16, struct crypto2dev_sign_op)
#define CRYPTO2DEV_IOC_DO_VERIFY         _IOWR(CRYPTO2DEV_IOC_MAGIC, 17, struct crypto2dev_verify_op)
#define CRYPTO2DEV_IOC_DO_AGREE          _IOWR(CRYPTO2DEV_IOC_MAGIC, 18, struct crypto2dev_agree_op)

/* OPERATION fd session reset — re-arms a finalized session for a new operation */
#define CRYPTO2DEV_IOC_RESET             _IO(CRYPTO2DEV_IOC_MAGIC, 19)

/*
 * CRYPTO2DEV_IOC_REQUIRE_FIPS — require FIPS mode to be active for this fd.
 *
 * Must be called on an UNSET fd before CRYPTO2DEV_IOC_INIT. Once set, any
 * subsequent INIT returns -ENOENT if no FIPS provider (is_fips == 1) is
 * currently loaded in the registry — even if a non-FIPS provider could
 * service the requested algorithm.
 *
 * Use this when the caller must have FIPS-validated crypto and should fail
 * loudly rather than proceed with an unvalidated implementation. Without this
 * ioctl, if no FIPS provider is loaded, the lookup falls through to any
 * available non-FIPS provider. With this ioctl, that fallback is a hard error.
 *
 * Note: when at least one FIPS provider is loaded, the registry already
 * enforces FIPS-only dispatch for all lookups regardless of this flag. This
 * ioctl only matters when no FIPS provider is loaded at all.
 *
 * Returns 0 on success.
 * Returns -EBUSY if the fd is already initialized (not UNSET).
 */
#define CRYPTO2DEV_IOC_REQUIRE_FIPS      _IO(CRYPTO2DEV_IOC_MAGIC, 20)

/*
 * CRYPTO2DEV_IOC_FINALIZE — signal end-of-input for an OPERATION fd.
 *
 * Explicit finalization separates "no more input" from "drain output". The
 * typical write/read/finalize flow:
 *
 *   fd = open("/dev/crypto2dev", O_RDWR);
 *   ioctl(fd, CRYPTO2DEV_IOC_INIT, &init_op);
 *   ioctl(fd, CRYPTO2DEV_IOC_SET_IV, &iv_op);   // for ciphers
 *   write(fd, plaintext, len);                    // calls update()
 *   ioctl(fd, CRYPTO2DEV_IOC_FINALIZE);           // calls finalize()
 *   read(fd, ciphertext, sizeof(ciphertext));      // drain output
 *
 * Interleaved writes and reads are also supported:
 *   while (more_input)  { write(fd, chunk, n); read(fd, out, sizeof(out)); }
 *   ioctl(fd, CRYPTO2DEV_IOC_FINALIZE);
 *   read(fd, final_out, sizeof(final_out));   // EOF when all output drained
 *
 * For hash/HMAC/CMAC: read() before FINALIZE returns 0 bytes (providers
 * buffer all input). After FINALIZE, read() returns the digest.
 *
 * Returns 0 on success.
 * Returns -ENODEV if the fd is not an OPERATION fd.
 * Returns -EINVAL if the fd is already finalized.
 * Returns -EINVAL if IV is required but not yet set.
 * Returns -EIO if the session is in error state (prior update() failed).
 */
#define CRYPTO2DEV_IOC_FINALIZE          _IO(CRYPTO2DEV_IOC_MAGIC, 21)

/*
 * CRYPTO2DEV_IOC_DO_KDF — in-kernel key derivation (HKDF or PBKDF2).
 *
 * Derives a key from sensitive input material without exposing derived bytes
 * to userspace. On success, the fd transitions from UNSET to KEY fd; the
 * derived key is stored in the kernel as an opaque key context. The resulting
 * KEY fd may be passed as @key_fd in CRYPTO2DEV_IOC_INIT for subsequent
 * symmetric crypto sessions using @out_algo.
 *
 * SP 800-56C and SP 800-132 require KDFs to operate on keying material within
 * the FIPS module boundary. This ioctl satisfies that requirement: derived key
 * bytes exist only in kernel memory and are zeroized before the ioctl returns.
 *
 * Input key material (IKM for HKDF, password for PBKDF2) is provided one of
 * two ways:
 *   (A) write()-before-ioctl: caller writes raw bytes to the fd, then calls
 *       this ioctl. The write buffer is consumed and zeroized after the KDF.
 *   (B) ikm_fd: set ikm_fd to a KEY fd that holds the IKM. The key material
 *       is read from that fd's key_ctx; the ikm_fd is not modified. Only valid
 *       for HKDF (PBKDF2 password must be from write() — passwords are not
 *       stored as KEY fds). Set ikm_fd = -1 to use method (A).
 *
 * @algo:         KDF algorithm string: "hkdf(sha256)", "hkdf(sha384)",
 *                "pbkdf2(sha256)", "pbkdf2(sha384)", "pbkdf2(sha512)".
 *                The embedded hash name selects the HMAC primitive.
 *
 * @out_algo:     Algorithm the derived key will be used for, e.g. "cbc(aes)",
 *                "gcm(aes)", "hmac(sha256)". This is a binding label, not a
 *                hint: the resulting KEY fd may only be used in
 *                CRYPTO2DEV_IOC_INIT with op.algo == out_algo (SP 800-57 key
 *                separation). Must be a registered symmetric algorithm;
 *                asymmetric algos are not valid targets.
 *
 * @salt:         Optional salt bytes (HKDF: RFC 5869 §3.1; PBKDF2: RFC 8018
 *                §5.2). For PBKDF2, salt_len must be >= 16 bytes (SP 800-132
 *                §5.1 minimum of 128 bits). For HKDF, salt_len = 0 causes
 *                a zero-filled salt per RFC 5869 §2.2.
 *
 * @salt_len:     Length of @salt in bytes; must be <= CRYPTO2DEV_KDF_SALT_MAXLEN.
 *                For PBKDF2: must be >= 16 (SP 800-132 §5.1).
 *
 * @info:         HKDF context/application-specific label (RFC 5869 §3.2).
 *                Ignored for PBKDF2. Set info_len = 0 if not required.
 *
 * @info_len:     Length of @info in bytes; must be <= CRYPTO2DEV_KDF_INFO_MAXLEN.
 *
 * @okm_len:      Output keying material length in bytes. Must be > 0 and match
 *                the key size required by @out_algo (e.g. 16/24/32 for AES).
 *                Maximum is determined by the KDF: HKDF max = 255 × HashLen;
 *                PBKDF2 max = (2^32 - 1) × HashLen. Values beyond the
 *                maximum return -EMSGSIZE.
 *
 * @iterations:   PBKDF2 iteration count (RFC 8018 §5.2 / SP 800-132 §5.2).
 *                Must be 0 for HKDF (non-zero returns -EINVAL). Must be
 *                >= 1000 for PBKDF2 (SP 800-132 §5.2 minimum). Recommended
 *                >= 600000 per OWASP Password Storage Cheat Sheet 2023.
 *
 * @ikm_fd:       KEY fd holding IKM for HKDF, or -1 to use write() data.
 *                Must be -1 for PBKDF2 (passwords come from write() only).
 *
 * The @out_algo label is enforced: the resulting KEY fd may only be used in
 * CRYPTO2DEV_IOC_INIT with op.algo matching @out_algo exactly. Cross-algo
 * use of derived key material violates key separation (SP 800-57).
 *
 * Returns 0 on success; fd is now a KEY fd labelled with @out_algo.
 * Returns -ENODEV     if the fd is not an UNSET fd.
 * Returns -ENOENT     if no registered provider supports @algo.
 * Returns -EACCES     if FIPS gate is not OPERATIONAL.
 * Returns -EINVAL     if @algo or @out_algo is empty, or parameters are invalid.
 * Returns -EINVAL     if @iterations != 0 for HKDF.
 * Returns -EINVAL     if @iterations < 1000 for PBKDF2.
 * Returns -EINVAL     if @salt_len < 16 for PBKDF2 (SP 800-132 §5.1).
 * Returns -EINVAL     if no IKM bytes were written before this ioctl.
 * Returns -EMSGSIZE   if @okm_len > CRYPTO2DEV_KDF_OKM_MAXLEN.
 * Returns -EOPNOTSUPP if the matched provider does not implement kdf.
 * Returns -ENOMEM     on kernel allocation failure.
 *
 * Note: the @out_algo binding is enforced by CRYPTO2DEV_IOC_INIT, not here.
 * INIT returns -EINVAL if op.algo does not match the KEY fd's out_algo label.
 */

struct crypto2dev_kdf_op {
	char   algo    [CRYPTO2DEV_ALGO_MAXLEN]; /* KDF: "hkdf(sha256)", "pbkdf2(sha256)", ... */
	char   out_algo[CRYPTO2DEV_ALGO_MAXLEN]; /* target: "cbc(aes)", "gcm(aes)", ... */
	__u8   salt    [CRYPTO2DEV_KDF_SALT_MAXLEN];
	__u32  salt_len;                         /* 0 = no salt (HKDF); >= 16 for PBKDF2 */
	__u8   info    [CRYPTO2DEV_KDF_INFO_MAXLEN]; /* HKDF label; ignored for PBKDF2 */
	__u32  info_len;                         /* 0 = no info */
	__u32  okm_len;                          /* derived key length in bytes; must be > 0 */
	__u32  iterations;                       /* PBKDF2: >= 1000; HKDF: must be 0 */
	__s32  ikm_fd;                           /* KEY fd for HKDF IKM, or -1 */
	__u8   exportable;                       /* 1 = allow KEY_EXPORT_PRIVATE on the resulting fd */
	__u8   _pad[3];                          /* reserved; must be zero */
};

#define CRYPTO2DEV_IOC_DO_KDF        _IOWR(CRYPTO2DEV_IOC_MAGIC, 22, struct crypto2dev_kdf_op)

#endif /* _UAPI_CRYPTO2DEV_IOCTL_H */
