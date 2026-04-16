/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * crypto2dev_provider.h — provider registration API for crypto2dev
 *
 * This header is GPL-only and is NOT part of the UAPI.
 *
 * A provider is a kernel module that wraps one or more cryptographic
 * implementations and registers them with the crypto2dev framework via
 * crypto2dev_register_provider(). The framework dispatches all chardev
 * operations through the algo_ops vtable; the provider owns all
 * algorithm-specific state and memory.
 *
 * Dispatch rule: first-registered provider that handles a given algo string
 * wins per (algo, provider) pair. If a second provider registers the same
 * algo name, the registration is accepted (return 0) but a pr_warn is emitted
 * and the duplicate algo is silently dropped — the first provider keeps it.
 * The caller may request a specific provider by name in the ioctl; the
 * framework then skips non-matching providers during lookup.
 *
 * Module reference counting: crypto2dev_lookup_algo() calls try_module_get()
 * on the matching provider's owner. The returned reference must be released
 * via module_put() when the session is freed. This prevents provider module
 * unload while a session is active.
 *
 * Load orders:
 *   wolfcrypt.ko -> crypto2dev.ko -> crypto2dev_wolfssl.ko
 *   crypto2dev.ko -> crypto2dev_kcapi.ko
 */

#ifndef _CRYPTO2DEV_PROVIDER_H
#define _CRYPTO2DEV_PROVIDER_H

#include <linux/module.h>
#include <linux/list.h>
#include <linux/types.h>
#include "uapi/crypto2dev_ioctl.h"

/*
 * CRYPTO2DEV_MAX_PAYLOAD — maximum bytes a provider may buffer in its session
 * context (for batch ciphers that accumulate input during update() calls).
 * Streaming providers (hash, MAC) do not buffer and are not limited by this.
 * The framework enforces this limit at the write() layer; providers should
 * enforce it in update() as a defensive check.
 */
#define CRYPTO2DEV_MAX_PAYLOAD  (1U << 20)   /* 1 MB */

/**
 * struct crypto2dev_algo_ops - per-algorithm dispatch table
 *
 * NULL callbacks mean "not applicable for this algorithm". The framework
 * returns -EOPNOTSUPP if a caller invokes an ioctl whose callback is NULL.
 *
 * Error convention: all callbacks return kernel errno (negative on failure,
 * 0 on success). Providers must translate implementation-specific error codes
 * to kernel errno before returning.
 *
 * Locking: the framework holds the per-fd session mutex across every
 * callback invocation. Providers must not attempt to acquire the same mutex.
 * The session mutex is a regular sleeping mutex; providers may sleep.
 *
 * === KEY MANAGEMENT ===
 *
 * Providers that support asymmetric operations must implement the key_*
 * callbacks. key_import / key_generate allocate a provider-specific key
 * object (*key_ctx) and return it to the framework. The framework stores
 * key_ctx in the KEY fd's state.
 *
 * KEY fds hold asymmetric keys (RSA, EC, X25519) or symmetric keys
 * derived via CRYPTO2DEV_IOC_DO_KDF (key_type CRYPTO2DEV_KEY_SYMMETRIC).
 * For symmetric KDF-derived keys, the framework extracts the raw bytes
 * and passes them inline to sess_init() — providers do not receive a
 * key_ctx for symmetric keys; they only see the (key, keylen) pair.
 * Asymmetric KEY fds may not be passed to CRYPTO2DEV_IOC_INIT.
 *
 * === STREAMING DATA PATH ===
 *
 * Data flows through update() and finalize():
 *
 *   update()   — called on each write(). May produce output immediately
 *                (stream ciphers, partial blocks) or defer it (hash, GCM).
 *                Providers that must batch all input before producing output
 *                (e.g. SHA, GCM) return *outlen == 0 from update() and
 *                accumulate input internally in *ctx.
 *
 *   finalize() — called once when read() is issued. Produces the final output:
 *                digest bytes for hash/MAC, final ciphertext block for CBC,
 *                auth tag for GCM (returned separately via get_tag()), or
 *                signature bytes for SIGN. For verify, returns 0 bytes and
 *                -EBADMSG on authentication failure.
 *
 * The framework allocates a fixed-capacity output buffer per session and
 * passes (out, outbuf_size) to update() and finalize(). For update():
 *   out         = outbuf + bytes_already_accumulated
 *   outbuf_size = remaining_capacity
 * The provider writes at most outbuf_size bytes and sets *outlen accordingly.
 * WARN_ON fires (and -EIO is returned) if outlen > outbuf_size.
 */
struct crypto2dev_algo_ops {
	/**
	 * algo: canonical algorithm name, e.g. "cbc(aes)", "sha256".
	 * Must be a pointer to static storage valid for the lifetime of the
	 * provider module. Lookup is exact, case-sensitive string match.
	 */
	const char *algo;

	/**
	 * fips_gate: check whether the provider's FIPS boundary is operational.
	 * Called by the framework before every provider callback that touches
	 * cryptographic state (sess_init, set_iv, gen_iv, set_aad, set_tag,
	 * update, finalize, get_tag, sign, verify, agree, kdf, sess_reset,
	 * key_import, key_generate, key_export_public, key_export_private).
	 * NOT called for sess_free or key_free (cleanup must always proceed).
	 * NULL means the provider does not enforce FIPS gating.
	 * Returns 0 if operational, -EACCES if not.
	 */
	int (*fips_gate)(void);

	/**
	 * sess_init: allocate and initialize a session context.
	 * @ctx:    [out] on success: kzalloc'd provider-managed context;
	 *          on failure: must be NULL; the provider must have freed any
	 *          partial allocations before returning an error.
	 * @op:     CRYPTO2DEV_OP_ENCRYPT / DECRYPT / HASH
	 * @key:    inline key bytes (NULL and keylen==0 for un-keyed hash)
	 * @keylen: inline key length in bytes
	 *
	 * Returns 0 on success, negative errno on failure.
	 */
	int (*sess_init)(void **ctx, u32 op,
			 const u8 *key, u32 keylen);

	/**
	 * sess_free: zeroize key material and free the session context.
	 * Provider must call memzero_explicit() over all sensitive fields
	 * before kfree(). Return type is void — must not fail.
	 * Called on fd close() and on error unwind after a successful sess_init.
	 */
	void (*sess_free)(void *ctx);

	/**
	 * set_iv: set IV or nonce for the session.
	 * NULL for algorithms that do not use an IV (hash, MAC, asymmetric).
	 * Must be called after sess_init and before the first update().
	 * Returns 0 on success, negative errno on failure.
	 */
	int (*set_iv)(void *ctx, const u8 *iv, u32 ivlen);

	/**
	 * gen_iv: generate a random IV using the provider's approved DRBG.
	 * NULL means the framework falls back to get_random_bytes().
	 * For FIPS providers: call wc_RNG_GenerateBlock (wolfCrypt DRBG).
	 * For non-FIPS providers: call get_random_bytes or equivalent.
	 * The generated IV is written to @iv (exactly @ivlen bytes).
	 * The framework then calls set_iv() with the same bytes.
	 * NULL for algorithms that do not use an IV.
	 * Returns 0 on success, negative errno on failure.
	 */
	int (*gen_iv)(void *ctx, u8 *iv, u32 ivlen);

	/**
	 * set_aad: set additional authenticated data (AEAD algorithms only).
	 * NULL for non-AEAD algorithms.
	 * Provider must copy and store the AAD internally in *ctx.
	 * Must be called after set_iv and before the first update().
	 * Returns 0 on success, negative errno on failure.
	 */
	int (*set_aad)(void *ctx, const u8 *aad, u32 aadlen);

	/**
	 * set_tag: provide the expected authentication tag (AEAD decrypt only).
	 * NULL for non-AEAD algorithms and for AEAD encrypt.
	 * Must be called before the first update() for AEAD decryption.
	 * Returns 0 on success, negative errno on failure.
	 */
	int (*set_tag)(void *ctx, const u8 *tag, u32 taglen);

	/**
	 * get_tag: retrieve the authentication tag after AEAD encryption.
	 * NULL for non-AEAD algorithms and for AEAD decrypt.
	 * Must be called after a successful finalize() for AEAD encryption.
	 * Returns 0 on success, negative errno on failure.
	 */
	int (*get_tag)(void *ctx, u8 *tag, u32 *taglen);

	/**
	 * sign: one-shot asymmetric sign.
	 * Called by the framework to handle CRYPTO2DEV_IOC_DO_SIGN.
	 * @key_ctx:    key object from a KEY fd (always from this provider)
	 * @hash_algo:  name of the hash algorithm used to produce @digest
	 *              (e.g. "sha256"). Used by RSA to construct the PKCS#1 v1.5
	 *              DigestInfo prefix. May be NULL/empty for algorithms that
	 *              do not require it (e.g. raw ECDSA with an implicit hash).
	 *              The provider MUST NOT hash @digest — it is always a
	 *              pre-computed digest supplied by the caller.
	 * @digest:     pre-computed digest to sign (never a raw message)
	 * @digest_len: length of @digest in bytes
	 * @sig:        [out] output buffer for the DER-encoded signature
	 * @sig_bufsz:  capacity of @sig in bytes
	 * @sig_len:    [out] actual signature length in bytes
	 * NULL for all non-asymmetric algorithms.
	 * Returns 0 on success, -EOPNOTSUPP if not supported, other errno on error.
	 * Returns -EACCES if FIPS gating rejects the operation.
	 */
	int (*sign)(void *key_ctx, const char *hash_algo,
		    const u8 *digest, u32 digest_len,
		    u8 *sig, u32 sig_bufsz, u32 *sig_len);

	/**
	 * verify: one-shot asymmetric signature verification.
	 * Called by the framework to handle CRYPTO2DEV_IOC_DO_VERIFY.
	 * @key_ctx:    key object from a KEY fd (public key or key pair)
	 * @hash_algo:  name of the hash algorithm used to produce @digest.
	 *              Semantics identical to sign() above. The provider MUST
	 *              NOT hash @digest — it is always a pre-computed digest.
	 * @digest:     pre-computed digest (never a raw message)
	 * @digest_len: length of @digest in bytes
	 * @sig:        signature bytes to verify
	 * @sig_len:    length of @sig in bytes
	 * NULL for all non-asymmetric algorithms.
	 * Returns 0 if the signature is valid.
	 * Returns -EBADMSG if the signature does not verify.
	 * Returns -EACCES if FIPS gating rejects the operation.
	 */
	int (*verify)(void *key_ctx, const char *hash_algo,
		      const u8 *digest, u32 digest_len,
		      const u8 *sig, u32 sig_len);

	/**
	 * agree: one-shot key agreement with in-device HKDF.
	 * Called by the framework to handle CRYPTO2DEV_IOC_DO_AGREE.
	 * The provider must:
	 *   1. Compute ECDH shared secret Z from key_ctx and peer_pubkey.
	 *   2. Run HKDF (RFC 5869): Extract(salt, Z) → PRK, Expand(PRK, info, okm_len) → OKM.
	 *   3. Write exactly okm_len bytes into okm[].
	 *   4. Zeroize Z and PRK before returning.
	 * The raw Z value must never be written outside the provider.
	 * @key_ctx:         key object holding the local private key
	 * @peer_pubkey:     peer's public key bytes
	 * @peer_pubkey_len: length of peer_pubkey[] in bytes
	 * @salt:            HKDF salt (NULL or empty → RFC 5869 §2.2 default)
	 * @salt_len:        length of salt[] in bytes (0 = use default)
	 * @info:            HKDF context/info string (may be NULL or empty)
	 * @info_len:        length of info[] in bytes (0 = empty)
	 * @okm:             [out] output buffer for derived key material
	 * @okm_len:         exact number of OKM bytes to produce
	 * NULL for all non-key-agreement algorithms.
	 * Returns 0 on success, negative errno on failure.
	 */
	int (*agree)(void *key_ctx,
		     const u8 *peer_pubkey, u32 peer_pubkey_len,
		     const u8 *salt, u32 salt_len,
		     const u8 *info, u32 info_len,
		     u8 *okm, u32 okm_len);

	/**
	 * kdf: one-shot key derivation (HKDF or PBKDF2).
	 * Called by the framework to handle CRYPTO2DEV_IOC_DO_KDF.
	 * The provider derives @out_len bytes of key material and writes them to
	 * @out. This is a pure function: no per-session state; no ctx parameter.
	 *
	 * For HKDF (RFC 5869 / SP 800-56C rev2):
	 *   @ikm / @ikm_len: input keying material
	 *   @salt / @salt_len: optional salt (0-length → RFC 5869 §2.2 default)
	 *   @info / @info_len: context-specific label
	 *   @iterations: ignored (pass 0)
	 *
	 * For PBKDF2 (RFC 8018 / SP 800-132):
	 *   @ikm / @ikm_len: password bytes
	 *   @salt / @salt_len: required salt
	 *   @info / @info_len: ignored (pass NULL / 0)
	 *   @iterations: iteration count (>= 1000 enforced by the framework)
	 *
	 * @ikm:        input key material or password
	 * @ikm_len:    length of ikm in bytes (> 0)
	 * @salt:       salt bytes (may be NULL if salt_len == 0)
	 * @salt_len:   length of salt in bytes
	 * @info:       HKDF context info (may be NULL if info_len == 0)
	 * @info_len:   length of info in bytes
	 * @iterations: PBKDF2 iteration count (0 for HKDF)
	 * @out:        output buffer — exactly @out_len bytes written on success
	 * @out_len:    requested output length in bytes
	 *
	 * NULL if this algo is not a KDF.
	 * Returns 0 on success, negative errno on failure.
	 */
	int (*kdf)(const u8 *ikm, u32 ikm_len,
		   const u8 *salt, u32 salt_len,
		   const u8 *info, u32 info_len,
		   u32 iterations,
		   u8 *out, u32 out_len);

	/**
	 * min_iterations: minimum iteration count for this KDF algorithm.
	 * 0 = no minimum (HKDF has no iteration count).
	 * PBKDF2 providers set this to 1000 (SP 800-132 §5.2).
	 * The framework enforces this after ops lookup: if min_iterations > 0
	 * and op.iterations < min_iterations, DO_KDF returns -EINVAL.
	 */
	u32 min_iterations;

	/**
	 * min_salt_len: minimum salt length in bytes for this KDF algorithm.
	 * 0 = no minimum (HKDF salt is optional).
	 * PBKDF2 providers set this to 16 (SP 800-132 §5.1: >= 128 bits).
	 * The framework enforces this after ops lookup: if min_salt_len > 0
	 * and op.salt_len < min_salt_len, DO_KDF returns -EINVAL.
	 */
	u32 min_salt_len;

	/**
	 * sess_reset: re-arm a finalized session for a new operation.
	 * Called by the framework to handle CRYPTO2DEV_IOC_RESET.
	 * The implementation must reset all streaming state (digest state
	 * machines, ciphertext buffers, processed-flag) to the equivalent
	 * of a freshly completed sess_init — same key, same algorithm, but
	 * the IV is cleared and must be re-supplied via SET_IV / GEN_IV.
	 * Providers that do not support reuse should leave this NULL; the
	 * framework returns -EOPNOTSUPP.
	 * Must not fail after a successful sess_init.
	 * Returns 0 on success, negative errno on failure.
	 */
	int (*sess_reset)(void *ctx);

	/**
	 * update: consume a chunk of input and optionally produce output.
	 *
	 * Called by the framework on each write(). May produce output immediately
	 * (stream ciphers, complete cipher blocks) or produce nothing and buffer
	 * internally (hash algorithms, GCM). Either is valid.
	 *
	 * @in:          input data (kernel memory, valid for this call only)
	 * @inlen:       input length in bytes
	 * @out:         output buffer (framework-allocated; write at out[0..outbuf_size-1])
	 * @outbuf_size: available bytes at @out
	 * @outlen:      [out] bytes written to @out (must be <= outbuf_size)
	 *
	 * Returns 0 on success, negative errno on failure.
	 * If *outlen > outbuf_size the framework emits WARN_ON and returns -EIO.
	 *
	 * Providers that buffer all input internally (hash, GCM) should set
	 * *outlen = 0 and return 0.
	 */
	int (*update)(void *ctx, const u8 *in, size_t inlen,
		      u8 *out, size_t outbuf_size, size_t *outlen);

	/**
	 * finalize: flush buffered input and produce the final output.
	 *
	 * Called once by the framework when read() is invoked. Must produce all
	 * remaining output:
	 *   - Hash/MAC:       the digest bytes (e.g. 32 bytes for SHA-256)
	 *   - Symmetric enc:  final ciphertext block(s), or 0 bytes if already flushed
	 *   - Symmetric dec:  final plaintext block(s)
	 *   - AEAD enc:       ciphertext bytes; auth tag returned separately via get_tag()
	 *   - AEAD dec:       plaintext bytes; returns -EBADMSG on tag mismatch
	 *
	 * @out:         output buffer (framework-allocated)
	 * @outbuf_size: available bytes at @out
	 * @outlen:      [out] bytes written to @out (must be <= outbuf_size)
	 *
	 * Returns 0 on success.
	 * Returns -EBADMSG for AEAD authentication failure or VERIFY signature mismatch.
	 * If *outlen > outbuf_size the framework emits WARN_ON and returns -EIO.
	 *
	 * AEAD SECURITY REQUIREMENT: for AEAD decrypt, tag comparison MUST be
	 * constant-time. Do NOT use memcmp(). Delegate to wc_AesGcmDecrypt()
	 * (wolfCrypt) or crypto_aead_decrypt() (kernel AEAD) — both use
	 * constant-time comparison internally. A timing-variable comparison
	 * allows byte-by-byte tag forgery.
	 */
	int (*finalize)(void *ctx, u8 *out, size_t outbuf_size, size_t *outlen);

	/**
	 * get_finalize_output_size: return the maximum bytes finalize() may write
	 * to the output buffer. If NULL, the framework reserves
	 * CRYPTO2DEV_HASH_MAXLEN bytes. Providers that can produce more than
	 * CRYPTO2DEV_HASH_MAXLEN bytes in finalize() (e.g. batching AEAD that
	 * flushes accumulated data) MUST implement this.
	 */
	size_t (*get_finalize_output_size)(void *ctx);

	/*
	 * Key management — implement for asymmetric algorithms (ECDSA, ECDH, RSA).
	 * All NULL for symmetric ciphers, hash, HMAC, and CMAC.
	 *
	 * key_ctx is opaque to the framework. It is allocated by key_import or
	 * key_generate and freed by key_free. The framework stores it in the KEY
	 * fd's state and passes it to sess_init() when an OPERATION fd references
	 * a KEY fd. The provider may cast key_ctx to its own internal type.
	 */

	/**
	 * key_import: allocate a key_ctx and import raw key material.
	 * @key_ctx:  [out] kzalloc'd provider key object on success; NULL on failure
	 * @key_type: CRYPTO2DEV_KEY_PRIVATE, _PUBLIC, or _PAIR
	 * @raw:      raw key bytes in the format described in the UAPI header
	 * @rawlen:   length of raw key bytes
	 * NULL if this algorithm does not support key import.
	 * Returns 0 on success, negative errno on failure.
	 */
	int  (*key_import)(void **key_ctx, u32 key_type,
			   const u8 *raw, u32 rawlen);

	/**
	 * key_generate: generate a new key pair and return it as a key_ctx.
	 * @key_ctx: [out] kzalloc'd provider key object on success; NULL on failure
	 * The generated key is always a KEY_PAIR.
	 * NULL if this algorithm does not support key generation.
	 * Returns 0 on success, negative errno on failure.
	 */
	int  (*key_generate)(void **key_ctx);

	/**
	 * key_export_public: serialize the public key to raw bytes.
	 * @key_ctx: provider key object from key_import or key_generate
	 * @out:     output buffer
	 * @bufsz:   capacity of output buffer
	 * @outlen:  [out] bytes written
	 * NULL if this algorithm does not support public key export.
	 * Returns 0 on success, -ENOKEY if no public key is present.
	 */
	int  (*key_export_public)(void *key_ctx,
				  u8 *out, u32 bufsz, u32 *outlen);

	/**
	 * key_export_private: serialize the private key to raw bytes.
	 * Called only when the KEY fd was created with exportable == 1.
	 * The framework enforces the exportable check; the provider does not
	 * need to repeat it.
	 * NULL if this algorithm does not support private key export.
	 * Returns 0 on success, -ENOKEY if no private key is present.
	 */
	int  (*key_export_private)(void *key_ctx,
				   u8 *out, u32 bufsz, u32 *outlen);

	/**
	 * key_size: return the encoded key size in bytes without allocating.
	 * Optional fast path used by KEY_GET_INFO to avoid a full trial export.
	 * @key_ctx:  provider key object from key_import or key_generate
	 * @key_type: CRYPTO2DEV_KEY_PUBLIC or CRYPTO2DEV_KEY_PRIVATE
	 * Must NOT allocate memory or call wolfCrypt export functions.
	 * Returns the size in bytes, or 0 if this provider does not support
	 * the fast path for the requested key_type (framework falls back to
	 * trial export via key_export_public / key_export_private).
	 * NULL callbacks are treated as "always return 0".
	 */
	int  (*key_size)(void *key_ctx, u32 key_type);

	/**
	 * key_free: zeroize and free a key_ctx.
	 * Always called exactly once per key_import/key_generate that succeeded.
	 * Must zeroize all private key material with memzero_explicit before kfree.
	 * Must not fail. NULL if key_import and key_generate are both NULL.
	 */
	void (*key_free)(void *key_ctx);
};

/**
 * struct crypto2dev_provider - a registered crypto provider
 *
 * Embed statically in your provider module. Fill all fields before calling
 * crypto2dev_register_provider(). Do not modify any field after registration.
 *
 * Example:
 *
 *   static const struct crypto2dev_algo_ops *wolfssl_algos[] = {
 *       &wolfssl_aes_cbc_ops,
 *       &wolfssl_aes_gcm_ops,
 *       &wolfssl_sha256_ops,
 *       &wolfssl_ecdsa_p256_ops,
 *       NULL,
 *   };
 *
 *   static struct crypto2dev_provider wolfssl_provider = {
 *       .name      = "wolfssl",
 *       .algos     = wolfssl_algos,
 *       .num_algos = ARRAY_SIZE(wolfssl_algos) - 1,
 *       .owner     = THIS_MODULE,
 *   };
 */
struct crypto2dev_provider {
	/** name: human-readable provider name, e.g. "wolfssl", "kcapi". */
	const char *name;

	/**
	 * is_fips: set to 1 if this provider's algorithms are implemented
	 * inside a FIPS 140-3 validated cryptographic boundary (e.g. wolfCrypt
	 * FIPS module). Leave 0 for non-validated providers (kernel crypto API,
	 * hardware without FIPS cert, etc.).
	 *
	 * Once any provider with is_fips == 1 is registered, the framework
	 * enters FIPS mode: all algorithm lookups that would resolve to a
	 * non-FIPS provider return NULL instead, making non-FIPS crypto paths
	 * hard failures rather than silent downgrades.
	 */
	u32 is_fips;

	/**
	 * algos: array of pointers to algo_ops structs.
	 * Terminated by a NULL pointer (num_algos entries before the NULL).
	 */
	const struct crypto2dev_algo_ops **algos;

	/** num_algos: number of valid entries in algos[]. */
	u32 num_algos;

	/**
	 * owner: set to THIS_MODULE. The framework calls try_module_get(owner)
	 * when a session claims an algo from this provider, and module_put(owner)
	 * when the session is freed. This prevents rmmod while sessions are active.
	 */
	struct module *owner;

	/**
	 * version: human-readable library version string for this provider.
	 * Shown in /sys/class/misc/crypto2dev/providers alongside the provider
	 * name and FIPS flag. May be NULL (displayed as "(unknown)").
	 * Example: "wolfCrypt FIPS v5.7.0 (CMVP #4718)",
	 *          "Linux kernel crypto API 6.8.0".
	 * Do not modify after registration.
	 */
	const char *version;

	/** list: framework-internal. Do not initialize or touch. */
	struct list_head list;
};

/**
 * crypto2dev_register_provider - register a provider with the framework.
 *
 * Called from the provider module's module_init(). Multiple providers may
 * register the same algorithm; the best match for a given lookup is chosen
 * according to the FIPS enforcement rules (see crypto2dev_lookup_algo).
 *
 * If p->is_fips == 1, increments the framework's FIPS-provider counter,
 * activating FIPS enforcement for all subsequent lookups.
 *
 * Returns 0 on success, negative errno on error.
 */
int crypto2dev_register_provider(struct crypto2dev_provider *p);

/** CRYPTO2DEV_VERSION_MAXLEN: max length of a provider version string. */
#define CRYPTO2DEV_VERSION_MAXLEN  64

/**
 * struct crypto2dev_provider_info - snapshot of one registered provider.
 *
 * Filled by crypto2dev_enumerate_providers(). All strings are NUL-terminated
 * and truncated to their respective MAXLEN constants.
 */
struct crypto2dev_provider_info {
	char name   [CRYPTO2DEV_PROVIDER_MAXLEN];
	char version[CRYPTO2DEV_VERSION_MAXLEN];
	u32  is_fips;
};

/**
 * crypto2dev_fips_provider_loaded - return true if any FIPS provider is active.
 *
 * Returns true if at least one provider with is_fips == 1 is currently
 * registered. When this returns true, crypto2dev_lookup_algo() will reject
 * any algorithm that is only served by non-FIPS providers.
 */
bool crypto2dev_fips_provider_loaded(void);

/**
 * crypto2dev_enumerate_providers - snapshot all registered providers.
 *
 * Fills @buf with up to @capacity entries. If @buf is NULL or @capacity is 0,
 * no data is copied; the return value indicates the total number of providers.
 *
 * @buf:      caller-allocated array (may be NULL if capacity == 0)
 * @capacity: number of slots in @buf[]
 * Returns:   total number of registered providers (may exceed capacity)
 */
u32 crypto2dev_enumerate_providers(struct crypto2dev_provider_info *buf,
				   u32 capacity);

/**
 * crypto2dev_unregister_provider - remove a provider from the framework.
 *
 * Called from the provider module's module_exit(). Existing sessions that are
 * already dispatched through this provider hold a module reference and will
 * continue until closed; this call waits for no sessions and returns
 * immediately.
 */
void crypto2dev_unregister_provider(struct crypto2dev_provider *p);

/**
 * crypto2dev_lookup_algo - find registered ops for the named algorithm.
 *
 * If @provider is non-NULL and non-empty, only the named provider is checked.
 *
 * FIPS enforcement: if any FIPS provider (is_fips == 1) is currently loaded,
 * non-FIPS providers are skipped entirely — their algorithms are not reachable.
 * This applies even to explicit provider-name requests: specifying provider=kcapi
 * when wolfssl is loaded returns NULL. A FIPS provider must handle the algo or
 * the lookup fails.
 *
 * On success, increments the matching provider's module refcount via
 * try_module_get(). The caller is responsible for calling module_put() on
 * the returned *owner_module when the session is freed.
 *
 * @algo:              algorithm name string (e.g. "cbc(aes)")
 * @provider:          provider filter (e.g. "wolfssl"), or NULL / "" for any
 * @owner_module:      [out] set to the owning module; caller must module_put()
 * @provider_name_out: [out] set to the matched provider's name string; valid
 *                     until module_put(). May be NULL to ignore.
 * Returns the algo_ops pointer, or NULL if no matching provider is found.
 */
const struct crypto2dev_algo_ops *crypto2dev_lookup_algo(
	const char *algo, const char *provider,
	struct module **owner_module,
	const char **provider_name_out);

/**
 * crypto2dev_algo_count - return the total number of registered algorithms.
 *
 * Counts the sum of num_algos across all registered providers. Used by
 * CRYPTO2DEV_IOC_STATUS to report num_algorithms.
 */
u32 crypto2dev_algo_count(void);

/**
 * crypto2dev_enumerate_algos - fill a buffer with all registered algorithm info.
 *
 * Fills @buf with up to @capacity entries describing each registered algo.
 * If @buf is NULL or @capacity is 0, no data is copied; the return value
 * indicates the total number of registered algorithms.
 *
 * @buf:      kernel-space buffer to fill (may be NULL if capacity == 0)
 * @capacity: maximum number of entries to write into @buf
 * Returns:   total number of registered algorithms (may exceed capacity)
 *
 * Note: includes all providers, including duplicates (same algo different
 * provider). Use the provider field to distinguish.
 */
u32 crypto2dev_enumerate_algos(struct crypto2dev_algo_info *buf, u32 capacity);

/**
 * crypto2dev_fips_aggregate - aggregate FIPS state across all providers.
 *
 * Iterates all registered providers' fips_gate() callbacks:
 *   - If no provider has a fips_gate: returns CRYPTO2DEV_FIPS_NO_PROVIDER.
 *   - If all fips_gate providers return 0: returns CRYPTO2DEV_FIPS_OPERATIONAL.
 *   - If any fips_gate provider returns non-zero: returns
 *     CRYPTO2DEV_FIPS_NOT_OPERATIONAL.
 *
 * Note: this checks the aggregate state at the module level. Per-operation
 * FIPS gating is enforced independently via fips_gate() in each ops vtable.
 */
u32 crypto2dev_fips_aggregate(void);

#endif /* _CRYPTO2DEV_PROVIDER_H */
