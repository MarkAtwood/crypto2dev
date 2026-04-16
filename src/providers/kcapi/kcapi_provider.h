/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * kcapi_provider.h — internal header for the crypto2dev kernel crypto API provider
 *
 * The kcapi provider wraps the Linux kernel crypto API (crypto_alloc_skcipher,
 * crypto_alloc_ahash, crypto_alloc_aead) and presents it through the crypto2dev
 * provider vtable. Algorithm name strings are passed directly to the kernel so
 * the kernel selects the best registered implementation.
 *
 * No FIPS gate: fips_gate is NULL for all algo_ops. If the kernel is configured
 * with CONFIG_CRYPTO_FIPS, the kernel crypto subsystem enforces FIPS compliance
 * internally; crypto2dev_kcapi does not duplicate that gating.
 */

#ifndef _KCAPI_PROVIDER_H
#define _KCAPI_PROVIDER_H

#include "../../../include/crypto2dev_provider.h"

/* skcipher: cbc(aes), ctr(aes), xts(aes) */
extern const struct crypto2dev_algo_ops kcapi_cbc_aes_ops;
extern const struct crypto2dev_algo_ops kcapi_ctr_aes_ops;
extern const struct crypto2dev_algo_ops kcapi_xts_aes_ops;

/* hash: sha256, sha384, sha512, sha3-256, sha3-384, sha3-512 */
extern const struct crypto2dev_algo_ops kcapi_sha256_ops;
extern const struct crypto2dev_algo_ops kcapi_sha384_ops;
extern const struct crypto2dev_algo_ops kcapi_sha512_ops;
extern const struct crypto2dev_algo_ops kcapi_sha3_256_ops;
extern const struct crypto2dev_algo_ops kcapi_sha3_384_ops;
extern const struct crypto2dev_algo_ops kcapi_sha3_512_ops;

/* hmac: hmac(sha256), hmac(sha384), hmac(sha512) */
extern const struct crypto2dev_algo_ops kcapi_hmac_sha256_ops;
extern const struct crypto2dev_algo_ops kcapi_hmac_sha384_ops;
extern const struct crypto2dev_algo_ops kcapi_hmac_sha512_ops;

/* cmac */
extern const struct crypto2dev_algo_ops kcapi_cmac_aes_ops;

/* aead: gcm(aes) */
extern const struct crypto2dev_algo_ops kcapi_gcm_aes_ops;

/* kdf: hkdf(sha256/384/512), pbkdf2(sha256/384/512) */
extern const struct crypto2dev_algo_ops kcapi_hkdf_sha256_ops;
extern const struct crypto2dev_algo_ops kcapi_hkdf_sha384_ops;
extern const struct crypto2dev_algo_ops kcapi_hkdf_sha512_ops;
extern const struct crypto2dev_algo_ops kcapi_pbkdf2_sha256_ops;
extern const struct crypto2dev_algo_ops kcapi_pbkdf2_sha384_ops;
extern const struct crypto2dev_algo_ops kcapi_pbkdf2_sha512_ops;

#endif /* _KCAPI_PROVIDER_H */
