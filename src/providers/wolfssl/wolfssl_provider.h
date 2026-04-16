/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _WOLFSSL_PROVIDER_H
#define _WOLFSSL_PROVIDER_H

#include "../../../include/crypto2dev_provider.h"

int wolfssl_fips_gate(void);

extern const struct crypto2dev_algo_ops wolfssl_aes_cbc_ops;
extern const struct crypto2dev_algo_ops wolfssl_aes_gcm_ops;
extern const struct crypto2dev_algo_ops wolfssl_sha256_ops;
extern const struct crypto2dev_algo_ops wolfssl_sha384_ops;
extern const struct crypto2dev_algo_ops wolfssl_sha512_ops;
extern const struct crypto2dev_algo_ops wolfssl_sha3_256_ops;
extern const struct crypto2dev_algo_ops wolfssl_sha3_384_ops;
extern const struct crypto2dev_algo_ops wolfssl_sha3_512_ops;
extern const struct crypto2dev_algo_ops wolfssl_hmac_sha256_ops;
extern const struct crypto2dev_algo_ops wolfssl_hmac_sha384_ops;
extern const struct crypto2dev_algo_ops wolfssl_hmac_sha512_ops;
extern const struct crypto2dev_algo_ops wolfssl_cmac_aes_ops;

/* kdf: hkdf(sha256/384/512) and pbkdf2(sha256/384/512) */
extern const struct crypto2dev_algo_ops wolfssl_hkdf_sha256_ops;
extern const struct crypto2dev_algo_ops wolfssl_hkdf_sha384_ops;
extern const struct crypto2dev_algo_ops wolfssl_hkdf_sha512_ops;
extern const struct crypto2dev_algo_ops wolfssl_pbkdf2_sha256_ops;
extern const struct crypto2dev_algo_ops wolfssl_pbkdf2_sha384_ops;
extern const struct crypto2dev_algo_ops wolfssl_pbkdf2_sha512_ops;

/* rsa: PKCS#1 v1.5 sign/verify */
extern const struct crypto2dev_algo_ops wolfssl_rsa_2048_ops;
extern const struct crypto2dev_algo_ops wolfssl_rsa_4096_ops;

/* ecdh: ECDH key agreement with embedded HKDF */
extern const struct crypto2dev_algo_ops wolfssl_ecdh_p256_ops;
extern const struct crypto2dev_algo_ops wolfssl_ecdh_p384_ops;

/* ecdsa: ECDSA sign/verify */
extern const struct crypto2dev_algo_ops wolfssl_ecdsa_p256_ops;
extern const struct crypto2dev_algo_ops wolfssl_ecdsa_p384_ops;

#endif /* _WOLFSSL_PROVIDER_H */
