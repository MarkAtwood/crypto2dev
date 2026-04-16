/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * wolfssl_ec_key.h — shared ECC key management declarations
 *
 * Included by wolfssl_ecdh.c and wolfssl_ecdsa.c.
 * Implementations are in wolfssl_ec_key.c (compiled once).
 *
 * Per-algo wrappers in each .c file call wolfssl_fips_gate() before
 * delegating to these functions.
 */

#ifndef _WOLFSSL_EC_KEY_H
#define _WOLFSSL_EC_KEY_H

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>

#include "../../../include/uapi/crypto2dev_ioctl.h"
#include "wolfssl_provider.h"

#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
/* Curve ID aliases — use these throughout instead of raw enum values */
#define WOLFKM_ECC_P256   ECC_SECP256R1
#define WOLFKM_ECC_P384   ECC_SECP384R1

/* P-256: 32-byte scalar, 65-byte uncompressed public point */
#define EC_P256_SCALAR_LEN  32u
#define EC_P256_PUBKEY_LEN  65u

/* P-384: 48-byte scalar, 97-byte uncompressed public point */
#define EC_P384_SCALAR_LEN  48u
#define EC_P384_PUBKEY_LEN  97u

struct wolfssl_ec_ctx {
	ecc_key key;
	WC_RNG  rng;
	int  curve_id;       /* WOLFKM_ECC_P256 or WOLFKM_ECC_P384 */
	u32  key_type;       /* CRYPTO2DEV_KEY_PRIVATE/PUBLIC/PAIR */
	u32  scalar_len;     /* 32 for P-256, 48 for P-384 */
	u32  pubkey_len;     /* 65 for P-256, 97 for P-384 */
	bool rng_inited;
	bool key_inited;
};

/* Translate a wolfCrypt error code to a kernel errno.  Implemented in
 * wolfssl_ec_key.c — one definition, one rate-limit bucket. */
int wolfssl_ec_xlat_err(int wc_err);

int wolfssl_ec_key_import(void **key_ctx, u32 key_type,
			  const u8 *raw, u32 rawlen,
			  int curve_id, u32 scalar_len,
			  u32 pubkey_len);

int wolfssl_ec_key_generate(void **key_ctx, int curve_id,
			    u32 scalar_len, u32 pubkey_len);

int wolfssl_ec_key_export_public(void *key_ctx,
				 u8 *out, u32 bufsz, u32 *outlen);

int wolfssl_ec_key_export_private(void *key_ctx,
				  u8 *out, u32 bufsz, u32 *outlen);

int wolfssl_ec_key_size(void *key_ctx, u32 key_type);

void wolfssl_ec_key_free(void *key_ctx);

#endif /* _WOLFSSL_EC_KEY_H */
